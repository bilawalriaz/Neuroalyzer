//! Named-entity recognition with a PII-tuned GLiNER model (gline-rs + ONNX
//! Runtime), behind the `ner` cargo feature.
//!
//! Only prose is fed to the model: user messages and tool-result text, with
//! code blocks and code-looking paragraphs skipped (see `prose.rs`). Agents
//! re-read the same content constantly, so each chunk is keyed by its BLAKE3
//! hash and inferred once per run. Inference is batched per file.

use crate::config::NerConfig;
use crate::detect::Finding;
use anyhow::{Result, bail};

/// Model: knowledgator/gliner-pii-base-v1.0 (Apache-2.0, span mode), the
/// quantised ONNX export, pinned to a commit and checked by SHA-256.
pub const MODEL_ID: &str = "knowledgator/gliner-pii-base-v1.0";
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
const MODEL_REV: &str = "61726e0ad791dcab3e29339bbec3ad42ded65641";
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
const FILES: &[(&str, &str, &str, u64)] = &[
    (
        "onnx/model_quint8.onnx",
        "model.onnx",
        "0514c8fd86d0513ce5351a3267f132b57d5bcd8f99a90d43cde1228092881d19",
        196_757_174,
    ),
    (
        "tokenizer.json",
        "tokenizer.json",
        "ee028763434d18611c1c36356ea1d050e90a9fa94ede57fac48b39f85f818ad1",
        8_649_232,
    ),
];

/// Words per chunk. The model's limit is 512 tokens including the label prompt.
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
const CHUNK_WORDS: usize = 160;
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
const BATCH: usize = 8;

pub fn model_dir() -> std::path::PathBuf {
    crate::paths::models_dir().join(MODEL_ID.replace('/', "--"))
}

#[cfg(not(feature = "ner"))]
mod imp {
    use super::*;

    pub struct Ner;

    impl Ner {
        pub fn load(_cfg: &NerConfig, _quiet: bool) -> Result<Self> {
            bail!("this build has no NER support (built with --no-default-features)")
        }
        pub fn prepare<'a>(&self, _texts: impl Iterator<Item = &'a str>) {}
        pub fn find(&self, _text: &str, _out: &mut Vec<Finding>) {}
        pub fn stats(&self) -> (u64, u64) {
            (0, 0)
        }
    }

    pub fn fetch(_quiet: bool) -> Result<()> {
        bail!("this build has no NER support. Rebuild with default features (`cargo build --release`) to use it.")
    }
}

#[cfg(feature = "ner")]
mod imp {
    use super::*;
    use crate::detect::P_NER;
    use anyhow::Context;
    use gliner::model::input::text::TextInput;
    use gliner::model::pipeline::span::SpanMode;
    use gliner::model::{GLiNER, params::Parameters};
    use orp::params::RuntimeParameters;
    use sha2::Digest;
    use std::collections::{HashMap, HashSet};
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, RwLock};

    type Spans = Arc<Vec<(u32, u32, u8)>>;

    pub struct Ner {
        model: Mutex<GLiNER<SpanMode>>,
        labels: Vec<String>,
        kinds: Vec<&'static str>,
        cache: RwLock<HashMap<[u8; 32], Spans>>,
        inferred: AtomicU64,
        hits: AtomicU64,
    }

    fn kind_for(label: &str) -> &'static str {
        match label.to_ascii_lowercase().as_str() {
            "person" | "name" | "full name" => "PERSON",
            "address" | "street address" | "location" => "ADDRESS",
            "organization" | "organisation" | "company" => "ORG",
            "date of birth" | "dob" | "birth date" => "DOB",
            other => Box::leak(
                other
                    .to_ascii_uppercase()
                    .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                    .into_boxed_str(),
            ),
        }
    }

    fn sha256_file(p: &std::path::Path) -> Result<String> {
        let mut f = std::fs::File::open(p)?;
        let mut h = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()))
    }

    fn present() -> bool {
        let d = model_dir();
        FILES
            .iter()
            .all(|(_, local, _, size)| std::fs::metadata(d.join(local)).is_ok_and(|m| m.len() == *size))
    }

    pub fn fetch(quiet: bool) -> Result<()> {
        let d = model_dir();
        crate::paths::ensure_private_dir(&d)?;
        for (remote, local, sha, size) in FILES {
            let target = d.join(local);
            if std::fs::metadata(&target).is_ok_and(|m| m.len() == *size) && sha256_file(&target)? == *sha {
                if !quiet {
                    eprintln!("{local} is already downloaded and verified.");
                }
                continue;
            }
            let url = format!("https://huggingface.co/{MODEL_ID}/resolve/{MODEL_REV}/{remote}");
            if !quiet {
                eprintln!(
                    "Downloading {local} ({}) from Hugging Face...",
                    crate::report::human(*size)
                );
            }
            let resp = ureq::get(&url).call().with_context(|| {
                format!("couldn't download {url}. Check your network or proxy, then run `sesscrub model fetch`.")
            })?;
            let mut reader = resp.into_body().into_reader();
            let tmp = d.join(format!("{local}.partial"));
            let mut f = std::fs::File::create(&tmp)?;
            let pb = if quiet {
                indicatif::ProgressBar::hidden()
            } else {
                indicatif::ProgressBar::new(*size)
            };
            pb.set_style(
                indicatif::ProgressStyle::with_template("  [{bar:30}] {bytes}/{total_bytes} {bytes_per_sec}")
                    .unwrap()
                    .progress_chars("=> "),
            );
            let mut h = sha2::Sha256::new();
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = reader.read(&mut buf).context("download interrupted")?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
                f.write_all(&buf[..n])?;
                pb.inc(n as u64);
            }
            pb.finish_and_clear();
            f.sync_all()?;
            let got = hex::encode(h.finalize());
            if got != *sha {
                let _ = std::fs::remove_file(&tmp);
                bail!("{local} failed its SHA-256 check (expected {sha}, got {got}). Nothing was kept.");
            }
            std::fs::rename(&tmp, &target)?;
        }
        if !quiet {
            eprintln!("NER model ready in {}", d.display());
        }
        Ok(())
    }

    impl Ner {
        pub fn load(cfg: &NerConfig, quiet: bool) -> Result<Self> {
            if !present() {
                if std::env::var_os("SESSCRUB_NO_DOWNLOAD").is_some() {
                    bail!("the NER model isn't downloaded. Run `sesscrub model fetch`, or use --no-ner");
                }
                if !quiet {
                    eprintln!("The NER model isn't downloaded yet; fetching it once (about 205 MB).");
                }
                fetch(quiet)?;
            }
            if cfg.labels.is_empty() || cfg.labels.len() > 250 {
                bail!("ner.labels must list between 1 and 250 labels");
            }
            let d = model_dir();
            let params = Parameters::default()
                .with_threshold(cfg.threshold)
                .with_max_length(Some(512));
            let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
            let rt = RuntimeParameters::default().with_threads(threads);
            let model = GLiNER::<SpanMode>::new(params, rt, d.join("tokenizer.json"), d.join("model.onnx"))
                .map_err(|e| anyhow::anyhow!("couldn't load the NER model: {e}"))?;
            Ok(Self {
                model: Mutex::new(model),
                kinds: cfg.labels.iter().map(|l| kind_for(l)).collect(),
                labels: cfg.labels.clone(),
                cache: RwLock::new(HashMap::new()),
                inferred: AtomicU64::new(0),
                hits: AtomicU64::new(0),
            })
        }

        fn infer(&self, chunks: &[(&str, [u8; 32])]) {
            for batch in chunks.chunks(BATCH) {
                let m = self.model.lock().unwrap();
                // Another thread may have inferred these while we waited for the model.
                let batch: Vec<(&str, [u8; 32])> = {
                    let cache = self.cache.read().unwrap();
                    batch.iter().filter(|(_, h)| !cache.contains_key(h)).copied().collect()
                };
                if batch.is_empty() {
                    continue;
                }
                let texts: Vec<String> = batch.iter().map(|(t, _)| t.to_string()).collect();
                let Ok(input) = TextInput::new(texts, self.labels.clone()) else {
                    continue;
                };
                let out = m.inference(input);
                drop(m);
                let Ok(out) = out else { continue };
                let mut cache = self.cache.write().unwrap();
                for (i, (_, h)) in batch.iter().enumerate() {
                    let spans: Vec<(u32, u32, u8)> = out
                        .spans
                        .get(i)
                        .map(|v| {
                            v.iter()
                                .filter_map(|s| {
                                    let (a, b) = s.offsets();
                                    let li = self.labels.iter().position(|l| l == s.class())?;
                                    Some((a as u32, b as u32, li as u8))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    cache.insert(*h, Arc::new(spans));
                }
                self.inferred.fetch_add(batch.len() as u64, Ordering::Relaxed);
            }
        }

        /// Infer every unseen chunk of these texts, batched.
        pub fn prepare<'a>(&self, texts: impl Iterator<Item = &'a str>) {
            let mut pending: Vec<(&str, [u8; 32])> = vec![];
            let mut seen: HashSet<[u8; 32]> = HashSet::new();
            let texts: Vec<&str> = texts.collect();
            {
                let cache = self.cache.read().unwrap();
                for t in &texts {
                    for (s, e) in crate::prose::chunks(t, CHUNK_WORDS) {
                        let c = &t[s..e];
                        let h = *blake3::hash(c.as_bytes()).as_bytes();
                        if !cache.contains_key(&h) && seen.insert(h) {
                            pending.push((c, h));
                        }
                    }
                }
            }
            if !pending.is_empty() {
                self.infer(&pending);
            }
        }

        pub fn find(&self, text: &str, out: &mut Vec<Finding>) {
            for (s, e) in crate::prose::chunks(text, CHUNK_WORDS) {
                let c = &text[s..e];
                let h = *blake3::hash(c.as_bytes()).as_bytes();
                let cached = self.cache.read().unwrap().get(&h).cloned();
                let spans = match cached {
                    Some(sp) => {
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        sp
                    }
                    None => {
                        self.infer(&[(c, h)]);
                        match self.cache.read().unwrap().get(&h).cloned() {
                            Some(sp) => sp,
                            None => continue,
                        }
                    }
                };
                for &(a, b, li) in spans.iter() {
                    let (a, b) = (s + a as usize, s + b as usize);
                    if b <= text.len() && a < b && text.is_char_boundary(a) && text.is_char_boundary(b) {
                        out.push(Finding {
                            start: a,
                            end: b,
                            kind: self.kinds[li as usize],
                            detector: "ner",
                            prio: P_NER,
                        });
                    }
                }
            }
        }

        pub fn stats(&self) -> (u64, u64) {
            (self.inferred.load(Ordering::Relaxed), self.hits.load(Ordering::Relaxed))
        }
    }
}

pub use imp::{Ner, fetch};
