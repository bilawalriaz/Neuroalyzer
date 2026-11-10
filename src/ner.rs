//! Named-entity recognition with a PII-tuned GLiNER model (gline-rs + ONNX
//! Runtime), behind the `ner` cargo feature.
//!
//! Only prose is fed to the model: user messages and tool-result text, with
//! code blocks and code-looking paragraphs skipped (see `prose.rs`). Agents
//! re-read the same content constantly, so each chunk is keyed by its BLAKE3
//! hash and inferred once.
//!
//! A run works corpus-wide in three stages (driven by `run.rs`):
//!
//! 1. collect: walk every file the way redaction will, and record each prose
//!    chunk that has no cached result, deduplicated across the whole corpus;
//! 2. infer: run the model over the unique chunks, longest first, on a pool of
//!    workers that share one model (no lock: ONNX Runtime sessions allow
//!    concurrent runs);
//! 3. apply: redaction looks every chunk up in the cache.
//!
//! Text collected in stage 1 is capped (`COLLECT_BUDGET`); a corpus with more
//! uncached prose than that is processed in several rounds.

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

/// Most chunk text held in memory between the collect and infer stages.
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
const COLLECT_BUDGET: u64 = 1 << 30;

pub fn model_dir() -> std::path::PathBuf {
    crate::paths::models_dir().join(MODEL_ID.replace('/', "--"))
}

/// Where inference runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Device {
    /// Pick the fastest available. CPU unless a GPU provider was compiled in
    /// and loads; CoreML is opt-in (it measured slower than CPU for this model).
    #[default]
    Auto,
    Cpu,
    CoreMl,
    Cuda,
    DirectMl,
}

impl std::str::FromStr for Device {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Device::Auto),
            "cpu" => Ok(Device::Cpu),
            "coreml" => Ok(Device::CoreMl),
            "cuda" => Ok(Device::Cuda),
            "directml" | "dml" => Ok(Device::DirectMl),
            other => Err(format!(
                "unknown NER device '{other}' (auto, cpu, coreml, cuda, directml)"
            )),
        }
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Device::Auto => "auto",
            Device::Cpu => "cpu",
            Device::CoreMl => "coreml",
            Device::Cuda => "cuda",
            Device::DirectMl => "directml",
        })
    }
}

/// How the model runs: `sessions` workers, each with `threads` intra-op
/// threads, sending `batch` chunks per call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Runtime {
    pub sessions: usize,
    pub threads: usize,
    pub batch: usize,
    pub device: Device,
}

impl Runtime {
    /// Defaults for this machine: one single-threaded worker per physical
    /// core. On an M3 Pro (6P+6E), 12 x 1 ran 1.5x faster than one session
    /// with 6 threads, and beat 6 x 1, 8 x 1 and 3 x 2: the model has an LSTM,
    /// which parallelises poorly within a call, so whole calls in parallel
    /// win, and efficiency cores add throughput when nothing waits on them.
    pub fn auto(cores: &crate::hw::Cores) -> Self {
        Runtime {
            sessions: cores.physical().max(1),
            threads: 1,
            batch: 1,
            device: Device::Auto,
        }
    }
}

/// Chunks gathered by the collect stage.
#[derive(Default)]
pub struct Pending {
    pub chunks: Vec<([u8; 32], Box<str>)>,
    /// False when the collect budget filled up; collect again after inferring.
    pub complete: bool,
}

/// Rough model-word count: the GLiNER splitter emits word runs and single
/// punctuation marks. Used for scheduling and progress, not for chunking.
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
fn work_units(s: &str) -> u64 {
    let mut n = 0u64;
    let mut in_word = false;
    for c in s.chars() {
        if c.is_alphanumeric() || (in_word && (c == '_' || c == '-')) {
            if !in_word {
                n += 1;
                in_word = true;
            }
        } else {
            in_word = false;
            if !c.is_whitespace() {
                n += 1;
            }
        }
    }
    n.max(1)
}

#[cfg(not(feature = "ner"))]
mod imp {
    use super::*;

    pub struct Ner;

    impl Ner {
        pub fn load(_cfg: &NerConfig, _rt: Runtime, _quiet: bool) -> Result<Self> {
            bail!("this build has no NER support (built with --no-default-features)")
        }
        pub fn find(&self, _text: &str, _out: &mut Vec<Finding>) {}
        pub fn collecting(&self) -> bool {
            false
        }
        pub fn begin_collect(&self) {}
        pub fn end_collect(&self) -> Pending {
            Pending {
                complete: true,
                ..Default::default()
            }
        }
        pub fn infer_all(&self, _p: Pending, _pb: &indicatif::ProgressBar) {}
        pub fn stats(&self) -> (u64, u64) {
            (0, 0)
        }
        pub fn describe(&self) -> String {
            String::new()
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
    use composable::Composable;
    use gliner::model::input::text::TextInput;
    use gliner::model::params::Parameters;
    use gliner::model::pipeline::span::{SpanMode, SpanPipeline};
    use orp::pipeline::Pipeline;
    use ort::session::{Session, builder::GraphOptimizationLevel};
    use sha2::Digest;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::{Duration, Instant};

    type Spans = Arc<Vec<(u32, u32, u8)>>;
    type Hash = [u8; 32];

    const SHARDS: usize = 64;

    /// A map split by the first hash byte, so worker threads rarely contend.
    struct Sharded<V>(Vec<RwLock<HashMap<Hash, V>>>);

    impl<V: Clone> Sharded<V> {
        fn new() -> Self {
            Sharded((0..SHARDS).map(|_| RwLock::new(HashMap::new())).collect())
        }
        fn shard(&self, h: &Hash) -> &RwLock<HashMap<Hash, V>> {
            &self.0[h[0] as usize % SHARDS]
        }
        fn get(&self, h: &Hash) -> Option<V> {
            self.shard(h).read().unwrap().get(h).cloned()
        }
        fn contains(&self, h: &Hash) -> bool {
            self.shard(h).read().unwrap().contains_key(h)
        }
        fn insert(&self, h: Hash, v: V) -> bool {
            self.shard(&h).write().unwrap().insert(h, v).is_none()
        }
        fn drain(&self) -> Vec<(Hash, V)> {
            self.0
                .iter()
                .flat_map(|s| s.write().unwrap().drain().collect::<Vec<_>>())
                .collect()
        }
    }

    pub struct Ner {
        sessions: Vec<Session>,
        pipeline: SpanMode,
        params: Parameters,
        rt: Runtime,
        device: Device,
        labels: Vec<String>,
        kinds: Vec<&'static str>,
        cache: Sharded<Spans>,
        collecting: AtomicBool,
        pending: Sharded<Arc<str>>,
        pending_bytes: AtomicU64,
        overflow: AtomicBool,
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
                format!("couldn't download {url}. Check your network or proxy, then run `neuroalyzer model fetch`.")
            })?;
            let reader = resp.into_body().into_reader();
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
            let r = crate::fsutil::install_verified(&d, local, reader, sha, |n| pb.inc(n));
            pb.finish_and_clear();
            r?;
        }
        if !quiet {
            eprintln!("NER model ready in {}", d.display());
        }
        Ok(())
    }

    fn build_session(
        path: &std::path::Path,
        threads: usize,
        device: Device,
        prepacked: &ort::session::builder::PrepackedWeights,
    ) -> Result<(Session, Device)> {
        let base = || -> Result<ort::session::builder::SessionBuilder> {
            Ok(Session::builder()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(threads)?
                .with_inter_threads(1)?
                // Spinning burned a third of all CPU in profiles: workers wait
                // on each other between short ops. Block instead.
                .with_intra_op_spinning(false)?
                .with_inter_op_spinning(false)?
                .with_prepacked_weights(prepacked)?)
        };
        let try_ep = |ep: ort::execution_providers::ExecutionProviderDispatch| -> Result<Session> {
            Ok(base()?
                .with_execution_providers([ep.error_on_failure()])?
                .commit_from_file(path)?)
        };
        let _ = &try_ep;
        match device {
            Device::Auto | Device::Cpu => {}
            #[cfg(feature = "coreml")]
            Device::CoreMl => {
                use ort::execution_providers::CoreMLExecutionProvider;
                let s = try_ep(CoreMLExecutionProvider::default().with_subgraphs().build())
                    .context("couldn't start the CoreML execution provider")?;
                return Ok((s, Device::CoreMl));
            }
            #[cfg(feature = "cuda")]
            Device::Cuda => {
                use ort::execution_providers::CUDAExecutionProvider;
                let s = try_ep(CUDAExecutionProvider::default().build())
                    .context("couldn't start the CUDA execution provider")?;
                return Ok((s, Device::Cuda));
            }
            #[cfg(feature = "directml")]
            Device::DirectMl => {
                use ort::execution_providers::DirectMLExecutionProvider;
                let s = try_ep(DirectMLExecutionProvider::default().build())
                    .context("couldn't start the DirectML execution provider")?;
                return Ok((s, Device::DirectMl));
            }
            #[allow(unreachable_patterns)]
            other => {
                bail!("this build has no {other} support. Rebuild with `--features {other}`, or use --ner-device cpu")
            }
        }
        if device == Device::Auto {
            #[cfg(feature = "cuda")]
            {
                use ort::execution_providers::CUDAExecutionProvider;
                if let Ok(s) = try_ep(CUDAExecutionProvider::default().build()) {
                    return Ok((s, Device::Cuda));
                }
            }
            #[cfg(feature = "directml")]
            {
                use ort::execution_providers::DirectMLExecutionProvider;
                if let Ok(s) = try_ep(DirectMLExecutionProvider::default().build()) {
                    return Ok((s, Device::DirectMl));
                }
            }
        }
        Ok((base()?.commit_from_file(path)?, Device::Cpu))
    }

    impl Ner {
        pub fn load(cfg: &NerConfig, rt: Runtime, quiet: bool) -> Result<Self> {
            if !present() {
                if std::env::var_os(crate::paths::env_name("NO_DOWNLOAD")).is_some() {
                    bail!(
                        "the NER model isn't downloaded. Run `{} model fetch`, or use --no-ner",
                        env!("CARGO_PKG_NAME")
                    );
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
            let pipeline = SpanPipeline::new(d.join("tokenizer.json"))
                .map_err(|e| anyhow::anyhow!("couldn't load the NER tokenizer: {e}"))?;
            let rt = Runtime {
                sessions: rt.sessions.max(1),
                threads: rt.threads.max(1),
                batch: rt.batch.max(1),
                device: rt.device,
            };
            // Single-threaded workers on CPU share one session: ONNX Runtime
            // allows concurrent runs, each on its caller's thread, and the
            // weights are loaded once. Multi-threaded workers each need their
            // own intra-op pool, so they get their own session (sharing
            // prepacked weights).
            let prepacked = ort::session::builder::PrepackedWeights::new();
            let model = d.join("model.onnx");
            let (first, device) = build_session(&model, rt.threads, rt.device, &prepacked)
                .map_err(|e| anyhow::anyhow!("couldn't load the NER model: {e:#}"))?;
            let n = if rt.threads == 1 && device == Device::Cpu {
                1
            } else {
                rt.sessions
            };
            let mut sessions = vec![first];
            for _ in 1..n {
                sessions.push(
                    build_session(&model, rt.threads, device, &prepacked)
                        .map_err(|e| anyhow::anyhow!("couldn't load the NER model: {e:#}"))?
                        .0,
                );
            }
            Ok(Self {
                sessions,
                pipeline,
                params,
                rt,
                device,
                kinds: cfg.labels.iter().map(|l| kind_for(l)).collect(),
                labels: cfg.labels.clone(),
                cache: Sharded::new(),
                collecting: AtomicBool::new(false),
                pending: Sharded::new(),
                pending_bytes: AtomicU64::new(0),
                overflow: AtomicBool::new(false),
                inferred: AtomicU64::new(0),
                hits: AtomicU64::new(0),
            })
        }

        /// The runtime plan actually in use, for `-v`.
        pub fn describe(&self) -> String {
            format!(
                "{} worker{} x {} thread{}, {} session{}, batch {}, device {}",
                self.rt.sessions,
                if self.rt.sessions == 1 { "" } else { "s" },
                self.rt.threads,
                if self.rt.threads == 1 { "" } else { "s" },
                self.sessions.len(),
                if self.sessions.len() == 1 { "" } else { "s" },
                self.rt.batch,
                self.device
            )
        }

        /// Run the model on a batch of chunks; one result per input.
        fn run(&self, session: &Session, texts: &[&str]) -> Result<Vec<Vec<(u32, u32, u8)>>> {
            let input = TextInput::new(texts.iter().map(|t| t.to_string()).collect(), self.labels.clone())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let (inputs, ctx) = self
                .pipeline
                .pre_processor(&self.params)
                .apply(input)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let outputs = session.run(inputs)?;
            let out = self
                .pipeline
                .post_processor(&self.params)
                .apply((outputs, ctx))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok((0..texts.len())
                .map(|i| {
                    out.spans
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
                        .unwrap_or_default()
                })
                .collect())
        }

        pub fn collecting(&self) -> bool {
            self.collecting.load(Ordering::Relaxed)
        }

        /// Start stage 1: `find` records uncached chunks instead of inferring.
        pub fn begin_collect(&self) {
            self.overflow.store(false, Ordering::Relaxed);
            self.pending_bytes.store(0, Ordering::Relaxed);
            self.collecting.store(true, Ordering::Release);
        }

        /// End stage 1 and hand over what was collected.
        pub fn end_collect(&self) -> Pending {
            self.collecting.store(false, Ordering::Release);
            Pending {
                chunks: self
                    .pending
                    .drain()
                    .into_iter()
                    .map(|(h, t)| (h, Box::from(&*t)))
                    .collect(),
                complete: !self.overflow.load(Ordering::Relaxed),
            }
        }

        fn collect(&self, h: Hash, c: &str) {
            if self.cache.contains(&h) || self.pending.contains(&h) {
                return;
            }
            let n = self.pending_bytes.fetch_add(c.len() as u64, Ordering::Relaxed);
            if n > COLLECT_BUDGET {
                self.overflow.store(true, Ordering::Relaxed);
                return;
            }
            self.pending.insert(h, Arc::from(c));
        }

        /// Stage 2: infer every collected chunk, longest first, on the worker
        /// pool. `pb` counts work units (≈ model words), so its rate and ETA
        /// track the real cost; its message shows chunks.
        pub fn infer_all(&self, p: Pending, pb: &indicatif::ProgressBar) {
            let mut chunks: Vec<(Hash, Box<str>, u64)> = p
                .chunks
                .into_iter()
                .map(|(h, t)| {
                    let w = work_units(&t);
                    (h, t, w)
                })
                .collect();
            if chunks.is_empty() {
                return;
            }
            chunks.sort_by_key(|c| std::cmp::Reverse(c.2));
            let total_chunks = chunks.len() as u64;
            pb.set_length(chunks.iter().map(|c| c.2).sum());
            pb.set_position(0);
            let batch = self.rt.batch;
            let groups: Vec<&[(Hash, Box<str>, u64)]> = chunks.chunks(batch).collect();
            let next = AtomicUsize::new(0);
            let done = AtomicU64::new(0);
            let started = Instant::now();
            let last_msg = Mutex::new(Instant::now() - Duration::from_secs(1));
            let update = |force: bool| {
                let Ok(mut t) = last_msg.try_lock() else { return };
                if !force && t.elapsed() < Duration::from_millis(250) {
                    return;
                }
                *t = Instant::now();
                let d = done.load(Ordering::Relaxed);
                let secs = started.elapsed().as_secs_f64().max(0.001);
                pb.set_message(format!("{d}/{total_chunks} chunks, {:.0}/s", d as f64 / secs));
            };
            std::thread::scope(|s| {
                for w in 0..self.rt.sessions {
                    let session = &self.sessions[w % self.sessions.len()];
                    let (groups, next, done, update) = (&groups, &next, &done, &update);
                    s.spawn(move || {
                        loop {
                            let k = next.fetch_add(1, Ordering::Relaxed);
                            let Some(g) = groups.get(k) else { break };
                            let texts: Vec<&str> = g.iter().map(|c| &*c.1).collect();
                            // A chunk the model can't take is retried alone when
                            // redaction reaches it; a failure there skips it, as before.
                            if let Ok(spans) = self.run(session, &texts) {
                                for (c, sp) in g.iter().zip(spans) {
                                    self.cache.insert(c.0, Arc::new(sp));
                                }
                                self.inferred.fetch_add(g.len() as u64, Ordering::Relaxed);
                            }
                            done.fetch_add(g.len() as u64, Ordering::Relaxed);
                            pb.inc(g.iter().map(|c| c.2).sum());
                            update(false);
                        }
                    });
                }
            });
            update(true);
        }

        pub fn find(&self, text: &str, out: &mut Vec<Finding>) {
            let collecting = self.collecting();
            for (s, e) in crate::prose::chunks(text, CHUNK_WORDS) {
                let c = &text[s..e];
                let h = *blake3::hash(c.as_bytes()).as_bytes();
                if collecting {
                    self.collect(h, c);
                    continue;
                }
                let spans = match self.cache.get(&h) {
                    Some(sp) => {
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        sp
                    }
                    None => match self.run(&self.sessions[0], &[c]) {
                        Ok(mut v) => {
                            let sp: Spans = Arc::new(v.pop().unwrap_or_default());
                            self.cache.insert(h, sp.clone());
                            self.inferred.fetch_add(1, Ordering::Relaxed);
                            sp
                        }
                        Err(_) => continue,
                    },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_units_counts_words_and_marks() {
        assert_eq!(work_units("Hello, world!"), 4);
        assert_eq!(work_units("re-run the_thing"), 2);
        assert_eq!(work_units(""), 1);
    }

    #[test]
    fn device_parses() {
        assert_eq!("CoreML".parse::<Device>(), Ok(Device::CoreMl));
        assert_eq!("dml".parse::<Device>(), Ok(Device::DirectMl));
        assert!("tpu".parse::<Device>().is_err());
    }
}
