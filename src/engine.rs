//! Per-file processing: find findings, and (when rewriting) produce redacted
//! output. JSON, JSONL and text are rewritten by splicing; SQLite is updated
//! in place by `sqlite.rs`.

use crate::detect::{self, Ctx, Detectors, Finding};
use crate::discovery::{Format, Job, Schema};
use crate::jsonscan;
use crate::ner::Ner;
use crate::prose;
use crate::token::Tokenizer;
use std::collections::BTreeMap;

pub type Counts = BTreeMap<(&'static str, &'static str), u64>;

pub fn add_counts(into: &mut Counts, from: &Counts) {
    for (k, v) in from {
        *into.entry(*k).or_default() += v;
    }
}

pub struct Engine {
    pub det: Detectors,
    pub tok: Tokenizer,
    pub ner: Option<Ner>,
}

#[derive(Default)]
pub struct Outcome {
    pub counts: Counts,
    /// Redacted bytes, for JSON/JSONL/text when rewriting.
    pub new_bytes: Option<Vec<u8>>,
    pub would_change: bool,
    pub drift: Option<String>,
    pub bytes: u64,
}

impl Engine {
    /// Redact one decoded string. Returns the new string if anything changed.
    pub fn redact_str(&self, s: &str, key: &str, counts: &mut Counts) -> Option<String> {
        let mut found: Vec<Finding> = vec![];
        if self.det.record_may_match(s.as_bytes()) {
            self.det.detect(s, Ctx { key }, &mut found);
            let base = found.len();
            detect::tabular::detect(s, &mut found);
            self.det.filter(s, &mut found, base);
        }
        if let Some(ner) = &self.ner
            && prose::is_prose_key(key)
        {
            let base = found.len();
            ner.find(s, &mut found);
            self.det.filter(s, &mut found, base);
        }
        if found.is_empty() {
            return None;
        }
        let found = detect::merge(found);
        let mut out = String::with_capacity(s.len());
        let mut last = 0;
        for f in &found {
            // Spans always fall on char boundaries (regex/AC over &str), but be defensive.
            if !s.is_char_boundary(f.start) || !s.is_char_boundary(f.end) || f.start < last {
                continue;
            }
            out.push_str(&s[last..f.start]);
            out.push_str(&self.tok.token(f.kind, &s[f.start..f.end]));
            last = f.end;
            *counts.entry((f.kind, f.detector)).or_default() += 1;
        }
        out.push_str(&s[last..]);
        if out == s { None } else { Some(out) }
    }

    /// Redact one string literal of `raw`, if it needs it.
    fn redact_literal(
        &self,
        raw: &[u8],
        span: std::ops::Range<usize>,
        key: Option<&[u8]>,
        counts: &mut Counts,
    ) -> Option<(usize, usize, String)> {
        let lit_bytes = &raw[span.clone()];
        if self.ner.is_none() && !self.det.record_may_match(lit_bytes) {
            return None;
        }
        let val = jsonscan::decode(lit_bytes)?;
        let key = jsonscan::key_str(key);
        self.redact_str(&val, &key, counts)
            .map(|new| (span.start, span.end, jsonscan::encode(&new)))
    }

    /// Redact every string value inside one JSON document. Returns new bytes if changed.
    /// Err(()) means the bytes aren't JSON.
    #[allow(clippy::result_unit_err)]
    pub fn redact_json(&self, raw: &[u8], counts: &mut Counts) -> Result<Option<Vec<u8>>, ()> {
        // A single cell can hold hundreds of megabytes (OpenCode stores whole
        // messages). Split the per-string work across threads so one huge
        // database row can't pin the scan to a single core.
        const PARALLEL_JSON: usize = 4 << 20;
        let mut edits: Vec<(usize, usize, String)> = vec![];
        if raw.len() >= PARALLEL_JSON {
            use rayon::prelude::*;
            let mut lits: Vec<(std::ops::Range<usize>, Option<&[u8]>)> = vec![];
            let ok = jsonscan::for_each_string(raw, |lit| lits.push((lit.span, lit.key)));
            if !ok {
                return Err(());
            }
            type Part = (Vec<(usize, usize, String)>, Counts);
            let parts: Vec<Part> = lits
                .par_chunks(1024)
                .map(|chunk| {
                    let mut counts = Counts::new();
                    let mut edits = vec![];
                    for (span, key) in chunk {
                        if let Some(e) = self.redact_literal(raw, span.clone(), *key, &mut counts) {
                            edits.push(e);
                        }
                    }
                    (edits, counts)
                })
                .collect();
            for (e, c) in parts {
                add_counts(counts, &c);
                edits.extend(e);
            }
        } else {
            let ok = jsonscan::for_each_string(raw, |lit| {
                if let Some(e) = self.redact_literal(raw, lit.span, lit.key, counts) {
                    edits.push(e);
                }
            });
            if !ok {
                return Err(());
            }
        }
        if edits.is_empty() {
            // The scanner is lenient; make sure plain text isn't mistaken for JSON.
            let first = raw.iter().find(|b| !b.is_ascii_whitespace());
            if !matches!(first, Some(b'{' | b'[' | b'"'))
                && serde_json::from_slice::<serde::de::IgnoredAny>(raw).is_err()
            {
                return Err(());
            }
            return Ok(None);
        }
        let mut out = Vec::with_capacity(raw.len());
        let mut last = 0;
        for (s, e, rep) in edits {
            out.extend_from_slice(&raw[last..s]);
            out.extend_from_slice(rep.as_bytes());
            last = e;
        }
        out.extend_from_slice(&raw[last..]);
        // Never produce invalid JSON.
        if serde_json::from_slice::<serde::de::IgnoredAny>(&out).is_err() {
            return Err(());
        }
        Ok(Some(out))
    }

    fn redact_text(&self, raw: &[u8], counts: &mut Counts) -> Option<Vec<u8>> {
        let mut out: Option<Vec<u8>> = None;
        let mut off = 0;
        for line in raw.split_inclusive(|&b| b == b'\n') {
            let changed = std::str::from_utf8(line).ok().and_then(|l| {
                if self.ner.is_none() && !self.det.record_may_match(line) {
                    return None;
                }
                self.redact_str(l, "", counts)
            });
            match (changed, &mut out) {
                (Some(new), None) => {
                    let mut v = Vec::with_capacity(raw.len());
                    v.extend_from_slice(&raw[..off]);
                    v.extend_from_slice(new.as_bytes());
                    out = Some(v);
                }
                (Some(new), Some(v)) => v.extend_from_slice(new.as_bytes()),
                (None, Some(v)) => v.extend_from_slice(line),
                (None, None) => {}
            }
            off += line.len();
        }
        out
    }

    fn redact_jsonl(&self, raw: &[u8], counts: &mut Counts, drift: &mut bool) -> Option<Vec<u8>> {
        let mut out: Option<Vec<u8>> = None;
        let mut off = 0;
        for line in raw.split_inclusive(|&b| b == b'\n') {
            let body_len = line.len() - line.iter().rev().take_while(|&&b| b == b'\n' || b == b'\r').count();
            let body = &line[..body_len];
            let mut changed: Option<Vec<u8>> = None;
            if !body.iter().all(u8::is_ascii_whitespace) && (self.ner.is_some() || self.det.record_may_match(body)) {
                match self.redact_json(body, counts) {
                    Ok(Some(new)) => changed = Some(new),
                    Ok(None) => {}
                    Err(()) => {
                        *drift = true;
                        if let Ok(l) = std::str::from_utf8(body) {
                            changed = self.redact_str(l, "", counts).map(String::into_bytes);
                        }
                    }
                }
            }
            match (changed, &mut out) {
                (Some(new), None) => {
                    let mut v = Vec::with_capacity(raw.len());
                    v.extend_from_slice(&raw[..off]);
                    v.extend_from_slice(&new);
                    v.extend_from_slice(&line[body_len..]);
                    out = Some(v);
                }
                (Some(new), Some(v)) => {
                    v.extend_from_slice(&new);
                    v.extend_from_slice(&line[body_len..]);
                }
                (None, Some(v)) => v.extend_from_slice(line),
                (None, None) => {}
            }
            off += line.len();
        }
        out
    }

    /// Feed NER every prose string in the file first, so inference is batched.
    fn ner_prepare(&self, raw: &[u8], format: Format) {
        let Some(ner) = &self.ner else { return };
        let mut texts: Vec<String> = vec![];
        match format {
            Format::Json | Format::Jsonl => {
                jsonscan::for_each_string(raw, |lit| {
                    if prose::is_prose_key(&jsonscan::key_str(lit.key))
                        && let Some(v) = jsonscan::decode(&raw[lit.span])
                    {
                        texts.push(v.into_owned());
                    }
                });
            }
            // Text is redacted line by line, so prepare the same units.
            Format::Text => texts.extend(String::from_utf8_lossy(raw).split_inclusive('\n').map(str::to_owned)),
            Format::Sqlite | Format::JsonlZst => {}
        }
        ner.prepare(texts.iter().map(String::as_str));
    }

    /// Process a JSON, JSONL or text file held in memory.
    pub fn process_bytes(&self, job: &Job, raw: &[u8]) -> Outcome {
        if job.format == Format::JsonlZst {
            return self.process_zst(job, raw);
        }
        let mut o = Outcome {
            bytes: raw.len() as u64,
            ..Default::default()
        };
        let mut format = job.format;
        // Format sniffing and fallback.
        if format == Format::Json && serde_json::from_slice::<serde::de::IgnoredAny>(raw).is_err() {
            let all_lines_json = raw
                .split(|&b| b == b'\n')
                .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
                .all(|l| serde_json::from_slice::<serde::de::IgnoredAny>(l).is_ok());
            format = if all_lines_json { Format::Jsonl } else { Format::Text };
            o.drift = Some(format!(
                "expected a JSON document, found {}",
                if all_lines_json { "JSON lines" } else { "non-JSON text" }
            ));
        }
        if o.drift.is_none()
            && let Some(msg) = schema_drift(job.schema, raw, format)
        {
            o.drift = Some(msg);
        }
        self.ner_prepare(raw, format);
        let mut line_drift = false;
        o.new_bytes = match format {
            Format::Json => match self.redact_json(raw, &mut o.counts) {
                Ok(v) => v,
                Err(()) => {
                    o.drift
                        .get_or_insert_with(|| "JSON scan failed; handled as text".into());
                    self.redact_text(raw, &mut o.counts)
                }
            },
            Format::Jsonl => self.redact_jsonl(raw, &mut o.counts, &mut line_drift),
            Format::Text => self.redact_text(raw, &mut o.counts),
            Format::Sqlite | Format::JsonlZst => None,
        };
        if line_drift {
            o.drift
                .get_or_insert_with(|| "some lines weren't JSON; handled them as text".into());
        }
        o.would_change = o.new_bytes.is_some();
        o
    }
}

impl Engine {
    /// Decompress, redact as JSONL, recompress. A file that won't decompress
    /// is reported and left alone.
    fn process_zst(&self, job: &Job, raw: &[u8]) -> Outcome {
        let plain = match zstd::stream::decode_all(raw) {
            Ok(p) => p,
            Err(e) => {
                return Outcome {
                    bytes: raw.len() as u64,
                    drift: Some(format!("couldn't decompress zstd ({e}); left as is")),
                    ..Default::default()
                };
            }
        };
        let inner = Job {
            format: Format::Jsonl,
            ..job.clone()
        };
        let mut o = self.process_bytes(&inner, &plain);
        o.bytes = raw.len() as u64;
        if let Some(nb) = o.new_bytes.take() {
            match zstd::stream::encode_all(&nb[..], 3) {
                Ok(c) => o.new_bytes = Some(c),
                Err(e) => {
                    o.drift = Some(format!("couldn't recompress zstd ({e}); left as is"));
                    o.would_change = false;
                }
            }
        }
        o
    }
}

/// Cheap structural checks per known schema. Returns a note on mismatch.
fn schema_drift(schema: Schema, raw: &[u8], format: Format) -> Option<String> {
    let first_line = || -> Option<serde_json::Value> {
        let l = raw
            .split(|&b| b == b'\n')
            .find(|l| !l.iter().all(u8::is_ascii_whitespace))?;
        serde_json::from_slice(l).ok()
    };
    let head = &raw[..raw.len().min(64 * 1024)];
    let has = |needle: &str| head.windows(needle.len()).any(|w| w == needle.as_bytes());
    let ok = match schema {
        Schema::Generic => true,
        Schema::VscodeChat => match format {
            Format::Jsonl => first_line().is_some_and(|v| v.get("kind").is_some()),
            _ => has("\"requests\"") || has("\"sessionId\""),
        },
        Schema::CopilotEvents => first_line().is_some_and(|v| v.get("type").is_some() && v.get("data").is_some()),
        Schema::OmpSession => first_line().is_some_and(|v| v.get("type").and_then(|t| t.as_str()) == Some("session")),
        Schema::OpencodeJson => has("\"id\""),
        Schema::ClaudeSession | Schema::DroidSession => first_line().is_some_and(|v| v.get("type").is_some()),
        Schema::CodexRollout => first_line().is_some_and(|v| v.get("type").is_some() && v.get("payload").is_some()),
        Schema::GeminiChat => has("\"messages\"") || has("\"sessionId\""),
        Schema::VscodeState | Schema::OpencodeDb | Schema::HermesDb => true,
    };
    if ok {
        None
    } else {
        Some(format!(
            "didn't match the expected {} layout; scanned it generically",
            schema.name()
        ))
    }
}
