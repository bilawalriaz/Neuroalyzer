//! Reports: terminal summary, JSON and Markdown. Never contains raw values,
//! only types, detectors and counts.

use crate::engine::Counts;
use anyhow::Result;
use console::style;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Serialize, Clone)]
pub struct Count {
    #[serde(rename = "type")]
    pub kind: String,
    pub detector: String,
    pub count: u64,
}

pub fn counts_vec(c: &Counts) -> Vec<Count> {
    c.iter()
        .map(|(&(k, d), &n)| Count {
            kind: k.into(),
            detector: d.into(),
            count: n,
        })
        .collect()
}

#[derive(Serialize, Clone)]
pub struct FileReport {
    pub path: String,
    pub format: String,
    pub bytes: u64,
    pub findings: Vec<Count>,
    pub modified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<String>,
}

#[derive(Serialize)]
pub struct ToolReport {
    pub tool: String,
    pub files_scanned: usize,
    pub findings: Vec<Count>,
    pub files: Vec<FileReport>,
}

#[derive(Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct Drift {
    pub path: String,
    pub note: String,
}

#[derive(Serialize, Default, Clone)]
pub struct Engines {
    pub gitleaks_version: String,
    pub gitleaks_rules: usize,
    pub gitleaks_rules_skipped: usize,
    pub known_values: usize,
    pub ner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ner_note: Option<String>,
    pub ner_chunks_inferred: u64,
    pub ner_cache_hits: u64,
}

#[derive(Serialize)]
pub struct Report {
    pub neuroalyzer_version: String,
    pub mode: String,
    pub started_at: String,
    pub elapsed_secs: f64,
    pub bytes_scanned: u64,
    pub throughput_mb_per_sec: f64,
    pub files_scanned: usize,
    pub files_with_findings: usize,
    pub files_modified: usize,
    pub files_skipped: Vec<Skipped>,
    pub totals: Vec<Count>,
    pub format_drift: Vec<Drift>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    pub engines: Engines,
    pub tools: Vec<ToolReport>,
}

impl Report {
    pub fn build(
        mode: &str,
        started: chrono::DateTime<chrono::Local>,
        elapsed: f64,
        files: Vec<(String, FileReport)>,
        engines: Engines,
        archive: Option<PathBuf>,
    ) -> Report {
        let mut by_tool: BTreeMap<String, Vec<FileReport>> = BTreeMap::new();
        for (t, f) in files {
            by_tool.entry(t).or_default().push(f);
        }
        let mut totals: BTreeMap<(String, String), u64> = BTreeMap::new();
        let mut tools = vec![];
        let (mut scanned, mut with, mut modified, mut bytes) = (0, 0, 0, 0u64);
        let mut skipped = vec![];
        let mut drift = vec![];
        for (tool, mut files) in by_tool {
            files.sort_by(|a, b| a.path.cmp(&b.path));
            let mut tt: BTreeMap<(String, String), u64> = BTreeMap::new();
            for f in &files {
                scanned += 1;
                bytes += f.bytes;
                if !f.findings.is_empty() {
                    with += 1;
                }
                if f.modified {
                    modified += 1;
                }
                if let Some(r) = &f.skipped {
                    skipped.push(Skipped {
                        path: f.path.clone(),
                        reason: r.clone(),
                    });
                }
                if let Some(d) = &f.drift {
                    drift.push(Drift {
                        path: f.path.clone(),
                        note: d.clone(),
                    });
                }
                for c in &f.findings {
                    *tt.entry((c.kind.clone(), c.detector.clone())).or_default() += c.count;
                    *totals.entry((c.kind.clone(), c.detector.clone())).or_default() += c.count;
                }
            }
            tools.push(ToolReport {
                tool,
                files_scanned: files.len(),
                findings: tt
                    .into_iter()
                    .map(|((k, d), n)| Count {
                        kind: k,
                        detector: d,
                        count: n,
                    })
                    .collect(),
                files,
            });
        }
        Report {
            neuroalyzer_version: env!("CARGO_PKG_VERSION").into(),
            mode: mode.into(),
            started_at: started.to_rfc3339(),
            elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
            bytes_scanned: bytes,
            throughput_mb_per_sec: if elapsed > 0.0 {
                ((bytes as f64 / 1e6 / elapsed) * 10.0).round() / 10.0
            } else {
                0.0
            },
            files_scanned: scanned,
            files_with_findings: with,
            files_modified: modified,
            files_skipped: skipped,
            totals: totals
                .into_iter()
                .map(|((k, d), n)| Count {
                    kind: k,
                    detector: d,
                    count: n,
                })
                .collect(),
            format_drift: drift,
            archive: archive.map(|p| p.display().to_string()),
            engines,
            tools,
        }
    }

    pub fn total_findings(&self) -> u64 {
        self.totals.iter().map(|c| c.count).sum()
    }

    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "# Neuroalyzer {} report\n", self.mode);
        let _ = writeln!(
            s,
            "Started {}. Took {:.1}s for {} ({:.1} MB/s).\n",
            self.started_at,
            self.elapsed_secs,
            human(self.bytes_scanned),
            self.throughput_mb_per_sec
        );
        let verb = if self.mode == "scan" {
            "with findings"
        } else {
            "modified"
        };
        let n = if self.mode == "scan" {
            self.files_with_findings
        } else {
            self.files_modified
        };
        let _ = writeln!(
            s,
            "Files scanned: {}. Files {verb}: {n}. Files skipped: {}.\n",
            self.files_scanned,
            self.files_skipped.len()
        );
        if let Some(a) = &self.archive {
            let _ = writeln!(s, "Backup archive: `{a}`\n");
        }
        let _ = writeln!(s, "## Findings by type\n");
        if self.totals.is_empty() {
            let _ = writeln!(s, "None.\n");
        } else {
            let _ = writeln!(s, "| Type | Detector | Count |\n|---|---|---:|");
            for c in &self.totals {
                let _ = writeln!(s, "| {} | {} | {} |", c.kind, c.detector, c.count);
            }
            s.push('\n');
        }
        for t in &self.tools {
            let _ = writeln!(s, "## {}\n", t.tool);
            let _ = writeln!(s, "{} files scanned.\n", t.files_scanned);
            for f in t
                .files
                .iter()
                .filter(|f| !f.findings.is_empty() || f.skipped.is_some() || f.drift.is_some())
            {
                let _ = writeln!(s, "### `{}`\n", f.path);
                if let Some(r) = &f.skipped {
                    let _ = writeln!(s, "Skipped: {r}\n");
                }
                if let Some(d) = &f.drift {
                    let _ = writeln!(s, "Format drift: {d}\n");
                }
                if !f.findings.is_empty() {
                    let _ = writeln!(s, "| Type | Detector | Count |\n|---|---|---:|");
                    for c in &f.findings {
                        let _ = writeln!(s, "| {} | {} | {} |", c.kind, c.detector, c.count);
                    }
                    s.push('\n');
                }
            }
        }
        let e = &self.engines;
        let _ = writeln!(s, "## Detectors\n");
        let _ = writeln!(
            s,
            "- gitleaks rules {}: {} loaded, {} not applicable",
            e.gitleaks_version, e.gitleaks_rules, e.gitleaks_rules_skipped
        );
        let _ = writeln!(s, "- Known values from .env files: {}", e.known_values);
        let _ = writeln!(
            s,
            "- NER: {}",
            if e.ner {
                format!(
                    "on ({} chunks inferred, {} cache hits)",
                    e.ner_chunks_inferred, e.ner_cache_hits
                )
            } else {
                e.ner_note.clone().unwrap_or_else(|| "off".into())
            }
        );
        s
    }

    /// Write report-<timestamp>.json and .md into `dir`. Returns the paths.
    pub fn write_files(&self, dir: &Path) -> Result<(PathBuf, PathBuf)> {
        crate::paths::ensure_private_dir(dir)?;
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let j = dir.join(format!("report-{ts}.json"));
        let m = dir.join(format!("report-{ts}.md"));
        std::fs::write(&j, serde_json::to_vec_pretty(self)?)?;
        std::fs::write(&m, self.to_markdown())?;
        crate::paths::make_private(&j)?;
        crate::paths::make_private(&m)?;
        Ok((j, m))
    }

    pub fn print_summary(&self) {
        let e = eprintln_styled;
        e(&format!("{}", style(format!("Neuroalyzer {}", self.mode)).bold()));
        let tools: Vec<String> = self
            .tools
            .iter()
            .map(|t| format!("{} ({} files)", t.tool, t.files_scanned))
            .collect();
        e(&format!(
            "  Tools found     {}",
            if tools.is_empty() {
                "none".into()
            } else {
                tools.join(", ")
            }
        ));
        e(&format!(
            "  Files scanned   {} ({})",
            self.files_scanned,
            human(self.bytes_scanned)
        ));
        if self.mode == "scan" {
            e(&format!("  With findings   {}", self.files_with_findings));
        } else {
            e(&format!("  Modified        {}", self.files_modified));
        }
        if !self.files_skipped.is_empty() {
            let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
            for s in &self.files_skipped {
                let r = s.reason.split(':').next().unwrap_or(&s.reason).to_string();
                *reasons.entry(r).or_default() += 1;
            }
            let r: Vec<String> = reasons.iter().map(|(k, v)| format!("{v} {k}")).collect();
            e(&format!(
                "  Skipped         {} ({})",
                self.files_skipped.len(),
                r.join(", ")
            ));
        }
        e(&format!(
            "  Time            {:.1}s, {:.1} MB/s",
            self.elapsed_secs, self.throughput_mb_per_sec
        ));
        if self.totals.is_empty() {
            e(&format!("\n  {}", style("No findings.").green()));
        } else {
            e(&format!(
                "\n  {:<10} {:<34} {:>8}",
                style("Type").bold(),
                style("Detector").bold(),
                style("Count").bold()
            ));
            for c in &self.totals {
                e(&format!("  {:<10} {:<34} {:>8}", c.kind, c.detector, c.count));
            }
            e(&format!(
                "  {:<10} {:<34} {:>8}",
                "",
                style("total").dim(),
                self.total_findings()
            ));
        }
        if !self.format_drift.is_empty() {
            e(&format!(
                "\n  {} {} file(s) didn't match the expected format and were scanned generically:",
                style("Format drift:").yellow(),
                self.format_drift.len()
            ));
            for d in self.format_drift.iter().take(5) {
                e(&format!("    {}: {}", d.path, d.note));
            }
            if self.format_drift.len() > 5 {
                e(&format!(
                    "    ...and {} more (see the report)",
                    self.format_drift.len() - 5
                ));
            }
        }
        if let Some(n) = &self.engines.ner_note {
            e(&format!("\n  {} {n}", style("NER:").yellow()));
        }
        if let Some(a) = &self.archive {
            e(&format!("\n  Backup          {a}"));
        }
    }
}

fn eprintln_styled(s: &str) {
    eprintln!("{s}");
}

pub fn human(b: u64) -> String {
    let b = b as f64;
    if b >= 1e9 {
        format!("{:.2} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.1} KB", b / 1e3)
    } else {
        format!("{b} B")
    }
}
