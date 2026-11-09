//! Known-value matching: find the project dirs that sessions refer to, read
//! their `.env*` files, and collect values of secret-looking keys. Exact
//! occurrences of those values are redacted wherever they appear.

use crate::discovery::{Format, Job, Schema};
use regex::Regex;
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(key|token|secret|pass|pwd|auth|credential|dsn|private|cookie|session)").unwrap()
});
static URL_PW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"://[^\s:/@]+:([^\s@/]+)@").unwrap());

fn from_file_uri(u: &str) -> Option<PathBuf> {
    let rest = u.strip_prefix("file://")?;
    let mut dec = String::new();
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&rest[i + 1..i + 3], 16)
        {
            dec.push(v as char);
            i += 3;
            continue;
        }
        dec.push(b[i] as char);
        i += 1;
    }
    // Windows: /c:/Users/... -> c:/Users/...
    if dec.len() > 3 && dec.as_bytes()[0] == b'/' && dec.as_bytes()[2] == b':' {
        dec.remove(0);
    }
    Some(PathBuf::from(dec))
}

fn first_lines(p: &Path, n: usize) -> Vec<serde_json::Value> {
    let Ok(f) = std::fs::File::open(p) else { return vec![] };
    BufReader::new(f)
        .lines()
        .take(n)
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

/// Project directories referenced by session metadata.
pub fn project_dirs(jobs: &[Job], root: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut ws_seen: BTreeSet<PathBuf> = BTreeSet::new();
    for j in jobs {
        match j.schema {
            Schema::VscodeChat => {
                // workspaceStorage/<id>/chatSessions/x.jsonl -> workspaceStorage/<id>/workspace.json
                if let Some(ws) = j.path.parent().and_then(Path::parent).map(|p| p.join("workspace.json"))
                    && ws_seen.insert(ws.clone())
                    && let Some(v) = std::fs::read(&ws)
                        .ok()
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    && let Some(p) = v.get("folder").and_then(|f| f.as_str()).and_then(from_file_uri)
                {
                    dirs.insert(p);
                }
            }
            Schema::CopilotEvents => {
                for v in first_lines(&j.path, 5) {
                    if let Some(c) = v.pointer("/data/context/cwd").and_then(|c| c.as_str()) {
                        dirs.insert(PathBuf::from(c));
                    }
                }
            }
            Schema::OmpSession | Schema::DroidSession if j.format == Format::Jsonl => {
                for v in first_lines(&j.path, 1) {
                    if let Some(c) = v.get("cwd").and_then(|c| c.as_str()) {
                        dirs.insert(PathBuf::from(c));
                    }
                }
            }
            Schema::ClaudeSession => {
                // The first lines can be queue operations without a cwd.
                if let Some(c) = first_lines(&j.path, 20)
                    .iter()
                    .find_map(|v| v.get("cwd").and_then(|c| c.as_str()).map(PathBuf::from))
                {
                    dirs.insert(c);
                }
            }
            Schema::CodexRollout if j.format == Format::Jsonl => {
                for v in first_lines(&j.path, 1) {
                    if let Some(c) = v.pointer("/payload/cwd").and_then(|c| c.as_str()) {
                        dirs.insert(PathBuf::from(c));
                    }
                }
            }
            Schema::OpencodeDb if j.format == Format::Sqlite => {
                if let Ok(c) = crate::sqlite::open_readonly(&j.path) {
                    for t in ["session_v2", "session"] {
                        if let Ok(mut st) = c.prepare(&format!("SELECT DISTINCT directory FROM {t}"))
                            && let Ok(rows) = st.query_map([], |r| r.get::<_, Option<String>>(0))
                        {
                            for d in rows.flatten().flatten() {
                                dirs.insert(PathBuf::from(d));
                            }
                        }
                    }
                }
            }
            _ => {
                if j.path.file_name().is_some_and(|n| n == "workspace.yaml")
                    && let Ok(t) = std::fs::read_to_string(&j.path)
                {
                    for l in t.lines() {
                        if let Some(c) = l.strip_prefix("cwd:") {
                            dirs.insert(PathBuf::from(c.trim().trim_matches('"')));
                        }
                    }
                }
            }
        }
    }
    let mut out = vec![];
    for d in dirs {
        if d.is_dir() {
            out.push(d);
        } else if let Some(r) = root {
            // Copied trees: try the path re-rooted under --root.
            let rel: PathBuf = d
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .collect();
            let cand = r.join(rel);
            if cand.is_dir() {
                out.push(cand);
            }
        }
    }
    out
}

fn is_env_file(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && !name.ends_with(".example")
        && !name.ends_with(".sample")
        && !name.ends_with(".template")
        && !name.ends_with(".dist")
}

/// Values of secret-looking keys in `.env*` files within these dirs (depth <= 3).
pub fn collect(dirs: &[PathBuf]) -> Vec<String> {
    let mut vals: BTreeSet<String> = BTreeSet::new();
    for d in dirs {
        let walker = walkdir::WalkDir::new(d).max_depth(3).into_iter().filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            !(e.file_type().is_dir()
                && matches!(
                    n.as_ref(),
                    "node_modules" | ".git" | "target" | "vendor" | "dist" | ".venv" | "venv"
                ))
        });
        for e in walker.filter_map(Result::ok) {
            if !e.file_type().is_file() || !is_env_file(&e.file_name().to_string_lossy()) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            for line in text.lines() {
                let l = line.trim();
                let l = l.strip_prefix("export ").unwrap_or(l);
                if l.starts_with('#') {
                    continue;
                }
                let Some((k, v)) = l.split_once('=') else { continue };
                let k = k.trim();
                let mut v = v.trim();
                if let Some(i) = v.find(" #")
                    && !v.starts_with('"')
                    && !v.starts_with('\'')
                {
                    v = v[..i].trim();
                }
                let v = v.trim_matches(|c| c == '"' || c == '\'');
                if !SECRET_KEY.is_match(k) {
                    continue;
                }
                if let Some(c) = URL_PW.captures(v) {
                    vals.insert(c[1].to_string());
                    continue;
                }
                if v.len() >= 6 && !crate::detect::is_placeholder(v) && !v.contains(char::is_whitespace) {
                    vals.insert(v.to_string());
                }
            }
        }
    }
    vals.into_iter().collect()
}
