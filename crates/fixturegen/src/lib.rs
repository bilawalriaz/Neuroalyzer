//! Generates fake home-directory trees of AI coding agent session data, for testing secret and
//! PII redaction. Every value is synthetic. The manifest lists each planted value and decoy so a
//! redaction run can be checked against it.

mod content;
mod rng;
mod values;
mod writers;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::content::{Gen, Project, Session};
use crate::writers::{Out, VsCodeSpot};

/// Operating system layout for the VS Code user-data directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Mac,
    Linux,
    Windows,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub seed: u64,
    pub sessions_per_tool: usize,
    pub layouts: Vec<Layout>,
    pub target_bytes: Option<u64>,
    pub with_insiders: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            seed: 42,
            sessions_per_tool: 3,
            layouts: vec![Layout::Mac, Layout::Linux, Layout::Windows],
            target_bytes: None,
            with_insiders: true,
        }
    }
}

/// A value that was written into the fixture tree, with its kind.
#[derive(Clone, Debug)]
pub struct Planted {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Default)]
pub struct Manifest {
    pub planted: Vec<Planted>,
    pub decoys: Vec<String>,
    pub projects: Vec<PathBuf>,
}

impl Manifest {
    pub fn to_json(&self) -> String {
        let planted: Vec<Value> = self
            .planted
            .iter()
            .map(|p| json!({"kind": p.kind, "value": p.value}))
            .collect();
        let projects: Vec<String> = self.projects.iter().map(|p| p.display().to_string()).collect();
        let doc = json!({
            "planted": planted,
            "decoys": self.decoys,
            "projects": projects,
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    }
}

#[derive(Clone, Copy)]
enum Kind {
    VsCode { spot: usize, extras: bool },
    Copilot,
    OpenCode,
    Omp,
}

struct Run {
    out: Out,
    conn: rusqlite::Connection,
    recorder: Gen,
    projects: Vec<Project>,
    spots: Vec<VsCodeSpot>,
    index: usize,
}

impl Run {
    /// Builds the next session for `kind` and writes it out.
    fn emit_new(&mut self, kind: Kind, filler_turns: usize) -> io::Result<()> {
        let vscode = matches!(kind, Kind::VsCode { .. });
        let s = content::build_session(&mut self.recorder, &self.projects, self.index, filler_turns, vscode);
        self.index += 1;
        self.emit(kind, &s)
    }

    fn emit(&mut self, kind: Kind, s: &Session) -> io::Result<()> {
        let project = &self.projects[s.project];
        match kind {
            Kind::VsCode { spot, extras } => {
                let spot = VsCodeSpot {
                    extras,
                    ..self.spots[spot]
                };
                writers::write_vscode(&mut self.out, s, project, spot)
            }
            Kind::Copilot => writers::write_copilot(&mut self.out, &mut self.recorder.rng, s, project),
            Kind::OpenCode => writers::write_opencode(&mut self.out, &self.conn, &mut self.recorder.rng, s, project),
            Kind::Omp => writers::write_omp(&mut self.out, &mut self.recorder.rng, s, project),
        }
    }
}

fn vscode_spots(opts: &Options) -> Vec<VsCodeSpot> {
    let mut editions: Vec<&'static str> = vec!["Code"];
    if opts.with_insiders {
        editions.push("Code - Insiders");
    }
    let mut spots = Vec::new();
    for &layout in &opts.layouts {
        for &edition in &editions {
            spots.push(VsCodeSpot {
                layout,
                edition,
                extras: false,
            });
        }
    }
    spots
}

/// Writes the fixture tree under `root` (treated as the user's home directory) and returns the
/// manifest of everything planted. The output depends only on `opts`.
pub fn generate(root: &Path, opts: &Options) -> io::Result<Manifest> {
    fs::create_dir_all(root)?;
    let root = std::path::absolute(root)?;
    let mut recorder = Gen::new(opts.seed);
    let projects = content::make_projects(&mut recorder, &root);
    let mut out = Out::new(root.clone());
    for project in &projects {
        writers::write_project(&mut out, project)?;
    }
    let conn = writers::open_opencode_db(&root.join(".local").join("share").join("opencode").join("opencode.db"))?;
    let spots = vscode_spots(opts);
    let mut run = Run {
        out,
        conn,
        recorder,
        projects,
        spots,
        index: 0,
    };

    for spot in 0..run.spots.len() {
        for n in 0..opts.sessions_per_tool {
            run.emit_new(Kind::VsCode { spot, extras: n == 0 }, 0)?;
        }
    }
    for _ in 0..opts.sessions_per_tool {
        run.emit_new(Kind::Copilot, 0)?;
    }
    for _ in 0..opts.sessions_per_tool {
        run.emit_new(Kind::OpenCode, 0)?;
    }
    for _ in 0..opts.sessions_per_tool {
        run.emit_new(Kind::Omp, 0)?;
    }

    if let Some(target) = opts.target_bytes {
        let mut cycle: Vec<Kind> = (0..run.spots.len())
            .map(|spot| Kind::VsCode { spot, extras: false })
            .collect();
        cycle.extend([Kind::Copilot, Kind::OpenCode, Kind::Omp]);
        let mut k = 0usize;
        while run.out.bytes < target {
            let kind = cycle[k % cycle.len()];
            k += 1;
            run.emit_new(kind, content::FILLER_TURNS)?;
        }
    }

    writers::commit(&run.conn)?;
    let Run { recorder, projects, .. } = run;
    let (planted, decoys) = recorder.finish();
    Ok(Manifest {
        planted,
        decoys,
        projects: projects.iter().map(|p| p.dir.clone()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("fixturegen-{name}-{}-{nanos}", std::process::id()))
    }

    fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_files(&path, files);
            } else {
                files.push(path);
            }
        }
    }

    #[test]
    fn default_generation_covers_all_tools_and_parses() {
        let root = scratch_dir("default");
        let manifest = generate(&root, &Options::default()).expect("generate");

        let mut files = Vec::new();
        collect_files(&root, &mut files);
        let has = |needle: &str| files.iter().any(|p| p.to_string_lossy().contains(needle));
        assert!(has("Library/Application Support/Code/User/workspaceStorage"));
        assert!(has("Code - Insiders"));
        assert!(has(".config/Code/User"));
        assert!(has("AppData/Roaming/Code/User"));
        assert!(has("globalStorage/emptyWindowChatSessions"));
        assert!(has("state.vscdb"));
        assert!(has(".copilot/session-state"));
        assert!(has("events.jsonl"));
        assert!(has(".omp/agent/sessions/-proj-"));
        assert!(root.join(".local/share/opencode/opencode.db").exists());
        assert!(has("storage/session/message"));

        let mut parsed = 0usize;
        for path in &files {
            let text = fs::read_to_string(path).unwrap_or_default();
            match path.extension().and_then(|e| e.to_str()) {
                Some("jsonl") => {
                    for line in text.lines().filter(|l| !l.trim().is_empty()) {
                        serde_json::from_str::<Value>(line).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                    }
                    parsed += 1;
                }
                Some("json") => {
                    serde_json::from_str::<Value>(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                    parsed += 1;
                }
                _ => {}
            }
        }
        assert!(parsed > 0);

        let kinds: HashSet<&str> = manifest.planted.iter().map(|p| p.kind.as_str()).collect();
        for kind in [
            "SECRET", "EMAIL", "PHONE", "POSTCODE", "NINO", "NHS", "CARD", "IBAN", "KNOWN", "TABULAR", "PERSON",
            "ADDRESS", "ORG",
        ] {
            assert!(kinds.contains(kind), "manifest missing kind {kind}");
        }
        assert!(!manifest.decoys.is_empty());
        assert_eq!(manifest.projects.len(), 3);
        for project in &manifest.projects {
            let env = fs::read_to_string(project.join(".env")).expect("project .env");
            assert!(env.contains("APP_NAME=demo"));
        }

        let unique: HashSet<&str> = manifest.planted.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(unique.len(), manifest.planted.len(), "planted values not deduped");
        let unique_decoys: HashSet<&str> = manifest.decoys.iter().map(String::as_str).collect();
        assert_eq!(unique_decoys.len(), manifest.decoys.len());

        let doc: Value = serde_json::from_str(&manifest.to_json()).expect("manifest json");
        assert!(doc["planted"].is_array());
        assert!(doc["decoys"].is_array());
        assert_eq!(doc["projects"].as_array().map(Vec::len), Some(3));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn same_seed_gives_same_manifest() {
        let opts = Options {
            sessions_per_tool: 1,
            layouts: vec![Layout::Linux],
            ..Options::default()
        };
        let a = scratch_dir("seed-a");
        let b = scratch_dir("seed-b");
        let ma = generate(&a, &opts).expect("generate a");
        let mb = generate(&b, &opts).expect("generate b");
        assert_eq!(ma.planted.len(), mb.planted.len());
        assert!(ma.planted.iter().zip(&mb.planted).all(|(x, y)| x.value == y.value));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }

    #[test]
    fn size_target_adds_sessions_until_reached() {
        let root = scratch_dir("target");
        let opts = Options {
            sessions_per_tool: 1,
            layouts: vec![Layout::Mac],
            target_bytes: Some(1024 * 1024),
            with_insiders: false,
            ..Options::default()
        };
        let manifest = generate(&root, &opts).expect("generate");
        let mut files = Vec::new();
        collect_files(&root, &mut files);
        let total: u64 = files.iter().filter_map(|p| fs::metadata(p).ok()).map(|m| m.len()).sum();
        assert!(total >= 1024 * 1024, "tree is {total} bytes");
        assert!(!manifest.planted.is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
