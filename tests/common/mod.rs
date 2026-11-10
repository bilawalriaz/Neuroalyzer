#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

pub const PASSWORD: &str = "correct horse battery staple 42";

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub data: PathBuf,
    pub pwfile: PathBuf,
    pub manifest: fixturegen::Manifest,
}

pub fn backdate(root: &Path) {
    let old = SystemTime::now() - Duration::from_secs(3600);
    for e in walkdir(root) {
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&e) {
            let _ = f.set_modified(old);
        }
    }
}

pub fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

pub fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("home");
    let data = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    let manifest = fixturegen::generate(&root, &fixturegen::Options::default()).unwrap();
    backdate(&root);
    let pwfile = dir.path().join("pw");
    std::fs::write(&pwfile, format!("{PASSWORD}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pwfile, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Fixture {
        dir,
        root,
        data,
        pwfile,
        manifest,
    }
}

impl Fixture {
    pub fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_neuralyzer"));
        c.env("NEURALYZER_DATA_DIR", &self.data)
            .env("NEURALYZER_CONFIG", self.dir.path().join("no-config.toml"))
            .env("NEURALYZER_NO_KEYRING", "1")
            .env_remove("NEURALYZER_PASSWORD")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        c
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    pub fn root_s(&self) -> String {
        self.root.display().to_string()
    }

    pub fn pw_s(&self) -> String {
        self.pwfile.display().to_string()
    }

    pub fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        walkdir(&self.root)
            .into_iter()
            .filter(|p| !p.to_string_lossy().ends_with("-shm"))
            .map(|p| {
                let b = std::fs::read(&p).unwrap();
                (p, b)
            })
            .collect()
    }
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Forms a value can take on disk: raw and JSON-escaped.
pub fn forms(v: &str) -> Vec<Vec<u8>> {
    let mut f = vec![v.as_bytes().to_vec()];
    let esc = serde_json::to_string(v).unwrap();
    let esc = esc[1..esc.len() - 1].to_string();
    if esc != v {
        f.push(esc.as_bytes().to_vec());
    }
    f
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

pub fn diff_snap(a: &BTreeMap<PathBuf, Vec<u8>>, b: &BTreeMap<PathBuf, Vec<u8>>) -> Vec<String> {
    let mut d = vec![];
    for (p, x) in a {
        match b.get(p) {
            Some(y) if x == y => {}
            Some(_) => d.push(format!("changed: {}", p.display())),
            None => d.push(format!("missing: {}", p.display())),
        }
    }
    for p in b.keys() {
        if !a.contains_key(p) {
            d.push(format!("extra: {}", p.display()));
        }
    }
    d
}

pub fn recover(fx: &Fixture, archive: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    let dest = fx.dir.path().join("recovered");
    let output = fx.run(&[
        "restore",
        archive,
        "--into",
        dest.to_str().unwrap(),
        "--password-file",
        &fx.pw_s(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dest.join("manifest.json")).unwrap()).unwrap();
    assert!(
        manifest.get("undo_identity").is_none(),
        "recovery manifest contains the undo key"
    );
    manifest["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                PathBuf::from(entry["path"].as_str().unwrap()),
                std::fs::read(dest.join(entry["id"].as_str().unwrap())).unwrap(),
            )
        })
        .collect()
}

pub fn assert_recovered(fx: &Fixture, archive: &str, before: &BTreeMap<PathBuf, Vec<u8>>) {
    let live = fx.snapshot();
    let recovered = recover(fx, archive);
    let mut rebuilt = live.clone();
    rebuilt.extend(recovered);
    for (path, original) in before {
        assert_eq!(rebuilt.get(path), Some(original), "{}", path.display());
    }
    assert_eq!(fx.snapshot(), live, "recovery changed the live files");
}
