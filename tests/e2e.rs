//! End-to-end tests against generated fixture trees.

mod common;
use common::*;
use std::collections::BTreeMap;

/// Kinds only the NER model finds; skipped when NER is off.
const NER_ONLY: &[&str] = &["PERSON", "ADDRESS", "ORG"];

/// Minimum recall per kind (fraction of planted values gone after clean).
fn min_recall(kind: &str) -> f64 {
    match kind {
        "TABULAR" => 0.95,
        _ => 1.0,
    }
}

fn all_bytes(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    walkdir(root)
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
}

#[test]
fn scan_clean_restore_roundtrip() {
    let fx = fixture();
    let before = fx.snapshot();

    // scan: read-only, finds things, exit 1.
    let o = fx.run(&["scan", "--root", &fx.root_s(), "--no-ner", "--json"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(rep["files_scanned"].as_u64().unwrap() > 20);
    for t in ["copilot", "opencode", "omp"] {
        assert!(
            rep["tools"].as_array().unwrap().iter().any(|x| x["tool"] == t),
            "tool {t} missing"
        );
    }
    let d = diff_snap(&before, &fx.snapshot());
    assert!(d.is_empty(), "scan must not change anything: {d:?}");
    let raw_report = String::from_utf8_lossy(&o.stdout).to_string();
    for p in &fx.manifest.planted {
        assert!(!raw_report.contains(&p.value), "report leaked a {} value", p.kind);
    }

    // clean
    let o = fx.run(&[
        "clean",
        "--root",
        &fx.root_s(),
        "--no-ner",
        "--yes",
        "--password-file",
        &fx.pw_s(),
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(rep["archive"].is_string());
    assert!(rep["files_modified"].as_u64().unwrap() > 10);

    // Every output file is still valid.
    for (p, b) in all_bytes(&fx.root) {
        let name = p.to_string_lossy().to_string();
        if name.ends_with(".json") {
            serde_json::from_slice::<serde_json::Value>(&b).unwrap_or_else(|e| panic!("{name}: {e}"));
        } else if name.ends_with(".jsonl") {
            for l in b.split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
                serde_json::from_slice::<serde_json::Value>(l).unwrap_or_else(|e| panic!("{name}: {e}"));
            }
        } else if b.starts_with(b"SQLite format 3\0") {
            let c = rusqlite::Connection::open(&p).unwrap();
            let r: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
            assert_eq!(r, "ok", "{name}");
        }
    }

    // No plaintext of any planted value remains (raw bytes, including SQLite and WAL files).
    // Session data only: the fixture's project dirs hold the source .env files.
    let projects = fx.root.join("projects");
    let files: Vec<_> = all_bytes(&fx.root)
        .into_iter()
        .filter(|(p, _)| !p.starts_with(&projects))
        .collect();
    let mut table: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut leaks = vec![];
    for p in &fx.manifest.planted {
        if NER_ONLY.contains(&p.kind.as_str()) {
            continue;
        }
        // Table cells that also appear inside prose addresses or names are NER territory.
        if p.kind == "TABULAR"
            && fx
                .manifest
                .planted
                .iter()
                .any(|q| NER_ONLY.contains(&q.kind.as_str()) && q.value.contains(&p.value))
        {
            continue;
        }
        let e = table.entry(p.kind.clone()).or_default();
        e.0 += 1;
        let found = files
            .iter()
            .find(|(_, b)| forms(&p.value).iter().any(|f| contains(b, f)));
        match found {
            None => e.1 += 1,
            Some((path, _)) => leaks.push(format!("{} {:?} in {}", p.kind, p.value, path.display())),
        }
    }
    // Decoys must survive.
    let mut decoys_lost = vec![];
    for d in &fx.manifest.decoys {
        if !files.iter().any(|(_, b)| forms(d).iter().any(|f| contains(b, f))) {
            decoys_lost.push(d.clone());
        }
    }
    eprintln!("\n{:<10} {:>8} {:>8} {:>8}", "kind", "planted", "removed", "recall");
    let mut fail = vec![];
    for (k, (n, ok)) in &table {
        let r = *ok as f64 / *n as f64;
        eprintln!("{k:<10} {n:>8} {ok:>8} {r:>8.3}");
        if r < min_recall(k) {
            fail.push(k.clone());
        }
    }
    let precision = 1.0 - decoys_lost.len() as f64 / fx.manifest.decoys.len().max(1) as f64;
    eprintln!(
        "decoys kept: {}/{} (precision {precision:.3})",
        fx.manifest.decoys.len() - decoys_lost.len(),
        fx.manifest.decoys.len()
    );
    for l in leaks.iter().take(20) {
        eprintln!("leak: {l}");
    }
    assert!(fail.is_empty(), "recall below threshold for {fail:?}");
    assert!(decoys_lost.is_empty(), "decoys were redacted: {decoys_lost:?}");

    // Wrong password fails cleanly.
    let bad = fx.dir.path().join("badpw");
    std::fs::write(&bad, "not the right password at all").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let archive = rep["archive"].as_str().unwrap().to_string();
    let o = fx.run(&["restore", &archive, "--password-file", &bad.display().to_string()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("wrong password"), "{}", stderr(&o));

    // Restore gives byte-identical originals.
    let o = fx.run(&["restore", &archive, "--password-file", &fx.pw_s()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let after = fx.snapshot();
    let mut diffs = vec![];
    for (p, b) in &before {
        match after.get(p) {
            Some(a) if a == b => {}
            Some(_) => diffs.push(format!("changed: {}", p.display())),
            None => diffs.push(format!("missing: {}", p.display())),
        }
    }
    for p in after.keys() {
        if !before.contains_key(p) && !p.to_string_lossy().ends_with("-wal") {
            diffs.push(format!("extra: {}", p.display()));
        }
    }
    assert!(diffs.is_empty(), "restore not lossless:\n{}", diffs.join("\n"));

    // Clean is idempotent after restore + clean again (same tokens).
    let o = fx.run(&[
        "clean",
        "--root",
        &fx.root_s(),
        "--no-ner",
        "--yes",
        "--password-file",
        &fx.pw_s(),
        "--json",
        "--keep",
        "1",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let archives = std::fs::read_dir(fx.data.join("archives")).unwrap().count();
    assert_eq!(archives, 2, "keep=1 should leave one archive and its sidecar");
}

#[test]
fn password_sources() {
    let fx = fixture();
    let base = [
        "clean",
        "--root",
        &fx.root_s(),
        "--no-ner",
        "--yes",
        "--only",
        "omp",
        "--json",
    ];
    // Env var.
    let o = fx.cmd().args(base).env("SESSCRUB_PASSWORD", PASSWORD).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("SESSCRUB_PASSWORD"), "expected env warning");
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let archive = rep["archive"].as_str().unwrap().to_string();
    // Stdin.
    use std::io::Write;
    let mut child = fx
        .cmd()
        .args(["restore", &archive, "--password-stdin"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    // No source and no TTY: clear error.
    let o = fx.run(&["restore", &archive]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("--password-file"), "{}", stderr(&o));
    // Insecure password file refused (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = fx.dir.path().join("loose");
        std::fs::write(&p, PASSWORD).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let o = fx.run(&["restore", &archive, "--password-file", &p.display().to_string()]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("chmod 600"), "{}", stderr(&o));
        let o = fx.run(&[
            "restore",
            &archive,
            "--password-file",
            &p.display().to_string(),
            "--insecure-password-file",
        ]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    }
}

#[test]
fn active_and_locked_files_are_skipped() {
    let fx = fixture();
    let files = walkdir(&fx.root.join(".omp"));
    let jsonl: Vec<_> = files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    assert!(jsonl.len() >= 2);
    // Recently modified.
    let recent = jsonl[0].clone();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&recent)
        .unwrap()
        .set_modified(std::time::SystemTime::now())
        .unwrap();
    let recent_bytes = std::fs::read(&recent).unwrap();
    // Locked by another handle.
    let locked = jsonl[1].clone();
    let locked_bytes = std::fs::read(&locked).unwrap();
    let lf = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&locked)
        .unwrap();
    lf.lock().unwrap();
    let o = fx.run(&[
        "clean",
        "--root",
        &fx.root_s(),
        "--no-ner",
        "--yes",
        "--only",
        "omp",
        "--password-file",
        &fx.pw_s(),
        "--json",
    ]);
    lf.unlock().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let skipped: Vec<(String, String)> = rep["files_skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["path"].as_str().unwrap().to_string(),
                s["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        skipped
            .iter()
            .any(|(p, r)| p == &recent.display().to_string() && r.starts_with("active")),
        "{skipped:?}"
    );
    assert_eq!(std::fs::read(&recent).unwrap(), recent_bytes);
    if cfg!(not(windows)) {
        assert!(
            skipped
                .iter()
                .any(|(p, r)| p == &locked.display().to_string() && r.starts_with("active")),
            "{skipped:?}"
        );
    }
    assert_eq!(std::fs::read(&locked).unwrap(), locked_bytes);
}

#[test]
fn format_drift_fallback() {
    let fx = fixture();
    // Mutate: an omp session whose header is unexpected and that contains a non-JSON line,
    // and a VS Code .json session that is really JSON lines.
    let omp = walkdir(&fx.root.join(".omp"))
        .into_iter()
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap();
    let email = fx
        .manifest
        .planted
        .iter()
        .find(|p| p.kind == "EMAIL")
        .unwrap()
        .value
        .clone();
    let body = format!(
        "{{\"kind\":\"weird\",\"note\":\"hi\"}}\nplain text line mailing {email}\n{{\"nested\":{{\"deep\":[\"contact {email}\"]}}}}\n"
    );
    std::fs::write(&omp, body).unwrap();
    let vs = walkdir(&fx.root)
        .into_iter()
        .find(|p| p.to_string_lossy().contains("chatSessions") && p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    std::fs::write(&vs, format!("{{\"a\":\"{email}\"}}\n{{\"b\":\"x\"}}\n")).unwrap();
    backdate(&fx.root);
    let o = fx.run(&[
        "clean",
        "--root",
        &fx.root_s(),
        "--no-ner",
        "--yes",
        "--password-file",
        &fx.pw_s(),
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let drift: Vec<String> = rep["format_drift"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap().to_string())
        .collect();
    assert!(drift.contains(&omp.display().to_string()), "{drift:?}");
    assert!(drift.contains(&vs.display().to_string()), "{drift:?}");
    for p in [&omp, &vs] {
        let b = std::fs::read_to_string(p).unwrap();
        assert!(!b.contains(&email), "{} still has the email", p.display());
    }
    // The JSON lines that were JSON stay JSON.
    let b = std::fs::read_to_string(&vs).unwrap();
    for l in b.lines() {
        serde_json::from_str::<serde_json::Value>(l).unwrap();
    }
}

#[test]
fn list_works() {
    let fx = fixture();
    let o = fx.run(&["list", "--root", &fx.root_s(), "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    // The fixture generator only builds trees for these three tools.
    for t in v["tools"].as_array().unwrap() {
        if ["copilot", "opencode", "omp"].iter().any(|n| t["tool"] == *n) {
            assert!(t["files"].as_u64().unwrap() > 0, "{t}");
        }
    }
}

fn clean_args(fx: &Fixture) -> Vec<String> {
    [
        "clean",
        "--root",
        &fx.root_s(),
        "--no-ner",
        "--yes",
        "--password-file",
        &fx.pw_s(),
        "--json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn restore_is_lossless(before: &BTreeMap<std::path::PathBuf, Vec<u8>>, after: &BTreeMap<std::path::PathBuf, Vec<u8>>) {
    let mut diffs = vec![];
    for (p, b) in before {
        match after.get(p) {
            Some(a) if a == b => {}
            Some(_) => diffs.push(format!("changed: {}", p.display())),
            None => diffs.push(format!("missing: {}", p.display())),
        }
    }
    assert!(diffs.is_empty(), "restore not lossless:\n{}", diffs.join("\n"));
}

/// Regression (state: archive without after-sidecar). A clean that dies after
/// redacting but before writing `.after.age` used to leave a backup that
/// restore refused file by file ("changed since cleaning", exit 2) unless the
/// user passed --force. The journal now makes it restorable as is.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "fault injection is compiled into debug builds only")]
fn interrupted_clean_is_restorable_without_force() {
    let fx = fixture();
    let before = fx.snapshot();
    let o = fx
        .cmd()
        .args(clean_args(&fx))
        .env("SESSCRUB_TEST_FAULT", "after-redact")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    let names: Vec<String> = std::fs::read_dir(fx.data.join("archives"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(!names.iter().any(|n| n.ends_with(".after.age")), "{names:?}");
    let archive = names
        .iter()
        .find(|n| n.ends_with(".tar.zst.age"))
        .expect("archive")
        .clone();
    assert!(names.iter().any(|n| n.ends_with(".after.journal")), "{names:?}");
    assert!(
        !diff_snap(&before, &fx.snapshot()).is_empty(),
        "files should be redacted"
    );

    let o = fx.run(&["restore", &archive, "--password-file", &fx.pw_s()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("recovery journal"), "{}", stderr(&o));
    restore_is_lossless(&before, &fx.snapshot());
}

/// Regression: a VACUUM failure after the redaction committed was reported as
/// an error with `modified: false`, and the database got no after-hash, so
/// restore treated it as edited since cleaning.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "fault injection is compiled into debug builds only")]
fn vacuum_failure_after_commit_is_reported_as_modified() {
    let fx = fixture();
    let before = fx.snapshot();
    let mut args = clean_args(&fx);
    args.extend(["--only".into(), "opencode".into()]);
    let o = fx
        .cmd()
        .args(&args)
        .env("SESSCRUB_TEST_FAULT", "vacuum")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let dbs: Vec<&serde_json::Value> = rep["tools"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|t| t["files"].as_array().unwrap())
        .filter(|f| f["format"] == "sqlite")
        .collect();
    assert!(!dbs.is_empty());
    for f in dbs {
        assert_eq!(f["modified"], true, "{f}");
        assert!(f["skipped"].is_null(), "{f}");
        assert!(f["drift"].as_str().unwrap_or("").contains("VACUUM failed"), "{f}");
    }
    let archive = rep["archive"].as_str().unwrap().to_string();
    let o = fx.run(&["restore", &archive, "--password-file", &fx.pw_s()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    restore_is_lossless(&before, &fx.snapshot());
}

/// Regression: two cleans (or a clean and a restore) could run at once on one
/// data dir, racing on archive names, session files and prune.
#[test]
fn concurrent_runs_are_refused() {
    let fx = fixture();
    std::fs::create_dir_all(&fx.data).unwrap();
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(fx.data.join("sesscrub.lock"))
        .unwrap();
    held.lock().unwrap();
    let before = fx.snapshot();
    let o = fx.cmd().args(clean_args(&fx)).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("another sesscrub"), "{}", stderr(&o));
    assert!(diff_snap(&before, &fx.snapshot()).is_empty());
    held.unlock().unwrap();
    let o = fx.cmd().args(clean_args(&fx)).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let archive = rep["archive"].as_str().unwrap().to_string();
    held.lock().unwrap();
    let o = fx.run(&["restore", &archive, "--password-file", &fx.pw_s()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("another sesscrub"), "{}", stderr(&o));
}

/// Regression: restore replaced files that another process held locked.
#[cfg(unix)]
#[test]
fn restore_skips_locked_files() {
    let fx = fixture();
    let before = fx.snapshot();
    let mut args = clean_args(&fx);
    args.extend(["--only".into(), "omp".into()]);
    let o = fx.cmd().args(&args).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let archive = rep["archive"].as_str().unwrap().to_string();
    let target = walkdir(&fx.root.join(".omp"))
        .into_iter()
        .find(|p| p.extension().is_some_and(|e| e == "jsonl") && before.get(p) != std::fs::read(p).ok().as_ref())
        .expect("a redacted omp file");
    let redacted = std::fs::read(&target).unwrap();
    let lf = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target)
        .unwrap();
    lf.lock().unwrap();
    let o = fx.run(&["restore", &archive, "--password-file", &fx.pw_s(), "--force"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("locked by another process"), "{}", stderr(&o));
    assert_eq!(
        std::fs::read(&target).unwrap(),
        redacted,
        "a locked file must not be replaced"
    );
    lf.unlock().unwrap();
    let o = fx.run(&["restore", &archive, "--password-file", &fx.pw_s()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    restore_is_lossless(&before, &fx.snapshot());
}
