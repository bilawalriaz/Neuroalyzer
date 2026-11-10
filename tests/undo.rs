//! Edit-level restore tests using generated Copilot CLI events.
mod common;

use common::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Output;

fn session() -> (Fixture, PathBuf) {
    let mut fx = fixture();
    fs::remove_dir_all(&fx.root).unwrap();
    fx.root = fx.dir.path().join("undo-home");
    let path = fx.root.join(".copilot/session-state/test-session/events.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    (fx, path)
}

fn events(from: usize, to: usize) -> String {
    (from..=to)
        .map(|n| format!(
            r#"  {{ "type": "user.message", "id": "event-{n}", "data": {{ "a/b~": [{{"content":"Hello\u0020user{n}@example.test"}}], "number": 1e+02 }} }}"#
        ) + if n % 2 == 0 { "\r\n" } else { "\n" })
        .collect()
}

fn clean(fx: &Fixture, fault: Option<&str>) -> Output {
    let mut cmd = fx.cmd();
    cmd.args([
        "clean",
        "--root",
        &fx.root_s(),
        "--only",
        "copilot",
        "--no-ner",
        "--min-age",
        "0",
        "--yes",
        "--password-file",
        &fx.pw_s(),
        "--json",
    ]);
    if let Some(fault) = fault {
        cmd.env("NEURALYZER_TEST_FAULT", fault);
    }
    cmd.output().unwrap()
}

fn clean_archive(fx: &Fixture) -> String {
    let output = clean(fx, None);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["files_modified"], 1, "{report}");
    report["archive"].as_str().unwrap().into()
}

fn restore(fx: &Fixture, archive: &str, code: i32) -> Output {
    let output = fx.run(&["restore", archive, "--password-file", &fx.pw_s()]);
    assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
    output
}

fn append(path: &Path, content: &str) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
}

#[test]
fn two_cleans_can_be_undone_independently() {
    let (fx, path) = session();
    let first = events(1, 10);
    let second = events(11, 15);
    fs::write(&path, &first).unwrap();
    let a = clean_archive(&fx);
    for archive_file in walkdir(&fx.data.join("archives")) {
        let bytes = fs::read(&archive_file).unwrap();
        assert!(!contains(&bytes, b"example.test"));
        assert!(!contains(&bytes, b"[EMAIL:"));
    }
    let cleaned_a = fs::read_to_string(&path).unwrap();
    assert!(cleaned_a.contains("[EMAIL:"));
    append(&path, &second);
    let b = clean_archive(&fx);
    let cleaned_b = fs::read_to_string(&path).unwrap();
    let tail = cleaned_b.strip_prefix(&cleaned_a).unwrap();
    assert_ne!(tail, second);

    restore(&fx, &a, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{first}{tail}"));
    restore(&fx, &a, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{first}{tail}"));
    restore(&fx, &b, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{first}{second}"));
}

#[test]
fn newer_edit_conflicts_until_it_is_undone() {
    let (fx, path) = session();
    let project = fx.root.join("project");
    fs::create_dir(&project).unwrap();
    let start = serde_json::json!({
        "id": "start", "type": "session.start", "data": {"context": {"cwd": project}}
    });
    let original = format!("{start}\n{}", events(1, 2).replace("Hello", "fixture-rotation-marker"));
    fs::write(&path, &original).unwrap();
    let a = clean_archive(&fx);
    let cleaned_a = fs::read(&path).unwrap();
    fs::write(project.join(".env"), "DEMO_SECRET=fixture-rotation-marker\n").unwrap();
    let b = clean_archive(&fx);
    let cleaned_b = fs::read(&path).unwrap();
    let output = restore(&fx, &a, 2);
    assert!(stderr(&output).contains("no longer matches"));
    assert_eq!(fs::read(&path).unwrap(), cleaned_b);
    restore(&fx, &b, 0);
    assert_eq!(fs::read(&path).unwrap(), cleaned_a);
    restore(&fx, &a, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn ambiguous_missing_or_changed_fields_skip_the_entire_session() {
    let (fx, path) = session();
    let original = events(1, 2);
    fs::write(&path, &original).unwrap();
    let archive = clean_archive(&fx);
    let clean = fs::read_to_string(&path).unwrap();
    let (first, second) = clean.split_once('\n').unwrap();
    for (edited, reason) in [
        (format!("{clean}{second}"), "duplicate event ID"),
        (format!("{first}\n"), "event ID no longer exists"),
        (
            clean.replace("\"id\": \"event-2\"", "\"parentId\": \"event-2\""),
            "missing or invalid event ID",
        ),
        (
            format!("{first}\n{}", second.replace("\"content\"", "\"text\"")),
            "field no longer exists",
        ),
        (
            format!("{}\n{second}", first.replace("Hello ", "Edited ")),
            "no longer matches",
        ),
    ] {
        fs::write(&path, &edited).unwrap();
        let output = restore(&fx, &archive, 2);
        assert!(stderr(&output).contains(reason), "{}", stderr(&output));
        assert!(!stderr(&output).contains("example.test"));
        assert_eq!(fs::read_to_string(&path).unwrap(), edited);
    }
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "fault injection requires a debug build")]
fn interruption_before_and_after_rename() {
    for fault in ["undo-before-rename", "undo-after-rename"] {
        let (fx, path) = session();
        let original = events(1, 2);
        fs::write(&path, &original).unwrap();
        let output = clean(&fx, Some(fault));
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        let archive = walkdir(&fx.data.join("archives"))
            .into_iter()
            .find(|p| p.to_string_lossy().ends_with(".tar.zst.age"))
            .unwrap();
        let mut expected = original.clone();
        if fault == "undo-before-rename" {
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
            // If someone independently writes the exact staged values, matching
            // replacement bytes alone must not make the unapplied edit eligible.
            let staged = walkdir(path.parent().unwrap())
                .into_iter()
                .find(|p| p.file_name().is_some_and(|n| n == "session"))
                .unwrap();
            expected = fs::read_to_string(staged).unwrap();
            fs::write(&path, &expected).unwrap();
        } else {
            assert_ne!(fs::read_to_string(&path).unwrap(), original);
        }
        let tail = events(3, 4);
        append(&path, &tail);
        restore(&fx, archive.to_str().unwrap(), 0);
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{expected}{tail}"));
    }
}

#[test]
fn missing_undo_only_allows_recovery_to_a_new_folder() {
    let (fx, path) = session();
    let original = events(1, 2);
    fs::write(&path, &original).unwrap();
    let archive = clean_archive(&fx);
    let cleaned = fs::read(&path).unwrap();
    let old_style_archive = fx.dir.path().join("archive-only.tar.zst.age");
    fs::copy(&archive, &old_style_archive).unwrap();
    let name = old_style_archive.to_str().unwrap();
    assert!(stderr(&restore(&fx, name, 2)).contains("no undo record"));
    assert_eq!(recover(&fx, name)[&path], original.as_bytes());
    assert_eq!(fs::read(&path).unwrap(), cleaned);
}

#[cfg(unix)]
#[test]
fn restore_skips_locked_sessions() {
    let (fx, path) = session();
    let original = events(1, 2);
    fs::write(&path, &original).unwrap();
    let archive = clean_archive(&fx);
    let cleaned = fs::read(&path).unwrap();
    let live = fs::File::open(&path).unwrap();
    live.lock().unwrap();
    assert!(stderr(&restore(&fx, &archive, 2)).contains("locked by another process"));
    assert_eq!(fs::read(&path).unwrap(), cleaned);
    live.unlock().unwrap();
    restore(&fx, &archive, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn legacy_manifest_recovers_without_touching_live_files() {
    let (fx, path) = session();
    let original = events(1, 1);
    let live = events(2, 2);
    fs::write(&path, &live).unwrap();
    let archive = fx.dir.path().join("legacy.tar.zst.age");
    let encryptor = age::Encryptor::with_user_passphrase(PASSWORD.to_owned().into());
    let encrypted = encryptor.wrap_output(fs::File::create(&archive).unwrap()).unwrap();
    let mut tar = tar::Builder::new(zstd::Encoder::new(encrypted, 0).unwrap());
    let manifest = serde_json::json!({
        "version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "neuralyzer_version": "3.0.4",
        "entries": [{
            "id": "files/000000", "group": 0, "role": "main", "tool": "copilot",
            "path": path, "size": original.len(), "mtime": 0, "mode": null,
            "before": blake3::hash(original.as_bytes()).to_hex().as_str()
        }]
    })
    .to_string();
    for (name, data) in [("manifest.json", manifest), ("files/000000", original.clone())] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, name, data.as_bytes()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap().finish().unwrap();

    let archive = archive.to_str().unwrap();
    assert!(stderr(&restore(&fx, archive, 2)).contains("no undo record"));
    assert_eq!(recover(&fx, archive)[&path], original.as_bytes());
    assert_eq!(fs::read_to_string(&path).unwrap(), live);
}

#[test]
fn clean_leaves_unidentifiable_events_untouched() {
    let (fx, path) = session();
    let original = events(1, 2).replace("event-2", "event-1");
    fs::write(&path, &original).unwrap();
    let output = clean(&fx, None);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("duplicate event ID"));
    assert!(!report.contains("example.test"));
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}
