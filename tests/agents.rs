//! Discovery and a clean/restore round trip for the agents added in 1.2:
//! Claude Code, Codex (including zstd-compressed rollouts), Gemini CLI,
//! Hermes Agent, OpenClaw, Factory Droid and pi.

mod common;
use common::*;
use std::path::Path;

const EMAIL: &str = "jane.doe@example.org";

fn put(root: &Path, rel: &str, body: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn plant(root: &Path) {
    let line = |extra: &str| format!("{{\"type\":\"user\",{extra}\"message\":\"mail me at {EMAIL}\"}}\n");
    put(
        root,
        ".claude/projects/-home-me-proj/0b1c.jsonl",
        line("\"cwd\":\"/home/me/proj\",\"sessionId\":\"0b1c\",").as_bytes(),
    );
    put(root, ".claude/plans/plan.md", format!("Contact {EMAIL}\n").as_bytes());
    let rollout = format!(
        "{{\"type\":\"session_meta\",\"payload\":{{\"cwd\":\"/home/me/proj\"}}}}\n{{\"type\":\"response_item\",\"payload\":{{\"text\":\"{EMAIL}\"}}}}\n"
    );
    put(root, ".codex/sessions/2026/11/09/rollout-a.jsonl", rollout.as_bytes());
    let zst = zstd::stream::encode_all(rollout.as_bytes(), 3).unwrap();
    put(root, ".codex/archived_sessions/rollout-b.jsonl.zst", &zst);
    put(
        root,
        ".gemini/tmp/abc/chats/session-1.json",
        format!("{{\"sessionId\":\"1\",\"messages\":[{{\"content\":\"{EMAIL}\"}}]}}").as_bytes(),
    );
    put(
        root,
        ".hermes/sessions/s1.jsonl",
        format!("{{\"role\":\"user\",\"content\":\"{EMAIL}\"}}\n").as_bytes(),
    );
    let db = root.join(".hermes/state.db");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(&format!(
        "CREATE TABLE sessions(id TEXT PRIMARY KEY);
         CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, content TEXT);
         INSERT INTO sessions VALUES('s1');
         INSERT INTO messages(session_id, content) VALUES('s1', 'write to {EMAIL}');"
    ))
    .unwrap();
    drop(c);
    let pi_line =
        format!("{{\"type\":\"session\",\"cwd\":\"/home/me/proj\"}}\n{{\"type\":\"message\",\"text\":\"{EMAIL}\"}}\n");
    put(root, ".openclaw/agents/main/sessions/s.jsonl", pi_line.as_bytes());
    put(root, ".pi/agent/sessions/--home-me--/s.jsonl", pi_line.as_bytes());
    put(
        root,
        ".factory/sessions/-home-me/s.jsonl",
        format!("{{\"type\":\"session_start\",\"cwd\":\"/home/me\"}}\n{{\"type\":\"message\",\"text\":\"{EMAIL}\"}}\n")
            .as_bytes(),
    );
}

#[test]
fn new_agents_roundtrip() {
    let fx = fixture();
    plant(&fx.root);
    backdate(&fx.root);
    let only = "claude,codex,gemini,hermes,openclaw,droid,pi";
    let before = fx.snapshot();

    let o = fx.run(&["scan", "--root", &fx.root_s(), "--only", only, "--no-ner", "--json"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    for t in only.split(',') {
        assert!(
            rep["tools"].as_array().unwrap().iter().any(|x| x["tool"] == t),
            "{t} not found: {}",
            rep["tools"]
        );
    }

    let o = fx.run(&[
        "clean",
        "--root",
        &fx.root_s(),
        "--only",
        only,
        "--no-ner",
        "--yes",
        "--password-file",
        &fx.pw_s(),
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let rep: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let name = rep["archive"].as_str().unwrap().to_string();

    for (p, b) in fx.snapshot() {
        if !before.contains_key(&p) || p.to_string_lossy().contains("copilot") {
            continue;
        }
        let plain = if p.to_string_lossy().ends_with(".zst") {
            zstd::stream::decode_all(&b[..]).expect("zst still decodes")
        } else {
            b
        };
        assert!(
            !contains(&plain, EMAIL.as_bytes()),
            "{} still has the email",
            p.display()
        );
    }
    let c = rusqlite::Connection::open(fx.root.join(".hermes/state.db")).unwrap();
    let v: String = c.query_row("SELECT content FROM messages", [], |r| r.get(0)).unwrap();
    assert!(v.contains("[EMAIL:"), "{v}");
    drop(c);

    assert_recovered(&fx, &name, &before);
}
