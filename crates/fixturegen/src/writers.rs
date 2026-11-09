//! Renders sessions into the on-disk layout of each tool.
//!
//! All file output goes through [`Out`], which streams through a `BufWriter` and counts bytes.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};

use crate::Layout;
use crate::content::{Project, Session, Turn};
use crate::rng::{ALNUM, HEX, Rng};
use crate::values;

/// Size of the title slot line in omp session files.
const TITLE_SLOT_BYTES: usize = 256;

const OPENCODE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS session_v2 (id TEXT PRIMARY KEY, directory TEXT, title TEXT);
CREATE TABLE IF NOT EXISTS session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER, data TEXT);
CREATE TABLE IF NOT EXISTS session_part (message_id TEXT, session_id TEXT, ordinal INTEGER, type TEXT, call_id TEXT, data TEXT, PRIMARY KEY (message_id, ordinal));
CREATE TABLE IF NOT EXISTS message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, data TEXT);
";

/// Output root plus a running count of bytes written.
pub struct Out {
    pub root: PathBuf,
    pub bytes: u64,
}

struct Counting<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Out {
    pub fn new(root: PathBuf) -> Self {
        Self { root, bytes: 0 }
    }

    fn write_with<F>(&mut self, path: &Path, body: F) -> io::Result<()>
    where
        F: FnOnce(&mut dyn Write) -> io::Result<()>,
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut counter = Counting {
            inner: BufWriter::with_capacity(256 * 1024, File::create(path)?),
            count: 0,
        };
        body(&mut counter)?;
        counter.inner.flush()?;
        self.bytes += counter.count;
        Ok(())
    }

    fn text(&mut self, path: &Path, body: &str) -> io::Result<()> {
        self.write_with(path, |w| w.write_all(body.as_bytes()))
    }

    fn json(&mut self, path: &Path, value: &Value) -> io::Result<()> {
        self.write_with(path, |w| serde_json::to_writer(w, value).map_err(io::Error::other))
    }

    fn json_pretty(&mut self, path: &Path, value: &Value) -> io::Result<()> {
        self.write_with(path, |w| {
            serde_json::to_writer_pretty(w, value).map_err(io::Error::other)
        })
    }
}

fn write_lines(w: &mut dyn Write, values: &[Value]) -> io::Result<()> {
    for value in values {
        serde_json::to_writer(&mut *w, value)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

fn db(e: rusqlite::Error) -> io::Error {
    io::Error::other(e)
}

/// Formats epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let day_secs = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        day_secs / 3600,
        day_secs % 3600 / 60,
        day_secs % 60
    )
}

/// Howard Hinnant's days-to-civil conversion.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn new_id(rng: &mut Rng, prefix: &str) -> String {
    format!("{prefix}_{}", rng.chars(ALNUM, 26))
}

fn hex_id(rng: &mut Rng) -> String {
    rng.chars(HEX, 8)
}

pub fn write_project(out: &mut Out, project: &Project) -> io::Result<()> {
    out.text(&project.dir.join(".env"), &project.env_text())
}

// ---------------------------------------------------------------- VS Code / Copilot Chat

/// One VS Code edition under one layout. `extras` adds the legacy `.json` and empty-window files.
#[derive(Clone, Copy, Debug)]
pub struct VsCodeSpot {
    pub layout: Layout,
    pub edition: &'static str,
    pub extras: bool,
}

fn user_data_root(layout: Layout) -> &'static str {
    match layout {
        Layout::Mac => "Library/Application Support",
        Layout::Linux => ".config",
        Layout::Windows => "AppData/Roaming",
    }
}

fn chat_header(s: &Session) -> Value {
    json!({
        "version": 3,
        "creationDate": s.created_ms,
        "sessionId": s.id,
        "requests": [],
        "responderUsername": "GitHub Copilot",
        "initialLocation": "panel",
    })
}

fn vscode_request(t: &Turn) -> Value {
    let mut response = vec![json!(t.assistant)];
    for tc in &t.tools {
        response.push(json!({
            "kind": "toolInvocationSerialized",
            "toolId": "run_in_terminal",
            "invocationMessage": {"value": tc.command},
            "isComplete": true,
            "resultDetails": {"output": tc.output},
        }));
    }
    json!({
        "requestId": t.request_id,
        "message": {"text": t.user, "parts": [{"kind": "text", "text": t.user}]},
        "variableData": {"variables": []},
        "response": response,
        "result": {"metadata": {}},
    })
}

pub fn write_vscode(out: &mut Out, s: &Session, project: &Project, spot: VsCodeSpot) -> io::Result<()> {
    let user = out
        .root
        .join(user_data_root(spot.layout))
        .join(spot.edition)
        .join("User");
    let ws = user.join("workspaceStorage").join(&s.ws_id);

    out.json(
        &ws.join("workspace.json"),
        &json!({"folder": format!("file://{}", project.dir_string())}),
    )?;

    let requests: Vec<Value> = s.turns.iter().map(vscode_request).collect();
    let header = chat_header(s);
    let mut lines = vec![json!({"kind": 0, "v": header})];
    lines.extend(requests.iter().map(|r| json!({"kind": 2, "k": ["requests"], "v": [r]})));
    let chat = ws.join("chatSessions").join(format!("{}.jsonl", s.id));
    out.write_with(&chat, |w| write_lines(w, &lines))?;

    if spot.extras {
        let mut legacy = header.clone();
        legacy["requests"] = Value::Array(requests);
        out.json_pretty(&ws.join("chatSessions").join(format!("{}.json", s.legacy_id)), &legacy)?;
        let empty = user
            .join("globalStorage")
            .join("emptyWindowChatSessions")
            .join(format!("{}.jsonl", s.legacy_id));
        out.write_with(&empty, |w| write_lines(w, &lines))?;
    }

    write_state_db(out, &ws.join("state.vscdb"), s)
}

fn write_state_db(out: &mut Out, path: &Path, s: &Session) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut entries = Map::new();
    entries.insert(
        s.id.clone(),
        json!({
            "sessionId": s.id,
            "title": s.title,
            "lastMessageDate": s.created_ms,
            "isEmpty": false,
        }),
    );
    let index = json!({"version": 1, "entries": entries}).to_string();
    let memento = Value::Array(
        s.turns
            .iter()
            .map(|t| {
                json!({
                    "requestId": t.request_id,
                    "message": {"text": t.user},
                    "response": [{"value": t.assistant}],
                })
            })
            .collect(),
    )
    .to_string();
    let rows = [
        ("chat.ChatSessionStore.index", index),
        ("memento/interactive-session", memento),
        ("workbench.panel.state", s.panel_json.clone()),
    ];

    let conn = Connection::open(path).map_err(db)?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);")
        .map_err(db)?;
    conn.execute_batch("BEGIN").map_err(db)?;
    for (key, value) in &rows {
        conn.execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params![*key, value.as_bytes()],
        )
        .map_err(db)?;
        out.bytes += value.len() as u64;
    }
    conn.execute_batch("COMMIT").map_err(db)
}

// ---------------------------------------------------------------- Copilot CLI

struct Events {
    items: Vec<Value>,
    last: Option<String>,
    at_ms: i64,
}

impl Events {
    fn new(start_ms: i64) -> Self {
        Self {
            items: Vec::new(),
            last: None,
            at_ms: start_ms,
        }
    }

    fn push(&mut self, rng: &mut Rng, kind: &str, data: Value) {
        let id = values::uuid(rng);
        self.items.push(json!({
            "id": id,
            "type": kind,
            "timestamp": iso(self.at_ms),
            "parentId": self.last,
            "data": data,
        }));
        self.last = Some(id);
        self.at_ms += 1500;
    }
}

pub fn write_copilot(out: &mut Out, rng: &mut Rng, s: &Session, project: &Project) -> io::Result<()> {
    let dir = out.root.join(".copilot").join("session-state").join(&s.id);
    let cwd = project.dir_string();
    let mut events = Events::new(s.created_ms);
    events.push(
        rng,
        "session.start",
        json!({
            "sessionId": s.id,
            "version": 1,
            "producer": "copilot-agent",
            "selectedModel": "gpt-5",
            "context": {"cwd": cwd},
        }),
    );
    for t in &s.turns {
        events.push(rng, "user.message", json!({"content": t.user, "attachments": []}));
        let message_id = values::uuid(rng);
        events.push(
            rng,
            "assistant.message",
            json!({"messageId": message_id, "content": t.assistant}),
        );
        for tc in &t.tools {
            events.push(
                rng,
                "tool.execution_start",
                json!({
                    "toolCallId": tc.call_id,
                    "toolName": "bash",
                    "arguments": {"command": tc.command},
                }),
            );
            events.push(
                rng,
                "tool.execution_complete",
                json!({
                    "toolCallId": tc.call_id,
                    "success": true,
                    "result": {"contents": [{"type": "terminal", "text": tc.output}]},
                }),
            );
        }
    }
    out.write_with(&dir.join("events.jsonl"), |w| write_lines(w, &events.items))?;
    out.text(&dir.join("plan.md"), &s.plan_md)?;
    out.text(
        &dir.join("workspace.yaml"),
        &format!("id: {}\ncwd: {}\n", s.id, project.dir_string()),
    )
}

// ---------------------------------------------------------------- OpenCode

enum OcPart {
    Text(String),
    Tool {
        call_id: String,
        command: String,
        output: String,
    },
}

struct OcMsg {
    id: String,
    role: &'static str,
    parts: Vec<(String, OcPart)>,
}

/// Legacy v1 part body (the `part` table `data` column and the JSON-tree file share it).
fn v1_part_body(part: &OcPart) -> Map<String, Value> {
    let mut body = Map::new();
    match part {
        OcPart::Text(text) => {
            body.insert("type".into(), json!("text"));
            body.insert("text".into(), json!(text));
        }
        OcPart::Tool {
            call_id,
            command,
            output,
        } => {
            body.insert("type".into(), json!("tool"));
            body.insert("callID".into(), json!(call_id));
            body.insert("tool".into(), json!("bash"));
            body.insert(
                "state".into(),
                json!({
                    "status": "completed",
                    "input": {"command": command},
                    "output": output,
                    "title": "bash",
                    "metadata": {},
                }),
            );
        }
    }
    body
}

/// Current `session_part` data shape.
fn new_part_data(part: &OcPart) -> Value {
    match part {
        OcPart::Text(text) => json!({"text": text}),
        OcPart::Tool {
            call_id,
            command,
            output,
        } => json!({
            "id": call_id,
            "name": "bash",
            "state": {
                "status": "completed",
                "input": {"command": command},
                "content": [{"type": "text", "text": output}],
                "metadata": {},
            },
        }),
    }
}

pub fn open_opencode_db(path: &Path) -> io::Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    for stale in [
        path.to_path_buf(),
        path.with_extension("db-wal"),
        path.with_extension("db-shm"),
    ] {
        let _ = fs::remove_file(stale);
    }
    let conn = Connection::open(path).map_err(db)?;
    conn.pragma_update(None, "journal_mode", "WAL").map_err(db)?;
    conn.execute_batch(OPENCODE_SCHEMA).map_err(db)?;
    conn.execute_batch("BEGIN").map_err(db)?;
    Ok(conn)
}

pub fn commit(conn: &Connection) -> io::Result<()> {
    conn.execute_batch("COMMIT").map_err(db)
}

pub fn write_opencode(
    out: &mut Out,
    conn: &Connection,
    rng: &mut Rng,
    s: &Session,
    project: &Project,
) -> io::Result<()> {
    let sid = format!("ses_{}", s.id.replace('-', ""));
    let mut messages = Vec::new();
    for t in &s.turns {
        let user_id = new_id(rng, "msg");
        let user_part = new_id(rng, "prt");
        messages.push(OcMsg {
            id: user_id,
            role: "user",
            parts: vec![(user_part, OcPart::Text(t.user.clone()))],
        });

        let assistant_id = new_id(rng, "msg");
        let mut parts = vec![(new_id(rng, "prt"), OcPart::Text(t.assistant.clone()))];
        for tc in &t.tools {
            parts.push((
                new_id(rng, "prt"),
                OcPart::Tool {
                    call_id: tc.call_id.clone(),
                    command: tc.command.clone(),
                    output: tc.output.clone(),
                },
            ));
        }
        messages.push(OcMsg {
            id: assistant_id,
            role: "assistant",
            parts,
        });
    }

    let legacy_root = out
        .root
        .join(".local")
        .join("share")
        .join("opencode")
        .join("storage")
        .join("session");
    let mut bytes = 0u64;
    conn.execute(
        "INSERT INTO session_v2 (id, directory, title) VALUES (?1, ?2, ?3)",
        params![sid, project.dir_string(), s.title],
    )
    .map_err(db)?;

    let mut seq = 0i64;
    for m in &messages {
        let session_data = match m.parts.first() {
            Some((_, OcPart::Text(text))) if m.role == "user" => json!({"text": text}),
            _ => json!({}),
        }
        .to_string();
        conn.execute(
            "INSERT INTO session_message (id, session_id, type, seq, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![m.id, sid, m.role, seq, session_data],
        )
        .map_err(db)?;
        bytes += session_data.len() as u64;
        seq += 1;

        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![m.id, sid, json!({"role": m.role}).to_string()],
        )
        .map_err(db)?;

        let created = s.created_ms + seq * 1000;
        let message_file = legacy_root.join("message").join(&sid).join(format!("{}.json", m.id));
        out.json(
            &message_file,
            &json!({"id": m.id, "sessionID": sid, "role": m.role, "time": {"created": created}}),
        )?;

        for (ordinal, (part_id, part)) in m.parts.iter().enumerate() {
            let body = v1_part_body(part);
            let legacy_data = Value::Object(body.clone()).to_string();
            conn.execute(
                "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
                params![part_id, m.id, sid, legacy_data],
            )
            .map_err(db)?;
            bytes += legacy_data.len() as u64;

            if m.role == "assistant" {
                let (part_type, call_id) = match part {
                    OcPart::Text(_) => ("text", None),
                    OcPart::Tool { call_id, .. } => ("tool", Some(call_id.clone())),
                };
                let data = new_part_data(part).to_string();
                conn.execute(
                    "INSERT INTO session_part (message_id, session_id, ordinal, type, call_id, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![m.id, sid, ordinal as i64, part_type, call_id, data],
                )
                .map_err(db)?;
                bytes += data.len() as u64;
            }

            let mut file_body = body;
            file_body.insert("id".into(), json!(part_id));
            file_body.insert("sessionID".into(), json!(sid));
            file_body.insert("messageID".into(), json!(m.id));
            let part_file = legacy_root
                .join("part")
                .join(&sid)
                .join(&m.id)
                .join(format!("{part_id}.json"));
            out.json(&part_file, &Value::Object(file_body))?;
        }
    }
    out.bytes += bytes;
    Ok(())
}

// ---------------------------------------------------------------- omp

struct OmpLog {
    lines: Vec<String>,
    parent: Option<String>,
    at_ms: i64,
}

impl OmpLog {
    fn add(&mut self, rng: &mut Rng, message: Value) {
        let id = hex_id(rng);
        let entry = json!({
            "type": "message",
            "id": id,
            "parentId": self.parent,
            "timestamp": iso(self.at_ms),
            "message": message,
        });
        self.lines.push(entry.to_string());
        self.parent = Some(id);
        self.at_ms += 1000;
    }
}

/// Title line padded so the whole JSON object is exactly `TITLE_SLOT_BYTES` long.
fn title_slot(title: &str, updated: &str) -> String {
    let render = |pad: &str| {
        format!(
            "{{\"type\":\"title\",\"v\":1,\"title\":{},\"updatedAt\":{},\"pad\":\"{}\"}}",
            Value::from(title),
            Value::from(updated),
            pad
        )
    };
    let overhead = render("").len();
    render(&"x".repeat(TITLE_SLOT_BYTES.saturating_sub(overhead)))
}

pub fn write_omp(out: &mut Out, rng: &mut Rng, s: &Session, project: &Project) -> io::Result<()> {
    let started = iso(s.created_ms);
    let dir = out
        .root
        .join(".omp")
        .join("agent")
        .join("sessions")
        .join(format!("-proj-{}", project.name));
    let file = dir.join(format!("{}_{}.jsonl", started.replace([':', '.'], "-"), s.id));
    let header = json!({
        "type": "session",
        "version": 3,
        "id": s.id,
        "timestamp": started,
        "cwd": project.dir_string(),
    });
    let mut log = OmpLog {
        lines: vec![header.to_string(), title_slot(&s.title, &started)],
        parent: None,
        at_ms: s.created_ms,
    };
    for t in &s.turns {
        log.add(rng, json!({"role": "user", "content": t.user}));
        let mut content = vec![json!({"type": "text", "text": t.assistant})];
        content.extend(t.tools.iter().map(|tc| {
            json!({
                "type": "toolCall",
                "id": tc.call_id,
                "name": "bash",
                "arguments": {"command": tc.command},
            })
        }));
        log.add(rng, json!({"role": "assistant", "content": content}));
        for tc in &t.tools {
            log.add(
                rng,
                json!({
                    "role": "toolResult",
                    "toolCallId": tc.call_id,
                    "toolName": "bash",
                    "content": [{"type": "text", "text": tc.output}],
                    "isError": false,
                }),
            );
        }
    }
    out.write_with(&file, |w| {
        for line in &log.lines {
            w.write_all(line.as_bytes())?;
            w.write_all(b"\n")?;
        }
        Ok(())
    })
}
