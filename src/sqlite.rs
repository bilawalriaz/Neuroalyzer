//! SQLite handling. Every TEXT cell, and every BLOB cell that decodes as UTF-8
//! JSON, is scanned. Updates run in one transaction with secure_delete on,
//! then the WAL is checkpointed and truncated so old plaintext doesn't linger.

use crate::discovery::{Job, Schema};
use crate::engine::{Counts, Engine, Outcome};
use anyhow::{Context, Result};
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::time::Duration;

pub enum SqlResult {
    Done(Outcome),
    Busy,
}

fn q(id: &str) -> String {
    format!("\"{}\"", id.replace('"', "\"\""))
}

/// Open for reading without creating -wal/-shm files when none exist.
pub fn open_readonly(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if crate::fsutil::companions(path, true)[1].exists() {
        Connection::open_with_flags(path, flags)
    } else {
        Connection::open_with_flags(file_uri(path) + "?immutable=1", flags | OpenFlags::SQLITE_OPEN_URI)
    }
}

fn file_uri(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    // file:///abs/path on Unix, file:///C:/path on Windows.
    let mut out = String::from("file://");
    if !s.starts_with('/') {
        out.push('/');
    }
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::DatabaseBusy || f.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

fn redact_cell(engine: &Engine, s: &str, col: &str, counts: &mut Counts) -> Option<String> {
    let t = s.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        match engine.redact_json(s.as_bytes(), counts) {
            Ok(Some(b)) => return String::from_utf8(b).ok(),
            Ok(None) => return None,
            Err(()) => {}
        }
    }
    if let Some(ner) = &engine.ner {
        ner.prepare(std::iter::once(s));
    }
    engine.redact_str(s, col, counts)
}

pub fn process(engine: &Engine, job: &Job, write: bool) -> Result<SqlResult> {
    let flags = if write {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
    };
    let wal = crate::fsutil::companions(&job.path, true)[1].clone();
    // Read-only opens of a WAL database create -wal/-shm files. With no WAL
    // present there's nothing to miss, so open it immutable and touch nothing.
    let conn = if !write && !wal.exists() {
        Connection::open_with_flags(file_uri(&job.path) + "?immutable=1", flags | OpenFlags::SQLITE_OPEN_URI)
    } else {
        Connection::open_with_flags(&job.path, flags)
    }
    .with_context(|| format!("couldn't open {}", job.path.display()))?;
    conn.busy_timeout(Duration::from_secs(2))?;
    let mut o = Outcome {
        bytes: job.size,
        ..Default::default()
    };

    let tables: Vec<(String, String)> = match conn
        .prepare("SELECT name, COALESCE(sql,'') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut st| {
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()
        }) {
        Ok(t) => t,
        Err(e) if is_busy(&e) => return Ok(SqlResult::Busy),
        Err(e) => return Err(e).context("reading the schema"),
    };
    let virtual_tables: Vec<&str> = tables
        .iter()
        .filter(|(_, sql)| sql.to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE"))
        .map(|(n, _)| n.as_str())
        .collect();
    let names: Vec<&str> = tables.iter().map(|(n, _)| n.as_str()).collect();
    let expected_ok = match job.schema {
        Schema::VscodeState => names.contains(&"ItemTable"),
        Schema::OpencodeDb => ["session_part", "part", "session_message", "message", "messages"]
            .iter()
            .any(|t| names.contains(t)),
        _ => true,
    };
    if !expected_ok {
        o.drift = Some(format!(
            "didn't match the expected {} layout; scanned every table generically",
            job.schema.name()
        ));
    }
    let mut notes: Vec<String> = vec![];
    let mut updates: Vec<(String, String, i64, Value)> = vec![];
    for (table, sql) in &tables {
        if virtual_tables.contains(&table.as_str())
            || virtual_tables.iter().any(|v| table.starts_with(&format!("{v}_")))
        {
            notes.push(format!("skipped full-text index table {table}"));
            continue;
        }
        if sql.to_ascii_uppercase().contains("WITHOUT ROWID") {
            notes.push(format!("skipped table {table} (WITHOUT ROWID)"));
            continue;
        }
        let cols: Vec<String> = conn
            .prepare(&format!("PRAGMA table_info({})", q(table)))?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<_>>()?;
        if cols.is_empty() {
            continue;
        }
        // In VS Code's state.vscdb only touch chat-related rows.
        let key_filter = job.schema == Schema::VscodeState && table == "ItemTable" && cols.iter().any(|c| c == "key");
        let key_idx = cols.iter().position(|c| c == "key");
        let sel = format!(
            "SELECT rowid, {} FROM {}",
            cols.iter().map(|c| q(c)).collect::<Vec<_>>().join(", "),
            q(table)
        );
        let mut st = conn.prepare(&sel)?;
        let mut rows = st.query([])?;
        loop {
            let row = match rows.next() {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(e) if is_busy(&e) => return Ok(SqlResult::Busy),
                Err(e) => return Err(e.into()),
            };
            let rowid: i64 = row.get(0)?;
            if key_filter {
                let k: String = row.get::<_, Option<String>>(1 + key_idx.unwrap())?.unwrap_or_default();
                let kl = k.to_ascii_lowercase();
                if !(kl.contains("chat") || kl.contains("copilot") || kl.contains("interactive")) {
                    continue;
                }
            }
            for (ci, col) in cols.iter().enumerate() {
                let colname = col.to_ascii_lowercase();
                match row.get_ref(ci + 1)? {
                    ValueRef::Text(b) => {
                        if let Ok(s) = std::str::from_utf8(b)
                            && let Some(new) = redact_cell(engine, s, &colname, &mut o.counts)
                        {
                            updates.push((table.clone(), col.clone(), rowid, Value::Text(new)));
                        }
                    }
                    ValueRef::Blob(b) => {
                        if let Ok(s) = std::str::from_utf8(b) {
                            let t = s.trim_start();
                            if (t.starts_with('{') || t.starts_with('['))
                                && serde_json::from_str::<serde::de::IgnoredAny>(s).is_ok()
                                && let Some(new) = redact_cell(engine, s, &colname, &mut o.counts)
                            {
                                updates.push((table.clone(), col.clone(), rowid, Value::Blob(new.into_bytes())));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if !notes.is_empty() {
        let n = notes.join("; ");
        o.drift = Some(match o.drift.take() {
            Some(d) => format!("{d}; {n}"),
            None => n,
        });
    }
    o.would_change = !updates.is_empty();
    if write && !updates.is_empty() {
        conn.pragma_update(None, "secure_delete", "ON")?;
        let mut conn = conn;
        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(t) => t,
            Err(e) if is_busy(&e) => return Ok(SqlResult::Busy),
            Err(e) => return Err(e.into()),
        };
        for (table, col, rowid, val) in &updates {
            tx.execute(
                &format!("UPDATE {} SET {} = ?1 WHERE rowid = ?2", q(table), q(col)),
                rusqlite::params![val, rowid],
            )?;
        }
        tx.commit()?;
        // Old row versions survive in free pages and slack space from the
        // app's own earlier updates. VACUUM rebuilds the file without them.
        match conn.execute_batch("VACUUM") {
            Ok(()) => {}
            Err(e) if is_busy(&e) => {}
            Err(e) => return Err(e).context("VACUUM after redaction"),
        }
        // Push everything into the main file and truncate the WAL.
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        conn.close().map_err(|(_, e)| e)?;
    }
    Ok(SqlResult::Done(o))
}
