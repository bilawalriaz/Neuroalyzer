//! Edit-level undo for Copilot CLI events.jsonl.
use crate::{backup, fsutil};
use age::secrecy::SecretString;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};

type Fields = BTreeMap<String, Range<usize>>;
type Events = BTreeMap<String, Fields>;

#[derive(Deserialize, Serialize)]
struct Edit {
    event: String,
    field: String,
    original: String,
    replacement: String,
}

#[derive(Deserialize, Serialize)]
struct Record {
    run: String,
    entry: String,
    stage: PathBuf,
    edits: Vec<Edit>,
}

struct Object<'a>(BTreeMap<String, &'a RawValue>);

impl<'de> Deserialize<'de> for Object<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Object<'de>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object with unique keys")
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = BTreeMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    if fields.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(Object(fields))
            }
        }
        d.deserialize_map(Visitor)
    }
}

fn object(raw: &[u8]) -> Result<Object<'_>> {
    // Parser errors can quote input. Keep them out of reports.
    serde_json::from_slice(raw).map_err(|_| anyhow::anyhow!("invalid JSON object or duplicate object key"))
}

fn collect(raw: &RawValue, base: usize, path: &str, fields: &mut Fields) -> Result<()> {
    let s = raw.get();
    match s.as_bytes()[0] {
        b'"' => {
            let start = s.as_ptr() as usize - base;
            fields.insert(path.into(), start..start + s.len());
        }
        b'{' => {
            for (key, value) in object(s.as_bytes())?.0 {
                let key = key.replace('~', "~0").replace('/', "~1");
                collect(value, base, &format!("{path}/{key}"), fields)?;
            }
        }
        b'[' => {
            let values: Vec<&RawValue> = serde_json::from_str(s).map_err(|_| anyhow::anyhow!("invalid JSON array"))?;
            for (i, value) in values.into_iter().enumerate() {
                collect(value, base, &format!("{path}/{i}"), fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn index(bytes: &[u8]) -> Result<Events> {
    let mut events = Events::new();
    for line in bytes
        .split(|&b| b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        // Validate nested values and enforce serde_json's nesting limit before
        // walking borrowed raw values for their exact spans.
        serde_json::from_slice::<serde_json::Value>(line).map_err(|_| anyhow::anyhow!("invalid JSON event"))?;
        let mut object = object(line)?.0;
        let id: String = object
            .remove("id")
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
            .filter(|id: &String| !id.is_empty())
            .context("missing or invalid event ID")?;
        let mut fields = Fields::new();
        for (key, value) in object {
            let key = key.replace('~', "~0").replace('/', "~1");
            collect(value, bytes.as_ptr() as usize, &format!("/{key}"), &mut fields)?;
        }
        ensure!(events.insert(id, fields).is_none(), "duplicate event ID");
    }
    Ok(events)
}

fn splice(bytes: &[u8], mut changes: Vec<(Range<usize>, &[u8])>) -> Result<Vec<u8>> {
    changes.sort_unstable_by_key(|(span, _)| span.start);
    let mut out = Vec::with_capacity(bytes.len());
    let mut last = 0;
    for (span, replacement) in changes {
        ensure!(last <= span.start, "duplicate edit target");
        out.extend_from_slice(&bytes[last..span.start]);
        out.extend_from_slice(replacement);
        last = span.end;
    }
    out.extend_from_slice(&bytes[last..]);
    Ok(out)
}

fn plan(before: &[u8], after: &[u8]) -> Result<Vec<Edit>> {
    let old = index(before)?;
    let new = index(after)?;
    let mut edits = Vec::new();
    let mut changes = Vec::new();
    for (event, fields) in old {
        let next = new.get(&event).context("redaction changed an event ID")?;
        for (field, span) in fields {
            let original = &before[span.clone()];
            let replacement = &after[next.get(&field).context("redaction changed a field path")?.clone()];
            if original != replacement {
                changes.push((span, replacement));
                edits.push(Edit {
                    event: event.clone(),
                    field,
                    original: std::str::from_utf8(original)?.into(),
                    replacement: std::str::from_utf8(replacement)?.into(),
                });
            }
        }
    }
    ensure!(
        !edits.is_empty() && splice(before, changes)? == after,
        "redaction changed bytes outside editable strings"
    );
    Ok(edits)
}

fn reverse(bytes: &[u8], edits: &[Edit]) -> Result<Option<Vec<u8>>> {
    let events = index(bytes)?;
    let mut changes = Vec::new();
    for edit in edits {
        let event = events.get(&edit.event).context("event ID no longer exists")?;
        let span = event.get(&edit.field).context("edited string field no longer exists")?;
        let current = &bytes[span.clone()];
        if current == edit.replacement.as_bytes() {
            changes.push((span.clone(), edit.original.as_bytes()));
        } else {
            ensure!(
                current == edit.original.as_bytes(),
                "edited field no longer matches the replacement"
            );
        }
    }
    if changes.is_empty() {
        return Ok(None);
    }
    ensure!(
        changes.len() == edits.len(),
        "some edited fields no longer match the replacement"
    );
    let output = splice(bytes, changes)?;
    index(&output)?;
    Ok(Some(output))
}

pub(crate) fn supported(job: &crate::discovery::Job) -> bool {
    use crate::discovery::{Format, Schema};
    matches!(job.schema, Schema::CopilotEvents)
        && matches!(job.format, Format::Jsonl)
        && job.path.file_name().is_some_and(|name| name == "events.jsonl")
}

pub(crate) fn dir(archive: &Path) -> PathBuf {
    backup::after_path(archive).with_extension("undo")
}

fn record_path(archive: &Path, entry: &backup::Entry) -> Result<PathBuf> {
    let id = entry.id.strip_prefix("files/").context("invalid undo entry ID")?;
    ensure!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "invalid undo entry ID"
    );
    Ok(dir(archive).join(format!("{id}.age")))
}

fn receipt(record: &Path) -> PathBuf {
    record.with_extension("applied")
}

fn receipt_id(run: &str, entry: &str) -> Vec<u8> {
    format!("{run}/{entry}").into_bytes()
}

pub(crate) struct Run<'a> {
    pub archive: &'a Path,
    pub id: &'a str,
    pub identity: &'a age::x25519::Identity,
}

impl Run<'_> {
    pub(crate) fn clean(
        &self,
        job: &crate::discovery::Job,
        entry: &backup::Entry,
        engine: &crate::engine::Engine,
        journal: &backup::Journal,
    ) -> Result<Option<(crate::engine::Outcome, Option<String>)>> {
        let target = Path::new(&entry.path);
        ensure!(
            std::fs::symlink_metadata(target)?.is_file(),
            "session is not a regular file"
        );
        let bytes = std::fs::read(target)?;
        if fsutil::hash_bytes(&bytes) != entry.before {
            return Ok(None);
        }
        let mut outcome = engine.process_bytes(job, &bytes);
        let Some(output) = outcome.new_bytes.take() else {
            return Ok(Some((outcome, None)));
        };
        let edits = plan(&bytes, &output)?;
        let record_path = record_path(self.archive, entry)?;
        let parent = target.parent().context("session file has no parent")?;
        let mut builder = tempfile::Builder::new();
        builder.prefix(".neuralyzer-undo-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let staging = builder.tempdir_in(parent)?;
        let staged = staging.path().join("session");
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&staged)?;
        file.write_all(&output)?;
        file.set_permissions(std::fs::metadata(target)?.permissions())?;
        file.sync_all()?;
        drop(file);
        fsutil::sync_required(staging.path())?;
        fsutil::sync_required(parent)?;
        crate::paths::ensure_private_dir(&dir(self.archive))?;
        fsutil::sync_required(self.archive.parent().context("backup has no parent")?)?;
        backup::write_undo(
            &record_path,
            &Record {
                run: self.id.into(),
                entry: entry.id.clone(),
                stage: staging.path().into(),
                edits,
            },
            self.identity,
        )?;
        let after = fsutil::hash_bytes(&output);
        let staging = staging.keep();
        journal.record(&entry.id, Some(&after))?;
        // After recording the intent, only the successful rename may remove
        // the staged file. Keep its parent as a witness across interruption.
        if crate::fault::hit("undo-before-rename") {
            std::process::exit(3);
        }
        if !fsutil::replace_checked(&staged, target, &entry.before)? {
            return Ok(None);
        }
        if crate::fault::hit("undo-after-rename") {
            std::process::exit(3);
        }
        if let Err(e) = (|| -> Result<()> {
            fsutil::sync_required(parent)?;
            fsutil::sync_required(&staging)?;
            fsutil::atomic_write(&receipt(&record_path), &receipt_id(self.id, &entry.id))?;
            fsutil::sync_required(&dir(self.archive))?;
            std::fs::remove_dir(&staging)?;
            Ok(())
        })() {
            outcome.drift = Some(format!("couldn't finalize undo receipt: {e:#}"));
        }
        Ok(Some((outcome, Some(after))))
    }
}

pub(crate) fn restore(archive: &Path, pw: &SecretString) -> Result<backup::RestoreOutcome> {
    let (manifest, identity) = backup::read_manifest(archive, pw)?;
    let mut out = backup::RestoreOutcome::default();
    for entry in manifest.entries.iter().filter(|entry| entry.role == "main") {
        let result = restore_entry(archive, identity.as_ref(), &manifest, entry);
        match result {
            Ok(true) => out.restored.push(entry.path.clone()),
            Ok(false) => out.unchanged.push(entry.path.clone()),
            Err(e) => out.skipped.push((entry.path.clone(), format!("{e:#}"))),
        }
    }
    Ok(out)
}

fn restore_entry(
    archive: &Path,
    identity: Option<&age::x25519::Identity>,
    manifest: &backup::Manifest,
    entry: &backup::Entry,
) -> Result<bool> {
    let target = Path::new(&entry.path);
    ensure!(
        entry.tool == "copilot" && target.file_name().is_some_and(|name| name == "events.jsonl"),
        "edit restore is only available for Copilot CLI events.jsonl; use restore --into"
    );
    let path = record_path(archive, entry)?;
    ensure!(
        path.is_file(),
        "no undo record; use restore --into to recover the backup"
    );
    let identity = identity.context("no undo key; use restore --into to recover the backup")?;
    let record: Record = backup::read_undo(&path, identity)?;
    ensure!(
        !manifest.run_id.is_empty() && record.run == manifest.run_id && record.entry == entry.id,
        "undo record belongs to a different backup entry"
    );
    let applied = match std::fs::read(receipt(&path)) {
        Ok(id) => id == receipt_id(&record.run, &record.entry),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // This unique directory is retained until the durable receipt exists.
            // A missing directory cannot establish that an edit was applied.
            ensure!(record.stage.is_dir(), "missing commit evidence; use restore --into");
            match std::fs::symlink_metadata(record.stage.join("session")) {
                Ok(_) => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(applied, "invalid undo receipt");
    if let Some(reason) = fsutil::lock_reason(target) {
        bail!("{reason}");
    }
    ensure!(
        std::fs::symlink_metadata(target)?.is_file(),
        "session is not a regular file"
    );
    let bytes = std::fs::read(target)?;
    let hash = fsutil::hash_bytes(&bytes);
    let output = reverse(&bytes, &record.edits)?;
    drop(bytes);
    let result = fsutil::rewrite_checked(target, &hash, |_| ((), output), |_| Ok(()))?;
    match result {
        fsutil::Rewrite::Done { after, .. } => Ok(after.is_some()),
        fsutil::Rewrite::Changed => bail!("session changed during restore"),
    }
}
