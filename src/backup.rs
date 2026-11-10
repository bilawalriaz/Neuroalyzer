//! Encrypted backups.
//!
//! Layout: `neuralyzer-<ts>.tar.zst.age` is a tar stream, zstd-compressed (level
//! 3, multithreaded), then age-encrypted with a scrypt passphrase. Nothing is
//! written to disk in plaintext. The first tar entry is `manifest.json` (paths,
//! sizes, mtimes, modes and BLAKE3 "before" hashes); file bodies follow as
//! `files/NNNNNN`.
//!
//! The "after" hashes only exist once redaction finishes, so they go in a small
//! sidecar, `neuralyzer-<ts>.after.age`, encrypted with the same password. That
//! keeps the archive itself write-once and verifiable before any session file
//! is touched.

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

pub const ARCHIVE_EXT: &str = ".tar.zst.age";
pub const AFTER_EXT: &str = ".after.age";
pub const JOURNAL_EXT: &str = ".after.journal";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub id: String,
    /// Files in the same group (a SQLite db and its -wal) are restored together.
    pub group: usize,
    pub role: String,
    pub tool: String,
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub mode: Option<u32>,
    pub before: String,
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub created_at: String,
    pub neuralyzer_version: String,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct After {
    pub archive: String,
    /// Entry id -> hash after redaction (None: the file no longer exists).
    /// Only entries clean actually wrote are listed (sidecars written before
    /// v0.1.1 list every entry).
    pub after: BTreeMap<String, Option<String>>,
}

pub struct Source {
    pub group: usize,
    pub role: &'static str,
    pub tool: String,
    pub path: PathBuf,
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn encryptor(pw: &SecretString) -> age::Encryptor {
    age::Encryptor::with_user_passphrase(pw.clone())
}

fn decrypt_reader<R: Read>(r: R, pw: &SecretString) -> Result<impl Read> {
    let d = age::Decryptor::new(r).context("this doesn't look like a neuralyzer archive")?;
    let id = age::scrypt::Identity::new(pw.clone());
    d.decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                anyhow::anyhow!("wrong password, or the archive is damaged")
            }
            other => anyhow::anyhow!("couldn't decrypt the archive: {other}"),
        })
}

struct HashingReader<R> {
    inner: R,
    h: blake3::Hasher,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.h.update(&buf[..n]);
        Ok(n)
    }
}

/// Pick a fresh archive name and claim it by creating its `.partial` file with
/// `create_new`, so two runs in the same second can never share (and truncate)
/// one partial file. A suffix is added on collision: `-1`, `-2`, ...
fn reserve(dir: &Path) -> Result<(PathBuf, File)> {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    for i in 0u32.. {
        let base = if i == 0 {
            dir.join(format!("neuralyzer-{ts}"))
        } else {
            dir.join(format!("neuralyzer-{ts}-{i}"))
        };
        let final_path = archive_path(&base);
        if final_path.exists() {
            continue;
        }
        let partial = partial_path(&final_path);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&partial) {
            Ok(f) => return Ok((final_path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("couldn't create {}", partial.display())),
        }
    }
    unreachable!()
}

fn partial_path(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.partial", p.display()))
}

/// Ordering key from an archive file name: (timestamp, collision suffix).
/// `None` for names neuralyzer didn't make.
pub fn name_key(name: &str) -> Option<(String, u32)> {
    let stem = name.strip_prefix("neuralyzer-")?.strip_suffix(ARCHIVE_EXT)?;
    let (ts, n) = match stem.get(15..) {
        Some("") => (stem, 0),
        Some(rest) => (&stem[..15], rest.strip_prefix('-')?.parse().ok()?),
        None => return None,
    };
    let ok = ts.len() == 15
        && ts
            .bytes()
            .enumerate()
            .all(|(i, b)| if i == 8 { b == b'-' } else { b.is_ascii_digit() });
    ok.then(|| (ts.to_string(), n))
}

pub fn archive_path(base: &Path) -> PathBuf {
    PathBuf::from(format!("{}{ARCHIVE_EXT}", base.display()))
}

pub fn after_path(archive: &Path) -> PathBuf {
    let s = archive.display().to_string();
    PathBuf::from(format!("{}{AFTER_EXT}", s.strip_suffix(ARCHIVE_EXT).unwrap_or(&s)))
}

pub fn journal_path(archive: &Path) -> PathBuf {
    let s = archive.display().to_string();
    PathBuf::from(format!("{}{JOURNAL_EXT}", s.strip_suffix(ARCHIVE_EXT).unwrap_or(&s)))
}

fn file_meta(p: &Path) -> Result<(u64, i64, Option<u32>)> {
    let m = std::fs::metadata(p).with_context(|| format!("couldn't read {}", p.display()))?;
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64);
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(m.permissions().mode())
    };
    #[cfg(not(unix))]
    let mode = None;
    Ok((m.len(), mtime, mode))
}

/// Create and verify an archive of `sources`. Returns the archive path and manifest.
pub fn create(
    sources: &[Source],
    pw: &SecretString,
    dir: &Path,
    progress: &indicatif::ProgressBar,
) -> Result<(PathBuf, Manifest)> {
    crate::paths::ensure_private_dir(dir)?;
    let mut entries = vec![];
    for (i, s) in sources.iter().enumerate() {
        let (size, mtime, mode) = file_meta(&s.path)?;
        let before = crate::fsutil::hash_file(&s.path)?.context("a file disappeared before it could be backed up")?;
        entries.push(Entry {
            id: format!("files/{i:06}"),
            group: s.group,
            role: s.role.into(),
            tool: s.tool.clone(),
            path: s.path.display().to_string(),
            size,
            mtime,
            mode,
            before,
        });
    }
    let manifest = Manifest {
        version: 1,
        created_at: chrono::Local::now().to_rfc3339(),
        neuralyzer_version: env!("CARGO_PKG_VERSION").into(),
        entries,
    };
    let (final_path, f) = reserve(dir)?;
    let partial = partial_path(&final_path);
    let result = (|| -> Result<()> {
        crate::paths::make_private(&partial)?;
        let enc = encryptor(pw).wrap_output(BufWriter::with_capacity(1 << 20, f))?;
        let mut z = zstd::Encoder::new(enc, 3)?;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()) as u32;
        z.multithread(threads.clamp(1, 8))?;
        let mut tar = tar::Builder::new(z);
        let mj = serde_json::to_vec_pretty(&manifest)?;
        let mut h = tar::Header::new_gnu();
        h.set_size(mj.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar.append_data(&mut h, "manifest.json", &mj[..])?;
        for e in &manifest.entries {
            let f = File::open(&e.path).with_context(|| format!("couldn't open {}", e.path))?;
            let mut r = HashingReader {
                inner: BufReader::with_capacity(1 << 20, f).take(e.size),
                h: blake3::Hasher::new(),
            };
            let mut h = tar::Header::new_gnu();
            h.set_size(e.size);
            h.set_mode(0o600);
            h.set_cksum();
            tar.append_data(&mut h, &e.id, &mut r)
                .with_context(|| format!("couldn't back up {}", e.path))?;
            if r.h.finalize().to_hex().as_str() != e.before {
                bail!(
                    "{} changed while it was being backed up. Nothing was modified; run clean again.",
                    e.path
                );
            }
            progress.inc(e.size);
        }
        let z = tar.into_inner()?;
        let enc = z.finish()?;
        let mut bw = enc.finish()?;
        bw.flush()?;
        let f = bw.into_inner().map_err(io_err)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    if let Err(e) = verify(&partial, pw, &manifest) {
        let _ = std::fs::remove_file(&partial);
        return Err(e.context("backup verification failed, so no session files were changed"));
    }
    std::fs::rename(&partial, &final_path)?;
    crate::fsutil::sync_dir(dir);
    Ok((final_path, manifest))
}

/// Re-open, decrypt and check the entry count and every hash.
pub fn verify(path: &Path, pw: &SecretString, expected: &Manifest) -> Result<()> {
    let f = File::open(path)?;
    let dec = decrypt_reader(BufReader::with_capacity(1 << 20, f), pw)?;
    let z = zstd::Decoder::new(dec)?;
    let mut ar = tar::Archive::new(z);
    let mut seen = 0usize;
    let mut manifest_ok = false;
    for ent in ar.entries()? {
        let mut ent = ent?;
        let name = ent.path()?.to_string_lossy().to_string();
        if name == "manifest.json" {
            let m: Manifest = serde_json::from_reader(&mut ent)?;
            manifest_ok = m.entries.len() == expected.entries.len();
            continue;
        }
        let e = expected
            .entries
            .iter()
            .find(|e| e.id == name)
            .with_context(|| format!("unexpected entry {name}"))?;
        let mut h = blake3::Hasher::new();
        std::io::copy(&mut ent, &mut h)?;
        if h.finalize().to_hex().as_str() != e.before {
            bail!("hash mismatch for {}", e.path);
        }
        seen += 1;
    }
    if !manifest_ok || seen != expected.entries.len() {
        bail!("expected {} files, found {seen}", expected.entries.len());
    }
    Ok(())
}

pub fn write_after(archive: &Path, after: &After, pw: &SecretString) -> Result<()> {
    let p = after_path(archive);
    let tmp = PathBuf::from(format!("{}.partial", p.display()));
    let f = File::create(&tmp)?;
    crate::paths::make_private(&tmp)?;
    let mut w = encryptor(pw).wrap_output(BufWriter::new(f))?;
    w.write_all(&serde_json::to_vec(after)?)?;
    let mut bw = w.finish()?;
    bw.flush()?;
    bw.into_inner().map_err(io_err)?.sync_all()?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Where restore got its after-hashes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterSource {
    Sidecar,
    /// The clean was interrupted before the sidecar was written.
    Journal,
    Missing,
}

pub fn load_after(archive: &Path, pw: &SecretString) -> Result<(Option<After>, AfterSource)> {
    if let Some(a) = read_after(archive, pw)? {
        return Ok((Some(a), AfterSource::Sidecar));
    }
    match read_journal(&journal_path(archive))? {
        Some(a) => Ok((Some(a), AfterSource::Journal)),
        None => Ok((None, AfterSource::Missing)),
    }
}

pub fn read_after(archive: &Path, pw: &SecretString) -> Result<Option<After>> {
    let p = after_path(archive);
    if !p.exists() {
        return Ok(None);
    }
    let mut r = decrypt_reader(BufReader::new(File::open(&p)?), pw)?;
    let mut buf = vec![];
    r.read_to_end(&mut buf)?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

pub struct ArchiveInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub modified: chrono::DateTime<chrono::Local>,
}

pub fn list(dir: &Path) -> Vec<ArchiveInfo> {
    let mut v: Vec<ArchiveInfo> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(ARCHIVE_EXT) {
                return None;
            }
            let m = e.metadata().ok()?;
            Some(ArchiveInfo {
                path: e.path(),
                name,
                size: m.len(),
                modified: m.modified().ok()?.into(),
            })
        })
        .collect();
    // Newest first. Compare the timestamp, then the collision suffix as a
    // number: plain name order puts `-1` below the un-suffixed archive of the
    // same second and `-10` below `-2`. Names neuralyzer didn't make go last.
    v.sort_by(|a, b| match (name_key(&a.name), name_key(&b.name)) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => b.name.cmp(&a.name),
    });
    v
}

/// Keep the newest `keep` archives (and their sidecars); delete the rest.
/// Only archives with names neuralyzer made are counted or deleted. Leftover
/// `.partial` files from interrupted runs are removed too: the caller holds the
/// run lock, so no other run can be writing one.
pub fn prune(dir: &Path, keep: usize) -> Vec<PathBuf> {
    let mut removed = vec![];
    let ours = list(dir).into_iter().filter(|a| name_key(&a.name).is_some());
    for a in ours.skip(keep.max(1)) {
        if std::fs::remove_file(&a.path).is_ok() {
            let _ = std::fs::remove_file(after_path(&a.path));
            let _ = std::fs::remove_file(journal_path(&a.path));
            removed.push(a.path);
        }
    }
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with("neuralyzer-") && n.ends_with(".partial") {
            let _ = std::fs::remove_file(e.path());
        }
    }
    removed
}

// ---------- after-hash journal ----------

/// Crash-safe record of after-redaction hashes, written while `clean` runs.
///
/// The encrypted sidecar can only be written once the whole redaction pass is
/// over. A run that stops before then (Ctrl-C, crash, power loss, disk full)
/// would leave redacted files with no after-hashes, and restore would then
/// treat every one of them as edited since cleaning. The journal closes that
/// gap: each hash is appended and fsynced before the file it describes is
/// replaced, so it is never behind the disk. It holds only entry ids and
/// BLAKE3 hashes of redacted content, never file contents, and is owner-only.
/// It is deleted once the sidecar is safely written.
pub struct Journal {
    path: PathBuf,
    f: std::sync::Mutex<File>,
}

impl Journal {
    pub fn create(archive: &Path) -> Result<Self> {
        let path = journal_path(archive);
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("couldn't create {}", path.display()))?;
        crate::paths::make_private(&path)?;
        Ok(Self {
            path,
            f: std::sync::Mutex::new(f),
        })
    }

    /// Record that entry `id` now hashes to `hash` (`None`: the file is gone).
    pub fn record(&self, id: &str, hash: Option<&str>) -> Result<()> {
        let mut f = self.f.lock().unwrap();
        writeln!(f, "{id}\t{}", hash.unwrap_or("-"))?;
        f.sync_data()?;
        Ok(())
    }

    /// The sidecar now holds everything; drop the journal.
    pub fn remove(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_journal(p: &Path) -> Result<Option<After>> {
    let s = match std::fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("couldn't read {}", p.display())),
    };
    let mut a = After::default();
    // A torn last line (crash mid-append) is ignored; later lines win.
    for line in s.lines() {
        if let Some((id, h)) = line.split_once('\t')
            && id.starts_with("files/")
            && (h == "-" || (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())))
        {
            a.after.insert(id.to_string(), (h != "-").then(|| h.to_string()));
        }
    }
    Ok(Some(a))
}

// ---------- restore ----------

#[derive(Default)]
pub struct RestoreOutcome {
    pub restored: Vec<String>,
    pub unchanged: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub after_source: Option<AfterSource>,
}

pub enum Decision {
    Restore,
    Skip(String),
}

/// Stream the archive and put files back. `decide` is called when a file
/// changed since cleaning (it returns true to overwrite).
pub fn restore(
    archive: &Path,
    pw: &SecretString,
    force: bool,
    mut decide: impl FnMut(&Entry) -> bool,
    progress: &indicatif::ProgressBar,
) -> Result<RestoreOutcome> {
    let (after, source) = load_after(archive, pw)?;
    let f = File::open(archive).with_context(|| format!("couldn't open {}", archive.display()))?;
    let dec = decrypt_reader(BufReader::with_capacity(1 << 20, f), pw)?;
    let z = zstd::Decoder::new(dec)?;
    let mut ar = tar::Archive::new(z);
    let mut manifest: Option<Manifest> = None;
    let mut out = RestoreOutcome {
        after_source: Some(source),
        ..Default::default()
    };
    let mut group_decision: BTreeMap<usize, Result<bool, String>> = BTreeMap::new();
    for ent in ar.entries()? {
        let mut ent = ent?;
        let name = ent.path()?.to_string_lossy().to_string();
        if name == "manifest.json" {
            manifest = Some(serde_json::from_reader(&mut ent).context("the archive manifest is damaged")?);
            if let Some(m) = &manifest {
                progress.set_length(m.entries.iter().map(|e| e.size).sum());
            }
            continue;
        }
        let m = manifest.as_ref().context("the archive has no manifest")?;
        let e = m
            .entries
            .iter()
            .find(|e| e.id == name)
            .with_context(|| format!("unexpected archive entry {name}"))?
            .clone();
        let target = PathBuf::from(&e.path);
        let current = crate::fsutil::hash_file(&target)?;
        // Decide once per group (the main file comes first).
        let go = group_decision
            .entry(e.group)
            .or_insert_with(|| {
                let group: Vec<&Entry> = m.entries.iter().filter(|x| x.group == e.group).collect();
                let all_original = group.iter().all(|x| {
                    crate::fsutil::hash_file(Path::new(&x.path)).ok().flatten().as_deref() == Some(x.before.as_str())
                });
                if all_original {
                    return Ok(false);
                }
                // Replacing a file another process holds open loses that
                // process's later writes (they go to the old inode) or gets
                // overwritten by them. Never do it, even with --force.
                if let Some(r) = group.iter().find_map(|x| {
                    let p = Path::new(&x.path);
                    if p.exists() { crate::fsutil::lock_reason(p) } else { None }
                }) {
                    return Err(format!("{r}; not overwritten. Close the app and run restore again"));
                }
                let matches_after = after.as_ref().is_some_and(|a| {
                    group.iter().all(|x| {
                        let now = crate::fsutil::hash_file(Path::new(&x.path)).ok().flatten();
                        a.after.get(&x.id).map(|h| h.as_deref()) == Some(now.as_deref())
                    })
                });
                if matches_after || force {
                    return Ok(true);
                }
                let untouched = source == AfterSource::Sidecar
                    && after.as_ref().is_some_and(|a| group.iter().all(|x| !a.after.contains_key(&x.id)));
                if untouched {
                    return Err(
                        "clean didn't change this file (it changed on its own after the backup); not overwritten (use --force)"
                            .into(),
                    );
                }
                Ok(decide(&e))
            })
            .clone();
        if current.as_deref() == Some(e.before.as_str()) {
            out.unchanged.push(e.path.clone());
            std::io::copy(&mut ent, &mut std::io::sink())?;
            progress.inc(e.size);
            continue;
        }
        if go != Ok(true) {
            let reason = go
                .err()
                .unwrap_or_else(|| "changed since cleaning; not overwritten (use --force)".into());
            out.skipped.push((e.path.clone(), reason));
            std::io::copy(&mut ent, &mut std::io::sink())?;
            progress.inc(e.size);
            continue;
        }
        let dir = target.parent().context("bad path in archive")?;
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".neuralyzer-restore-")
            .tempfile_in(dir)?;
        let mut hr = HashingReader {
            inner: &mut ent,
            h: blake3::Hasher::new(),
        };
        std::io::copy(&mut hr, tmp.as_file_mut())?;
        if hr.h.finalize().to_hex().as_str() != e.before {
            out.skipped.push((
                e.path.clone(),
                "archive entry is damaged (hash mismatch); left as is".into(),
            ));
            continue;
        }
        tmp.as_file().sync_all()?;
        #[cfg(unix)]
        if let Some(mode) = e.mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode & 0o7777))?;
        }
        let mt = std::time::UNIX_EPOCH + std::time::Duration::from_secs(e.mtime.max(0) as u64);
        let _ = tmp.as_file().set_modified(mt);
        tmp.persist(&target)
            .map_err(|er| er.error)
            .with_context(|| format!("couldn't write {}", target.display()))?;
        if e.role == "main" && m.entries.iter().any(|x| x.group == e.group && x.role != "main") {
            // A restored SQLite db must not pair with a stale shared-memory index.
            let _ = std::fs::remove_file(crate::fsutil::shm_path(&target));
        }
        if e.role == "main" {
            for suf in ["-wal", "-journal"] {
                let in_backup = m
                    .entries
                    .iter()
                    .any(|x| x.group == e.group && x.role == suf.trim_start_matches('-'));
                let p = PathBuf::from(format!("{}{suf}", target.display()));
                if !in_backup && p.exists() && crate::discovery::is_sqlite(&target) {
                    let _ = std::fs::remove_file(&p);
                    let _ = std::fs::remove_file(crate::fsutil::shm_path(&target));
                }
            }
        }
        progress.inc(e.size);
        out.restored.push(e.path.clone());
    }
    if manifest.is_none() {
        bail!("the archive is empty or damaged");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn name_key_parses_neuralyzer_names_only() {
        assert_eq!(
            name_key("neuralyzer-20261109-120000.tar.zst.age"),
            Some(("20261109-120000".into(), 0))
        );
        assert_eq!(
            name_key("neuralyzer-20261109-120000-12.tar.zst.age"),
            Some(("20261109-120000".into(), 12))
        );
        assert_eq!(name_key("my-copy.tar.zst.age"), None);
        assert_eq!(name_key("neuralyzer-2026-11-09.tar.zst.age"), None);
        assert_eq!(name_key("neuralyzer-20261109-120000-x.tar.zst.age"), None);
    }

    /// Regression: `-1` sorted below the un-suffixed archive of the same second
    /// and `-10` below `-2`, so list showed them out of order and prune deleted
    /// the newest backup.
    #[test]
    fn collision_suffixes_sort_newest_first() {
        let d = tempfile::tempdir().unwrap();
        for n in [
            "neuralyzer-20261109-115959.tar.zst.age",
            "neuralyzer-20261109-120000.tar.zst.age",
            "neuralyzer-20261109-120000-1.tar.zst.age",
            "neuralyzer-20261109-120000-2.tar.zst.age",
            "neuralyzer-20261109-120000-10.tar.zst.age",
        ] {
            touch(d.path(), n);
        }
        let names: Vec<String> = list(d.path()).into_iter().map(|a| a.name).collect();
        assert_eq!(
            names,
            [
                "neuralyzer-20261109-120000-10.tar.zst.age",
                "neuralyzer-20261109-120000-2.tar.zst.age",
                "neuralyzer-20261109-120000-1.tar.zst.age",
                "neuralyzer-20261109-120000.tar.zst.age",
                "neuralyzer-20261109-115959.tar.zst.age",
            ]
        );
    }

    #[test]
    fn prune_keeps_the_newest_collision_and_foreign_files() {
        let d = tempfile::tempdir().unwrap();
        for n in [
            "neuralyzer-20261109-120000.tar.zst.age",
            "neuralyzer-20261109-120000.after.age",
            "neuralyzer-20261109-120000-1.tar.zst.age",
            "neuralyzer-20261109-120000-1.after.age",
            "hand-copied.tar.zst.age",
            "neuralyzer-20261109-110000.tar.zst.age.partial",
        ] {
            touch(d.path(), n);
        }
        let removed = prune(d.path(), 1);
        assert_eq!(removed.len(), 1);
        let mut left: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "hand-copied.tar.zst.age",
                "neuralyzer-20261109-120000-1.after.age",
                "neuralyzer-20261109-120000-1.tar.zst.age",
            ]
        );
    }

    /// Regression: two runs in the same second both opened the same
    /// `.partial` with `File::create`, truncating each other's archive.
    #[test]
    fn concurrent_reservations_get_distinct_names() {
        let d = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8).map(|_| s.spawn(|| reserve(d.path()).unwrap().0)).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let uniq: std::collections::BTreeSet<_> = paths.iter().collect();
        assert_eq!(uniq.len(), paths.len(), "{paths:?}");
    }

    #[test]
    fn journal_round_trip_ignores_torn_lines() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("neuralyzer-20261109-120000.tar.zst.age");
        let j = Journal::create(&a).unwrap();
        let h = "a".repeat(64);
        j.record("files/000000", Some(&h)).unwrap();
        j.record("files/000001", None).unwrap();
        j.record("files/000000", Some(&"b".repeat(64))).unwrap();
        drop(j);
        let mut f = std::fs::OpenOptions::new().append(true).open(journal_path(&a)).unwrap();
        f.write_all(b"files/000002\tabc").unwrap();
        let got = read_journal(&journal_path(&a)).unwrap().unwrap();
        assert_eq!(got.after.len(), 2);
        assert_eq!(got.after["files/000000"].as_deref(), Some("b".repeat(64).as_str()));
        assert_eq!(got.after["files/000001"], None);
    }
}

#[cfg(test)]
mod restore_tests {
    use super::*;

    /// Regression: clean used to give files it skipped (because they changed
    /// after the backup) an after-hash equal to their new contents, so restore
    /// thought they were "as clean left them" and rolled the agent's edits back
    /// to the older backup copy without asking.
    #[test]
    fn restore_leaves_files_clean_never_wrote() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("s.jsonl");
        std::fs::write(&f, b"original\n").unwrap();
        let pw = SecretString::from("correct horse battery staple 42".to_string());
        let src = [Source {
            group: 0,
            role: "main",
            tool: "custom".into(),
            path: f.clone(),
        }];
        let pb = indicatif::ProgressBar::hidden();
        let (a, _) = create(&src, &pw, &d.path().join("archives"), &pb).unwrap();
        // Clean skipped the file: the agent appended after the backup.
        std::fs::write(&f, b"original\nnew turn\n").unwrap();
        write_after(&a, &After::default(), &pw).unwrap();
        let out = restore(&a, &pw, false, |_| panic!("must not ask"), &pb).unwrap();
        assert!(out.restored.is_empty());
        assert_eq!(out.skipped.len(), 1);
        assert!(out.skipped[0].1.contains("clean didn't change"), "{:?}", out.skipped);
        assert_eq!(std::fs::read(&f).unwrap(), b"original\nnew turn\n");
    }
}
