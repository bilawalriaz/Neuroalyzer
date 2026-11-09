//! Encrypted backups.
//!
//! Layout: `sesscrub-<ts>.tar.zst.age` is a tar stream, zstd-compressed (level
//! 3, multithreaded), then age-encrypted with a scrypt passphrase. Nothing is
//! written to disk in plaintext. The first tar entry is `manifest.json` (paths,
//! sizes, mtimes, modes and BLAKE3 "before" hashes); file bodies follow as
//! `files/NNNNNN`.
//!
//! The "after" hashes only exist once redaction finishes, so they go in a small
//! sidecar, `sesscrub-<ts>.after.age`, encrypted with the same password. That
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
    pub sesscrub_version: String,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct After {
    pub archive: String,
    /// Entry id -> hash after redaction (None: the file no longer exists).
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
    let d = age::Decryptor::new(r).context("this doesn't look like a sesscrub archive")?;
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

fn unique_base(dir: &Path) -> PathBuf {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let mut base = dir.join(format!("sesscrub-{ts}"));
    let mut i = 1;
    while PathBuf::from(format!("{}{ARCHIVE_EXT}", base.display())).exists() {
        base = dir.join(format!("sesscrub-{ts}-{i}"));
        i += 1;
    }
    base
}

pub fn archive_path(base: &Path) -> PathBuf {
    PathBuf::from(format!("{}{ARCHIVE_EXT}", base.display()))
}

pub fn after_path(archive: &Path) -> PathBuf {
    let s = archive.display().to_string();
    PathBuf::from(format!("{}{AFTER_EXT}", s.strip_suffix(ARCHIVE_EXT).unwrap_or(&s)))
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
        let before = crate::fsutil::hash_file(&s.path)?.context("file vanished before backup")?;
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
        sesscrub_version: env!("CARGO_PKG_VERSION").into(),
        entries,
    };
    let base = unique_base(dir);
    let final_path = archive_path(&base);
    let partial = PathBuf::from(format!("{}.partial", final_path.display()));
    let result = (|| -> Result<()> {
        let f = File::create(&partial).with_context(|| format!("couldn't create {}", partial.display()))?;
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
    v.sort_by(|a, b| b.name.cmp(&a.name));
    v
}

/// Keep the newest `keep` archives (and their sidecars); delete the rest.
pub fn prune(dir: &Path, keep: usize) -> Vec<PathBuf> {
    let mut removed = vec![];
    for a in list(dir).into_iter().skip(keep.max(1)) {
        if std::fs::remove_file(&a.path).is_ok() {
            let _ = std::fs::remove_file(after_path(&a.path));
            removed.push(a.path);
        }
    }
    removed
}

// ---------- restore ----------

#[derive(Default)]
pub struct RestoreOutcome {
    pub restored: Vec<String>,
    pub unchanged: Vec<String>,
    pub skipped: Vec<(String, String)>,
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
    let after = read_after(archive, pw)?;
    let f = File::open(archive).with_context(|| format!("couldn't open {}", archive.display()))?;
    let dec = decrypt_reader(BufReader::with_capacity(1 << 20, f), pw)?;
    let z = zstd::Decoder::new(dec)?;
    let mut ar = tar::Archive::new(z);
    let mut manifest: Option<Manifest> = None;
    let mut out = RestoreOutcome::default();
    let mut group_decision: BTreeMap<usize, bool> = BTreeMap::new();
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
        let go = *group_decision.entry(e.group).or_insert_with(|| {
            let group: Vec<&Entry> = m.entries.iter().filter(|x| x.group == e.group).collect();
            let all_original = group.iter().all(|x| {
                crate::fsutil::hash_file(Path::new(&x.path)).ok().flatten().as_deref() == Some(x.before.as_str())
            });
            if all_original {
                return false;
            }
            let matches_after = after.as_ref().is_some_and(|a| {
                group.iter().all(|x| {
                    let now = crate::fsutil::hash_file(Path::new(&x.path)).ok().flatten();
                    a.after.get(&x.id).map(|h| h.as_deref()) == Some(now.as_deref())
                })
            });
            matches_after || force || decide(&e)
        });
        if current.as_deref() == Some(e.before.as_str()) {
            out.unchanged.push(e.path.clone());
            std::io::copy(&mut ent, &mut std::io::sink())?;
            progress.inc(e.size);
            continue;
        }
        if !go {
            out.skipped.push((
                e.path.clone(),
                "changed since cleaning; not overwritten (use --force)".into(),
            ));
            std::io::copy(&mut ent, &mut std::io::sink())?;
            progress.inc(e.size);
            continue;
        }
        let dir = target.parent().context("bad path in archive")?;
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::Builder::new().prefix(".sesscrub-restore-").tempfile_in(dir)?;
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
