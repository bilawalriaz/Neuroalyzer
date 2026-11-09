//! File helpers: activity checks, atomic writes, hashing, reading.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Files that make up one logical file (SQLite keeps state in -wal/-journal).
pub fn companions(p: &Path, sqlite: bool) -> Vec<PathBuf> {
    let mut v = vec![p.to_path_buf()];
    if sqlite {
        for suf in ["-wal", "-journal"] {
            let mut s = p.as_os_str().to_owned();
            s.push(suf);
            v.push(PathBuf::from(s));
        }
    }
    v
}

pub fn shm_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push("-shm");
    PathBuf::from(s)
}

/// Returns a reason if the file looks in use: recently modified, locked, or
/// (on Windows) open in another process.
pub fn active_reason(p: &Path, sqlite: bool, min_age: Duration) -> Option<String> {
    let now = SystemTime::now();
    for f in companions(p, sqlite) {
        let Ok(meta) = std::fs::metadata(&f) else { continue };
        if let Ok(m) = meta.modified()
            && let Ok(age) = now.duration_since(m)
            && age < min_age
        {
            return Some(format!("active: modified {}s ago", age.as_secs()));
        }
    }
    lock_reason(p)
}

/// Returns a reason if another process holds the file locked (Unix) or open
/// (Windows), or if it can't be opened for writing.
pub fn lock_reason(p: &Path) -> Option<String> {
    open_elsewhere(p)
}

#[cfg(windows)]
fn open_elsewhere(p: &Path) -> Option<String> {
    use std::os::windows::fs::OpenOptionsExt;
    // Share mode 0: fails with a sharing violation if anyone else has it open.
    match std::fs::OpenOptions::new().read(true).write(true).share_mode(0).open(p) {
        Ok(_) => None,
        Err(e) if e.raw_os_error() == Some(32) || e.raw_os_error() == Some(33) => {
            Some("active: open in another process".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Some("not writable: permission denied".into()),
        Err(_) => None,
    }
}

#[cfg(not(windows))]
fn open_elsewhere(p: &Path) -> Option<String> {
    let f = match std::fs::OpenOptions::new().read(true).write(true).open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Some("not writable: permission denied".into());
        }
        Err(_) => return None,
    };
    match f.try_lock() {
        Ok(()) => {
            let _ = f.unlock();
            None
        }
        Err(_) => Some("active: locked by another process".into()),
    }
}

/// Read a whole file, memory-mapping large ones.
pub enum Bytes {
    Vec(Vec<u8>),
    Map(memmap2::Mmap),
}

impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Vec(v) => v,
            Bytes::Map(m) => m,
        }
    }
}

pub fn read(p: &Path) -> Result<Bytes> {
    let f = File::open(p).with_context(|| format!("couldn't open {}", p.display()))?;
    let len = f.metadata()?.len();
    if len >= 4 * 1024 * 1024 {
        // SAFETY: we only read; a concurrent writer could change the bytes, and
        // the redaction step re-checks the file hash against the backup first.
        let m = unsafe { memmap2::Mmap::map(&f) }?;
        Ok(Bytes::Map(m))
    } else {
        let mut v = Vec::with_capacity(len as usize);
        (&f).read_to_end(&mut v)?;
        Ok(Bytes::Vec(v))
    }
}

pub fn hash_bytes(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

pub fn hash_file(p: &Path) -> Result<Option<String>> {
    if !p.exists() {
        return Ok(None);
    }
    let mut h = blake3::Hasher::new();
    let f = File::open(p).with_context(|| format!("couldn't open {}", p.display()))?;
    h.update_reader(f)?;
    Ok(Some(h.finalize().to_hex().to_string()))
}

/// Write via a temp file in the same dir, fsync, then rename over the target.
/// Keeps the original file's permissions.
pub fn atomic_write(p: &Path, data: &[u8]) -> Result<()> {
    let tmp = stage(p, data)?;
    persist(tmp, p)?;
    sync_dir(p.parent().context("file has no parent dir")?);
    Ok(())
}

fn stage(p: &Path, data: &[u8]) -> Result<tempfile::NamedTempFile> {
    let dir = p.parent().context("file has no parent dir")?;
    let perms = std::fs::metadata(p).ok().map(|m| m.permissions());
    let mut tmp = tempfile::Builder::new()
        .prefix(".sesscrub-")
        .tempfile_in(dir)
        .with_context(|| format!("couldn't create a temp file in {}", dir.display()))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    if let Some(perms) = perms {
        std::fs::set_permissions(tmp.path(), perms)?;
    }
    Ok(tmp)
}

/// Result of [`rewrite_checked`].
pub enum Rewrite<T> {
    /// `f` ran on bytes that matched `expected`; the file now holds its output
    /// (or is untouched when `f` returned no new bytes).
    Done { value: T, after: Option<String> },
    /// The file no longer matched `expected` (before reading, or just before
    /// the rename). Nothing was written.
    Changed,
}

/// Read `p` once, check those exact bytes against the backup hash `expected`,
/// run `f` on them, and replace the file with `f`'s output only if the file on
/// disk still matches `expected` immediately before the rename.
///
/// This closes the check-then-act gap of "hash the file, then read it again":
/// what gets redacted is exactly what was backed up, and a write that lands
/// while `f` runs is never overwritten. The file is read into memory rather
/// than mapped, so a concurrent truncation can't fault the process.
///
/// `after` is the hash of the new contents. `on_staged` runs with it after the
/// temp file is durable and before the rename, so a caller can journal the
/// hash it is about to produce.
pub fn rewrite_checked<T>(
    p: &Path,
    expected: &str,
    f: impl FnOnce(&[u8]) -> (T, Option<Vec<u8>>),
    on_staged: impl FnOnce(&str) -> Result<()>,
) -> Result<Rewrite<T>> {
    let bytes = std::fs::read(p).with_context(|| format!("couldn't read {}", p.display()))?;
    if hash_bytes(&bytes) != expected {
        return Ok(Rewrite::Changed);
    }
    let (value, new) = f(&bytes);
    drop(bytes);
    let Some(new) = new else {
        return Ok(Rewrite::Done { value, after: None });
    };
    let after = hash_bytes(&new);
    let tmp = stage(p, &new)?;
    drop(new);
    if hash_file(p)?.as_deref() != Some(expected) {
        return Ok(Rewrite::Changed);
    }
    on_staged(&after)?;
    persist(tmp, p)?;
    sync_dir(p.parent().context("file has no parent dir")?);
    Ok(Rewrite::Done {
        value,
        after: Some(after),
    })
}

/// Stream `r` into `dir/name`, checking its SHA-256. The data goes to a
/// uniquely named temp file that is removed on any failure, and only a verified
/// file is renamed into place, so concurrent or interrupted downloads never
/// leave a partial or mixed file under `name`.
pub fn install_verified(
    dir: &Path,
    name: &str,
    mut r: impl Read,
    sha256_hex: &str,
    mut progress: impl FnMut(u64),
) -> Result<()> {
    use sha2::Digest;
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".partial")
        .tempfile_in(dir)
        .with_context(|| format!("couldn't create a temp file in {}", dir.display()))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = r.read(&mut buf).context("download interrupted")?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        tmp.write_all(&buf[..n])?;
        progress(n as u64);
    }
    tmp.as_file().sync_all()?;
    let got = hex::encode(h.finalize());
    if got != sha256_hex {
        anyhow::bail!("{name} failed its SHA-256 check (expected {sha256_hex}, got {got}). Nothing was kept.");
    }
    tmp.persist(dir.join(name))
        .map_err(|e| e.error)
        .with_context(|| format!("couldn't move {name} into place"))?;
    sync_dir(dir);
    Ok(())
}

fn persist(tmp: tempfile::NamedTempFile, p: &Path) -> Result<()> {
    let mut tmp = tmp;
    // Windows: the target may be briefly held by an indexer or AV scanner.
    for attempt in 0..5 {
        match tmp.persist(p) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if attempt == 4 {
                    return Err(e.error).with_context(|| format!("couldn't replace {}", p.display()));
                }
                tmp = e.file;
                std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
            }
        }
    }
    unreachable!()
}

pub fn sync_dir(_dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(_dir) {
        let _ = d.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_checked_refuses_when_file_changed_before_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f.jsonl");
        std::fs::write(&p, b"original\n").unwrap();
        let backed_up = hash_bytes(b"original\n");
        std::fs::write(&p, b"original\nappended by the agent\n").unwrap();
        let r = rewrite_checked(&p, &backed_up, |_| ((), Some(b"redacted\n".to_vec())), |_| Ok(())).unwrap();
        assert!(matches!(r, Rewrite::Changed));
        assert_eq!(std::fs::read(&p).unwrap(), b"original\nappended by the agent\n");
    }

    /// Regression: a write that lands while the file is being redacted must not
    /// be overwritten by the redacted copy (lost update).
    #[test]
    fn rewrite_checked_does_not_clobber_a_concurrent_write() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f.jsonl");
        std::fs::write(&p, b"secret\n").unwrap();
        let backed_up = hash_bytes(b"secret\n");
        let mut journaled = false;
        let r = rewrite_checked(
            &p,
            &backed_up,
            |b| {
                assert_eq!(b, b"secret\n");
                // The agent appends while we redact.
                let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
                f.write_all(b"new turn\n").unwrap();
                ((), Some(b"[SECRET:00000000]\n".to_vec()))
            },
            |_| {
                journaled = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(r, Rewrite::Changed));
        assert!(!journaled, "nothing may be journaled for a write that didn't happen");
        assert_eq!(std::fs::read(&p).unwrap(), b"secret\nnew turn\n");
        let leftovers: Vec<_> = std::fs::read_dir(d.path()).unwrap().flatten().collect();
        assert_eq!(leftovers.len(), 1, "temp file must be cleaned up");
    }

    #[test]
    fn rewrite_checked_writes_and_reports_after_hash() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f.json");
        std::fs::write(&p, b"secret").unwrap();
        let mut staged = None;
        let r = rewrite_checked(
            &p,
            &hash_bytes(b"secret"),
            |_| (7, Some(b"clean".to_vec())),
            |h| {
                staged = Some(h.to_string());
                Ok(())
            },
        )
        .unwrap();
        let Rewrite::Done { value, after } = r else {
            panic!("expected a write")
        };
        assert_eq!(value, 7);
        assert_eq!(after.as_deref(), Some(hash_bytes(b"clean").as_str()));
        assert_eq!(staged, after);
        assert_eq!(std::fs::read(&p).unwrap(), b"clean");
    }

    #[test]
    fn install_verified_keeps_nothing_on_bad_hash() {
        let d = tempfile::tempdir().unwrap();
        let err = install_verified(d.path(), "model.onnx", &b"tampered"[..], &"0".repeat(64), |_| {}).unwrap_err();
        assert!(format!("{err:#}").contains("SHA-256"));
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            0,
            "no partial file may remain"
        );
    }

    #[test]
    fn install_verified_concurrent_downloads_never_mix() {
        use sha2::Digest;
        let d = tempfile::tempdir().unwrap();
        let body = vec![7u8; 300_000];
        let sha = hex::encode(sha2::Sha256::digest(&body));
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| install_verified(d.path(), "model.onnx", &body[..], &sha, |_| {}).unwrap());
            }
        });
        assert_eq!(std::fs::read(d.path().join("model.onnx")).unwrap(), body);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }
}
