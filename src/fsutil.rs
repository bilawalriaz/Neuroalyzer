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
    if let Some(r) = open_elsewhere(p) {
        return Some(r);
    }
    None
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
    persist(tmp, p)?;
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
