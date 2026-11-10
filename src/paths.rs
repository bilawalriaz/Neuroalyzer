//! Where neuroalyzer keeps its own files.
//!
//! `NEUROALYZER_DATA_DIR` overrides the data dir (archives, reports, model, HMAC
//! key). Tests use it to stay out of the real profile.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("NEUROALYZER_DATA_DIR") {
        return PathBuf::from(p);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neuroalyzer")
}

pub fn config_file() -> PathBuf {
    if let Some(p) = std::env::var_os("NEUROALYZER_CONFIG") {
        return PathBuf::from(p);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neuroalyzer")
        .join("config.toml")
}

pub fn archives_dir() -> PathBuf {
    data_dir().join("archives")
}

pub fn reports_dir() -> PathBuf {
    data_dir().join("reports")
}

/// `NEUROALYZER_MODEL_DIR` overrides where the NER model lives (shared caches, tests).
pub fn models_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("NEUROALYZER_MODEL_DIR") {
        return PathBuf::from(p);
    }
    data_dir().join("models")
}

/// Create a directory (and parents) that only the owner can read.
pub fn ensure_private_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p).with_context(|| format!("couldn't create {}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Restrict a file to the owner. No-op on Windows, where files in the user's
/// local app data dir already inherit an owner-only ACL.
pub fn make_private(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = p;
    Ok(())
}

/// Held for the whole of `clean` and `restore`. Two such runs at once could
/// race on the same session files and archive names, and one run's prune could
/// delete the backup another is still writing or reading, so only one runs at a
/// time per data dir. The OS releases the lock when the process exits, even on
/// a crash, so it never goes stale.
pub struct RunLock {
    _f: std::fs::File,
}

pub fn lock_data_dir() -> Result<RunLock> {
    let d = data_dir();
    ensure_private_dir(&d)?;
    let p = d.join("neuroalyzer.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)
        .with_context(|| format!("couldn't open {}", p.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(RunLock { _f: f }),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another neuroalyzer clean or restore is running (it holds {}). Wait for it to finish, then try again.",
            p.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => Err(e).with_context(|| format!("couldn't lock {}", p.display())),
    }
}
