//! Where neuralyzer keeps its own files.
//!
//! `NEURALYZER_DATA_DIR` overrides the data dir and places reports under it.
//! Tests use it to stay out of the real profile.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Environment variable `<PKG>_<suffix>` for this binary, e.g. `env_name("THREADS")`.
/// Derived from the package name so new variables follow a rename.
pub fn env_name(suffix: &str) -> String {
    format!(
        "{}_{suffix}",
        env!("CARGO_PKG_NAME").to_ascii_uppercase().replace('-', "_")
    )
}

/// Value of `<PKG>_<suffix>`, if set and not empty.
pub fn env_value(suffix: &str) -> Option<String> {
    std::env::var(env_name(suffix)).ok().filter(|v| !v.trim().is_empty())
}

pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("NEURALYZER_DATA_DIR") {
        return PathBuf::from(p);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neuralyzer")
}

pub fn config_file() -> PathBuf {
    if let Some(p) = std::env::var_os("NEURALYZER_CONFIG") {
        return PathBuf::from(p);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neuralyzer")
        .join("config.toml")
}

pub fn archives_dir() -> PathBuf {
    data_dir().join("archives")
}

pub fn reports_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    if std::env::var_os("NEURALYZER_DATA_DIR").is_none() {
        let exe = std::env::current_exe().context("couldn't locate the executable for report output")?;
        return exe
            .parent()
            .map(Path::to_path_buf)
            .context("the executable has no parent directory");
    }
    Ok(data_dir().join("reports"))
}

/// `NEURALYZER_MODEL_DIR` overrides where the NER model lives (shared caches, tests).
pub fn models_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("NEURALYZER_MODEL_DIR") {
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

/// Restrict a file to the owner on Unix. Windows files inherit directory ACLs.
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
    let p = d.join("neuralyzer.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)
        .with_context(|| format!("couldn't open {}", p.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(RunLock { _f: f }),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another neuralyzer clean or restore is running (it holds {}). Wait for it to finish, then try again.",
            p.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => Err(e).with_context(|| format!("couldn't lock {}", p.display())),
    }
}
