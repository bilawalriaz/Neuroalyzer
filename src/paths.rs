//! Where sesscrub keeps its own files.
//!
//! `SESSCRUB_DATA_DIR` overrides the data dir (archives, reports, model, HMAC
//! key). Tests use it to stay out of the real profile.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("SESSCRUB_DATA_DIR") {
        return PathBuf::from(p);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sesscrub")
}

pub fn config_file() -> PathBuf {
    if let Some(p) = std::env::var_os("SESSCRUB_CONFIG") {
        return PathBuf::from(p);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sesscrub")
        .join("config.toml")
}

pub fn archives_dir() -> PathBuf {
    data_dir().join("archives")
}

pub fn reports_dir() -> PathBuf {
    data_dir().join("reports")
}

/// `SESSCRUB_MODEL_DIR` overrides where the NER model lives (shared caches, tests).
pub fn models_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("SESSCRUB_MODEL_DIR") {
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
