//! Replacement tokens: `[TYPE:xxxxxxxx]`, where the hex is the first 8 chars of
//! HMAC-SHA256(install key, value). Same value, same token, on this install.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

pub struct Tokenizer {
    key: Zeroizing<Vec<u8>>,
}

impl Tokenizer {
    /// Load the per-install key, creating it on first use.
    ///
    /// The key must never change once created, or the same value would get a
    /// different token on the next run. So an existing key that can't be read
    /// or has the wrong length is an error, never silently replaced, and a new
    /// key is published with a no-clobber link: when two runs race to create
    /// it, both end up using the one that won.
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let p = data_dir.join("hmac.key");
        if let Some(k) = Self::read_existing(&p)? {
            return Ok(Self { key: k });
        }
        crate::paths::ensure_private_dir(data_dir)?;
        let mut k = Zeroizing::new(vec![0u8; 32]);
        rand::fill(&mut k[..]);
        // tempfile creates the file 0600 on Unix, so the key is never readable by others.
        let mut tmp = tempfile::Builder::new()
            .prefix(".hmac.key.")
            .tempfile_in(data_dir)
            .with_context(|| format!("couldn't create a temp file in {}", data_dir.display()))?;
        tmp.write_all(&k[..])?;
        tmp.as_file().sync_all()?;
        match tmp.persist_noclobber(&p) {
            Ok(_) => {
                crate::fsutil::sync_dir(data_dir);
                Ok(Self { key: k })
            }
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another run created it first; use theirs.
                let k = Self::read_existing(&p)?.context("hmac.key vanished while it was being created")?;
                Ok(Self { key: k })
            }
            Err(e) => Err(e.error).with_context(|| format!("couldn't write {}", p.display())),
        }
    }

    fn read_existing(p: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match std::fs::read(p) {
            Ok(k) if k.len() == 32 => Ok(Some(Zeroizing::new(k))),
            Ok(k) => bail!(
                "{} is damaged ({} bytes, expected 32). Tokens depend on it, so it wasn't replaced. \
                 Delete it to start a new key; tokens from earlier runs will then no longer match.",
                p.display(),
                k.len()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("couldn't read {}", p.display())),
        }
    }

    /// An ephemeral key, for read-only scans when no key exists yet.
    pub fn ephemeral() -> Self {
        let mut k = Zeroizing::new(vec![0u8; 32]);
        rand::fill(&mut k[..]);
        Self { key: k }
    }

    pub fn token(&self, kind: &str, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("any key length works");
        mac.update(value.as_bytes());
        let out = mac.finalize().into_bytes();
        format!("[{kind}:{}]", hex::encode(&out[..4]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_key_is_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("hmac.key");
        std::fs::write(&p, [1u8; 31]).unwrap();
        let err = Tokenizer::load_or_create(d.path())
            .err()
            .expect("a damaged key must be an error");
        assert!(format!("{err:#}").contains("damaged"));
        assert_eq!(
            std::fs::read(&p).unwrap(),
            vec![1u8; 31],
            "the key file must be left alone"
        );
    }

    #[test]
    fn concurrent_first_runs_agree_on_one_key() {
        for _ in 0..20 {
            let d = tempfile::tempdir().unwrap();
            let barrier = std::sync::Barrier::new(8);
            let tokens: Vec<String> = std::thread::scope(|s| {
                let hs: Vec<_> = (0..8)
                    .map(|_| {
                        s.spawn(|| {
                            barrier.wait();
                            Tokenizer::load_or_create(d.path()).unwrap().token("EMAIL", "a@b.c")
                        })
                    })
                    .collect();
                hs.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let on_disk = Tokenizer::load_or_create(d.path()).unwrap().token("EMAIL", "a@b.c");
            assert!(tokens.iter().all(|t| *t == on_disk), "{tokens:?} vs {on_disk}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        Tokenizer::load_or_create(d.path()).unwrap();
        let mode = std::fs::metadata(d.path().join("hmac.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}
