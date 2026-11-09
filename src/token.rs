//! Replacement tokens: `[TYPE:xxxxxxxx]`, where the hex is the first 8 chars of
//! HMAC-SHA256(install key, value). Same value, same token, on this install.

use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::path::Path;
use zeroize::Zeroizing;

pub struct Tokenizer {
    key: Zeroizing<Vec<u8>>,
}

impl Tokenizer {
    /// Load the per-install key, creating it on first use.
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let p = data_dir.join("hmac.key");
        if let Ok(k) = std::fs::read(&p)
            && k.len() == 32
        {
            return Ok(Self { key: Zeroizing::new(k) });
        }
        crate::paths::ensure_private_dir(data_dir)?;
        let mut k = Zeroizing::new(vec![0u8; 32]);
        rand::fill(&mut k[..]);
        let tmp = data_dir.join("hmac.key.tmp");
        std::fs::write(&tmp, &k[..]).with_context(|| format!("couldn't write {}", tmp.display()))?;
        crate::paths::make_private(&tmp)?;
        std::fs::rename(&tmp, &p)?;
        Ok(Self { key: k })
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
