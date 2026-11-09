use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub defaults: Defaults,
    pub allowlist: Allowlist,
    pub patterns: Vec<CustomPattern>,
    pub ner: NerConfig,
    pub ip: IpConfig,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    /// Tools to include, e.g. ["copilot", "opencode"].
    pub only: Option<Vec<String>>,
    /// Extra locations, like --also.
    pub also: Vec<PathBuf>,
    /// Run NER by default (when built with the `ner` feature).
    pub ner: Option<bool>,
    /// Number of backup archives to keep.
    pub keep: Option<usize>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Allowlist {
    /// Values that are never redacted (exact match).
    pub exact: Vec<String>,
    /// Regexes; a finding whose value matches any of them is not redacted.
    pub regex: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomPattern {
    pub name: String,
    /// Token type, e.g. "SECRET" or "CUSTOMER_ID".
    #[serde(rename = "type", default = "default_custom_type")]
    pub kind: String,
    pub regex: String,
    /// Capture group to redact (0 = whole match).
    #[serde(default)]
    pub group: usize,
}

fn default_custom_type() -> String {
    "SECRET".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NerConfig {
    pub threshold: f32,
    pub labels: Vec<String>,
}

impl Default for NerConfig {
    fn default() -> Self {
        Self {
            threshold: 0.5,
            labels: vec![
                "person".into(),
                "address".into(),
                "organization".into(),
                "date of birth".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpConfig {
    pub enabled: bool,
    pub include_private: bool,
}

impl Default for IpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_private: false,
        }
    }
}

impl Config {
    /// Load from an explicit path (must exist) or the default location (optional).
    pub fn load(explicit: Option<&Path>) -> Result<(Config, Option<PathBuf>)> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let p = crate::paths::config_file();
                if !p.exists() {
                    return Ok((Config::default(), None));
                }
                p
            }
        };
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("couldn't read config file {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("config file {} has an error", path.display()))?;
        Ok((cfg, Some(path)))
    }
}
