//! Named-entity recognition (GLiNER). Placeholder until milestone 5.

use crate::config::NerConfig;
use crate::detect::Finding;
use anyhow::{Result, bail};

pub struct Ner;

impl Ner {
    pub fn load(_cfg: &NerConfig, _quiet: bool) -> Result<Self> {
        bail!("NER isn't available in this build")
    }
    pub fn prepare<'a>(&self, _texts: impl Iterator<Item = &'a str>) {}
    pub fn find(&self, _text: &str, _out: &mut Vec<Finding>) {}
    pub fn stats(&self) -> (u64, u64) {
        (0, 0)
    }
}

pub fn fetch(_quiet: bool) -> Result<()> {
    bail!("this build has no NER support. Rebuild with the default features to use it.")
}
