//! Neuroalyzer: scrub secrets and PII from local AI coding agent session data.

pub mod backup;
pub mod config;
pub mod detect;
pub mod discovery;
pub mod engine;
pub mod fault;
pub mod fsutil;
pub mod hw;
pub mod jsonscan;
pub mod known;
pub mod ner;
pub mod password;
pub mod paths;
pub mod prose;
pub mod report;
pub mod run;
pub mod sqlite;
pub mod token;
