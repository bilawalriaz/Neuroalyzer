//! The gitleaks default ruleset, vendored as TOML and compiled once at start-up.
//!
//! Supported per rule: `regex`, `secretGroup`, `entropy`, `keywords`, and rule
//! allowlists with `regexes` (target secret/match/line) and `stopwords`.
//! Path-scoped rules and path-only allowlists don't apply to session data and
//! are skipped.

use anyhow::{Context, Result};
use regex::{Captures, Match, Regex, RegexBuilder};
use serde::Deserialize;

pub const GITLEAKS_VERSION: &str = "v8.30.1";
const RULES_TOML: &str = include_str!("../../rules/gitleaks.toml");

#[derive(Deserialize)]
struct GlConfig {
    allowlist: Option<GlAllow>,
    #[serde(default)]
    rules: Vec<GlRule>,
}

#[derive(Deserialize)]
struct GlRule {
    id: String,
    regex: Option<String>,
    #[serde(rename = "secretGroup")]
    secret_group: Option<usize>,
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    allowlists: Vec<GlAllow>,
    path: Option<String>,
    #[serde(rename = "skipReport", default)]
    skip_report: bool,
}

#[derive(Deserialize, Default)]
struct GlAllow {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(rename = "regexTarget")]
    regex_target: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    condition: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Target {
    Secret,
    Match,
    Line,
}

pub struct Allow {
    regexes: Vec<Regex>,
    stopwords: Vec<String>,
    target: Target,
}

pub struct Rule {
    pub id: &'static str,
    pub re: Regex,
    /// ASCII-boundary variant of `re`, present only when the rule has a `\b`.
    /// A Unicode word boundary forces `captures_iter` onto the PikeVM, so this
    /// DFA-friendly superset decides whether running `re` is worth it.
    pub fast: Option<Regex>,
    pub secret_group: Option<usize>,
    pub entropy: Option<f64>,
    pub keywords: Vec<String>,
    pub allow: Vec<Allow>,
}

pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// Rules without keywords: always evaluated.
    pub unkeyed: Vec<u32>,
    pub global: Allow,
    pub skipped: usize,
}

fn compile(s: &str) -> Option<Regex> {
    RegexBuilder::new(s)
        .size_limit(1 << 25)
        .dfa_size_limit(1 << 25)
        .build()
        .ok()
}

fn build_allow(a: &GlAllow) -> Option<Allow> {
    // Allowlists that depend on file paths can't be evaluated here.
    if !a.paths.is_empty() && a.condition.as_deref() == Some("AND") {
        return None;
    }
    if a.regexes.is_empty() && a.stopwords.is_empty() {
        return None;
    }
    Some(Allow {
        regexes: a.regexes.iter().filter_map(|r| compile(r)).collect(),
        stopwords: a.stopwords.iter().map(|s| s.to_ascii_lowercase()).collect(),
        target: match a.regex_target.as_deref() {
            Some("match") => Target::Match,
            Some("line") => Target::Line,
            _ => Target::Secret,
        },
    })
}

impl Allow {
    fn allows(&self, secret: &str, whole: &str, line: &str) -> bool {
        let target = match self.target {
            Target::Secret => secret,
            Target::Match => whole,
            Target::Line => line,
        };
        if self.regexes.iter().any(|r| r.is_match(target)) {
            return true;
        }
        if !self.stopwords.is_empty() {
            let s = secret.to_ascii_lowercase();
            return self.stopwords.iter().any(|w| s.contains(w.as_str()));
        }
        false
    }
}

impl RuleSet {
    pub fn load() -> Result<Self> {
        let cfg: GlConfig = toml::from_str(RULES_TOML).context("parsing the vendored gitleaks ruleset")?;
        let mut rules = vec![];
        let mut unkeyed = vec![];
        let mut skipped = 0;
        for r in cfg.rules {
            let Some(src) = r.regex.as_deref() else {
                skipped += 1;
                continue;
            };
            if r.path.is_some() || r.skip_report {
                skipped += 1;
                continue;
            }
            // Most gitleaks rules need whitespace, a quote or `;` after the
            // secret. In prose the secret often ends a sentence or sits in
            // brackets, so also accept common closing punctuation.
            let widened = src.replace(r#"(?:[\x60'"\s;]|\\[nr]|$)"#, r#"(?:[\x60'"\s;.,)\]}>]|\\[nr]|$)"#);
            let Some(re) = compile(&widened) else {
                skipped += 1;
                continue;
            };
            if r.keywords.is_empty() {
                unkeyed.push(rules.len() as u32);
            }
            let fast = widened
                .contains(r"\b")
                .then(|| compile(&widened.replace(r"\b", r"(?-u:\b)")))
                .flatten();
            rules.push(Rule {
                id: Box::leak(r.id.into_boxed_str()),
                re,
                fast,
                secret_group: r.secret_group,
                entropy: r.entropy,
                keywords: r.keywords,
                allow: r.allowlists.iter().filter_map(build_allow).collect(),
            });
        }
        let global = cfg.allowlist.as_ref().and_then(build_allow).unwrap_or(Allow {
            regexes: vec![],
            stopwords: vec![],
            target: Target::Secret,
        });
        Ok(Self {
            rules,
            unkeyed,
            global,
            skipped,
        })
    }

    pub fn globally_allowed(&self, secret: &str) -> bool {
        self.global.allows(secret, secret, secret)
    }
}

impl Rule {
    /// The capture that holds the secret: `secretGroup`, else the first
    /// participating group, else the whole match.
    pub fn secret_match<'t>(&self, caps: &Captures<'t>) -> Option<Match<'t>> {
        if let Some(g) = self.secret_group {
            return caps.get(g);
        }
        (1..caps.len())
            .find_map(|i| caps.get(i).filter(|m| !m.is_empty()))
            .or_else(|| caps.get(0))
    }

    pub fn allowed(&self, secret: &str, whole: &str, text: &str) -> bool {
        if let Some(min) = self.entropy
            && super::validators::entropy(secret) < min
        {
            return true;
        }
        if self.allow.is_empty() {
            return false;
        }
        // Find the line containing the match for line-targeted allowlists.
        let line = text.find(whole).map(|p| {
            let s = text[..p].rfind('\n').map_or(0, |i| i + 1);
            let e = text[p..].find('\n').map_or(text.len(), |i| p + i);
            &text[s..e]
        });
        self.allow
            .iter()
            .any(|a| a.allows(secret, whole, line.unwrap_or(whole)))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn loads() {
        let rs = super::RuleSet::load().unwrap();
        assert!(
            rs.rules.len() > 180,
            "only {} rules compiled ({} skipped)",
            rs.rules.len(),
            rs.skipped
        );
        let jwt = rs.rules.iter().find(|r| r.id == "jwt").unwrap();
        assert!(
            jwt.re.as_str().contains(".,)"),
            "terminator not widened: {}",
            jwt.re.as_str()
        );
    }
}
