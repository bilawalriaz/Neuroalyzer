//! Detection: prefilter, secrets (gitleaks rules, connection strings, key/value
//! entropy, known values), structured PII with validators, tabular data.

pub mod gitleaks;
pub mod tabular;
pub mod validators;

use crate::config::Config;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::sync::LazyLock;
use validators as v;

/// One detected span inside a decoded string.
#[derive(Clone, Debug)]
pub struct Finding {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    pub detector: &'static str,
    /// Higher wins when spans overlap.
    pub prio: u8,
}

/// Context for a string: the lowercased JSON key it sits under (if any).
#[derive(Clone, Copy, Default)]
pub struct Ctx<'a> {
    pub key: &'a str,
}

const P_KNOWN: u8 = 90;
const P_RULE: u8 = 80;
const P_CONN: u8 = 75;
const P_KEYCTX: u8 = 70;
const P_PII: u8 = 60;
const P_CUSTOM: u8 = 85;
pub const P_TABULAR: u8 = 40;
pub const P_NER: u8 = 30;

/// Literal anchors for the raw-bytes prefilter (in addition to gitleaks keywords).
const ANCHORS: &[&str] = &[
    "sk-",
    "sk-ant-",
    "sk_live",
    "rk_live",
    "AKIA",
    "ASIA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xox",
    "eyJ",
    "-----BEGIN",
    "Bearer",
    "Basic ",
    "@",
    "://",
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "auth",
    "credential",
    "private_key",
    "AIza",
    "nhs",
];

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[[A-Z][A-Z0-9_]*:[0-9a-f]{8}\]").unwrap());

struct PiiPat {
    kind: &'static str,
    detector: &'static str,
    re: Regex,
    check: fn(&str, &str, usize, usize, &Detectors) -> bool,
    /// `re` with ASCII word boundaries (see `ascii_word_bounds`): a superset
    /// that runs on the lazy DFA even when the text isn't ASCII.
    fast: Regex,
}

/// Longest match any bounded PII pattern can produce, with room to spare
/// (checked by a test). The one unbounded pattern, email, can't match
/// whitespace, which `PiiPat::find` relies on.
const PII_MAX_MATCH: usize = 128;

impl PiiPat {
    /// Every match of `re` in `text`, exactly as `re.find_iter(text)` returns
    /// them.
    ///
    /// On non-ASCII text a Unicode `\b` sends the regex engine to the PikeVM,
    /// about ten times slower, and on long tool output these patterns took
    /// 70% of scan CPU. So: find candidates with `fast` (a superset, on the
    /// DFA), widen each by `PII_MAX_MATCH` and then to whitespace, merge, and
    /// run `re` only inside those windows. A window edge is either the end of
    /// the text or next to whitespace, which is a non-word character to `\b`
    /// either way, so matches inside a window are the same as in the full
    /// text; and every exact match starts inside a candidate (it matches the
    /// superset at the same start, so the candidate scan either starts there
    /// or overlaps it) and fits in its window.
    fn find(&self, text: &str, mut f: impl FnMut(regex::Match<'_>, usize)) {
        if text.is_ascii() {
            for m in self.re.find_iter(text) {
                f(m, 0);
            }
            return;
        }
        let b = text.as_bytes();
        let back = |mut i: usize| {
            i = i.saturating_sub(PII_MAX_MATCH);
            while i > 0 && !text.is_char_boundary(i) {
                i -= 1;
            }
            while i > 0 && !text[..i].chars().next_back().is_some_and(char::is_whitespace) {
                i -= text[..i].chars().next_back().map_or(1, char::len_utf8);
            }
            i
        };
        let fwd = |mut i: usize| {
            i = (i + PII_MAX_MATCH).min(b.len());
            while i < b.len() && !text.is_char_boundary(i) {
                i += 1;
            }
            while i < b.len() && !text[i..].chars().next().is_some_and(char::is_whitespace) {
                i += text[i..].chars().next().map_or(1, char::len_utf8);
            }
            i
        };
        let mut windows: Vec<(usize, usize)> = vec![];
        for c in self.fast.find_iter(text) {
            let (ws, we) = (back(c.start()), fwd(c.end()));
            match windows.last_mut() {
                Some(last) if ws <= last.1 => last.1 = last.1.max(we),
                _ => windows.push((ws, we)),
            }
        }
        for (ws, we) in windows {
            for m in self.re.find_iter(&text[ws..we]) {
                f(m, ws);
            }
        }
    }
}

struct Custom {
    kind: &'static str,
    detector: &'static str,
    re: Regex,
    group: usize,
}

pub struct Detectors {
    anchors: AhoCorasick,
    /// For each anchor pattern: which gitleaks rules it enables.
    anchor_rules: Vec<Vec<u32>>,
    rules: gitleaks::RuleSet,
    pii: Vec<PiiPat>,
    /// One alternation of the ASCII-boundary PII variants, used as a fast
    /// prefilter. `RegexSet::matches` would be the obvious choice, but it is
    /// implemented with the PikeVM; a single `Regex::is_match` runs on the DFA.
    pii_pre: Regex,
    bytes_set: regex::bytes::RegexSet,
    keyctx: Regex,
    keyname: Regex,
    conn: Regex,
    ado: Regex,
    bearer: Regex,
    known: Option<AhoCorasick>,
    known_count: usize,
    custom: Vec<Custom>,
    allow_exact: HashSet<String>,
    allow_re: Vec<Regex>,
    pub ip_enabled: bool,
    pub ip_private: bool,
}

/// ASCII-only variant of a pattern's word boundaries. A Unicode `\b` cannot be
/// run by the lazy DFA, so regex-automata falls back to the PikeVM, an
/// interpreter that is roughly ten times slower. Every boundary in these
/// patterns sits next to an ASCII word character, so testing the ASCII variant
/// can only ever match *more*: it is a safe prefilter for the exact pattern.
fn ascii_word_bounds(s: &str) -> String {
    s.replace(r"\b", r"(?-u:\b)")
}

/// Placeholder until the ASCII variant is built from `re`.
fn no_fast() -> Regex {
    re("[^\\s\\S]")
}

fn re(s: &str) -> Regex {
    RegexBuilder::new(s)
        .size_limit(1 << 24)
        .build()
        .unwrap_or_else(|e| panic!("bad builtin regex {s}: {e}"))
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Neighbouring characters must not continue the token.
fn floor_cb(t: &str, mut i: usize) -> usize {
    while i > 0 && !t.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Punctuation in `extra` only counts as continuing the token when another
/// letter or digit follows it (so "call 07700 900123." still matches).
fn bounded(text: &str, s: usize, e: usize, extra: &[u8]) -> bool {
    let b = text.as_bytes();
    let before_ok = s == 0 || {
        let c = b[s - 1];
        !(c.is_ascii_alphanumeric() || (extra.contains(&c) && s >= 2 && b[s - 2].is_ascii_alphanumeric()))
    };
    let after_ok = e >= b.len() || {
        let c = b[e];
        !(c.is_ascii_alphanumeric() || (extra.contains(&c) && e + 1 < b.len() && b[e + 1].is_ascii_alphanumeric()))
    };
    before_ok && after_ok
}

fn chk_email(m: &str, _t: &str, _s: usize, _e: usize, _d: &Detectors) -> bool {
    let tld = m.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    const FILE_EXT: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "svg", "webp", "js", "ts", "tsx", "jsx", "py", "rs", "go", "css", "json", "md",
        "html", "lock", "toml", "yaml", "yml", "txt", "zip", "map",
    ];
    if FILE_EXT.contains(&tld.as_str()) {
        return false;
    }
    let local = m.split('@').next().unwrap_or("");
    !matches!(local, "git") && !m.ends_with("@users.noreply.github.com")
}
fn chk_phone(m: &str, t: &str, s: usize, e: usize, _d: &Detectors) -> bool {
    bounded(t, s, e, b"._-/:") && v::phone(m) && {
        let d = v::digits(m);
        !d.iter().all(|&x| x == d[0])
    }
}
fn chk_postcode(m: &str, _t: &str, _s: usize, _e: usize, _d: &Detectors) -> bool {
    v::postcode(m)
}
fn chk_nino(m: &str, _t: &str, _s: usize, _e: usize, _d: &Detectors) -> bool {
    v::nino(m)
}
fn chk_nhs_fmt(m: &str, t: &str, s: usize, e: usize, _d: &Detectors) -> bool {
    bounded(t, s, e, b"._-/:") && v::nhs(m)
}
fn chk_nhs_bare(m: &str, t: &str, s: usize, e: usize, _d: &Detectors) -> bool {
    if !bounded(t, s, e, b"._-/:") || !v::nhs(m) {
        return false;
    }
    let lo = floor_cb(t, s.saturating_sub(60));
    t[lo..s].to_ascii_lowercase().contains("nhs")
}
fn chk_card(m: &str, t: &str, s: usize, e: usize, _d: &Detectors) -> bool {
    bounded(t, s, e, b"._-/:") && v::card(m)
}
fn chk_iban(m: &str, _t: &str, _s: usize, _e: usize, _d: &Detectors) -> bool {
    v::iban(m)
}
fn chk_ip(m: &str, t: &str, s: usize, e: usize, d: &Detectors) -> bool {
    if !d.ip_enabled || !bounded(t, s, e, b"._-") {
        return false;
    }
    let lo = floor_cb(t, s.saturating_sub(12));
    let before = t[lo..s].to_ascii_lowercase();
    if before.ends_with('v') || before.ends_with('@') || before.contains("version") || before.ends_with("==") {
        return false;
    }
    v::ipv4_public(m, d.ip_private)
}

/// Values that are clearly placeholders, not secrets.
pub fn is_placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    let l = l.trim_matches(|c| c == '"' || c == '\'' || c == '`');
    l.is_empty()
        || l.starts_with("${")
        || l.starts_with("$(")
        || l.starts_with('<')
        || l.starts_with("{{")
        || l.starts_with('%')
        || l.starts_with("process.env")
        || l.starts_with("os.environ")
        || l.starts_with("env.")
        || l.starts_with("env(")
        || l.chars()
            .all(|c| c == '*' || c == 'x' || c == '.' || c == '-' || c == '_')
        || matches!(
            l,
            "password"
                | "passwd"
                | "secret"
                | "token"
                | "changeme"
                | "redacted"
                | "none"
                | "null"
                | "undefined"
                | "true"
                | "false"
                | "example"
                | "your_api_key"
                | "your-api-key"
                | "placeholder"
                | "pass"
                | "string"
                | "str"
        )
        || TOKEN_RE.is_match(v)
}

fn identifier_like(v: &str) -> bool {
    let mut chars = v.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && !v.chars().any(|c| c.is_ascii_digit())
}

impl Detectors {
    pub fn new(cfg: &Config, known_values: &[String]) -> Result<Self> {
        let rules = gitleaks::RuleSet::load()?;

        let mut anchor_pats: Vec<String> = ANCHORS.iter().map(|s| s.to_ascii_lowercase()).collect();
        let mut anchor_rules: Vec<Vec<u32>> = vec![vec![]; anchor_pats.len()];
        for (ri, r) in rules.rules.iter().enumerate() {
            for k in &r.keywords {
                let k = k.to_ascii_lowercase();
                let idx = match anchor_pats.iter().position(|p| *p == k) {
                    Some(i) => i,
                    None => {
                        anchor_pats.push(k);
                        anchor_rules.push(vec![]);
                        anchor_pats.len() - 1
                    }
                };
                anchor_rules[idx].push(ri as u32);
            }
        }
        let anchors = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&anchor_pats)
            .context("building anchor matcher")?;

        let pii: Vec<PiiPat> = vec![
            PiiPat {
                kind: "EMAIL",
                detector: "email",
                re: re(r"(?i)\b[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"),
                check: chk_email,
                fast: no_fast(),
            },
            PiiPat {
                kind: "PHONE",
                detector: "phone-uk",
                re: re(r"(?:\+44\s?(?:\(0\)\s?)?|\b0)\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}\b"),
                check: chk_phone,
                fast: no_fast(),
            },
            PiiPat {
                kind: "PHONE",
                detector: "phone-intl",
                re: re(r"\+[1-9]\d{0,2}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}\b"),
                check: chk_phone,
                fast: no_fast(),
            },
            PiiPat {
                kind: "POSTCODE",
                detector: "uk-postcode",
                re: re(r"\b(?:[A-Z]{1,2}\d[A-Z\d]?|GIR) ?\d[A-Z]{2}\b"),
                check: chk_postcode,
                fast: no_fast(),
            },
            PiiPat {
                kind: "NINO",
                detector: "uk-nino",
                re: re(r"\b[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"),
                check: chk_nino,
                fast: no_fast(),
            },
            PiiPat {
                kind: "NHS",
                detector: "nhs-number",
                re: re(r"\b\d{3}[ -]\d{3}[ -]\d{4}\b"),
                check: chk_nhs_fmt,
                fast: no_fast(),
            },
            PiiPat {
                kind: "NHS",
                detector: "nhs-number",
                re: re(r"\b\d{10}\b"),
                check: chk_nhs_bare,
                fast: no_fast(),
            },
            PiiPat {
                kind: "CARD",
                detector: "payment-card",
                re: re(r"\b(?:\d[ -]?){12,18}\d\b"),
                check: chk_card,
                fast: no_fast(),
            },
            PiiPat {
                kind: "IBAN",
                detector: "iban",
                re: re(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
                check: chk_iban,
                fast: no_fast(),
            },
            PiiPat {
                kind: "IP",
                detector: "ipv4",
                re: re(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
                check: chk_ip,
                fast: no_fast(),
            },
        ]
        .into_iter()
        .map(|mut p| {
            p.fast = re(&ascii_word_bounds(p.re.as_str()));
            p
        })
        .collect();
        // The exact patterns are run only on strings the ASCII-boundary
        // variant matched; see `ascii_word_bounds`.
        let pre_src = pii
            .iter()
            .map(|p| format!("(?:{})", ascii_word_bounds(p.re.as_str())))
            .collect::<Vec<_>>()
            .join("|");
        let pii_pre = RegexBuilder::new(&pre_src)
            .size_limit(1 << 24)
            .build()
            .context("building PII prefilter")?;

        let mut custom = vec![];
        for c in &cfg.patterns {
            let r = RegexBuilder::new(&c.regex)
                .size_limit(1 << 24)
                .build()
                .with_context(|| format!("custom pattern '{}' has a bad regex", c.name))?;
            custom.push(Custom {
                kind: leak(
                    c.kind
                        .to_ascii_uppercase()
                        .replace(|ch: char| !ch.is_ascii_alphanumeric(), "_"),
                ),
                detector: leak(format!("custom:{}", c.name)),
                re: r,
                group: c.group,
            });
        }

        // Raw-bytes prefilter: PII shapes, keyword-less gitleaks rules and custom patterns.
        // The PII entries use the ASCII-boundary variant, which matches a superset
        // of the exact patterns, so nothing is missed.
        let mut byte_pats: Vec<String> = pii.iter().map(|p| ascii_word_bounds(p.re.as_str())).collect();
        for &ri in &rules.unkeyed {
            byte_pats.push(rules.rules[ri as usize].re.as_str().to_string());
        }
        byte_pats.extend(custom.iter().map(|c| c.re.as_str().to_string()));
        let bytes_set = regex::bytes::RegexSetBuilder::new(&byte_pats)
            .size_limit(1 << 26)
            .dfa_size_limit(1 << 26)
            .build()
            .context("building prefilter")?;

        let known_vals: Vec<&String> = known_values.iter().filter(|v| v.len() >= 6).collect();
        let known = if known_vals.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&known_vals)?,
            )
        };

        let mut allow_re = vec![];
        for r in &cfg.allowlist.regex {
            allow_re.push(Regex::new(r).with_context(|| format!("allowlist regex '{r}' is invalid"))?);
        }

        Ok(Self {
            anchors,
            anchor_rules,
            rules,
            pii,
            pii_pre,
            bytes_set,
            keyctx: re(
                r#"(?i)(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|pwd|authorization|auth[_-]?token|credentials?|private[_-]?key|access[_-]?key|client[_-]?secret)[a-z0-9_-]{0,20}\\{0,3}["']?\s*[:=]\s*\\{0,3}["']?(?:Bearer\s+|Basic\s+)?([A-Za-z0-9+/=_\-.~!@#$%^&*]{6,})"#,
            ),
            keyname: re(
                r"(?i)(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|pwd|authorization|credential|private[_-]?key|access[_-]?key)",
            ),
            conn: re(r#"\b[a-zA-Z][a-zA-Z0-9+.-]{1,30}://[^\s:/@'"<>]+:([^\s@'"/<>]+)@[^\s'"/<>]+"#),
            ado: re(r#"(?i)\b(?:password|pwd)\s*=\s*([^;'"\s]{4,})"#),
            bearer: re(r"\bBearer\s+([A-Za-z0-9\-._~+/]{16,}=*)"),
            known,
            known_count: known_vals.len(),
            custom,
            allow_exact: cfg.allowlist.exact.iter().cloned().collect(),
            allow_re,
            ip_enabled: cfg.ip.enabled,
            ip_private: cfg.ip.include_private,
        })
    }

    pub fn rule_stats(&self) -> (usize, usize, &'static str) {
        (self.rules.rules.len(), self.rules.skipped, gitleaks::GITLEAKS_VERSION)
    }

    pub fn known_count(&self) -> usize {
        self.known_count
    }

    /// Cheap check on raw record bytes. False means nothing in this record can match.
    pub fn record_may_match(&self, raw: &[u8]) -> bool {
        self.anchors.is_match(raw)
            || self.known.as_ref().is_some_and(|k| k.is_match(raw))
            || self.bytes_set.is_match(raw)
    }

    fn allowed(&self, value: &str) -> bool {
        self.allow_exact.contains(value) || self.allow_re.iter().any(|r| r.is_match(value))
    }

    /// Run every regex detector over one decoded string.
    pub fn detect(&self, text: &str, ctx: Ctx, out: &mut Vec<Finding>) {
        let base = out.len();
        // Known values.
        if let Some(k) = &self.known {
            for m in k.find_iter(text) {
                out.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    kind: "SECRET",
                    detector: "known-value",
                    prio: P_KNOWN,
                });
            }
        }
        // gitleaks rules selected by keyword.
        let mut selected: Vec<u32> = self.rules.unkeyed.clone();
        for m in self.anchors.find_overlapping_iter(text) {
            selected.extend_from_slice(&self.anchor_rules[m.pattern().as_usize()]);
        }
        selected.sort_unstable();
        selected.dedup();
        for ri in selected {
            let r = &self.rules.rules[ri as usize];
            // The ASCII variant matches a superset, so a miss here means the
            // exact rule cannot match either.
            if let Some(f) = &r.fast
                && !f.is_match(text)
            {
                continue;
            }
            for caps in r.re.captures_iter(text) {
                let Some(m) = r.secret_match(&caps) else { continue };
                let secret = m.as_str();
                if r.allowed(secret, caps.get(0).unwrap().as_str(), text) || self.rules.globally_allowed(secret) {
                    continue;
                }
                if is_placeholder(secret) {
                    continue;
                }
                out.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    kind: "SECRET",
                    detector: r.id,
                    prio: P_RULE,
                });
            }
        }
        // Connection strings and ADO-style password fields.
        for caps in self.conn.captures_iter(text) {
            let m = caps.get(1).unwrap();
            if !is_placeholder(m.as_str()) {
                out.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    kind: "SECRET",
                    detector: "connection-string",
                    prio: P_CONN,
                });
            }
        }
        for caps in self.ado.captures_iter(text) {
            let m = caps.get(1).unwrap();
            if !is_placeholder(m.as_str()) && !identifier_like(m.as_str()) {
                out.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    kind: "SECRET",
                    detector: "connection-string",
                    prio: P_CONN,
                });
            }
        }
        for caps in self.bearer.captures_iter(text) {
            let m = caps.get(1).unwrap();
            if v::entropy(m.as_str()) >= 3.0 && !is_placeholder(m.as_str()) {
                out.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    kind: "SECRET",
                    detector: "bearer-token",
                    prio: P_KEYCTX,
                });
            }
        }
        // key = value with entropy.
        for caps in self.keyctx.captures_iter(text) {
            let whole = caps.get(0).unwrap().as_str().to_ascii_lowercase();
            let m = caps.get(1).unwrap();
            let is_pw = whole.contains("pass") || whole.contains("pwd");
            let quoted = m.start() > 0 && matches!(text.as_bytes()[m.start() - 1], b'"' | b'\'');
            if secretish(m.as_str(), is_pw, quoted) {
                out.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    kind: "SECRET",
                    detector: "keyword-entropy",
                    prio: P_KEYCTX,
                });
            }
        }
        // The JSON key itself is key-like: judge the whole value.
        if !ctx.key.is_empty()
            && self.keyname.is_match(ctx.key)
            && !ctx.key.contains("tokens")
            && !ctx.key.ends_with("count")
        {
            let t = text.trim();
            if !t.contains(char::is_whitespace) {
                let is_pw = ctx.key.contains("pass") || ctx.key.contains("pwd");
                if secretish(t, is_pw, true) {
                    let s = text.len() - text.trim_start().len();
                    out.push(Finding {
                        start: s,
                        end: s + t.len(),
                        kind: "SECRET",
                        detector: "keyword-entropy",
                        prio: P_KEYCTX,
                    });
                }
            }
        }
        // Structured PII. The ASCII-boundary prefilter is a superset of the
        // exact patterns, so running every exact pattern once it matches keeps
        // the findings identical.
        if self.pii_pre.is_match(text) {
            for p in &self.pii {
                p.find(text, |m, off| {
                    let (start, end) = (off + m.start(), off + m.end());
                    if p.kind == "IBAN" {
                        if let Some(e) = trim_iban(m.as_str()) {
                            out.push(Finding {
                                start,
                                end: start + e,
                                kind: p.kind,
                                detector: p.detector,
                                prio: P_PII,
                            });
                        }
                        return;
                    }
                    if (p.check)(m.as_str(), text, start, end, self) {
                        out.push(Finding {
                            start,
                            end,
                            kind: p.kind,
                            detector: p.detector,
                            prio: P_PII,
                        });
                    }
                });
            }
        }
        for c in &self.custom {
            for caps in c.re.captures_iter(text) {
                if let Some(m) = caps.get(c.group) {
                    out.push(Finding {
                        start: m.start(),
                        end: m.end(),
                        kind: c.kind,
                        detector: c.detector,
                        prio: P_CUSTOM,
                    });
                }
            }
        }
        self.filter(text, out, base);
    }

    /// Drop allowlisted findings and anything overlapping an existing token.
    pub fn filter(&self, text: &str, out: &mut Vec<Finding>, base: usize) {
        if out.len() == base {
            return;
        }
        let tokens: Vec<(usize, usize)> = if text.contains('[') {
            TOKEN_RE.find_iter(text).map(|m| (m.start(), m.end())).collect()
        } else {
            vec![]
        };
        let mut i = base;
        while i < out.len() {
            let f = &out[i];
            let val = &text[f.start..f.end];
            let overlaps_token = tokens.iter().any(|&(s, e)| f.start < e && s < f.end);
            if f.start >= f.end || overlaps_token || self.allowed(val) {
                out.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
}

/// `literal`: the value is a quoted string, not code like `user.password`.
fn secretish(v: &str, is_password: bool, literal: bool) -> bool {
    if is_placeholder(v) || TOKEN_RE.is_match(v) {
        return false;
    }
    if is_password {
        return v.len() >= 6 && (literal || !identifier_like(v));
    }
    v.len() >= 16
        && v.chars().any(|c| c.is_ascii_digit())
        && v.chars().any(|c| c.is_ascii_alphabetic())
        && v::entropy(v) >= 3.0
}

/// Find the longest prefix (at group boundaries) that is a valid IBAN.
fn trim_iban(m: &str) -> Option<usize> {
    let mut ends: Vec<usize> = m.match_indices(' ').map(|(i, _)| i).collect();
    ends.push(m.len());
    ends.into_iter().rev().find(|&e| v::iban(&m[..e]))
}

/// Merge overlapping findings into non-overlapping spans, keeping the
/// highest-priority type for each merged span.
pub fn merge(mut f: Vec<Finding>) -> Vec<Finding> {
    if f.len() < 2 {
        return f;
    }
    f.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Finding> = Vec::with_capacity(f.len());
    for x in f {
        if let Some(last) = out.last_mut()
            && x.start < last.end
        {
            if x.prio > last.prio {
                last.kind = x.kind;
                last.detector = x.detector;
                last.prio = x.prio;
            }
            last.end = last.end.max(x.end);
            continue;
        }
        out.push(x);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PiiPat::find` must return exactly what `re.find_iter` does, on text
    /// mixing scripts, odd whitespace and near-miss numbers.
    #[test]
    fn windowed_pii_matches_full_scan() {
        let d = Detectors::new(&Config::default(), &[]).unwrap();
        let parts = [
            "Ünïcödé ",
            "東京 ",
            "jane.doe@gmail.com",
            "é",
            "07700 900123",
            "+44 7700 900123",
            "\u{a0}",
            "SW1A 2AA",
            "AB 12 34 56 C",
            "943 476 5919",
            "9434765919",
            "4111 1111 1111 1111",
            "GB82 WEST 1234 5698 7654 32",
            "8.8.8.8",
            " ",
            "\n",
            "ß0123456789ß",
            "x",
            "-",
            ".",
            "@",
            "Kelvin\u{212a}@ex.com",
            "  ",
            "0",
            "12",
            "ab",
        ];
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..400 {
            let n = 5 + (next() % 300) as usize;
            let mut t = String::new();
            for _ in 0..n {
                t.push_str(parts[(next() % parts.len() as u64) as usize]);
            }
            if round % 3 == 0 {
                t.push_str(&"y".repeat(200)); // long run without whitespace
            }
            for p in &d.pii {
                let want: Vec<(usize, usize)> = p.re.find_iter(&t).map(|m| (m.start(), m.end())).collect();
                let mut got = vec![];
                p.find(&t, |m, off| got.push((off + m.start(), off + m.end())));
                assert_eq!(got, want, "{} on {t:?}", p.detector);
            }
        }
    }

    /// The windowing in `PiiPat::find` assumes bounded patterns stay under
    /// `PII_MAX_MATCH` and unbounded ones can't cross whitespace.
    #[test]
    fn pii_patterns_fit_the_window() {
        let d = Detectors::new(&Config::default(), &[]).unwrap();
        for p in &d.pii {
            let hir = regex_syntax::parse(p.re.as_str()).unwrap();
            match hir.properties().maximum_len() {
                Some(n) => assert!(n < PII_MAX_MATCH, "{} can match {n} bytes", p.detector),
                None => {
                    assert!(
                        !p.re.as_str().contains("\\s") && !p.re.as_str().contains(' '),
                        "{}",
                        p.detector
                    );
                    for ws in [" ", "\t", "\n", "\u{a0}", "\u{3000}"] {
                        let t = format!("a.b{ws}c@example.com");
                        assert!(p.re.find_iter(&t).all(|m| !m.as_str().contains(ws)), "{}", p.detector);
                    }
                }
            }
        }
    }

    fn d() -> Detectors {
        Detectors::new(&Config::default(), &["maple-orbit-7731-quiet".to_string()]).unwrap()
    }

    fn kinds(d: &Detectors, t: &str) -> Vec<(String, String)> {
        let mut out = vec![];
        d.detect(t, Ctx::default(), &mut out);
        merge(out)
            .into_iter()
            .map(|f| (f.kind.to_string(), t[f.start..f.end].to_string()))
            .collect()
    }

    #[test]
    fn pii() {
        let d = d();
        let k = kinds(
            &d,
            "mail jane.doe@gmail.com or call 07700 900123. NI AB 12 34 56 C, at SW1A 2AA",
        );
        let ks: Vec<&str> = k.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(ks, vec!["EMAIL", "PHONE", "NINO", "POSTCODE"], "{k:?}");
    }

    #[test]
    fn decoys() {
        let d = d();
        for t in [
            "version 1.24.3 and v2.0.0-beta.1",
            "commit 3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a",
            "id 550e8400-e29b-41d4-a716-446655440000",
            "const token = await getToken();",
            "listening on 127.0.0.1:3000 and 192.168.1.20",
            "created 2026-01-02T03:04:05Z id 100234",
            "image logo@2x.png",
        ] {
            assert!(kinds(&d, t).is_empty(), "{t}: {:?}", kinds(&d, t));
        }
    }

    #[test]
    fn secrets() {
        let d = d();
        let aws = format!("{}{}", "AKIA", "Z7QWERTYUIOPLKJH");
        let k = kinds(&d, &format!("export AWS_ACCESS_KEY_ID={aws}"));
        assert!(k.iter().any(|x| x.1 == aws), "{k:?}");
        let k = kinds(&d, "postgres://app:s3cr3tP4ss@db:5432/x");
        assert_eq!(k[0].1, "s3cr3tP4ss");
        let k = kinds(&d, "the value maple-orbit-7731-quiet is here");
        assert_eq!(k[0].1, "maple-orbit-7731-quiet");
        let k = kinds(&d, r#"{\"password\": \"hunter2hunter2\"}"#);
        assert!(k.iter().any(|x| x.1 == "hunter2hunter2"), "{k:?}");
    }

    #[test]
    fn idempotent() {
        let d = d();
        assert!(kinds(&d, "email [EMAIL:0a1b2c3d] here").is_empty());
    }
}
