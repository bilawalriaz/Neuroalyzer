//! Tabular heuristic. When a string holds a table (CSV/TSV, markdown, SQL CLI
//! output or a JSON array of objects) and some column is mostly emails or
//! phone numbers, every cell in those rows is redacted except obvious non-PII
//! (numeric IDs, dates, booleans, enum-like values). This catches bulk
//! customer data pulled in by DB queries and file reads.

use super::{Finding, P_TABULAR, validators as v};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9-]+\.)+[a-z]{2,24}$").unwrap());
static PHONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\+?[\d\s().-]{9,20}$").unwrap());
static DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?|\d{1,2}/\d{1,2}/\d{2,4}|\d{2}:\d{2}(?::\d{2})?)$").unwrap()
});
static RULE_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*[|+]?\s*:?-{3,}:?\s*(?:[|+]\s*:?-{3,}:?\s*)*[|+]?\s*$").unwrap());

pub fn is_contact(s: &str) -> bool {
    let s = s.trim();
    (EMAIL.is_match(s)) || (PHONE.is_match(s) && v::phone(s))
}

fn non_pii(cell: &str, col_distinct: usize, col_rows: usize) -> bool {
    let c = cell.trim();
    if c.is_empty() {
        return true;
    }
    let l = c.to_ascii_lowercase();
    if matches!(
        l.as_str(),
        "true" | "false" | "yes" | "no" | "t" | "f" | "null" | "none" | "nil" | "n/a" | "-"
    ) {
        return true;
    }
    if c.chars().all(|ch| ch.is_ascii_digit()) && c.len() <= 9 {
        return true;
    }
    if c.parse::<f64>().is_ok() && c.contains('.') {
        return true;
    }
    if DATE.is_match(c) {
        return true;
    }
    // Enum-like: a column with very few distinct values, or a repeated
    // all-lowercase / all-caps code word. Capitalised words (names, towns) aren't enums.
    let codeword = c.len() <= 16
        && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        && (c.chars().all(|ch| !ch.is_ascii_uppercase()) || c.chars().all(|ch| !ch.is_ascii_lowercase()));
    col_rows >= 4 && (col_distinct <= 3 || (codeword && col_distinct * 2 <= col_rows)) && !c.contains('@')
}

/// Split one table line into trimmed cells with byte ranges into the line.
fn split_cells(line: &str, delim: u8) -> Vec<(usize, usize)> {
    let b = line.as_bytes();
    let mut cells = vec![];
    let mut start = 0;
    let mut in_q = false;
    for (i, &c) in b.iter().enumerate() {
        if c == b'"' && delim == b',' {
            in_q = !in_q;
        } else if c == delim && !in_q {
            cells.push((start, i));
            start = i + 1;
        }
    }
    cells.push((start, b.len()));
    if delim == b'|' {
        // Leading/trailing pipes produce empty edge cells.
        if cells.first().is_some_and(|&(s, e)| line[s..e].trim().is_empty()) {
            cells.remove(0);
        }
        if cells.last().is_some_and(|&(s, e)| line[s..e].trim().is_empty()) {
            cells.pop();
        }
    }
    cells
        .into_iter()
        .map(|(s, e)| {
            let raw = &line[s..e];
            let lt = raw.len() - raw.trim_start().len();
            let t = raw.trim();
            let (mut s2, mut e2) = (s + lt, s + lt + t.len());
            if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
                s2 += 1;
                e2 -= 1;
            }
            (s2, e2)
        })
        .collect()
}

struct Row {
    off: usize,
    cells: Vec<(usize, usize)>,
}

fn emit_table(text: &str, rows: &[Row], out: &mut Vec<Finding>) {
    if rows.len() < 3 {
        return;
    }
    let ncols = rows[0].cells.len();
    let cell = |r: &Row, c: usize| -> &str {
        let (s, e) = r.cells[c];
        &text[r.off + s..r.off + e]
    };
    let header_is_data = (0..ncols).any(|c| is_contact(cell(&rows[0], c)));
    let data = if header_is_data { rows } else { &rows[1..] };
    if data.len() < 2 {
        return;
    }
    let contact_cols: Vec<usize> = (0..ncols)
        .filter(|&c| {
            let hits = data.iter().filter(|r| is_contact(cell(r, c))).count();
            hits * 10 >= data.len() * 6
        })
        .collect();
    if contact_cols.is_empty() {
        return;
    }
    let distinct: Vec<usize> = (0..ncols)
        .map(|c| data.iter().map(|r| cell(r, c)).collect::<HashSet<_>>().len())
        .collect();
    for r in data {
        if !contact_cols.iter().any(|&c| is_contact(cell(r, c))) {
            continue;
        }
        for (c, &dc) in distinct.iter().enumerate() {
            let val = cell(r, c);
            if non_pii(val, dc, data.len()) {
                continue;
            }
            let (s, e) = r.cells[c];
            out.push(Finding {
                start: r.off + s,
                end: r.off + e,
                kind: "PII",
                detector: "tabular",
                prio: P_TABULAR,
            });
        }
    }
}

fn detect_lines(text: &str, out: &mut Vec<Finding>) {
    // Collect lines with offsets.
    let mut lines: Vec<(usize, &str)> = vec![];
    let mut off = 0;
    for l in text.split('\n') {
        lines.push((off, l.strip_suffix('\r').unwrap_or(l)));
        off += l.len() + 1;
    }
    for delim in *b"|\t," {
        let mut block: Vec<Row> = vec![];
        let mut width = 0;
        let flush = |block: &mut Vec<Row>, out: &mut Vec<Finding>| {
            emit_table(text, block, out);
            block.clear();
        };
        for &(o, l) in &lines {
            if delim == b'|' && RULE_LINE.is_match(l) && !block.is_empty() {
                continue;
            }
            if !l.as_bytes().contains(&delim) {
                flush(&mut block, out);
                continue;
            }
            let cells = split_cells(l, delim);
            if cells.len() < 2 || (!block.is_empty() && cells.len() != width) {
                flush(&mut block, out);
                if cells.len() < 2 {
                    continue;
                }
            }
            width = cells.len();
            block.push(Row { off: o, cells });
        }
        flush(&mut block, out);
    }
}

/// JSON array of objects inside a string.
fn detect_json(text: &str, out: &mut Vec<Finding>) {
    let raw = text.as_bytes();
    // Gather (object id, key, value span, decoded value).
    let mut items: Vec<(usize, String, usize, usize, String)> = vec![];
    let ok = crate::jsonscan::for_each_string(raw, |s| {
        if let (Some(obj), Some(val)) = (s.object, crate::jsonscan::decode(&raw[s.span.clone()])) {
            items.push((
                obj,
                crate::jsonscan::key_str(s.key),
                s.span.start + 1,
                s.span.end - 1,
                val.into_owned(),
            ));
        }
    });
    if !ok || items.is_empty() {
        return;
    }
    let objs: HashSet<usize> = items.iter().map(|i| i.0).collect();
    if objs.len() < 2 {
        return;
    }
    let keys: HashSet<&str> = items.iter().map(|i| i.1.as_str()).collect();
    let contact_keys: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|k| {
            let vals: Vec<&String> = items.iter().filter(|i| i.1 == *k).map(|i| &i.4).collect();
            vals.len() >= 2 && vals.iter().filter(|v| is_contact(v)).count() * 10 >= vals.len() * 6
        })
        .collect();
    if contact_keys.is_empty() {
        return;
    }
    let rows: HashSet<usize> = items
        .iter()
        .filter(|i| contact_keys.contains(&i.1.as_str()) && is_contact(&i.4))
        .map(|i| i.0)
        .collect();
    for (obj, key, s, e, val) in &items {
        if !rows.contains(obj) {
            continue;
        }
        let col: Vec<&String> = items.iter().filter(|i| &i.1 == key).map(|i| &i.4).collect();
        let distinct = col.iter().collect::<HashSet<_>>().len();
        if non_pii(val, distinct, col.len()) {
            continue;
        }
        out.push(Finding {
            start: *s,
            end: *e,
            kind: "PII",
            detector: "tabular",
            prio: P_TABULAR,
        });
    }
}

pub fn detect(text: &str, out: &mut Vec<Finding>) {
    if text.len() < 20 {
        return;
    }
    let t = text.trim_start();
    if t.starts_with('[') && t.contains('{') {
        detect_json(text, out);
    }
    if text.matches('\n').count() >= 2 {
        detect_lines(text, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vals(t: &str) -> Vec<String> {
        let mut o = vec![];
        detect(t, &mut o);
        let mut v: Vec<String> = o.iter().map(|f| t[f.start..f.end].to_string()).collect();
        v.sort();
        v.dedup();
        v
    }
    #[test]
    fn csv() {
        let t = "id,name,email,active\n1,Ann Lee,ann@x.co.uk,true\n2,Bo Chan,bo@y.com,false\n3,Cy Ode,cy@z.org,true\n";
        let v = vals(t);
        assert!(v.contains(&"Ann Lee".to_string()) && v.contains(&"bo@y.com".to_string()));
        assert!(!v.contains(&"1".to_string()) && !v.contains(&"true".to_string()) && !v.contains(&"name".to_string()));
    }
    #[test]
    fn psql() {
        let t = " id | name     | phone\n----+----------+---------------\n  1 | Ann Lee  | 07700 900123\n  2 | Bo Chan  | 07700 900456\n(2 rows)\n";
        let v = vals(t);
        assert!(v.contains(&"Bo Chan".to_string()), "{v:?}");
    }
    #[test]
    fn json_rows() {
        let t = r#"[{"id":1,"name":"Ann Lee","email":"ann@x.com","plan":"pro"},{"id":2,"name":"Bo Chan","email":"bo@y.com","plan":"pro"}]"#;
        let v = vals(t);
        assert!(v.contains(&"Ann Lee".to_string()), "{v:?}");
    }
    #[test]
    fn code_is_not_a_table() {
        assert!(vals("fn a(x: i32, y: i32) {\n  let z = (x, y);\n  call(a, b);\n}\n").is_empty());
    }
}
