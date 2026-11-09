//! Picking out prose for NER: which JSON fields hold prose, and how to cut a
//! string into model-sized chunks while skipping code.

/// JSON keys whose string values are user messages, assistant text or tool output.
pub fn is_prose_key(key: &str) -> bool {
    matches!(
        key,
        "" | "text"
            | "content"
            | "message"
            | "value"
            | "prompt"
            | "output"
            | "deltacontent"
            | "title"
            | "description"
            | "summary"
            | "body"
            | "query"
            | "result"
            | "contents"
            | "error"
            | "data"
            | "customtitle"
    )
}

/// Rough code detector for a paragraph: lots of code punctuation, or lines
/// that look like diffs or source.
pub fn looks_like_code(p: &str) -> bool {
    let n = p.len().max(1);
    let sym = p.bytes().filter(|b| b"{}();=<>[]$#\\".contains(b)).count();
    if sym * 100 / n >= 6 {
        return true;
    }
    let lines: Vec<&str> = p.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() >= 2 {
        let codey = lines
            .iter()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with("+ ")
                    || t.starts_with("- ") && l.starts_with('-')
                    || t.starts_with("@@")
                    || t.starts_with("//")
                    || t.starts_with("import ")
                    || t.starts_with("def ")
                    || t.starts_with("fn ")
                    || t.starts_with("let ")
                    || t.starts_with("const ")
                    || t.ends_with(';')
                    || t.ends_with('{')
                    || t.ends_with('}')
                    || l.starts_with("    ")
                    || l.starts_with('\t')
            })
            .count();
        if codey * 2 > lines.len() {
            return true;
        }
    }
    false
}

/// Cut `text` into prose chunks of at most `max_words` words. Fenced code
/// blocks and code-looking paragraphs are skipped. Returns byte ranges.
pub fn chunks(text: &str, max_words: usize) -> Vec<(usize, usize)> {
    let mut out = vec![];
    let mut in_fence = false;
    let mut para_start: Option<usize> = None;
    let mut off = 0;
    let mut paras: Vec<(usize, usize)> = vec![];
    for line in text.split_inclusive('\n') {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            if let Some(s) = para_start.take() {
                paras.push((s, off));
            }
            in_fence = !in_fence;
        } else if in_fence {
            // skip
        } else if t.trim().is_empty() {
            if let Some(s) = para_start.take() {
                paras.push((s, off));
            }
        } else if para_start.is_none() {
            para_start = Some(off);
        }
        off += line.len();
    }
    if let Some(s) = para_start
        && !in_fence
    {
        paras.push((s, off));
    }
    for (s, e) in paras {
        let p = &text[s..e];
        if p.trim().len() < 3 || looks_like_code(p) || !p.chars().any(|c| c.is_alphabetic()) {
            continue;
        }
        // Split by word count, on whitespace boundaries.
        let mut cs = s;
        let mut words = 0;
        let mut prev_ws = true;
        for (i, ch) in p.char_indices() {
            let ws = ch.is_whitespace();
            if !ws && prev_ws {
                words += 1;
                if words > max_words {
                    out.push((cs, s + i));
                    cs = s + i;
                    words = 1;
                }
            }
            prev_ws = ws;
        }
        let end = s + p.trim_end().len();
        if end > cs {
            out.push((cs, end));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn skips_code() {
        let t =
            "Please email Priya Sharma today.\n\n```rust\nfn main() { let x = 1; }\n```\nThanks, she lives in Leeds.";
        let c = chunks(t, 200);
        let got: Vec<&str> = c.iter().map(|&(s, e)| t[s..e].trim()).collect();
        assert_eq!(
            got,
            vec!["Please email Priya Sharma today.", "Thanks, she lives in Leeds."]
        );
    }
    #[test]
    fn splits_long() {
        let t = "word ".repeat(450);
        assert_eq!(chunks(&t, 200).len(), 3);
    }
}
