//! A small, allocation-light scanner that finds every string *value* in a JSON
//! document and reports its raw byte span plus the nearest object key.
//!
//! We splice redactions back into the original bytes rather than re-serialising
//! the whole document. That keeps key order, whitespace, number formatting and
//! escape style byte-identical everywhere we did not redact. Every rewritten
//! record is re-parsed with serde_json before it is committed.

use std::ops::Range;

/// One string value found in the document.
pub struct StrLit<'a> {
    /// Raw span including the surrounding quotes.
    pub span: Range<usize>,
    /// Raw bytes of the nearest enclosing key (without quotes, still escaped).
    pub key: Option<&'a [u8]>,
    /// Index of the innermost enclosing object (0-based, document order).
    pub object: Option<usize>,
}

#[derive(Clone, Copy)]
struct Frame {
    is_obj: bool,
    expecting_key: bool,
    key: Option<(usize, usize)>,
    obj_id: usize,
}

/// Visit every string value. Returns false if the bytes are obviously not JSON
/// (unterminated string or unbalanced brackets); callers then fall back.
pub fn for_each_string<'a>(raw: &'a [u8], mut f: impl FnMut(StrLit<'a>)) -> bool {
    let mut stack: Vec<Frame> = Vec::with_capacity(16);
    let mut obj_counter = 0usize;
    let mut i = 0usize;
    let n = raw.len();
    while i < n {
        match raw[i] {
            b'"' => {
                let start = i;
                i += 1;
                while i < n {
                    match raw[i] {
                        b'\\' => i += 2,
                        b'"' => break,
                        _ => i += 1,
                    }
                }
                if i >= n {
                    return false;
                }
                let end = i + 1;
                match stack.last_mut() {
                    Some(fr) if fr.is_obj && fr.expecting_key => {
                        fr.key = Some((start + 1, end - 1));
                    }
                    top => {
                        let (key, object) = match top {
                            Some(fr) => (
                                fr.key.map(|(a, b)| &raw[a..b]),
                                if fr.is_obj { Some(fr.obj_id) } else { None },
                            ),
                            None => (None, None),
                        };
                        // Arrays inherit the key and object of their parent.
                        let object = object.or_else(|| stack.iter().rev().find(|f| f.is_obj).map(|f| f.obj_id));
                        f(StrLit {
                            span: start..end,
                            key,
                            object,
                        });
                    }
                }
                i = end;
                continue;
            }
            b'{' => {
                stack.push(Frame {
                    is_obj: true,
                    expecting_key: true,
                    key: None,
                    obj_id: obj_counter,
                });
                obj_counter += 1;
            }
            b'[' => {
                let key = stack.last().and_then(|f| f.key);
                stack.push(Frame {
                    is_obj: false,
                    expecting_key: false,
                    key,
                    obj_id: 0,
                });
            }
            b'}' | b']' => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            b':' => {
                if let Some(fr) = stack.last_mut() {
                    fr.expecting_key = false;
                }
            }
            b',' => {
                if let Some(fr) = stack.last_mut()
                    && fr.is_obj
                {
                    fr.expecting_key = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    stack.is_empty()
}

/// Decode a raw JSON string literal (with quotes) into a Rust string.
pub fn decode(lit: &[u8]) -> Option<std::borrow::Cow<'_, str>> {
    let inner = &lit[1..lit.len() - 1];
    if !inner.contains(&b'\\') {
        return std::str::from_utf8(inner).ok().map(std::borrow::Cow::Borrowed);
    }
    serde_json::from_slice::<String>(lit).ok().map(std::borrow::Cow::Owned)
}

/// Encode a string as a JSON literal (with quotes).
pub fn encode(s: &str) -> String {
    serde_json::to_string(s).expect("string serialisation cannot fail")
}

/// Decode a key for context purposes (lossy is fine).
pub fn key_str(key: Option<&[u8]>) -> String {
    key.map(|k| String::from_utf8_lossy(k).to_ascii_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_values_not_keys() {
        let doc = br#"{"a":"x","b":["y",{"c":"z"}],"d":1}"#;
        let mut got = vec![];
        assert!(for_each_string(doc, |s| got
            .push((key_str(s.key), decode(&doc[s.span]).unwrap().into_owned()))));
        assert_eq!(
            got,
            vec![
                ("a".into(), "x".into()),
                ("b".into(), "y".into()),
                ("c".into(), "z".into())
            ]
        );
    }

    #[test]
    fn escapes() {
        let doc = br#"{"k":"he said \"hi\" \\ \u00e9"}"#;
        let mut v = String::new();
        for_each_string(doc, |s| v = decode(&doc[s.span]).unwrap().into_owned());
        assert_eq!(v, "he said \"hi\" \\ \u{e9}");
    }

    #[test]
    fn rejects_garbage() {
        assert!(!for_each_string(b"{\"a\":\"x", |_| {}));
    }
}
