//! Checksum and shape validators. A structured-PII match that fails its
//! validator is not redacted.

pub fn digits(s: &str) -> Vec<u8> {
    s.bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect()
}

pub fn luhn(s: &str) -> bool {
    let d = digits(s);
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &x) in d.iter().rev().enumerate() {
        let mut v = x as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Card numbers: Luhn plus a known issuer prefix and length.
pub fn card(s: &str) -> bool {
    let d = digits(s);
    if !luhn(s) || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let p2 = d[0] as u32 * 10 + d[1] as u32;
    let p4 = p2 * 100 + d[2] as u32 * 10 + d[3] as u32;
    let n = d.len();
    match d[0] {
        4 => n == 13 || n == 16 || n == 19,
        5 => (51..=55).contains(&p2) && n == 16,
        2 => (2221..=2720).contains(&p4) && n == 16,
        3 => (p2 == 34 || p2 == 37) && n == 15 || p2 == 35 && n == 16 || (p2 == 36 || p2 == 38 || p2 == 30) && n == 14,
        6 => (p4 == 6011 || p2 == 65) && n == 16,
        _ => false,
    }
}

/// NHS number: 10 digits, England/Wales/IoM ranges start 4-9, mod-11 check digit.
pub fn nhs(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 || d[0] < 4 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let sum: u32 = d[..9]
        .iter()
        .enumerate()
        .map(|(i, &x)| x as u32 * (10 - i as u32))
        .sum();
    let check = 11 - (sum % 11);
    let check = if check == 11 { 0 } else { check };
    check != 10 && check == d[9] as u32
}

pub fn iban_len(country: &str) -> Option<usize> {
    Some(match country {
        "AD" => 24,
        "AE" => 23,
        "AL" => 28,
        "AT" => 20,
        "AZ" => 28,
        "BA" => 20,
        "BE" => 16,
        "BG" => 22,
        "BH" => 22,
        "BR" => 29,
        "CH" => 21,
        "CR" => 22,
        "CY" => 28,
        "CZ" => 24,
        "DE" => 22,
        "DK" => 18,
        "DO" => 28,
        "EE" => 20,
        "EG" => 29,
        "ES" => 24,
        "FI" => 18,
        "FO" => 18,
        "FR" => 27,
        "GB" => 22,
        "GE" => 22,
        "GI" => 23,
        "GL" => 18,
        "GR" => 27,
        "GT" => 28,
        "HR" => 21,
        "HU" => 28,
        "IE" => 22,
        "IL" => 23,
        "IS" => 26,
        "IT" => 27,
        "JO" => 30,
        "KW" => 30,
        "KZ" => 20,
        "LB" => 28,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "LV" => 21,
        "MC" => 27,
        "MD" => 24,
        "ME" => 22,
        "MK" => 19,
        "MR" => 27,
        "MT" => 31,
        "MU" => 30,
        "NL" => 18,
        "NO" => 15,
        "PK" => 24,
        "PL" => 28,
        "PS" => 29,
        "PT" => 25,
        "QA" => 29,
        "RO" => 24,
        "RS" => 22,
        "SA" => 24,
        "SE" => 24,
        "SI" => 19,
        "SK" => 24,
        "SM" => 27,
        "TN" => 24,
        "TR" => 26,
        "UA" => 29,
        "VG" => 24,
        "XK" => 20,
        _ => return None,
    })
}

pub fn iban(s: &str) -> bool {
    let c: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if c.len() < 15 || !c.is_char_boundary(2) {
        return false;
    }
    match iban_len(&c[..2]) {
        Some(n) if n == c.len() => {}
        _ => return false,
    }
    let rearranged = format!("{}{}", &c[4..], &c[..4]);
    let mut rem: u32 = 0;
    for ch in rearranged.chars() {
        let v = match ch {
            '0'..='9' => ch as u32 - '0' as u32,
            'A'..='Z' => ch as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

/// UK National Insurance number prefix rules.
pub fn nino(s: &str) -> bool {
    let c: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    if c.len() != 9 {
        return false;
    }
    let b = c.as_bytes();
    let bad_first = b"DFIQUV";
    let bad_second = b"DFIOQUV";
    if bad_first.contains(&b[0]) || bad_second.contains(&b[1]) {
        return false;
    }
    !matches!(&c[..2], "BG" | "GB" | "KN" | "NK" | "NT" | "TN" | "ZZ") && (b'A'..=b'D').contains(&b[8])
}

/// UK postcode shape rules beyond the regex.
pub fn postcode(s: &str) -> bool {
    let c: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(5..=7).contains(&c.len()) {
        return false;
    }
    let b = c.as_bytes();
    if b"QVX".contains(&b[0]) {
        return false;
    }
    if b[1].is_ascii_alphabetic() && b"IJZ".contains(&b[1]) {
        return false;
    }
    let inward = &b[b.len() - 2..];
    !inward.iter().any(|x| b"CIKMOV".contains(x))
}

/// E.164-ish digit count for phones.
pub fn phone(s: &str) -> bool {
    let d = digits(s);
    let intl = s.trim_start().starts_with('+');
    if intl {
        if !(8..=15).contains(&d.len()) {
            return false;
        }
        if d.starts_with(&[4, 4]) {
            // UK numbers after +44 have 10 digits (no trunk zero).
            return d.len() == 12;
        }
        true
    } else {
        // UK domestic with trunk zero: 10 or 11 digits.
        (d.len() == 11 || d.len() == 10) && d[0] == 0 && d[1] != 0
    }
}

pub fn ipv4_public(s: &str, include_private: bool) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || (p.len() > 1 && p.starts_with('0')) {
            return false;
        }
        match p.parse::<u16>() {
            Ok(v) if v <= 255 => o[i] = v as u8,
            _ => return false,
        }
    }
    let special = o[0] == 0 || o[0] >= 224 || o == [255, 255, 255, 255];
    if special {
        return false;
    }
    let private = o[0] == 10
        || o[0] == 127
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..=127).contains(&o[1]));
    include_private || !private
}

/// Shannon entropy in bits per char.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checks() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(card("4111111111111111"));
        assert!(!card("4444444444444444"));
        assert!(card("5555 5555 5555 4444"));
        assert!(!card("5555 5555 5555 4445"));
        assert!(nhs("943 476 5919"));
        assert!(!nhs("943 476 5918"));
        assert!(iban("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban("GB82 WEST 1234 5698 7654 33"));
        assert!(nino("AB 12 34 56 C"));
        assert!(!nino("GB 12 34 56 C"));
        assert!(postcode("SW1A 2AA"));
        assert!(!postcode("SW1A 2AC"));
        assert!(phone("07700 900123"));
        assert!(phone("+44 7700 900123"));
        assert!(!phone("+44 7700 90012"));
        assert!(ipv4_public("8.8.8.8", false));
        assert!(!ipv4_public("192.168.1.1", false));
        assert!(ipv4_public("192.168.1.1", true));
        assert!(entropy("aaaa") < 0.1);
    }
}
