//! Generators and validators for synthetic identifiers, secrets and decoys.
//!
//! Secret-shaped prefixes are assembled from pieces at runtime, so the source never contains a
//! literal secret-looking string. Every generated value is synthetic.

use crate::rng::{ALNUM, ALNUM_DASH_UNDERSCORE, ALNUM_UNDERSCORE, B32, B64, B64URL, DIGITS, HEX, Rng};

const NINO_FIRST: &[u8] = b"ABCEGHJKLMNOPRSTWXYZ";
const NINO_SECOND: &[u8] = b"ABCEGHJKLMNPRSTWXYZ";
const NINO_BAD_PREFIXES: &[&str] = &["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"];
const POSTCODE_OUTWARD: &[&str] = &[
    "SW1A", "M1", "B33", "CR2", "DN55", "LS6", "BS8", "NG1", "EH1", "OX1", "YO10", "CF10", "WF1", "SO14", "G2", "L18",
    "PE1", "HU1", "TN24", "RG1",
];
/// Inward-code letters: the set excludes C, I, K, M, O and V.
const POSTCODE_INWARD_LETTERS: &[u8] = b"ABDEFGHJLNPQRSTUWXYZ";
const BANK_CODES: &[&str] = &["HLFX", "MDLN", "NWBK", "BRCL", "TSBS", "PYLN", "KRAB", "FDLA"];

fn compact(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn digit_values(s: &str) -> Option<Vec<u32>> {
    s.chars().map(|c| c.to_digit(10)).collect()
}

/// Inserts a space after every `n` characters.
fn group(s: &str, n: usize) -> String {
    s.as_bytes()
        .chunks(n)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn digits_string(d: &[u32]) -> String {
    d.iter().map(|x| char::from(b'0' + *x as u8)).collect()
}

fn double_digit(x: u32) -> u32 {
    let y = x * 2;
    if y > 9 { y - 9 } else { y }
}

// ---------------------------------------------------------------- Luhn (cards)

pub fn luhn_ok(s: &str) -> bool {
    let Some(d) = digit_values(&compact(s)) else {
        return false;
    };
    d.len() >= 2
        && d.iter()
            .rev()
            .enumerate()
            .map(|(i, &x)| if i % 2 == 1 { double_digit(x) } else { x })
            .sum::<u32>()
            % 10
            == 0
}

/// Check digit for a payload whose check digit is still to be appended.
fn luhn_check_digit(payload: &[u32]) -> u32 {
    let sum: u32 = payload
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| if i % 2 == 0 { double_digit(x) } else { x })
        .sum();
    (10 - sum % 10) % 10
}

pub fn card_number(rng: &mut Rng) -> String {
    let mut payload: Vec<u32> = if rng.chance(50) {
        vec![4]
    } else {
        vec![5, rng.range(1, 5) as u32]
    };
    while payload.len() < 15 {
        payload.push(rng.below(10) as u32);
    }
    payload.push(luhn_check_digit(&payload));
    let card = group(&digits_string(&payload), 4);
    debug_assert!(luhn_ok(&card));
    card
}

// ---------------------------------------------------------------- NHS number

fn nhs_check(first_nine: &[u32]) -> Option<u32> {
    let sum: u32 = first_nine.iter().enumerate().map(|(i, &d)| d * (10 - i as u32)).sum();
    match 11 - sum % 11 {
        11 => Some(0),
        10 => None,
        c => Some(c),
    }
}

pub fn nhs_ok(s: &str) -> bool {
    match digit_values(&compact(s)) {
        Some(d) => d.len() == 10 && nhs_check(&d[..9]) == Some(d[9]),
        None => false,
    }
}

pub fn nhs_number(rng: &mut Rng) -> String {
    loop {
        let mut d = vec![rng.range(4, 9) as u32];
        while d.len() < 9 {
            d.push(rng.below(10) as u32);
        }
        if let Some(check) = nhs_check(&d) {
            d.push(check);
            let s = digits_string(&d);
            let out = format!("{} {} {}", &s[..3], &s[3..6], &s[6..]);
            debug_assert!(nhs_ok(&out));
            return out;
        }
    }
}

// ---------------------------------------------------------------- National Insurance

pub fn nino_ok(s: &str) -> bool {
    let c = compact(s).to_ascii_uppercase().into_bytes();
    if c.len() != 9 {
        return false;
    }
    let prefix = [c[0], c[1]];
    NINO_FIRST.contains(&c[0])
        && NINO_SECOND.contains(&c[1])
        && !NINO_BAD_PREFIXES.iter().any(|p| p.as_bytes() == prefix.as_slice())
        && c[2..8].iter().all(u8::is_ascii_digit)
        && b"ABCD".contains(&c[8])
}

pub fn nino(rng: &mut Rng) -> String {
    loop {
        let first = *rng.pick(NINO_FIRST);
        let second = *rng.pick(NINO_SECOND);
        let digits = rng.chars(DIGITS, 6);
        let suffix = *rng.pick(b"ABCD");
        let raw = format!(
            "{}{}{digits}{}",
            char::from(first),
            char::from(second),
            char::from(suffix)
        );
        if nino_ok(&raw) {
            let out = format!(
                "{} {} {} {} {}",
                &raw[0..2],
                &raw[2..4],
                &raw[4..6],
                &raw[6..8],
                &raw[8..9]
            );
            debug_assert!(nino_ok(&out));
            return out;
        }
    }
}

// ---------------------------------------------------------------- Postcode

pub fn postcode_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let (out, inn) = match parts.as_slice() {
        [o, i] => (o.as_bytes(), i.as_bytes()),
        _ => return false,
    };
    let inward_ok = inn.len() == 3
        && inn[0].is_ascii_digit()
        && inn[1..]
            .iter()
            .all(|c| c.is_ascii_uppercase() && !b"CIKMOV".contains(c));
    let outward_ok = (2..=4).contains(&out.len())
        && out[0].is_ascii_uppercase()
        && out.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && out.iter().any(u8::is_ascii_digit);
    inward_ok && outward_ok
}

pub fn postcode(rng: &mut Rng) -> String {
    let outward = *rng.pick(POSTCODE_OUTWARD);
    let digit = rng.below(10);
    let l1 = char::from(*rng.pick(POSTCODE_INWARD_LETTERS));
    let l2 = char::from(*rng.pick(POSTCODE_INWARD_LETTERS));
    let code = format!("{outward} {digit}{l1}{l2}");
    debug_assert!(postcode_ok(&code));
    code
}

// ---------------------------------------------------------------- Phones

pub fn uk_mobile(rng: &mut Rng) -> String {
    format!("07700 9{:05}", rng.below(100_000))
}

pub fn uk_mobile_intl(rng: &mut Rng) -> String {
    format!("+44 7700 9{:05}", rng.below(100_000))
}

pub fn us_number(rng: &mut Rng) -> String {
    format!("+1 415 555 0{:03}", rng.below(1000))
}

// ---------------------------------------------------------------- IBAN (GB)

/// ISO 7064 mod-97 over an alphanumeric string (letters map to 10..=35).
fn mod97(s: &str) -> u32 {
    s.chars().fold(0u32, |r, c| match c.to_digit(10) {
        Some(d) => (r * 10 + d) % 97,
        None => (r * 100 + (c as u32 - 'A' as u32 + 10)) % 97,
    })
}

pub fn iban_gb_ok(s: &str) -> bool {
    let c = compact(s).to_ascii_uppercase();
    if c.len() != 22
        || !c.bytes().all(|b| b.is_ascii_alphanumeric())
        || !c.starts_with("GB")
        || !c[2..4].bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    mod97(&format!("{}{}", &c[4..], &c[..4])) == 1
}

pub fn iban_gb(rng: &mut Rng) -> String {
    let bban = format!("{}{}", rng.pick(BANK_CODES), rng.chars(DIGITS, 14));
    let check = 98 - mod97(&format!("{bban}GB00"));
    let out = group(&format!("GB{check:02}{bban}"), 4);
    debug_assert!(iban_gb_ok(&out));
    out
}

// ---------------------------------------------------------------- Secrets

pub fn aws_access_key(rng: &mut Rng) -> String {
    format!("{}{}", ["AK", "IA"].concat(), rng.chars(B32, 16))
}

pub fn github_pat(rng: &mut Rng) -> String {
    format!("{}{}", ["gh", "p_"].concat(), rng.chars(ALNUM, 36))
}

pub fn github_fine_pat(rng: &mut Rng) -> String {
    format!("{}{}", ["github", "_pat_"].concat(), rng.chars(ALNUM_UNDERSCORE, 82))
}

pub fn slack_bot_token(rng: &mut Rng) -> String {
    let a = rng.range(10, 13) as usize;
    let b = rng.range(10, 13) as usize;
    format!(
        "{}{}-{}-{}",
        ["xox", "b-"].concat(),
        rng.chars(DIGITS, a),
        rng.chars(DIGITS, b),
        rng.chars(ALNUM, 24)
    )
}

pub fn openai_key(rng: &mut Rng) -> String {
    format!(
        "{}{}{}{}",
        ["s", "k-"].concat(),
        rng.chars(ALNUM, 20),
        ["T3", "BlbkFJ"].concat(),
        rng.chars(ALNUM, 20)
    )
}

pub fn anthropic_key(rng: &mut Rng) -> String {
    format!(
        "{}{}AA",
        ["sk-", "ant-", "api03-"].concat(),
        rng.chars(ALNUM_DASH_UNDERSCORE, 93)
    )
}

pub fn stripe_live_key(rng: &mut Rng) -> String {
    format!("{}{}", ["sk", "_live_"].concat(), rng.chars(ALNUM, 24))
}

fn b64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for i in 0..chunk.len() + 1 {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(B64URL[idx]));
        }
    }
    out
}

pub fn jwt(rng: &mut Rng) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload_json = format!(
        r#"{{"sub":"{}","name":"{}","iat":{}}}"#,
        rng.chars(DIGITS, 10),
        rng.chars(ALNUM, 12),
        rng.range(1_600_000_000, 1_790_000_000)
    );
    let payload = b64url(payload_json.as_bytes());
    let sig: Vec<u8> = (0..32).map(|_| rng.next_u64() as u8).collect();
    format!("{header}.{payload}.{}", b64url(&sig))
}

/// Returns (full PEM block, base64 body). Only the body is a secret value to record.
pub fn pem_key(rng: &mut Rng) -> (String, String) {
    let body = (0..5).map(|_| rng.chars(B64, 64)).collect::<Vec<_>>().join("\n");
    let block = format!(
        "{}\n{}\n{}",
        ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat(),
        body,
        ["-----END RSA ", "PRIVATE KEY-----"].concat()
    );
    (block, body)
}

pub fn pg_password(rng: &mut Rng) -> String {
    rng.chars(ALNUM, 16)
}

pub fn api_key(rng: &mut Rng) -> String {
    rng.chars(ALNUM, 32)
}

pub fn password(rng: &mut Rng) -> String {
    rng.chars(ALNUM, 20)
}

// ---------------------------------------------------------------- Decoys

pub fn uuid(rng: &mut Rng) -> String {
    let h = rng.chars(HEX, 32);
    let variant = ["8", "9", "a", "b"][rng.below(4)];
    format!(
        "{}-{}-4{}-{}{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        variant,
        &h[17..20],
        &h[20..32]
    )
}

pub fn git_sha(rng: &mut Rng) -> String {
    rng.chars(HEX, 40)
}

pub fn sha256(rng: &mut Rng) -> String {
    rng.chars(HEX, 64)
}

pub fn png_base64(rng: &mut Rng) -> String {
    format!("iVBORw0KGgo{}", rng.chars(B64, 200))
}

pub fn semver(rng: &mut Rng) -> String {
    format!("{}.{}.{}", rng.range(1, 3), rng.range(0, 30), rng.range(0, 40))
}

pub fn semver_beta(rng: &mut Rng) -> String {
    format!(
        "v{}.{}.{}-beta.{}",
        rng.range(1, 3),
        rng.range(0, 9),
        rng.range(0, 9),
        rng.range(1, 4)
    )
}

pub fn iso_timestamp(rng: &mut Rng) -> String {
    format!(
        "2026-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        rng.range(1, 12),
        rng.range(1, 28),
        rng.range(0, 23),
        rng.range(0, 59),
        rng.range(0, 59),
        rng.range(0, 999)
    )
}

pub fn iso_date(rng: &mut Rng) -> String {
    format!("2026-{:02}-{:02}", rng.range(1, 12), rng.range(1, 28))
}

pub fn numeric_id(rng: &mut Rng) -> String {
    rng.range(100_000, 999_999).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_pass_validators() {
        let mut rng = Rng::new(7);
        for _ in 0..500 {
            assert!(nhs_ok(&nhs_number(&mut rng)));
            assert!(luhn_ok(&card_number(&mut rng)));
            assert!(iban_gb_ok(&iban_gb(&mut rng)));
            assert!(nino_ok(&nino(&mut rng)));
            assert!(postcode_ok(&postcode(&mut rng)));
        }
    }

    #[test]
    fn validators_reject_corrupted_values() {
        let mut rng = Rng::new(11);
        for _ in 0..100 {
            let nhs = nhs_number(&mut rng);
            let last = nhs.chars().last().unwrap_or('0');
            let bad_digit = if last == '9' { '8' } else { '9' };
            let corrupted = format!("{}{bad_digit}", &nhs[..nhs.len() - 1]);
            assert!(!nhs_ok(&corrupted));

            let card = card_number(&mut rng);
            let mut digits: Vec<char> = card.chars().collect();
            let idx = digits.iter().rposition(|c| c.is_ascii_digit()).unwrap_or(0);
            digits[idx] = if digits[idx] == '0' { '1' } else { '0' };
            assert!(!luhn_ok(&digits.into_iter().collect::<String>()));

            let iban = iban_gb(&mut rng);
            let mut chars: Vec<char> = iban.chars().collect();
            let last_digit = chars.iter().rposition(|c| c.is_ascii_digit()).unwrap_or(0);
            chars[last_digit] = if chars[last_digit] == '0' { '1' } else { '0' };
            assert!(!iban_gb_ok(&chars.into_iter().collect::<String>()));
        }
    }

    #[test]
    fn published_example_vectors() {
        assert!(iban_gb_ok("GB82 WEST 1234 5698 7654 32"));
        assert!(postcode_ok("SW1A 2AA"));
        assert!(postcode_ok("M1 1AE"));
        assert!(!postcode_ok("M1 1CE"));
        assert!(nino_ok("AB 12 34 56 C"));
        assert!(!nino_ok("GB 12 34 56 C"));
        assert!(!nino_ok("AB 12 34 56 E"));
    }

    #[test]
    fn uuid_has_canonical_shape() {
        let mut rng = Rng::new(3);
        let u = uuid(&mut rng);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn jwt_has_three_parts() {
        let mut rng = Rng::new(5);
        let token = jwt(&mut rng);
        assert_eq!(token.split('.').count(), 3);
        let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
        assert!(token.starts_with(&format!("{header}.")));
    }
}
