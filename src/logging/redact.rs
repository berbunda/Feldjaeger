//! Redaction helpers for log and UI error strings.
//!
//! Never log passwords, private keys, passphrases, tokens, VLESS UUIDs, or
//! raw remote command output. Prefer structured allowlisted fields; when an
//! external error string must be recorded, pass it through [`sanitize_detail`].

/// Maximum number of Unicode scalar values retained in a sanitized detail.
pub const MAX_DETAIL_CHARS: usize = 240;

/// Redaction marker written in place of sensitive fragments.
pub const REDACTED: &str = "[REDACTED]";

/// Sanitizes an external error/detail string for logs and UI.
///
/// - Trims whitespace
/// - Redacts common secret markers (password, passphrase, token, bearer, private key)
/// - Redacts UUID-shaped tokens (including VLESS ids)
/// - Truncates to [`MAX_DETAIL_CHARS`] on a Unicode boundary
pub fn sanitize_detail(message: &str) -> String {
    let trimmed = message.trim();
    let mut sanitized = trimmed.to_owned();

    for needle in [
        "password=",
        "password:",
        "passphrase=",
        "passphrase:",
        "Password(",
        "token=",
        "token:",
        "bearer ",
        "authorization:",
        "private_key=",
        "private-key=",
        "private key:",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
    ] {
        if let Some(idx) = find_ignore_ascii_case(&sanitized, needle) {
            sanitized.truncate(idx);
            sanitized.push_str(REDACTED);
            break;
        }
    }

    sanitized = redact_uuid_shaped(&sanitized);
    truncate_chars(&sanitized, MAX_DETAIL_CHARS)
}

/// Returns `true` when `value` looks like a UUID (VLESS client id shape).
pub fn looks_like_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let is_hex = |b: u8| b.is_ascii_hexdigit();
    let groups = [(0, 8), (9, 4), (14, 4), (19, 4), (24, 12)];
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (start, len) in groups {
        if !bytes[start..start + len].iter().copied().all(is_hex) {
            return false;
        }
    }
    true
}

fn redact_uuid_shaped(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some((idx, candidate)) = next_uuid_candidate(rest) {
        output.push_str(&rest[..idx]);
        output.push_str(REDACTED);
        rest = &rest[idx + candidate.len()..];
    }
    output.push_str(rest);
    output
}

fn next_uuid_candidate(input: &str) -> Option<(usize, &str)> {
    if input.len() < 36 {
        return None;
    }
    for (start, _) in input.char_indices() {
        let end = start + 36;
        if end > input.len() || !input.is_char_boundary(end) {
            continue;
        }
        let slice = &input[start..end];
        if looks_like_uuid(slice) {
            return Some((start, slice));
        }
    }
    None
}

fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    for i in 0..=hay.len() - needle.len() {
        if hay[i..i + needle.len()]
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
    }
    None
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// User-facing connection failure text that points operators to the log file.
pub fn user_message_see_log(summary: &str) -> String {
    format!("{summary} See application log for details.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_marker() {
        let detail = sanitize_detail("boom password=secret-value trailing");
        assert!(!detail.contains("secret-value"));
        assert!(detail.contains(REDACTED));
    }

    #[test]
    fn redacts_passphrase_and_token_markers() {
        assert!(!sanitize_detail("x passphrase:hunter2").contains("hunter2"));
        assert!(!sanitize_detail("Authorization: Bearer abc.def").contains("abc.def"));
        assert!(!sanitize_detail("token=abc123").contains("abc123"));
    }

    #[test]
    fn redacts_private_key_pem_marker() {
        let detail = sanitize_detail("failed BEGIN OPENSSH PRIVATE KEY-----abc");
        assert!(detail.contains(REDACTED));
        assert!(!detail.contains("abc"));
    }

    #[test]
    fn redacts_vless_uuid() {
        let detail = sanitize_detail("client 550e8400-e29b-41d4-a716-446655440000 failed");
        assert!(!detail.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(detail.contains(REDACTED));
    }

    #[test]
    fn truncates_on_unicode_boundary() {
        let input = "ё".repeat(300);
        let detail = sanitize_detail(&input);
        assert!(detail.ends_with('…'));
        assert_eq!(detail.chars().count(), MAX_DETAIL_CHARS + 1);
    }

    #[test]
    fn user_message_points_to_log() {
        let message = user_message_see_log("Unable to connect to server.");
        assert!(message.contains("See application log for details."));
    }
}
