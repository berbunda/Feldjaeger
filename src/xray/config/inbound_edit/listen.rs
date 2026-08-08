//! Listen address validation for inbound shell edit.

use std::net::IpAddr;

use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Validates a non-empty listen string: IP (optional brackets) or conservative hostname.
pub fn validate_listen_address(listen: &str) -> ConfigModifyResult<()> {
    let trimmed = listen.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let candidate = strip_ip_brackets(trimmed);
    if candidate.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    if is_conservative_hostname(trimmed) {
        return Ok(());
    }

    Err(ConfigModifyError::new(
        ConfigModifyErrorKind::ValidationFailed,
        format!("invalid listen address: {trimmed}"),
    ))
}

fn strip_ip_brackets(value: &str) -> &str {
    if let Some(inner) = value.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        inner
    } else {
        value
    }
}

fn is_conservative_hostname(value: &str) -> bool {
    if value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    let mut label_len = 0usize;
    for ch in value.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {
                label_len += 1;
                if label_len > 63 {
                    return false;
                }
            }
            '.' => {
                if label_len == 0 {
                    return false;
                }
                label_len = 0;
            }
            _ => return false,
        }
    }
    label_len > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ipv4_and_bracketed_ipv6() {
        validate_listen_address("0.0.0.0").unwrap();
        validate_listen_address("127.0.0.1").unwrap();
        validate_listen_address("[::1]").unwrap();
    }

    #[test]
    fn accepts_hostname() {
        validate_listen_address("example.com").unwrap();
        validate_listen_address("vpn-edge1.local").unwrap();
    }

    #[test]
    fn rejects_junk() {
        assert!(validate_listen_address(":::").is_err());
        assert!(validate_listen_address("bad host").is_err());
    }
}
