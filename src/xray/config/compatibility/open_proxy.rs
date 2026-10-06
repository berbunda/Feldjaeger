//! Socks / `mixed` / HTTP inbounds that anyone on the Internet can use as a proxy.
//!
//! Both protocols carry no encryption of their own; the official docs (`inbounds/socks.md`) mark
//! them "not suitable for transmission over the public internet" and meant for a LAN or the local
//! machine. Without authentication on an outside-facing address they are an open proxy — abused
//! by third parties, and a common reason for a hosting provider to suspend the server.
//!
//! Authentication is read the way the core builds it (`XTLS/Xray-core@main`, `infra/conf`):
//! - `SocksServerConfig.Build()` (`socks`, alias `mixed`): `auth` other than exactly `"password"`
//!   — absent, `"noauth"`, anything else — is `NO_AUTH`, whatever `accounts` holds;
//! - `HTTPServerConfig.Build()`: a non-null `accounts` replaces `users` (an empty `[]` too), and
//!   no account left means no authentication.
//!
//! "Outside-facing" `listen`: absent / empty (the core's default `0.0.0.0`), an unspecified
//! address, or a public IP. Loopback and private ranges ([`super::plaintext_outbound`]'s list of
//! the core's reserved ranges) are the LAN / local use the docs describe; a Unix socket path
//! (`/…`, abstract `@…`) is no network listener. Anything else (a non-IP string the core would
//! not listen on) makes no claim.

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;

use super::plaintext_outbound::is_private_ip;

/// JSON path of the missing authentication when `inbound` is an open proxy, else `None`.
pub(super) fn open_proxy_location(inbound: &Value) -> Option<String> {
    let protocol = inbound.get("protocol").and_then(Value::as_str)?.trim().to_ascii_lowercase();
    let settings = inbound.get("settings");
    let location = match protocol.as_str() {
        "socks" | "mixed" => {
            let auth = settings.and_then(|settings| settings.get("auth"));
            if auth.and_then(Value::as_str) == Some("password") {
                return None;
            }
            "settings.auth"
        }
        "http" => http_unauthenticated_location(settings)?,
        _ => return None,
    };
    listen_is_exposed(inbound.get("listen")).then(|| location.to_owned())
}

/// `settings.accounts` / `settings.users` when the HTTP inbound authenticates nobody.
fn http_unauthenticated_location(settings: Option<&Value>) -> Option<&'static str> {
    let field = |key: &str| settings.and_then(|settings| settings.get(key)).filter(|value| !value.is_null());
    let (location, accounts) = match (field("accounts"), field("users")) {
        (Some(accounts), _) => ("settings.accounts", Some(accounts)),
        (None, Some(users)) => ("settings.users", Some(users)),
        (None, None) => ("settings.accounts", None),
    };
    match accounts {
        None => Some(location),
        Some(Value::Array(accounts)) if accounts.is_empty() => Some(location),
        // A non-empty list authenticates; a non-array fails the core's decode — no claim.
        Some(_) => None,
    }
}

/// Whether `listen` accepts connections from outside the machine and its private networks.
fn listen_is_exposed(listen: Option<&Value>) -> bool {
    let text = match listen {
        None | Some(Value::Null) => return true,
        Some(Value::String(text)) => text.trim(),
        Some(_) => return false,
    };
    if text.is_empty() {
        return true;
    }
    if text.starts_with('/') || text.starts_with('@') {
        return false;
    }
    let unbracketed = text.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(text);
    let ip = unbracketed
        .parse::<IpAddr>()
        .ok()
        .or_else(|| text.parse::<SocketAddr>().ok().map(|address| address.ip()));
    // `0.0.0.0` and `::` sit inside the core's private ranges, so they are checked first.
    ip.is_some_and(|ip| ip.is_unspecified() || !is_private_ip(ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn socks_without_password_on_default_listen_is_open() {
        assert_eq!(
            open_proxy_location(&json!({"protocol": "socks", "port": 1080})),
            Some("settings.auth".to_owned())
        );
        let noauth = json!({"protocol": "mixed", "listen": "0.0.0.0", "settings": {"auth": "noauth"}});
        assert_eq!(open_proxy_location(&noauth), Some("settings.auth".to_owned()));
    }

    #[test]
    fn socks_auth_is_case_sensitive_like_the_core() {
        // The core's switch has no case folding: "Password" falls to the NO_AUTH default.
        let inbound = json!({"protocol": "socks", "settings": {"auth": "Password", "accounts": [{"user": "a", "pass": "b"}]}});
        assert!(open_proxy_location(&inbound).is_some());
        let inbound = json!({"protocol": "socks", "settings": {"auth": "password"}});
        assert_eq!(open_proxy_location(&inbound), None);
    }

    #[test]
    fn http_accounts_replace_users_even_when_empty() {
        let users_only = json!({"protocol": "http", "settings": {"users": [{"user": "a", "pass": "b"}]}});
        assert_eq!(open_proxy_location(&users_only), None);
        let empty_accounts = json!({"protocol": "http", "settings": {"accounts": [], "users": [{"user": "a", "pass": "b"}]}});
        assert_eq!(open_proxy_location(&empty_accounts), Some("settings.accounts".to_owned()));
        let null_accounts = json!({"protocol": "http", "settings": {"accounts": null, "users": []}});
        assert_eq!(open_proxy_location(&null_accounts), Some("settings.users".to_owned()));
        assert_eq!(
            open_proxy_location(&json!({"protocol": "http"})),
            Some("settings.accounts".to_owned())
        );
    }

    #[test]
    fn local_and_private_listen_addresses_are_not_open() {
        for listen in ["127.0.0.1", "::1", "[::1]", "10.0.0.5", "192.168.1.1", "fd00::1", "/run/xray.sock", "@xray"] {
            let inbound = json!({"protocol": "socks", "listen": listen});
            assert_eq!(open_proxy_location(&inbound), None, "{listen}");
        }
    }

    #[test]
    fn wildcard_and_public_listen_addresses_are_open() {
        for listen in ["", "0.0.0.0", "::", "[::]", "1.2.3.4", "2a01:4f8::1"] {
            let inbound = json!({"protocol": "http", "listen": listen});
            assert!(open_proxy_location(&inbound).is_some(), "{listen}");
        }
    }

    #[test]
    fn other_protocols_are_never_open_proxies() {
        for protocol in ["vless", "trojan", "shadowsocks", "vmess", "tunnel"] {
            assert_eq!(open_proxy_location(&json!({"protocol": protocol})), None, "{protocol}");
        }
    }
}
