//! Redacted structural JSON diff for pre-save review (IB-L5).

use serde_json::Value;

/// One changed path in a redacted JSON comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonDiffEntry {
    /// Dot/bracket path (e.g. `inbounds[0].settings.clients[1].email`).
    pub path: String,
    /// How the value changed.
    pub kind: JsonDiffKind,
    /// Redacted display of the previous value (`None` when added).
    pub before: Option<String>,
    /// Redacted display of the new value (`None` when removed).
    pub after: Option<String>,
}

/// Kind of structural change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonDiffKind {
    /// Path exists only in the new document.
    Added,
    /// Path exists only in the old document.
    Removed,
    /// Path exists in both but values differ.
    Changed,
}

impl JsonDiffKind {
    /// Short label for UI rows.
    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "+",
            Self::Removed => "-",
            Self::Changed => "~",
        }
    }
}

/// Compares two JSON documents and returns redacted path-level changes.
///
/// Secret-bearing keys (`password`, `privateKey`, `id`, …) are shown as
/// `[REDACTED]` so operators can review shape without leaking secrets.
pub fn redacted_json_diff(before: &Value, after: &Value) -> Vec<JsonDiffEntry> {
    let mut out = Vec::new();
    diff_values("", before, after, &mut out);
    out
}

/// Parses bytes as JSON and diffs; on parse failure returns a single synthetic entry.
pub fn redacted_json_diff_bytes(before: &[u8], after: &[u8]) -> Vec<JsonDiffEntry> {
    let before_value = match serde_json::from_slice::<Value>(before) {
        Ok(value) => value,
        Err(_) => {
            return vec![JsonDiffEntry {
                path: "<file>".to_owned(),
                kind: JsonDiffKind::Changed,
                before: Some("<unparseable>".to_owned()),
                after: Some(summarize_bytes(after)),
            }];
        }
    };
    let after_value = match serde_json::from_slice::<Value>(after) {
        Ok(value) => value,
        Err(_) => {
            return vec![JsonDiffEntry {
                path: "<file>".to_owned(),
                kind: JsonDiffKind::Changed,
                before: Some(summarize_bytes(before)),
                after: Some("<unparseable>".to_owned()),
            }];
        }
    };
    redacted_json_diff(&before_value, &after_value)
}

/// Line-level diff for plain-text files (e.g. systemd unit bodies) that reuses the same
/// positional diff engine and `+`/`-`/`~` rendering as the JSON diff (Roadmap §3:126 — systemd
/// unit is not Xray JSON config, but Feldjäger fully replaces it on Apply, so a before/after
/// review deserves the same treatment). Each line becomes one array element; there is no
/// secret-key redaction concept for plain text, so lines are shown verbatim (quoted, as any
/// JSON string leaf would be).
pub fn redacted_json_diff_lines(before: &str, after: &str) -> Vec<JsonDiffEntry> {
    let before_value = Value::Array(before.lines().map(|l| Value::String(l.to_owned())).collect());
    let after_value = Value::Array(after.lines().map(|l| Value::String(l.to_owned())).collect());
    redacted_json_diff(&before_value, &after_value)
}

fn summarize_bytes(bytes: &[u8]) -> String {
    format!("<{} bytes>", bytes.len())
}

fn diff_values(path: &str, before: &Value, after: &Value, out: &mut Vec<JsonDiffEntry>) {
    if before == after {
        return;
    }

    match (before, after) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = join_path(path, key);
                match (left.get(key), right.get(key)) {
                    (Some(l), Some(r)) => diff_values(&child, l, r, out),
                    (None, Some(r)) => push_added(&child, key, r, out),
                    (Some(l), None) => push_removed(&child, key, l, out),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            let len = left.len().max(right.len());
            for index in 0..len {
                let child = format!("{path}[{index}]");
                match (left.get(index), right.get(index)) {
                    (Some(l), Some(r)) => diff_values(&child, l, r, out),
                    (None, Some(r)) => push_added(&child, "", r, out),
                    (Some(l), None) => push_removed(&child, "", l, out),
                    (None, None) => {}
                }
            }
        }
        _ => {
            let leaf_key = path.rsplit(['.', '[']).next().unwrap_or("");
            let leaf_key = leaf_key.trim_end_matches(']');
            out.push(JsonDiffEntry {
                path: if path.is_empty() {
                    "<root>".to_owned()
                } else {
                    path.to_owned()
                },
                kind: JsonDiffKind::Changed,
                before: Some(display_value(leaf_key, before)),
                after: Some(display_value(leaf_key, after)),
            });
        }
    }
}

fn push_added(path: &str, key: &str, value: &Value, out: &mut Vec<JsonDiffEntry>) {
    let leaf_key = if key.is_empty() {
        path_leaf_key(path)
    } else {
        key
    };
    out.push(JsonDiffEntry {
        path: path.to_owned(),
        kind: JsonDiffKind::Added,
        before: None,
        after: Some(display_value(leaf_key, value)),
    });
}

fn push_removed(path: &str, key: &str, value: &Value, out: &mut Vec<JsonDiffEntry>) {
    let leaf_key = if key.is_empty() {
        path_leaf_key(path)
    } else {
        key
    };
    out.push(JsonDiffEntry {
        path: path.to_owned(),
        kind: JsonDiffKind::Removed,
        before: Some(display_value(leaf_key, value)),
        after: None,
    });
}

fn path_leaf_key(path: &str) -> &str {
    let leaf = path.rsplit(['.', '[']).next().unwrap_or("");
    leaf.trim_end_matches(']')
}

fn join_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_owned()
    } else {
        format!("{parent}.{key}")
    }
}

fn is_secret_key(key: &str) -> bool {
    matches!(
        key,
        "password"
            | "passwd"
            | "privateKey"
            | "private_key"
            | "secretKey"
            | "secret"
            | "id"
            | "encryption"
            | "decryption"
            | "auth"
            | "token"
            | "apiKey"
            | "accessToken"
    )
}

fn display_value(key: &str, value: &Value) -> String {
    if is_secret_key(key) {
        return match value {
            Value::Null => "null".to_owned(),
            Value::String(s) if s.is_empty() => "\"\"".to_owned(),
            Value::String(_) | Value::Number(_) | Value::Bool(_) => "[REDACTED]".to_owned(),
            Value::Array(_) | Value::Object(_) => redact_value(value).to_string(),
        };
    }
    match value {
        Value::Object(map) => {
            let redacted: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| {
                    if is_secret_key(k) {
                        (k.clone(), Value::String("[REDACTED]".to_owned()))
                    } else {
                        (k.clone(), redact_value(v))
                    }
                })
                .collect();
            Value::Object(redacted).to_string()
        }
        Value::Array(items) => {
            // Arrays of clients: redact each element's secret fields.
            let redacted: Vec<Value> = items.iter().map(redact_value).collect();
            Value::Array(redacted).to_string()
        }
        other => compact_scalar(other),
    }
}

fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if is_secret_key(k) {
                    out.insert(k.clone(), Value::String("[REDACTED]".to_owned()));
                } else {
                    out.insert(k.clone(), redact_value(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        other => other.clone(),
    }
}

fn compact_scalar(value: &Value) -> String {
    match value {
        Value::String(s) if s.len() > 120 => format!("\"{}…\"", &s[..117]),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_email_change_and_redacts_password() {
        let before = json!({
            "inbounds": [{
                "settings": {
                    "clients": [{
                        "email": "a@example.com",
                        "password": "secret-one",
                        "id": "11111111-1111-1111-1111-111111111111"
                    }]
                }
            }]
        });
        let after = json!({
            "inbounds": [{
                "settings": {
                    "clients": [{
                        "email": "b@example.com",
                        "password": "secret-two",
                        "id": "22222222-2222-2222-2222-222222222222"
                    }]
                }
            }]
        });
        let diff = redacted_json_diff(&before, &after);
        let email = diff
            .iter()
            .find(|e| e.path.ends_with("email"))
            .expect("email change");
        assert_eq!(email.kind, JsonDiffKind::Changed);
        assert_eq!(email.before.as_deref(), Some("\"a@example.com\""));
        assert_eq!(email.after.as_deref(), Some("\"b@example.com\""));

        let password = diff
            .iter()
            .find(|e| e.path.ends_with("password"))
            .expect("password change");
        assert_eq!(password.before.as_deref(), Some("[REDACTED]"));
        assert_eq!(password.after.as_deref(), Some("[REDACTED]"));
        let joined = format!("{diff:?}");
        assert!(!joined.contains("secret-one"));
        assert!(!joined.contains("secret-two"));
        assert!(!joined.contains("11111111"));
    }

    #[test]
    fn detects_added_and_removed() {
        let before = json!({"tag": "old"});
        let after = json!({"port": 443});
        let diff = redacted_json_diff(&before, &after);
        assert!(diff.iter().any(|e| e.kind == JsonDiffKind::Removed));
        assert!(diff.iter().any(|e| e.kind == JsonDiffKind::Added));
    }

    #[test]
    fn identical_yields_empty() {
        let value = json!({"a": 1});
        assert!(redacted_json_diff(&value, &value).is_empty());
    }

    #[test]
    fn line_diff_detects_changed_and_added_lines() {
        let before = "User=nobody\nExecStart=/usr/local/bin/xray run -config /etc/xray/config.json";
        let after = "User=root\nExecStart=/usr/local/bin/xray run -config /etc/xray/config.json\nGroup=root";
        let diff = redacted_json_diff_lines(before, after);
        let changed = diff
            .iter()
            .find(|e| e.path == "[0]")
            .expect("line 0 changed");
        assert_eq!(changed.kind, JsonDiffKind::Changed);
        assert_eq!(changed.before.as_deref(), Some("\"User=nobody\""));
        assert_eq!(changed.after.as_deref(), Some("\"User=root\""));
        let added = diff
            .iter()
            .find(|e| e.path == "[2]")
            .expect("line 2 added");
        assert_eq!(added.kind, JsonDiffKind::Added);
    }

    #[test]
    fn line_diff_identical_yields_empty() {
        let body = "[Unit]\nDescription=Xray Service\n";
        assert!(redacted_json_diff_lines(body, body).is_empty());
    }
}
