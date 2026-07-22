# Feldjaeger

Feldjaeger is a local desktop control panel for managing remote Xray servers over SSH without exposing an admin web interface.

## Application logging

Feldjäger uses the Rust `tracing` ecosystem (`tracing`, `tracing-subscriber`, `tracing-appender`) for structured application diagnostics.

### Log location

| Platform | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\Feldjaeger\logs\feldjaeger.log` |
| Linux | `~/.local/share/feldjaeger/logs/feldjaeger.log` |
| macOS | `~/Library/Application Support/Feldjaeger/logs/feldjaeger.log` |

If the primary path cannot be created, Feldjäger falls back to:

1. stderr and `feldjaeger.log` next to the executable
2. stderr only

Rotation is not implemented yet.

### Format

```text
2026-01-01 12:00:00 INFO ssh Connected to server
```

Each line contains a local timestamp, level, module target, and message.

### Levels

- `ERROR` — unrecoverable problems that block an operation
- `WARN` — recoverable problems
- `INFO` — normal application operations (default)
- `DEBUG` — diagnostic detail (enable with `RUST_LOG=debug`)

### Security

Logs must never contain SSH passwords, private key contents, passphrases, authentication tokens, VLESS UUIDs, Xray JSON payloads, or raw remote stdout/stderr.

### Scope

This covers Feldjäger application logs only. Xray runtime logs and the in-app Logs page viewer are out of scope for the current stage.
