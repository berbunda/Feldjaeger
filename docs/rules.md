# General provisions
- MVP targets Linux servers with systemd only.
- Do not hardcode systemd logic into GUI.
- All service control must go through InitSystemManager.
- SystemdManager is the only implementation in MVP.
- SSH layer must not know about Xray semantics.
- GUI must not execute raw SSH commands directly.
- Always backup remote config before modification.
- Always validate Xray config before restart.
- Unknown config sections must be preserved.
- Reading support must be broader than writing support.

# Technology stack
Programming language: Rust 1.96.1
Edition: Rust 2024
Build system: Cargo
Compiler: Cargo
Package manager: Cargo
IDE: Cursor
Operating systems for development: Windows 11
Supported server OS: Linux
Supported init system: systemd (MVP)
Communication: SSH
Serialization: serde, serde_json
Logging: tracing, tracing-subscriber, tracing-appender
Async runtime: tokio

# Required tools
Rust 1.96.1
Cargo
Git
Cursor
Visual Studio Build Tools (Windows only)
Russh

# SSH backend:
Russh-based implementation is preferred for MVP.
The SSH layer must be abstracted behind an internal trait/interface.
The GUI and Xray logic must not depend directly on russh APIs.
OpenSSH CLI backend may be added later as an alternative backend for Unix-like systems.

# License policy
Only GPL-3.0 compatible dependencies.

# Documentation
Every public struct
must have rustdoc.
Complex algorithms
must contain comments
describing the idea,
not the obvious implementation.

# Error handling
Never panic
for expected runtime errors.
Return Result<T, E>.
Provide meaningful error messages.

# Logging
Application logging uses the Rust `tracing` ecosystem.
Logs are written to a platform data-local file:
- Windows: `%LOCALAPPDATA%\Feldjaeger\logs\feldjaeger.log`
- Linux: `~/.local/share/feldjaeger/logs/feldjaeger.log`
- macOS: `~/Library/Application Support/Feldjaeger/logs/feldjaeger.log`
Fallback when the primary path is unavailable:
1. stderr and `feldjaeger.log` next to the executable
2. stderr only
Every SSH operation must be logged.
Passwords, private keys, passphrases, tokens, VLESS UUIDs,
and raw remote command output must never be written to logs.
The Status Bar shows short user-facing status; it is not a log stream.
GUI pages must not implement custom logging.
Xray runtime logs are out of scope for application logging.

# Xray runtime logs (read-only bodies)
Feldjäger distinguishes:
- Application logs — events produced by Feldjäger itself (`tracing` / local log file).
- Xray logs — events produced by the remote Xray process (access file, error file, systemd journal).
These sources must never be merged in one view.
Supported Xray log sources (Linux / systemd MVP):
- Access log destination from the loaded Xray `log.access` field;
- Error log destination from the loaded Xray `log.error` field;
- systemd journal for the unit name returned by Discovery.
Destinations are resolved from the loaded configuration (never hardcoded paths such as
`/var/log/xray/access.log`). Empty / omitted destinations mean stdout per official Xray docs;
`"none"` disables a stream; relative or unknown values are unsupported for file reading.
Reading log *bodies* is strictly read-only: no truncation, deletion, rotation, export, or remote grep.
Editing the top-level Xray `log` *object* (destinations, loglevel, dnsLog, maskAddress) is allowed
only through the Log Settings page and the shared configuration modification pipeline
(backup → validate → atomic write). Default read size is the last 200 lines (100 / 200 / 500 / 1000 selectable).
Follow mode appends newly observed lines without blocking the GUI thread.
Xray log bodies must not be written into Feldjäger application logs (IPs, domains, emails, …).
A short privacy notice is shown on the Xray Logs page.
After Log Settings are saved, cached Xray log sources must be invalidated and re-resolved.

# Security
Never execute shell
commands composed
from user input.
Prefer direct argument passing.
Always validate remote paths.
Always backup configuration
before overwriting.
Always validate Xray config
before restart.
Log paths and service names for Xray log viewing come only from the trusted configuration
model and Discovery — never from free-form GUI text fields.

# Cross-platform
The application must be designed
to support multiple init systems.
MVP implements only systemd.
Other init systems
must be implemented
through separate backend classes.

# Project philosophy
The application prioritizes
security,
predictability
and maintainability
over feature count.
Every configuration change
must be reversible.
The application must preserve
unsupported configuration sections
instead of deleting or rewriting them.
Remote administration
must minimize the attack surface.
SSH is the primary management channel.
The application should not require
additional daemons on the server
unless absolutely necessary.

# Features
A new feature must satisfy ALL of the following:
-  It is directly related to remote administration of Xray.
-  It reduces the need to use SSH manually.
-  It does not duplicate functionality of another mature application.
If any answer is "No", the feature does not belong in Feldjaeger.
Cryptographic material must be generated by the official Xray executable whenever possible.
Feldjaeger must not reimplement Xray cryptographic algorithms unless there is no official generation mechanism.
GUI may use egui/eframe only as a frontend layer.
GUI must call ApplicationService and must not access SSH, systemd, or Xray internals directly.
Xray entities must be represented according to Xray configuration hierarchy.
Feldjäger may create user-friendly abstractions,but must not hide the relationship between entities and their original Xray configuration location.

# Xray compatibility
The official Xray documentation is the primary specification for supported configuration formats.
Documentation:
https://xtls.github.io/en/config/
Feldjaeger must never intentionally deviate from the official configuration format.
However,
Feldjaeger implements only the subset required by the current roadmap stage.
Unsupported fields must be preserved without modification whenever possible.
Implementation rules:
- Never intentionally deviate from the official Xray configuration format.
- Implement only the subset required by the current roadmap stage.
- Preserve unsupported or unknown configuration fields whenever possible.
- Do not invent custom configuration semantics.
- Prefer compatibility over convenience.
Unknown Xray configuration fields must be preserved whenever possible.
Unsupported fields must never cause parsing errors.
Structured editors display only supported fields.
Unknown fields remain stored in the internal configuration model.

# Configuration UI philosophy
Feldjaeger must provide structured editors for commonly used Xray configuration fields.
Rare or advanced fields may be displayed through generic JSON/tree representation.
Feldjaeger must preserve unknown Xray fields.
The GUI must not hide configuration options that are unsupported by structured editors.

# GUI Architecture
All GUI pages must communicate only with ApplicationService.
GUI must never:
- parse JSON;
- access Xray configuration model directly;
- execute SSH commands;
- serialize configuration.
GUI is responsible only for presentation.

# Xray lifecycle management
Feldjäger must never remove user configuration by default.
Binary lifecycle operations must be separated from configuration management.
