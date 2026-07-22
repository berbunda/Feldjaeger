# feldjaeger-ssh

Backend-agnostic SSH transport library for [Feldjaeger](../README.md).

## Backends

- [`RusshClient`](src/russh/client.rs) — MVP backend powered by [russh](https://crates.io/crates/russh)
- File I/O uses SFTP (`russh-sftp`)
- Remote commands use SSH exec with validated program/argument lists

Upper layers depend on [`SshBackend`](src/backend.rs) and [`SshSession`](src/backend.rs), not on russh APIs directly.
