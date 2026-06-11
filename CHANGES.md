# Changelog

All notable changes to Mina are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] — 0.2.0-dev

_Nothing yet._

---

## [0.1.0] — 2026-06-11

First tagged release. The core record-and-ship pipeline is complete.

### Added

- **Session lifecycle** — PAM `session-open` and `session-close` hooks
  record session metadata (user, source IP, hostname, timestamps) and
  persist state across the two separate PAM process invocations via
  `/run/mina/<ppid>.session`.
- **Command capture** — shell hook (`mina.sh.profile`) records every
  command with a millisecond timestamp into `/run/mina/<ppid>.cmds`.
  Supports bash and zsh.
- **File snapshotting** — paths extracted from commands are inspected
  (content-based text detection, 8 KB probe, configurable size limit
  and skip-path list) and snapshotted at session close.
- **Bundle assembly** — each session produces a directory containing
  `session.json`, `commands.log`, and a `files/` tree mirroring the
  absolute paths of captured files.
- **Transports** — three shipping backends:
  - `ssh` — rsync over SSH (pre-deployed key, `rsync`-restricted)
  - `local` — atomic copy + read-only rename into a local nest directory
  - `https` — stub, reserved for a future release
- **Retry** — all transports are retried once on transient failure;
  failure is logged but never blocks the user's shell exit.
- **`install-pam`** — single command that writes the `pam_exec` block
  into `/etc/pam.d/sshd` (guarded, idempotent), deploys the shell hook
  to `/etc/profile.d/mina.sh`, writes `/usr/lib/tmpfiles.d/mina.conf`,
  and bootstraps `/etc/mina.toml` from the bundled example.
- **`uninstall-pam`** — fully reverses `install-pam`; preserves
  `/etc/mina.toml` and all nest data.
- **Configuration** — TOML config at `/etc/mina.toml` with sane
  defaults for all optional fields.
- **CI** — `cargo test`, `cargo clippy`, `cargo fmt --check` on every
  push; rolling `dev` binary release (static musl) published to GitHub
  Releases on every main-branch push.

### Not yet in this release

- HTTPS transport implementation (`src/transport/https.rs` is a stub)
- `mina-nest` ingest server (`src/nest.rs` is a stub)
- Auditd command source (`AuditdSource` is a stub)
- `install-audit` subcommand
- Tier 2 integration tests (`tests/` directory)
- Syslog-on-failure for transports

See `STATUS.md` for the full roadmap.

