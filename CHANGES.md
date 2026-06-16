# Changelog

All notable changes to Mina are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] — 0.3.0-dev

_Nothing yet._

---

## [0.2.0] — 2026-06-16

### Fixed

- **`PAM_TYPE` guard in `session-open` / `session-close`** — `pam_exec`
  invokes every session module for *both* the open and close phases of a PAM
  session. Without a guard, `mina session-close` fired at login time (open
  phase), immediately consumed the `.session` file written by
  `mina session-open`, and deleted it before the user's shell started. The
  result was that `/run/mina` appeared silently empty for the entire session
  even though PAM was configured correctly. Both commands now check
  `$PAM_TYPE` and return early when called in the wrong phase (`open_session`
  for `session-close`, `close_session` for `session-open`).
  See `docs/troubleshooting.md § 4d` for the full diagnosis.

- **Shell hook: grandparent PID lookup for OpenSSH privsep** (`mina.sh.profile`) —
  In modern OpenSSH with privilege separation, `pam_exec` runs in a monitor
  process that is the shell's *grandparent*, not its direct parent. The shell
  hook wrote `$PPID.cmds`, but `mina session-open` recorded the monitor's PID
  as the session key. The two never matched, so every bundle shipped with an
  empty command log. The hook now reads `/proc/$PPID/stat` (one read, no loop)
  to get the grandparent PID, then tries both `$PPID` and the grandparent as
  candidate session keys, taking whichever has a matching `.session` file.

- **Shell hook: `exit 0` → `return 0`** (`mina.sh.profile`) — The hook is a
  sourced `/etc/profile.d/` script. Using `exit` instead of `return` would
  terminate the user's login shell if `/run/mina` was absent. Fixed to
  `return 0`.

- **Auto-skip mina's own directories at capture time** (`main.rs`) — When
  using local transport, browsing the nest directory during a session caused
  mina to snapshot its own previous bundles into the new one. Mina now
  automatically adds `local_destination`, `staging_dir`, and `/run/mina` to
  the effective skip list at pipeline time, regardless of what `skip_paths` is
  set to in the config. No user action required.

### Changed

- **Remove unused direct dependencies `thiserror` and `tracing`** — neither
  crate is referenced in the source. `thiserror` was never used; `tracing` is
  a transitive dependency of `tracing-subscriber`, which remains. Removing
  them allows the package to build entirely from Debian's `librust-*-dev`
  packages without network access.
  (patch by Benoît Allard)

### Documentation

- **`docs/troubleshooting.md`** — new guide covering every layer of the
  stack from `/run/mina` missing through PAM hooks, `pam-auth-update`,
  `UsePAM`, the `pam_exec` dual-phase bug, the OpenSSH privsep PID mismatch,
  and the shell hook, with a quick-start symptom table and a diagnostic
  checklist.

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

