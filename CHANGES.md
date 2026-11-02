# Changelog

All notable changes to Mina are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] — 0.3.0-dev

### Fixed

- **Relative paths are resolved in the user's working directory** (#3) —
  `cat ./debian_version` after `cd /etc` was looked up relative to the
  working directory of `mina session-close`, not the user's shell, so the
  file was missed, or a file with the same name elsewhere was captured.
  The shell hook now records the directory each command started in, and
  relative candidates (`./x`, `../x`, `a/b`) are resolved against it.
  Candidate paths are also normalised (`.` and `..` removed) before the
  `skip_paths` check and before mirroring under `files/`.
- **bash hook no longer logs commands that were not run** (#2) — the
  first prompt logged the last line of the previous session's
  `~/.bash_history`, and an empty line or Ctrl-C logged the previous
  command again. The hook now logs only when the last history entry
  changed since the previous prompt. With `HISTCONTROL=ignoredups` or
  `ignorespace`, commands that add no history entry are not logged; with
  history disabled, nothing is. zsh is unaffected.
- **Only login services open a session** (#4) — with the PAM lines in a
  stack shared by every service (Debian's `common-session`), cron jobs,
  `su`, `sudo`, `runuser` and `systemd --user` each opened a mina session:
  a bundle without source IP every hour, and a `.session` file for
  `systemd --user` that was never removed. `session-open` and
  `session-close` now do nothing unless `PAM_SERVICE` is in the new
  `[session] pam_services` list in `/etc/mina.toml` (default
  `["sshd", "login"]`: SSH and the local console). A missing or unreadable
  config uses the default; a missing `PAM_SERVICE` opens no session.
- **`su -` / `sudo -i` shells log into the enclosing login session** (#4)
  — the shell hook looked for the session only on its parent and
  grandparent, and read the grandparent from `/proc/<pid>/stat` in a way
  that broke on process names with spaces. It now walks up the process
  tree (at most 16 levels, stopping at PID 1) to the nearest ancestor with
  a session. A nested shell that cannot write the session's command log
  (`su - otheruser`) logs nothing instead of printing an error.
- **Accurate `files_skipped` in `session.json`** (#6) — paths under
  `skip_paths` and directories (e.g. after `ls /tmp/mina-staging/`) were
  listed as `"not found or not a file"`. They were never meant to be
  captured and are no longer listed. What remains has an accurate
  reason: `not found`, `too large (…)`, `binary file`, or
  `read error: …` (now also for a path that cannot be looked at, e.g.
  permission denied, which used to count as not found).
- **`commands.log` ends with a newline** (#6) — the last line had none.
- **Sessions starting in the same second no longer overwrite each other**
  (#5) — two sessions of the same user that started in the same second
  got the same bundle name: the second wrote over the first one's files,
  and the local transport then failed to move it into the nest, leaving a
  `.tmp_*` directory behind. The second bundle is now named
  `{YYYY-MM-DD_HH-MM-SS}_{user}_2` (then `_3`, …), both when it is
  assembled and when the local transport finds the name already taken in
  the nest. The local transport also removes its `.tmp_*` directory when
  shipping fails.

### Changed

- **Shell hook log format** (`/run/mina/<key>.cmds`) is now
  `<unix_timestamp_ms>\t<cwd>\t<command>`. Lines in the old
  `<unix_timestamp_ms>\t<command>` format (hook installed by mina <= 0.2,
  or a session still running across the upgrade) are still read, but
  relative paths in them are dropped instead of guessed. Re-run
  `mina install-pam` to update `/etc/profile.d/mina.sh`.
- **`commands.log` lines carry a full date** (#6) — each line is now
  `<timestamp>\t<command>` with an ISO-8601 UTC timestamp
  (`2026-10-30T14:03:46Z`) instead of a time of day (`14:03:46`) in no
  stated time zone, which was ambiguous for sessions crossing midnight.
  Scripts that grep or parse `HH:MM:SS` at the start of a line need
  adjusting. A line break inside a command is written as `\n`, so each
  line stays one command.

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

