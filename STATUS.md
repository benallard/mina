# Mina — Project Status

> Last audited: 2026-06-10  
> Completion estimate: ~50 %  
> Auditor: GitHub Copilot / initial weekend-project review

This file tracks what is done, what is stubbed, and what needs to be built.
Update it as work lands. Keep it honest — a wrong STATUS.md is worse than none.

---

## Component inventory

| # | Component | File(s) | State | Notes |
|---|---|---|---|---|
| 1 | Session metadata model | `src/pam_hook.rs` | ✅ Done | Trait-based, 3 unit tests |
| 2 | Shell hook command reader | `src/command_log.rs` | ✅ Done | Parser + file reader, 3 unit tests |
| 3 | Path extraction heuristic | `src/file_capture.rs` | ✅ Done | Conservative, 5 unit tests |
| 4 | Text detection + snapshotting | `src/file_capture.rs` | ✅ Done | Binary/size/exclusion handling, 3 tests |
| 5 | Bundle assembly | `src/bundle.rs` | ✅ Done | Writes session.json + commands.log + files/, 4 tests |
| 6 | Config parsing | `src/config.rs` | ✅ Done | TOML loading with sane defaults, 2 tests |
| 7 | Transport trait + FakeTransport | `src/transport/mod.rs` | ✅ Done | Ready for integration tests |
| 8 | SSH/rsync transport | `src/transport/ssh.rs` | 🟡 Partial | Works, retry in `ship_with_retry` (main.rs); no syslog yet |
| 9 | Shell hook script | `mina.sh.profile` | ✅ Done | Bash + zsh, ms timestamps, safe PROMPT_COMMAND chaining |
| 10 | CLI entry point (subcommands) | `src/main.rs` | ✅ Done | clap wired; session-open + session-close implemented (Step 2) |
| 11 | Session state persistence | `src/pam_hook.rs`, `src/main.rs` | ✅ Done | `SessionState` save/load/remove; keyed on sshd PPID |
| 12 | `session-close` orchestration | `src/main.rs` | ✅ Done | Full pipeline: commands → paths → snapshot → bundle → ship (retry once) → cleanup |
| 13 | `install-pam` / `uninstall-pam` | *(missing)* | ❌ Missing | pam_exec + profile.d + tmpfiles.d |
| 14 | HTTPS transport | `src/transport/https.rs` | ❌ Stub | `bail!("not yet implemented")` |
| 15 | Nest ingest server | `src/nest.rs` | ❌ Stub | `println!("not yet implemented")` |
| 16 | Auditd source | `src/command_log.rs` | ❌ Stub | `bail!("not yet implemented")` |
| 17 | Tier 2 integration tests | `tests/` | ❌ Missing | Directory does not exist |
| 18 | Config validation | `src/config.rs` | ❌ Missing | No TLS enforcement, no cross-field checks |

---

## Known quality issues (not blockers, but should be fixed)

| ID | Where | Issue |
|----|---|---|
| Q1 | `file_capture.rs` | `is_text_file` reads the **entire file** into memory, then only inspects the first 8 KB. Should open + read exactly 8 KB. |
| Q2 | `bundle.rs` | `commands.log` timestamps are **time-only** (`%H:%M:%S`). Multi-day sessions lose the date. Use full ISO-8601. |
| Q3 | `command_log.rs` | `FakeCommandSource` is private inside `#[cfg(test)]` — cannot be reused in `tests/`. Export via `#[cfg(any(test, feature="testing"))]` or similar. |
| Q4 | `file_capture.rs` | `snapshot` returns `SkipReason::NotFound` for **excluded** paths. Should be a dedicated `SkipReason::Excluded` for accurate `session.json` reporting. |
| Q5 | `config.rs` | ~~`staging_dir` has no default/constant.~~ ✅ Fixed — `staging_dir` field added to `Config` with default `/tmp/mina-staging`. |
| Q6 | `pam_hook.rs` | ~~`EnvPamSession` does not capture the **session PID**.~~ ✅ Fixed — PID comes from the state file written at `session-open`. |
| Q7 | `transport/ssh.rs` | ~~No **retry** on rsync failure.~~ ✅ Fixed — `ship_with_retry` in `main.rs` retries once (AGENTS.md satisfied). |
| Q8 | `transport/*.rs` | Neither transport logs to **syslog** on failure (AGENTS.md requirement). |
| Q9 | `config.rs` | `https_endpoint` is not validated for `https://` scheme at load time. |

---

## Roadmap

Work items in priority order. Check them off as they land.

- [x] **Step 1** — Add `clap` to `Cargo.toml`; wire all subcommands in `main.rs`
  (`install-pam`, `uninstall-pam`, `install-audit`, `session-open`, `session-close`, `version`)
- [x] **Step 2** — Session state file: write on `session-open`, read on `session-close`
  (`SessionState` in `pam_hook.rs`; session key = sshd child PPID; shell hook uses `$PPID`)
- [x] **Step 3** — `session-close` orchestration: load state → read commands → extract paths → snapshot → bundle → ship (with retry) → cleanup
- [ ] **Step 4** — `install-pam` / `uninstall-pam`: pam_exec entries, profile.d deploy, tmpfiles.d entry
- [ ] **Step 5** — Syslog-on-failure for all transports (retry already done in Step 3)
- [ ] **Step 6** — Create `tests/` with Tier 2 integration tests (full lifecycle, FakePam + FakeCommandSource)
- [ ] **Step 7** — Fix Q1–Q6 quality issues (is_text_file, timestamps, FakeCommandSource, SkipReason, staging_dir, session PID)
- [ ] **Step 8** — `Config::validate()` — TLS scheme enforcement, cross-field checks (Q9)
- [ ] **Step 9** — `HttpsTransport`: tarball creation + ureq/curl POST
- [ ] **Step 10** — `src/nest.rs`: minimal HTTP ingest server (TLS terminated by reverse proxy)
- [ ] **Step 11** — `AuditdSource`: `ausearch` integration
- [ ] **Step 12** — Pre-release: run manual testing runbook (`docs/manual-testing.md`), tag `v0.1.0`

---

## Hard constraints reminder (from AGENTS.md)

1. No database in core — nest is a directory tree
2. No new ports — SSH (22) or HTTPS (443) only
3. No binary file capture — skip silently, never fail open
4. No runtime deps on monitored machines — single static binary
5. PAM is the session boundary — not shell hooks alone
6. Capture at session close — not keystroke by keystroke


