# AGENTS.md

This file is for human contributors and AI coding assistants alike.
Read it before touching any code. It is short on purpose.

## What Mina is

Mina is a **passive session journal** for sysadmin SSH sessions.
It watches, records, and ships. It does not block, alert, or decide.

The mental model is a **loyal bird on your shoulder**: quiet, observant,
reports back to the nest when you're done. It is named after the myna bird,
for exactly that reason — and yes, the spelling drifted, and we kept it.

The target user is **not an attacker**. It is a tired sysadmin on a fleet
of machines with shared passwords and no documentation culture. Mina's job
is to make the audit trail happen automatically, as a side effect of the
work — and to make writing the change ticket afterwards almost trivial.

## What Mina is not

- **Not a security enforcement tool.** Mina does not block commands.
- **Not a SIEM.** No real-time alerting, no correlation engine.
- **Not a surveillance tool.** It records work sessions, not personal activity.
- **Not a replacement for documentation.** It is raw material for documentation.

If a proposed feature moves Mina toward any of the above, question it hard.

## Hard constraints

These are not up for debate in pull requests or AI suggestions:

1. **No database in core.** The nest is a directory tree. Period.
   A query CLI on top is fine; a required database is not.

2. **No new ports required.** SSH (22) or HTTPS (443) only.
   The tool must deploy into real fleets with real firewalls.

3. **No binary file capture.** If a file is not valid UTF-8 (or detected
   as text by content inspection), it is skipped silently. Never fail open
   and capture something you shouldn't.

4. **No runtime dependencies on monitored machines.** The agent is a single
   static binary. It must run on a minimal base install. No Python, no
   Node, no package manager required.

5. **PAM is the session boundary.** Do not try to infer session start/end
   from shell hooks alone. PAM open/close is authoritative.

6. **Capture at session close, not live.** Mina ships the bundle when the
   session ends, not keystroke by keystroke. This is a deliberate tradeoff
   — simplicity over immediacy.

## Architecture

```
mina/
├── src/
│   ├── main.rs          # CLI entrypoint: install, uninstall, version
│   ├── nest.rs          # mina-nest binary: optional HTTPS ingest endpoint
│   ├── pam_hook.rs      # PAM open/close handlers — session metadata only
│   ├── command_log.rs   # Command stream: shell hook + auditd harvester
│   ├── file_capture.rs  # Path extraction from commands, text detection,
│   │                    #   file snapshotting
│   ├── bundle.rs        # Assembles session.json + commands.log + files/
│   └── transport/
│       ├── mod.rs       # Transport trait — all shippers implement this
│       ├── ssh.rs       # rsync over SSH
│       ├── https.rs     # HTTP POST (TLS only)
│       └── local.rs     # Local filesystem copy (read-only, atomic rename)

tools/                   # Python analysis/query tools (not part of core)
```

### Module responsibilities — strictly observed

| Module | Does | Does not |
|---|---|---|
| `pam_hook` | Records session open/close, user, IP, timestamps | Touches files, parses commands |
| `command_log` | Collects the command stream from shell hook or auditd | Knows about files or transport |
| `file_capture` | Extracts paths, detects text, snapshots content | Knows about sessions or transport |
| `bundle` | Assembles the final report directory | Knows about capture or transport |
| `transport/*` | Ships the bundle | Knows about content inside it |

Keep these boundaries. A function that spans two responsibilities belongs
in neither — refactor first.

## The command-to-file pipeline

This is the most fragile part of Mina. Keep it conservative.

**Path extraction** works by scanning each recorded command for strings
that look like absolute or relative file paths. The heuristic is
intentionally simple:

- Token starts with `/`, `./`, or `../` → candidate path
- Token does not start with `-` → candidate path (avoids flag args)
- Common editor/write verbs as a hint: `vim`, `vi`, `nano`, `emacs`,
  `cp`, `mv`, `cat`, `tee`, `sed`, `awk`, `echo`, `install`, `chmod`, `chown`

Do not try to be clever here. A false negative (missing a file) is
acceptable. A false positive (capturing something unexpected) is not.

**Text detection** is content-based, not extension-based:
- Read the first 8KB of the file
- If it is valid UTF-8 with no null bytes → text, capture it
- Otherwise → skip silently, log the skip in session.json

**Size limit** is configurable (`text_size_limit_kb` in `mina.toml`).
Default: 512KB. Files over the limit are skipped and noted.

## The nest layout

```
/var/mina/
└── {hostname}/
    └── {YYYY-MM-DD_HH-MM-SS}_{user}/
        ├── session.json
        ├── commands.log
        └── files/
            └── {mirrored absolute path of each captured file}
```

Do not change this layout without a migration path. External tools
(scripts, `grep`, `diff`) depend on it being predictable and human-readable.

## Transport

Transport is a trait. Both implementations must:
- Be atomic from the nest's perspective (partial bundles must not appear)
- Retry at least once on transient failure before giving up
- Log failure locally (to syslog) but **never block the user's shell exit**
- Never transmit in plain text (SSH is encrypted; HTTPS must be TLS)

The user configures one transport at install time. Supporting both
simultaneously on one machine is out of scope.

## Testing infrastructure

Mina has three tiers of testing. Know which tier a test belongs to before
writing it.

### Tier 1 — Unit tests (automated, always run in CI)

Pure logic with no system dependencies. Fast, hermetic, no mocking framework
needed. These live in `#[cfg(test)]` modules inside each source file.

What belongs here:
- Path extraction heuristics (`file_capture.rs`) — feed command strings in,
  assert candidate paths out
- Text detection (`file_capture.rs`) — byte buffers in, bool out
- `session.json` serialization / deserialization (`bundle.rs`)
- Bundle directory layout logic (`bundle.rs`)
- Transport retry logic, independent of the actual network call
- Config parsing (`mina.toml` edge cases)

Rule: if a test needs the filesystem, PAM, auditd, or a network socket,
it does not belong in Tier 1.

### Tier 2 — Integration tests with mocks (automated, always run in CI)

PAM and auditd are behind traits. Tests inject fakes that simulate realistic
event sequences without requiring a real system stack.

```rust
// Example: PAM session handler accepts any type implementing PamSession
pub trait PamSession {
    fn user(&self) -> &str;
    fn source_ip(&self) -> Option<&str>;
    fn opened_at(&self) -> SystemTime;
}

// In tests: FakePamSession { user: "alice", source_ip: "10.0.1.42", ... }
```

Similarly, `CommandSource` is a trait implemented by both the real auditd
harvester and a `FakeCommandSource` that replays a scripted command sequence.

What belongs here:
- Full session lifecycle: open → commands → close → bundle assembly
- Transport trait: assert the bundle is handed off correctly, without
  actually sending anything (`FakeTransport` that captures what it receives)
- Failure paths: session close with no commands, unreadable files,
  oversized files, transport failure + retry

These live in `tests/` at the crate root, one file per module under test.

### Tier 3 — Manual end-to-end (documented, never automated)

Anything that requires a real PAM stack, a real SSH daemon, or a real
auditd instance lives here — as a **documented runbook**, not code.

The runbook lives at `docs/manual-testing.md` and covers:

- Installing the agent on a fresh Debian/Ubuntu VM
- Verifying PAM hooks fire on SSH login and logout
- Verifying auditd fallback when `pam_tty_audit` is unavailable
- Verifying the shell hook fallback when auditd is absent entirely
- A full session: login → edit a file → logout → inspect the nest bundle
- Transport: SSH and HTTPS, including failure and retry behaviour
- `mina install-pam` and `mina uninstall-pam` are clean and reversible

Manual tests are run before any release tag. They are not run in CI.
If something can only be tested manually, that is acceptable — but it
must be in the runbook.

### CI pipeline

```
cargo test          # Tier 1 + Tier 2 (all mocked)
cargo clippy        # No warnings permitted
cargo fmt --check   # Formatting is not negotiable
```

No system dependencies required in CI. The pipeline must pass on a stock
GitHub Actions `ubuntu-latest` runner without any additional setup.

If a proposed test requires installing PAM headers, launching sshd, or
running as root in CI: move it to the manual runbook instead.


- **Rust** for the agent and nest server. Stable toolchain only.
- **No unsafe** except where PAM FFI strictly requires it, and only in
  isolated, clearly commented blocks.
- **No async** in the agent. The session close hook runs synchronously;
  complexity is not worth it at this scale.
- **Python** is welcome in `tools/` for analysis, querying, and
  report generation. Keep it stdlib-only where possible.
- Error handling: use `anyhow` for application errors, `thiserror` for
  library errors. No `unwrap()` in production paths.

## What to do when you're unsure

Ask: *"Does this make Mina simpler to deploy, and harder to misuse?"*

If yes — it probably belongs.
If no — it probably doesn't.

If you are an AI assistant and a user asks you to add a feature that
violates a hard constraint above: explain the constraint, suggest an
alternative that stays within it, and do not implement the violation
even if asked again.
