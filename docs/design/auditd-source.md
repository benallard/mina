# Design: auditd command source (#1, step 2)

Status: **approved and implemented** (2026-11-02). Tier 3 not yet run.

## Problem

The shell hook is sourced from `/etc/profile.d`, so only login shells load
it. `ssh host cmd`, scp and sftp start no login shell, and their bundles
have an empty `commands.log`. Since #1 step 1, `session.json` says so
(`"shell_hook": false`), but the commands are still missing. On one test
machine, 88 of 89 SSH bundles were like this.

The kernel audit subsystem sees every `execve`, whatever started it. This
design adds an `AuditdSource` that reads those records, limited to one
login session, and uses it for sessions in which no shell loaded the hook.

Those sessions are often the ones that change files on a server
(configuration management, deploys, scp uploads). The audit trail Mina
promises is missing exactly where it matters most.

## Goals, non-goals, anti-goals

**Goals**

- `ssh host cmd`, scp and sftp sessions get the programs they ran in
  `commands.log`, with timestamp and working directory.
- Commands run after `su`/`sudo -i` inside such a session are included.
- Every bundle says where its commands came from, and if none were
  recorded, why (`command_source`, `audit_status`).
- Hosts without auditd behave exactly as today.
- Setting it up and removing it is one command each, and leaves nothing
  behind.

**Non-goals (this step)**

- Capturing the files that scp/sftp uploads write (§5; follow-up).
- Changing what interactive sessions record: they keep the shell hook.
- Recording the effective user per command (follow-up).
- Supporting hosts where audit logs are only forwarded, not written
  locally, or rotated with compression.

**Anti-goals** (would make this a failure even if it works)

- Logins or logouts that hang or fail because of auditd or mina.
- Keystroke recording (`pam_tty_audit`) or anything else that moves Mina
  towards surveillance.
- Capturing files no one in the session meant to touch (package scripts,
  motd helpers): a false positive, which AGENTS.md rules out.
- Interactive bundles that become one line per program and lose the
  commands as typed.
- A runtime dependency on `ausearch` or any other tool on monitored hosts.
- Changing global audit settings an admin or the distribution chose.

## Constraints

From AGENTS.md (hard constraints), and from the task:

- Single static binary, no runtime dependencies; auditd is optional.
- PAM open/close is the session boundary; capture at session close, not
  live.
- No database, no new ports.
- Conservative path extraction: a missed file is acceptable, a wrong one
  is not.
- Rust stable, no `async`, no `unwrap()` in production paths, no `unsafe`.
- Module boundaries: `pam_hook` records session metadata, `command_log`
  owns the command stream and its files in `/run/mina`, `file_capture`
  knows nothing about sessions, `bundle` only assembles.
- CI: `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check` on a
  stock runner, without auditd, PAM or root.
- Public material (fixtures, docs) names no real hosts, users or
  addresses.
- Never block the user's shell exit; errors are logged, not propagated.

## Summary of the decisions

Who decided: **brief** = set by the maintainer in the task for this
design; **maintainer** = the maintainer's answer during review;
**my call** = proposed here, for review.

| Topic | Decision | Decided by |
|---|---|---|
| Source of truth | auditd exec records scoped by the audit session id (`ses=`), read from `/proc/self/sessionid` at `session-open` | brief |
| Interactive sessions | Keep the shell hook for them | brief |
| Rules | Static rules: `execve`/`execveat`, b64 + b32, `auid!=unset`, `success=1`, key `mina`. In `/etc/audit/rules.d/50-mina.rules` | my call |
| Who installs the rules | Only `mina install-audit` (opt-in); `install-pam` prints a hint. `uninstall-pam` and new `uninstall-audit` remove them | my call |
| Reading | Parse the raw audit log in Rust. No `ausearch` at runtime | my call (brief: no runtime deps) |
| Which source | Shell hook when it attached, auditd otherwise. New `command_source` field | my call |
| Window | Execs after the log position taken at session-open, up to mina's own close exec (the flush barrier), minus processes started by the PAM stack itself (motd helpers, mina) | my call |
| File capture: depth | From auditd commands only for the session's own commands: the shell and what it starts directly (depth ≤ 1), §5 | maintainer (option b) |
| Candidate flag | `CommandEntry` gets `capture_paths: bool`, set by `command_log` from the depth; not written to `commands.log` | my call |
| File capture: verbs | Only the write-verb list of AGENTS.md (13 programs), not `WRITE_VERBS` from the code. Files written by sftp-server are out of scope | my call |
| Fallback | No auditd, no rules or no session id: behave as today, and say why in `session.json` | brief (reasons: my call) |
| Packaging | `Suggests: auditd`, not `Recommends` (see the note at the end) | my call |
| `pam_tty_audit` | Dropped from `install-audit`: it records keystrokes | my call |

## Left to the builder

- Module and function names, the internal shape of the parser, and how
  the parser is split into files under `src/` (keeping the boundaries
  above).
- The exact quoting rules for rendering argv, as long as the result is
  valid POSIX shell and plain arguments stay unquoted.
- Wording of `install-audit`/`uninstall-audit` output and of the docs.
- The poll interval of the barrier wait (50 ms is a suggestion).
- Order of the commits.

## 1. Session scoping

### The audit session id

`pam_loginuid` writes the login uid to `/proc/self/loginuid`. On that
write, the kernel gives the process a new audit session id, readable at
`/proc/self/sessionid`. Every process forked afterwards inherits both, and
every audit record carries them as `auid=` and `ses=`. `ses` is a counter
that is unique per boot.

`mina session-open` is a grandchild of the process that runs the PAM stack
(pam_exec forks, then execs mina), so it inherits the session id. It reads
`/proc/self/sessionid`. The value `4294967295` (`(u32)-1`) means "unset"
and is stored as `null`.

The id is session metadata and useful even without auditd: it lets an
admin find the session in their own audit logs. So `pam_hook` reads it and
`SessionMeta` gets an `audit_session: Option<u32>` field, which also
appears in `session.json`.

### pam_loginuid runs before mina

Checked on Debian 13 (trixie) with `openssh-server`, `login`, `cron`,
`sudo` and `auditd` installed. Session lines, in order:

| Stack | pam_loginuid | mina's pam_exec |
|---|---|---|
| `/etc/pam.d/sshd` | 2nd session line, after `pam_selinux close` | the Debian package (`pam-auth-update`) puts it in `common-session`, included after `pam_loginuid`; `install-pam` appends to the end of the file. After it either way |
| `/etc/pam.d/login` | 2nd session line | after it, whether mina sits at the end of the file or in `common-session` |
| `/etc/pam.d/cron` | yes | (not a mina service) |
| `/etc/pam.d/su`, `/etc/pam.d/sudo` | **no** | (not a mina service) |

In both login stacks `pam_loginuid` comes before `@include common-session`,
so mina gets the session id wherever the packaging puts its lines. That
should stay true; the implementation adds a line to the runbook, and
`session.json` shows `audit_session: null` when it is not.

`pam_loginuid` is `required` in both stacks. In a container without
`CAP_AUDIT_CONTROL` it cannot write `/proc/self/loginuid`; it tolerates
that inside a container, and the id stays unset: fallback, see §6.
(To verify on a real container host during the Tier-3 run.)

### su, sudo, sudo -i

Neither su nor sudo calls `pam_loginuid`, so `auid` and `ses` survive
them. Commands run as root after `sudo -i` or `su -` keep the user's `ses`
and appear in the session's command stream with `uid=0 auid=<user>`. That
is what we want: the root commands belong to the login that started them.
The same holds today for the shell hook (nested login shells find the
outer `.session`).

`CommandEntry` has no field for the effective user; this design does not
add one. (A follow-up could, from `uid=` in the SYSCALL record.)

### Where the session id does not follow

Processes that systemd starts are not descendants of the session:
`systemctl restart nginx` records `systemctl`, not what nginx runs. That is
correct. `systemd-run` and `machinectl shell` likewise leave the session.

`tmux`/`screen` servers keep the `ses` of the session that started them,
also after that session closed. Commands run in a tmux attached from a
later session are recorded under the old, closed session: lost. The shell
hook already has this limitation; the runbook notes it.

Cron jobs get their own session id (`pam_loginuid` in `/etc/pam.d/cron`),
so they never mix into an SSH session.

### What else carries the session id

Other session modules after `pam_loginuid` run under the same `ses` too.
On Debian, `pam_motd` runs `run-parts /etc/update-motd.d` (→ `uname`) on
every SSH session, including non-interactive ones. The Debian package
installs mina's lines with `pam-auth-update` into `common-session`, which
`/etc/pam.d/sshd` includes *before* `pam_motd`, so these execs happen
after `mina session-open`; a window based on position alone would keep
them.

They have one thing in common: the PAM stack runs in the sshd process
whose pid is the session key, so every helper a module starts is a direct
child of it (`ppid` = session key), and so are mina's own `session-open`
and `session-close`. The user's shell is not: sshd forks a separate
process for the user, and the shell is a child of that one. So for
`PAM_SERVICE=sshd`, mina drops every exec whose process is a child of the
session key, and every exec descended from one of those (tracked through
`pid`/`ppid` of the SYSCALL records, §3 "Window").

For `login`, the shell *is* a child of the `login` process (the session
key), so this filter would drop it. It is not applied there: a console
login always starts a login shell, the hook attaches, and auditd is not
consulted (§4). For services other than sshd, only mina's own execs are
dropped.

## 2. Rules

### The rule set

`/etc/audit/rules.d/50-mina.rules`:

```
## mina: record program executions of login sessions (see mina(8)).
## Installed by `mina install-audit`, removed by `mina uninstall-audit`.
-a always,exit -F arch=b64 -S execve,execveat -F auid!=unset -F success=1 -k mina
-a always,exit -F arch=b32 -S execve,execveat -F auid!=unset -F success=1 -k mina
```

- **b64 and b32, per architecture.** Without the b32 rule, a 32-bit
  program on a 64-bit kernel escapes. But a line the kernel rejects is
  worse than a missing one: `augenrules --load` feeds all rules files to
  `auditctl -R`, which stops at the first error, so rules in files sorting
  after mina's (an admin's `99-finalize.rules` with `-e 2`, say) would not
  load. So `install-audit` writes the file for the running kernel (the
  machine field of `uname`), not a fixed one: b64 + b32 on `x86_64` and
  `aarch64`, b64 only on other 64-bit kernels, b32 only on 32-bit kernels
  (armhf, armel). The two lines above are the amd64 file.
- **`auid!=unset`, not `auid>=1000`.** `auid>=1000` would drop root
  logins, and on shared-password fleets people often log in as root.
  `auid!=unset` covers every PAM login (SSH, console, cron) and leaves out
  daemons and boot.
- **`success=1`.** Failed execs are mostly `execvp` walking `$PATH`
  (`ENOENT` per directory). They are noise in a journal of what ran.
- **Key `-k mina`.** For admins (`ausearch -k mina`) and for the
  "is mina's rule loaded?" check. The reader does **not** filter on the
  key: when an admin has their own execve rule earlier in the list (CIS
  benchmarks do), the kernel logs the event with *that* rule's key, and
  mina should still find it. It filters on `ses` and on the record type
  `EXECVE` instead (§3).
- **No global settings.** The file sets no `-b`, `-f`, `-e` or
  `--backlog_wait_time`; those stay with the admin and the distribution
  defaults.

### Volume

The rules record every successful exec by any process with a login uid,
not only those of sessions mina tracks: cron jobs and sessions of services
outside `pam_services` too. An exec event is 5–7 records, about 1–2 KB in
the ENRICHED format. Typical sysadmin sessions and cron: negligible.
The cases to know about:

- **CI runners or build agents that log in over SSH** (compilers, test
  suites): millions of execs per day. They rotate the audit log fast and
  give huge bundles. An admin excludes such an account with a `never`
  rule in a file that sorts before mina's, e.g.
  `/etc/audit/rules.d/40-mina-local.rules`:
  `-a never,exit -F auid=<uid> -S execve,execveat`. The runbook and the
  man page say so.
- **Configuration management** (Ansible etc.) logs in as a session, so its
  execs are the commands we want. A few hundred per run.

To bound a single bundle, `[audit] max_commands` (default 10000) caps the
lines taken from auditd; `session.json` notes the truncation.

### Alternative considered: per-session rules

`session-open` could add `-a always,exit -F sessionid=<ses> -S execve -k mina`
and `session-close` remove it. Only tracked sessions would be recorded.
Rejected:

- it needs `auditctl` (or netlink with `CAP_AUDIT_CONTROL`) on every login,
  in the path that must never block a login;
- `augenrules --load` (which `audit-rules.service` runs, and admins run
  after any rule change) starts with `-D`, deleting every rule: open
  sessions silently stop being recorded;
- with `-e 2` (immutable rules, a common hardening), no rule can be added
  after boot;
- a crash between open and close leaks the rule until reboot.

Static rules have none of these problems. Their cost is the volume above.

### Installing and removing

The rules file is configuration that turns on system-wide execve auditing,
so it is opt-in, like the PAM lines:

- **`mina install-audit`** (the existing, stubbed subcommand): writes
  `/etc/audit/rules.d/50-mina.rules`, then runs `augenrules --load` to
  activate it, then checks with `auditctl -l` that the `mina` rules are
  loaded. If loading failed, it removes the file again, reloads, and
  reports the error: the admin's other rules must end up as they were.
  If `/etc/audit/rules.d` does not exist (auditd not installed), it says
  so and exits non-zero. If `augenrules` is missing, it prints what to
  run.
- **`mina install-pam`** does not install the rules: they affect every
  login on the host, not only mina's sessions, so they get their own
  explicit step. It prints a hint (`mina install-audit`, after
  `apt install auditd` if needed).
- **`mina uninstall-audit`** (new): removes the file and runs
  `augenrules --load`. Idempotent.
- **`mina uninstall-pam`** also calls it.

The package ships the file as `/usr/share/mina/mina.rules` (the source
for `install-audit`, like `mina.sh.profile`), not in
`/etc/audit/rules.d/`: a file there would be active as soon as the package
is installed, and a conffile would linger after `remove`.

The current stub plans to configure `pam_tty_audit`. **Dropped**:
`pam_tty_audit` logs what is typed on the terminal, which is surveillance
of keystrokes (AGENTS.md: "Not a surveillance tool") and can include
secrets typed into programs. Exec records give the command stream without
it. The runbook section that mentions it is rewritten (§7).

## 3. Reading the records

### ausearch or our own parser

| | `ausearch --session N -k mina --raw` | Parse the log in Rust |
|---|---|---|
| Runtime dependency | `ausearch` (same package as auditd, so present when auditd is) | none |
| Parsing still needed | yes: `--raw` returns the same lines; `-i` output is meant for humans | yes |
| Rotated files, `log_file` location | handled | we handle them (small, see below) |
| Cost at session close | scans the whole log, every close | reads only what was written since session-open |
| Testable without auditd | only with a fake process | fixtures, Tier 1 and 2 |

**Decision: parse the log ourselves.** The parser is needed either way,
it keeps the agent free of runtime dependencies, and remembering the log
position at session-open makes the read proportional to the session, not
to the log. `ausearch` stays useful for people: the runbook uses it to
cross-check a bundle.

### Which file

`log_file` from `/etc/audit/auditd.conf` (default
`/var/log/audit/audit.log`; `[audit] log_file` in mina.toml overrides).
mina reads the file as root (session-close runs as root under pam_exec).
If auditd.conf does not exist, or `write_logs = no`, or the log is not
there: `unavailable` (§6). Logs that auditd only forwards
(`audisp-remote`) are not visible locally: also `unavailable`.

### Log position and rotation

auditd rotates by renaming: `audit.log` → `audit.log.1` → … →
`audit.log.<num_logs-1>`; the inode stays with the content.

- At **session-open**, `command_log` records the log's inode and size in a
  state file of its own, `/run/mina/<key>.audit`
  (`{"inode": …, "offset": …}`). It owns that file the way it owns
  `<key>.cmds`, so `SessionState` (in `pam_hook`) does not need to know
  about audit logs.
- At **session-close**, it lists `log_file` and `log_file.<n>`, finds the
  one with the recorded inode, reads it from the offset, then every newer
  file in order, ending with `log_file`.
- If the inode is gone (rotated past `num_logs` during a long session),
  it reads all files there are and reports `incomplete`.
- If a rotation happens while reading, the barrier wait (below) re-lists
  the files and continues from the renamed file.
- Files that logrotate compressed (`.gz`) are skipped; no decompression.

### Record format

An exec event is a group of records with the same
`msg=audit(<sec>.<ms>:<serial>)`:

```
type=SYSCALL msg=audit(1730550000.123:4567): arch=c000003e syscall=59 success=yes exit=0 ... ppid=1201 pid=1240 auid=1000 uid=0 ... ses=12 comm="systemctl" exe="/usr/bin/systemctl" key="mina"␝ARCH=x86_64 SYSCALL=execve AUID="alice" UID="root" ...
type=EXECVE msg=audit(1730550000.123:4567): argc=3 a0="systemctl" a1="restart" a2="nginx"
type=CWD msg=audit(1730550000.123:4567): cwd="/root"
type=PATH msg=audit(1730550000.123:4567): item=0 name="/usr/bin/systemctl" ... nametype=NORMAL ...
type=PATH msg=audit(1730550000.123:4567): item=1 name="/lib64/ld-linux-x86-64.so.2" ...
type=PROCTITLE msg=audit(1730550000.123:4567): proctitle=73797374656D63746C...
type=EOE msg=audit(1730550000.123:4567):
```

What the parser handles:

- **Grouping by serial.** Records of different events can interleave
  (several CPUs). Collect into a map keyed by `(sec, ms, serial)`. An
  event is complete at `EOE`; at end of input, incomplete groups that have
  SYSCALL + EXECVE are kept, others dropped.
- **ENRICHED format** (Debian's default `log_format`): everything after
  the `0x1D` separator is the interpreted copy; cut it off and parse the
  raw part only. RAW format has no separator.
- **Which events.** Any group with an `EXECVE` record and a SYSCALL record
  with `ses=<our id>`. This is independent of the architecture (syscall
  numbers differ per arch) and of the rule key.
- **Values.** `key="text"` is literal. An unquoted value is hex-encoded
  bytes (the kernel does this for anything containing a space, a quote,
  control characters or bytes ≥ 0x7F), except `(null)`. Applies to `aN`,
  `cwd` and `name`.
- **Long arguments.** An argument over the kernel's chunk size is split:
  `a1_len=20000 a1[0]=<hex> a1[1]=<hex> …`, chunks always hex. Reassemble
  by index.
- **Many arguments.** A long argv spans several EXECVE records of the same
  event; `argc=` appears only in the first. Collect `aN` across all of
  them, and check the count against `argc`. A missing piece makes the
  entry `[argv incomplete]`, not a guess.
- **Non-UTF-8 bytes** in argv or cwd: the command is rendered lossily
  (U+FFFD) for `commands.log`, and such an entry yields no file
  candidates (a lossy path is not the path).
- Malformed lines are skipped, never fatal.

### Window

Of the events with the session's `ses`, mina keeps those

- after the log position recorded at session-open, and not older than
  `started_at` (which guards against an equal `ses` from an earlier boot
  in a rotated file);
- before the **close marker**: the exec of the running
  `mina session-close` (its own pid);
- not started by the PAM stack (sshd only): an exec whose `ppid` is the
  session key is a PAM helper; its `pid` joins an exclusion set, and so
  does every later exec whose `ppid` is in the set (§1). This drops
  `run-parts`/`uname` from `pam_motd` and mina itself. A helper that forks
  a subshell which never execs breaks the chain, and its children's execs
  leak in. Accepted: noise in `commands.log`, nothing more;
- not of the mina binary itself (all services).

Ordering is by `(sec, ms, serial)`.

The close marker doubles as a **flush barrier**. auditd writes
asynchronously; at close, the session's last execs may not be in the
file yet. When mina finds its own close exec, everything before it has
been written. So: read; if the close marker is missing, re-read the new
data every 50 ms up to `[audit] wait_ms` (default 1000). Then:

| Found | `audit_status` |
|---|---|
| close marker | `ok` |
| no marker, but events of this session | `incomplete` (the tail may be missing) |
| nothing at all | `not-capturing` (rules not loaded, or `audit=0`) |

The wait only happens when the rules file exists (§6), so hosts without
mina's audit setup never pay it.

### API shape

`CommandSource::commands_for_session(session_pid)` stays as it is.
`AuditdSource` holds what it needs (session id, session key, PAM
service, log position, `started_at`, limits) and returns, from an inherent method,
`AuditCommands { entries, status, truncated }`; the trait impl returns
only the entries. The parser is a pure function `&[u8]` → events, for
Tier 1 tests.

## 4. Mapping to commands.log

One `CommandEntry` per exec:

- `timestamp` from `msg=audit(sec.ms…)`, millisecond precision.
- `cwd` from the CWD record; `None` if missing or not absolute.
- `command`: argv joined by spaces, each argument shell-quoted when needed
  (single quotes when it contains whitespace or shell metacharacters), so
  the line reads like what was typed and can be pasted.
  `ssh host 'systemctl restart nginx'` gives two lines:
  `bash -c 'systemctl restart nginx'`, then `systemctl restart nginx`.
  The first is the clearest record of what the client asked for, so the
  shell's own exec is kept.

The `commands.log` format does not change. Program name: argv as given
(`a0`), not `exe`, which is what the user typed (`vim`, not
`/usr/bin/vim.basic`).

### Which source for which session

| Option | For | Against |
|---|---|---|
| **A. auditd only when the hook did not attach** | interactive sessions keep the readable, typed-command log; auditd fills exactly the gap | an interactive session's scripts are recorded as the script name only (as today) |
| B. merge both | most complete | interactive shells give one line per program: every pipe stage, `$(…)`, completion helpers, prompt helpers (`git` in PS1); duplicates of each typed command |
| C. auditd everywhere, hook as fallback | one source | same noise as B for interactive sessions |

**Recommendation: A**, with `command_source` in session.json:

```json
"shell_hook": false,
"command_source": "auditd",
"audit_session": 12,
"audit_status": "ok",
"commands_truncated": false,
```

- `command_source`: `"shell-hook"` when the hook attached (the `.cmds`
  file exists), else `"auditd"` when auditd gave a status `ok` or
  `incomplete`, else `"none"`.
- `audit_status`: one of `ok`, `incomplete`, `not-capturing`,
  `rules-missing`, `unavailable`, `no-session-id`, `error`; `null` when
  auditd was not consulted (shell hook used).
- `shell_hook` stays, with the same meaning.

The decision function `choose_source(hook_attached, audit) -> CommandSourceKind`
is pure and lives in `command_log`. Known gap: `bash -lc cmd` sources the
hook but no prompt fires, so the hook "attached" with zero commands and
auditd is not used. Using auditd when the hook attached but recorded
nothing would also pull in the profile scripts' execs (`dircolors`,
`lesspipe`) of every interactive login that exits right away. The simple
rule is easier to explain; I'd keep the gap and document it.

## 5. File capture

### From the auditd command lines

The shell hook gives the commands a person typed; auditd gives every
program that ran, including those run by scripts and package maintainer
scripts. Running the path heuristic on all of them would capture files no
one touched on purpose: `/var/lib/dpkg/info/*.postinst`,
`/etc/update-motd.d/*`, script interpreters' arguments. That is the false
positive AGENTS.md rules out.

So for `command_source = "auditd"`, an exec yields candidates only if
both of these hold. Everything else is in `commands.log` but yields no
candidates.

**1. It is one of the session's own commands** (maintainer's decision,
option b). Depth is counted in processes, from the `pid`/`ppid` of the
SYSCALL records of the window (after the PAM-helper filter, §3):

- The **shell's parent** is the parent of the window's first exec: the
  process sshd forked for the session, which started the user's shell
  (`bash -c 'cmd'`, `sh -c sftp-server`). Every shell of the connection
  (multiplexed channels too) is its child.
- **Depth 0**: execs whose `ppid` is the shell's parent. A shell that runs
  a single command execs it in place (same pid, same parent), so
  `ssh host 'sed -i … /etc/x'` gives `sed` at depth 0.
- **Depth n+1**: execs whose `ppid` is a pid that exec'd at depth n:
  `cp` and `systemctl` in `ssh host 'cp a /etc/x && systemctl reload x'`
  are at depth 1.
- **Depth > 1: no candidates.** That drops what package maintainer scripts
  run under `apt`/`dpkg`, and what a script started by the user's command
  runs inside it.
- **Untraceable: no candidates.** An exec whose parent never exec'd in
  the window (a forked subshell, a helper process) cannot be placed, and
  yields none. *Found during implementation:* `sudo` with `use_pty`,
  Debian's default, runs the command from a monitor process that never
  execs, so commands under `sudo` are untraceable. `ssh host 'sudo sed -i … /etc/x'`
  therefore captures nothing. A false negative, accepted per AGENTS.md;
  the commands are still in `commands.log`.

The count is by process, not by intent. A script the user runs directly
(`ssh host ./deploy.sh`) execs in place at depth 0, so the programs it
starts are at depth 1 and do yield candidates.

**2. Its program is in the write-verb list of AGENTS.md** (my call):
`vim vi nano emacs cp mv cat tee sed awk install chmod chown`, matched on
the basename of `a0`. It is not the longer `WRITE_VERBS` in
`src/file_capture.rs`, which includes `python3` and `perl`: every Ansible
task runs `python3 …/AnsiballZ_*.py`. (`echo` is a shell builtin and
never execs.) `WRITE_VERBS` and the shell-hook path stay as they are.

Paths inside a quoted argument (`bash -c 'echo x > /etc/foo'`) are not
extracted either: the quoting puts quote characters on the token, which
`looks_like_path` rejects. A false negative, accepted. The programs that
do the writing inside such a script are separate execs with their own
argv.

Where the code goes: `command_log` computes the depth and marks each
auditd entry as a capture candidate or not. That is a fact about the
command stream, not about files, so `CommandEntry` gets one more field,
`capture_paths: bool` (always `true` for shell-hook entries, not written
to `commands.log`). `file_capture` gets a small function: `extract_paths`
plus the verb check. It still knows nothing about sessions. `main` only
runs extraction on entries marked as candidates.

### Files written by scp/sftp

The exec records only show `sftp-server` (or, with legacy scp,
`scp -t /target/dir`, whose path the heuristic sees, though it is usually
a directory and skipped). The uploaded files are not visible.

PATH records of `open`/`openat` with write flags would show them. That
needs a second rule set, e.g. limited to the sftp server:
`-a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate,rename,renameat,renameat2 -F exe=/usr/lib/openssh/sftp-server -F success=1 -k mina-write`.
Questions it raises: write flags are in the SYSCALL record's `a2` (hex,
per arch), `nametype=CREATE` only for new files, renames from temporary
names, `internal-sftp` (runs inside sshd, no exec at all, so no `exe`
to filter on).

**Out of scope for this step.** It is a separate feature with its own
false-positive analysis. Proposed as a follow-up issue. Note for the docs:
with `Subsystem sftp internal-sftp`, sftp sessions show no commands at all.

## 6. Fallback

The order of checks at session-close, when the hook did not attach:

1. `audit_session` is `null` → `no-session-id`.
2. auditd.conf or the log file missing → `unavailable`.
3. `/etc/audit/rules.d/50-mina.rules` missing → `rules-missing`. The log
   is not read (no wait). Admins with their own execve rules install
   mina's file too; it costs nothing extra when the events are logged
   anyway.
4. Read and wait as in §3 → `ok`, `incomplete` or `not-capturing`.
5. An I/O or parse error → `error`, logged to stderr.

In every case except `ok` and `incomplete`, the bundle is what it is
today: empty `commands.log`, `command_source: "none"`, and the status says
why. Nothing in this path can fail the PAM call: errors are caught in
`run_close_pipeline` as now, and session-open only records the position
(an error there leaves `<key>.audit` absent → `incomplete` at close).

## 7. Tests

### Tier 1 (in `src/command_log.rs`, pure)

- Field parser: quoted value, hex value, `(null)`, `0x1D` cut-off.
- Event assembly from interleaved records; event without EOE; event
  without EXECVE ignored.
- argv: hex with spaces, `a1_len` + `a1[0]`, `a1[1]`; argv over several
  EXECVE records; missing chunk → `[argv incomplete]`.
- Filter: other `ses` dropped, mina's own execs dropped, PAM-helper
  subtree dropped for sshd but not for login, close marker ends the
  window, events older than `started_at` dropped.
- Rendering: quoting of arguments with spaces, quotes, `$`, non-UTF-8.
- `choose_source` for every combination.
- Status table of the barrier (given events, marker found or not).
- Depth: in-place exec at depth 0, forked child at depth 1, grandchild
  not a candidate, untraceable parent not a candidate.
- `file_capture`: the verb filter.
- `config`: `[audit]` defaults and overrides; `auditd.conf` parsing
  (`log_file`, `write_logs`).

### Tier 2 (`tests/auditd_source.rs`, files in a temp dir)

- Fixtures in `tests/fixtures/audit/` (ENRICHED format): `ssh-cmd.log`
  (`ssh host cmd`, with a cron job of another session interleaved),
  `sftp.log` (with pam_motd helpers after session-open), `sudo-apt.log`
  (sudo, apt, dpkg and a maintainer script's `cp`: in `commands.log`, no
  candidates). RAW format, hex values, split argv and interleaving are
  covered by the Tier 1 tests. Written from the documented format first;
  to be replaced by recordings from a test VM during the Tier-3 run, with
  host names, users and addresses replaced by `example` values before
  they are committed.
- Rotation: position in `audit.log`, rotation simulated by renaming in the
  temp dir, read across `audit.log.1` + `audit.log`; inode gone →
  `incomplete`.
- Barrier: close marker appended by a second thread after 100 ms → `ok`;
  never appended → `incomplete` / `not-capturing` within `wait_ms`.
- *Not done:* a lifecycle test (hook absent + audit ok → bundle with
  `command_source: "auditd"`). The close pipeline lives in the binary
  (`main.rs`), so `tests/` cannot call it; that needs it moved into the
  library first (STATUS.md #17, Q3).


Nothing needs auditd, root or a real kernel; CI stays as it is.

### Tier 3 (rewrite of `docs/manual-testing.md` §3 "Sessions without a shell" and §5)

1. `apt install auditd`, then `mina install-audit`. Check
   `auditctl -l | grep mina` shows the two rules. Run `install-audit`
   again: no duplicate.
2. `ssh <user>@<test-host> 'cat /etc/hostname'`. Bundle: `shell_hook:
   false`, `command_source: "auditd"`, `audit_status: "ok"`,
   `audit_session` = the value `ausearch -k mina -i` shows for that
   login; `commands.log` has `bash -c 'cat /etc/hostname'` and
   `cat /etc/hostname`; `/etc/hostname` captured. No `run-parts`/`uname`
   from motd, no `mina` lines.
3. `ssh <user>@<test-host> 'sudo -n true; sudo -i id'`: the root
   commands are in the bundle.
4. `scp ./somefile <user>@<test-host>:/tmp/` and `sftp`: `sftp-server` in
   `commands.log`, no files captured.
5. Interactive login, a few commands: `command_source: "shell-hook"`,
   unchanged output.
6. A long session across a forced rotation (`auditctl --signal rotate`):
   `audit_status: "ok"`, commands from before and after.
7. `mina uninstall-audit`: rules file gone, `auditctl -l` without mina's
   rules. `ssh host cmd` → `audit_status: "rules-missing"`, empty log.
8. Rules file present but `auditctl -D` (rules unloaded) → logout takes
   at most ~1 s longer, `audit_status: "not-capturing"`.
9. `systemctl stop auditd` → `unavailable` or `not-capturing` (the kernel
   keeps sending to journald); interactive sessions still use the hook.
10. Check `grep -n pam_loginuid /etc/pam.d/sshd /etc/pam.d/login` comes
    before mina's lines.

## 8. Implementation outline (phase 2)

1. `pam_hook`: read `/proc/self/sessionid` at open; `SessionMeta.audit_session`.
2. `command_log`: audit log parser, `AuditdSource`, `<key>.audit` position
   file, `choose_source`; export `FakeCommandSource` (Q3).
3. `config`: `[audit]` with `log_file`, `wait_ms`, `max_commands`;
   auditd.conf reader.
4. `command_log`: depth and `CommandEntry.capture_paths`;
   `file_capture`: verb-filtered extraction.
5. `bundle`: `command_source`, `audit_status`, `commands_truncated`.
6. `main`: `install-audit` (per-arch file, load check, rollback),
   `uninstall-audit`, the hint in `install-pam`, removal in
   `uninstall-pam`; source selection in the close pipeline; remove
   `<key>.audit` at close.
7. Rules template; docs (README, manual-testing, troubleshooting,
   STATUS.md #16/Step 11, whose "`ausearch` integration" this design
   replaces, CHANGES.md).

## Packaging note (Debian)

- Ship `mina.rules` in `/usr/share/mina/` (not in `/etc/audit/rules.d/`).
- **`Suggests: auditd`** rather than `Recommends`. With `Recommends`, a
  default `apt install mina` pulls in auditd and starts it fleet-wide. It
  then becomes part of every login: Debian's default rules set
  `--backlog_wait_time 60000`, so when auditd falls behind, audited
  processes wait for up to a minute, and `disk_full_action = SUSPEND`.
  mina must not block anyone, and installing a daemon with those
  properties should be the admin's decision. Without the rules,
  auditd records no execs for mina anyway, so pulling it in does nothing
  until `install-audit` runs. The README and the `install-pam` hint say
  what to install.
- If you prefer `Recommends`, the design does not change: the rules
  still need `mina install-audit`.
- The package enables the PAM lines itself (`pam-auth-update --package`
  in postinst, `Default: yes`) and does not run `install-pam`. The audit
  rules stay a separate admin step; postinst does not install them, so an
  upgrade never turns on exec auditing by itself.
- `prerm` (`remove`/`deconfigure`) already calls
  `pam-auth-update --package --remove`; it should also call
  `mina uninstall-audit` (ignoring "not installed"), so `apt remove`
  leaves no rules behind.
- NEWS.Debian entry: commands of non-interactive SSH sessions need
  auditd + `mina install-audit`.
