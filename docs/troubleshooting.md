# Troubleshooting: nothing appears in /run/mina

This guide covers the most common reason Mina appears silent after a fresh
Debian package install: the session pipeline is not running, so no `.session`
or `.cmds` files are ever written to `/run/mina`.

## Start here — match your symptom

| What you see | Jump to |
|---|---|
| `/run/mina` does not exist | [Step 1](#step-1--does-runmina-exist) |
| `/run/mina` exists but is **always empty**, even during an active session | [Step 2](#step-2--are-the-pam-hooks-active) — PAM hooks not firing |
| `/usr/share/pam-configs/mina` exists but no mina lines in `common-session` | [Step 2a](#2a--debian-package-install-pam-auth-update) — `pam-auth-update` not run |
| PAM config looks right, manual test works, but `/run/mina` is always empty | [Step 4d](#4d--pam_exec-calls-session-close-during-login-deleting-the-state-file-immediately) — `pam_exec` phase bug |
| `.session` file present but `.cmds` file has a different name (different PID) | [Step 5](#step-5--is-the-shell-hook-installed-and-active) — OpenSSH privsep PID mismatch |
| `/run/mina/<ppid>.session` appears but no `.cmds` file at all | [Step 5](#step-5--is-the-shell-hook-installed-and-active) — shell hook missing or inactive |
| Files appear in `/run/mina` but no bundle lands at the nest | [Step 6](#step-6--does-etcminatoml-exist-and-parse-correctly) — config or transport problem |

Work through the sections in order — each one rules out a layer of the stack.

---

## Quick orientation

`/var/run` is a symlink to `/run` on modern Debian/Ubuntu. The two paths are
identical. This guide uses `/run/mina` throughout.

What *should* be in `/run/mina` during an active SSH session:

| File | Written by | When |
|---|---|---|
| `<ppid>.session` | `mina session-open` (via PAM) | At login |
| `<ppid>.cmds` | shell hook (`/etc/profile.d/mina.sh`) | As commands run |

Both files are removed by `mina session-close` at logout. If you log out
before checking, the directory will be empty again — that is correct
behaviour. If `/run/mina` itself is missing, that is the first problem.

---

## Step 1 — Does /run/mina exist?

```bash
ls -la /run/mina
```

**Expected:** `drwxrwxrwt` (mode 1777, owned root:root).

**If missing or wrong permissions**, create it now and fix the root cause:

```bash
# Immediate fix (survives until reboot):
sudo mkdir -p /run/mina
sudo chmod 1777 /run/mina

# Permanent fix (survives reboots via systemd-tmpfiles):
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/mina.conf
```

If `/usr/lib/tmpfiles.d/mina.conf` is also missing, run:

```bash
sudo mina install-pam
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/mina.conf
```

> **Why this happens after a package install:**
> The Debian package writes the `tmpfiles.d` entry but `systemd-tmpfiles` only
> processes it at boot, or when explicitly triggered. A fresh install into a
> running system requires the manual `--create` call above.

---

## Step 2 — Are the PAM hooks active?

Mina hooks into PAM in one of two ways depending on how it was installed.
Check which one applies to you.

### 2a — Debian package install (pam-auth-update)

The Debian package installs a PAM config fragment at
`/usr/share/pam-configs/mina`. This fragment is **not active** until
`pam-auth-update` processes it — which must be triggered explicitly after
install (or happens automatically only if the package's `postinst` script
calls it).

**Check whether the fragment is installed:**

```bash
cat /usr/share/pam-configs/mina
```

**Check whether it has been activated:**

```bash
grep -i mina /etc/pam.d/common-session
```

**Expected output** (one or two `pam_exec` lines referencing mina):

```
session optional  pam_exec.so quiet /usr/bin/mina session-open
session optional  pam_exec.so quiet seteuid /usr/bin/mina session-close
```

**If the fragment is installed but `common-session` has no mina lines**, first
check whether `pam-auth-update` still manages the file:

```bash
head -5 /etc/pam.d/common-session
```

If the file is auto-managed, the header looks like:
```
# /etc/pam.d/common-session - session-related modules common to all services
# As of pam 1.0.1-6, this file is managed by pam-auth-update(8). ...
```

If the header is absent or different, the file has been **manually edited** at
some point. `pam-auth-update --package` (called by the package `postinst`)
silently backs off when it detects local modifications — even if `Default: yes`
is set in the fragment. Run it interactively to resolve this:

```bash
sudo pam-auth-update
# A menu appears — check "Mina SSH session auditor", then accept.
```

If the file is auto-managed but mina is still absent, force-enable it:

```bash
sudo pam-auth-update --enable mina
```

Then verify:

```bash
grep -i mina /etc/pam.d/common-session   # should now show the pam_exec lines
```

> **Why this happens:** `pam-auth-update --package` is the correct call from a
> Debian `postinst` script, and it runs fine — but it treats any manually
> edited `common-session` as hands-off. The package did the right thing; the
> admin needs to reconcile the local edits manually.

### 2b — Manual install (mina install-pam)

`mina install-pam` appends a guarded block directly to `/etc/pam.d/sshd`
(rather than using `pam-auth-update`). Use this method on non-Debian systems
or when `pam-auth-update` is not available.

**Check:**

```bash
grep -A5 "BEGIN mina" /etc/pam.d/sshd
```

**Expected output:**

```
# BEGIN mina
session optional pam_exec.so /usr/bin/mina session-open
session optional pam_exec.so /usr/bin/mina session-close
# END mina
```

**If missing:**

```bash
sudo mina install-pam
```

> **Note:** Do not use both methods at the same time. If the Debian package
> is installed, use `pam-auth-update`. If only the binary is present, use
> `mina install-pam`. Having both will cause `mina session-open` to be called
> twice per login.

### 2c — pam_exec.so is present?

Both methods depend on `pam_exec.so`. Verify it exists:

```bash
find /lib /usr/lib -name "pam_exec.so" 2>/dev/null
```

If not found:

```bash
sudo apt-get install libpam-runtime
```

---

## Step 3 — Is sshd using PAM?

```bash
grep -i "usepam" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

**Expected:** `UsePAM yes`

**If `UsePAM no`** or absent (some hardened images disable PAM), enable it:

```bash
sudo sed -i 's/^UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

> Without `UsePAM yes`, sshd never calls `pam_exec`, so `mina session-open`
> and `mina session-close` are never invoked, and nothing is ever written to
> `/run/mina`.

---

## Step 4 — Is mina session-open actually running at login?

If the PAM config looks correct (Steps 2–3 pass) but `/run/mina` is still
empty after a login, `mina session-open` is either not being invoked or is
failing silently.

### 4a — Check syslog

The `quiet` option in the pam-configs fragment suppresses output to the
user's terminal, but errors are still routed to syslog via PAM:

```bash
journalctl -t pam_exec --since "1 hour ago"
journalctl -t mina    --since "1 hour ago"
grep -i "mina\|pam_exec" /var/log/auth.log | tail -30
```

### 4b — Direct invocation test

This bypasses PAM entirely and calls the binary exactly as `pam_exec` would,
letting you see any errors directly:

```bash
sudo PAM_USER=$USER PAM_RHOST=127.0.0.1 PAM_TYPE=open_session /usr/bin/mina session-open
echo "exit: $?"
ls -la /run/mina/
```

**If a `<pid>.session` file appears:** the binary works; the issue is an
environment difference when called via `pam_exec`. Compare the environment
variables available to PAM vs. your shell.

**If the command errors:** the error message is the root cause. Common cases:

| Message | Cause | Fix |
|---|---|---|
| `No such file or directory` for `/usr/bin/mina` | Binary not installed at that path | `which mina` — update the pam-configs path or symlink |
| `/run/mina does not exist` | Directory missing | Create it (Step 1) |
| `failed to write session state: Permission denied` | `/run/mina` has wrong permissions | `chmod 1777 /run/mina` |
| `could not determine session key` | `/proc/self/stat` unreadable | Unusual; verify `/proc` is mounted |
| `failed to load /etc/mina.toml` | Config missing or unreadable | Step 6 |

### 4c — Binary works manually but PAM never calls it

If the direct invocation test (4b) succeeds — a `.session` file appears — but
logins still leave `/run/mina` empty, PAM is not reaching the mina lines.

**Check that `/etc/pam.d/sshd` includes `common-session`:**

```bash
grep "common-session\|pam_exec\|mina" /etc/pam.d/sshd
```

The `common-session` module is only used if `/etc/pam.d/sshd` includes it.
A typical Debian `/etc/pam.d/sshd` contains:

```
@include common-session
```

If that line is absent, the mina lines in `common-session` are never reached
for SSH sessions. Add the include, or add the mina `pam_exec` lines directly
to `/etc/pam.d/sshd` as a fallback.

**Check that sshd has PAM enabled:**

```bash
grep -i usepam /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

Expected: `UsePAM yes`. If absent or set to `no`, PAM is bypassed entirely
and no `pam_exec` module will ever run.

**Check whether the SSH daemon is OpenSSH or Dropbear:**

```bash
sshd -V 2>&1 | head -2
ls /usr/sbin/dropbear 2>/dev/null && echo "Dropbear present"
```

Dropbear does not support PAM. If the system uses Dropbear, the
`pam-auth-update` approach will never work. Options:

- Switch to OpenSSH: `apt-get install openssh-server`
- Use the shell-hook only (commands will be captured, but session open/close
  boundaries will not be PAM-authoritative — see `AGENTS.md` constraint 5)

### 4d — pam_exec calls session-close during login, deleting the state file immediately

**Symptom:** `/run/mina` is empty during a live session even though PAM, sshd,
and the binary all check out. Direct invocation of `mina session-open` creates
a `.session` file, but nothing persists after a real login.

**Root cause:** `pam_exec` invokes every session module for **both**
`pam_open_session` (at login) *and* `pam_close_session` (at logout). This
means `mina session-close` is called at login time — right after
`mina session-open` writes the `.session` file — and immediately consumes
and deletes it. By the time the user's shell starts, the file is gone.

`pam_exec` sets the `PAM_TYPE` environment variable to `open_session` or
`close_session` to distinguish the two phases.

**Confirm the bug** with the installed binary:

```bash
# Create a fake session file matching the current shell's parent PID
PPID_OF_MINA=$(sh -c 'echo $PPID')
echo "{\"session_key\":$PPID_OF_MINA,\"meta\":{\"host\":\"test\",\"user\":\"root\",\"source_ip\":null,\"started_at\":\"2026-06-16T00:00:00Z\",\"ended_at\":null}}" \
  > /run/mina/${PPID_OF_MINA}.session

ls /run/mina/   # file is present

PAM_USER=root PAM_TYPE=open_session /usr/bin/mina session-close
echo "exit: $?"

ls /run/mina/   # file is gone — session-close ran during open phase
```

The pipeline will report `"failed to load /etc/mina.toml"` (or attempt a
transport) but the `.session` file is **always** cleaned up, even on failure.
In a real login, `quiet` suppresses this error to the user's terminal, making
the directory appear silently empty.

**Fix:** Mina v0.1.0 and earlier did not check `PAM_TYPE`. Versions that
include the fix guard each command with an early return:

```rust
// session-open: skip when called in the close phase
if std::env::var("PAM_TYPE").as_deref() == Ok("close_session") {
    return Ok(());
}

// session-close: skip when called in the open phase
if std::env::var("PAM_TYPE").as_deref() == Ok("open_session") {
    return Ok(());
}
```

Rebuild and redeploy the package to pick up the fix.

---

## Step 5 — Is the shell hook installed and active?

```bash
ls -la /etc/profile.d/mina.sh
```

**If missing**, the Debian package's `postinst` did not install it.
Check what the package shipped:

```bash
dpkg -L mina | grep -i profile
ls /usr/share/mina/
```

The source file should be at `/usr/share/mina/mina.sh.profile`. If it is,
copy it manually:

```bash
cp /usr/share/mina/mina.sh.profile /etc/profile.d/mina.sh
```

> **Do not run `mina install-pam`** on a Debian package install. That command
> appends PAM lines directly to `/etc/pam.d/sshd`, which would create a
> duplicate on top of the lines already added to `common-session` by
> `pam-auth-update`. Each login would then invoke `mina session-open` and
> `mina session-close` twice.

**Root cause — missing step in the Debian `postinst`:** The `postinst` only
calls `pam-auth-update --package` and does not deploy the shell hook. The
`postinst` should also include:

```sh
# Install the shell hook
if [ -f /usr/share/mina/mina.sh.profile ]; then
    cp /usr/share/mina/mina.sh.profile /etc/profile.d/mina.sh
fi
```

And the corresponding `postrm` should remove it on uninstall:

```sh
case "$1" in
    remove|purge)
        rm -f /etc/profile.d/mina.sh
        pam-auth-update --package --remove mina
        ;;
esac
```

**Verify the hook is active in your current session:**

```bash
type _mina_log_command 2>/dev/null || echo "hook NOT loaded"
echo "PROMPT_COMMAND: $PROMPT_COMMAND"   # bash
shopt -q login_shell && echo "login shell" || echo "NOT a login shell"
```

The shell hook only activates for **interactive login shells** that source
`/etc/profile.d/`. It will be absent if:

- The shell is not a login shell (sshd configured with `bash` instead of
  `bash -l`, or `~/.ssh/authorized_keys` forces a non-login command)
- The user's `~/.bashrc` or `~/.bash_profile` does not source
  `/etc/profile.d/`
- The shell is `sh`, `dash`, or another shell that does not honour
  `/etc/profile.d/` at all

**Confirm the hook file is syntactically correct:**

```bash
bash --norc /etc/profile.d/mina.sh && echo "OK"
```

**Force-source it in the current session to test without re-logging in:**

```bash
source /etc/profile.d/mina.sh
type _mina_log_command    # should now exist
echo "PPID: $PPID"
ls /run/mina/             # run a command, then check for $PPID.cmds
```

**Check if the .cmds file is being written:**

```bash
# After sourcing the hook and running a command:
cat /run/mina/$PPID.cmds
# Expect: timestamp<TAB>command lines
```

> The shell hook silently skips logging if `/run/mina` does not exist
> (`[ -d "$_mina_log_dir" ] || exit 0`). Fix Step 1 first.

---

## Step 6 — Does /etc/mina.toml exist and parse correctly?

`mina session-close` reads `/etc/mina.toml` to find the transport destination.
If the config is missing or malformed, the session-close pipeline fails — but
the session-open state and command log files were still written to `/run/mina`
(they are then cleaned up by session-close even on failure).

```bash
cat /etc/mina.toml
```

**If missing:**

```bash
sudo cp /usr/share/mina/mina.toml.example /etc/mina.toml
sudo $EDITOR /etc/mina.toml   # set transport and destination
```

**Minimal working config for local transport** (bundles land on the same
machine — useful for verifying the full pipeline without a remote nest):

```toml
[nest]
transport = "local"
local_destination = "/var/mina"

[capture]
text_size_limit_kb = 512
skip_paths = ["/proc", "/sys", "/dev", "/tmp", "/run"]
```

> Mina automatically skips its own `local_destination`, `staging_dir`, and
> `/run/mina` at capture time, so previous bundles are never snapshotted into
> new ones even if a user browses the nest during a session.

---

## Step 7 — Full end-to-end smoke test

Once Steps 1–6 are clean, verify the full pipeline:

```bash
# 1. Open a second SSH session to this machine
# 2. Run a command that touches a text file:
echo "smoke test" > /tmp/mina_test.txt
cat /tmp/mina_test.txt

# 3. Check /run/mina while the session is still open:
ls -la /run/mina/
# Expect: <ppid>.session and <ppid>.cmds

# 4. Log out of the second session

# 5. Inspect the bundle (local transport example):
ls -lt /var/mina/$(hostname)/
cat /var/mina/$(hostname)/*/session.json
cat /var/mina/$(hostname)/*/commands.log
```

> `/tmp` is in `skip_paths` by default, so `/tmp/mina_test.txt` will not
> be captured in `files/`. Edit a file under `/etc/` to test file capture.

---

## Diagnostic checklist (quick reference)

```
[ ] /run/mina exists and is mode 1777
[ ] /usr/lib/tmpfiles.d/mina.conf exists
[ ] grep "BEGIN mina" /etc/pam.d/sshd  → shows pam_exec lines
[ ] UsePAM yes in /etc/ssh/sshd_config
[ ] pam_exec.so is present on the system
[ ] /etc/profile.d/mina.sh exists
[ ] /etc/mina.toml exists and has valid transport config
[ ] syslog shows no mina errors on login
[ ] /run/mina/<ppid>.session appears during a live session
[ ] /run/mina/<ppid>.cmds is populated as commands are run
```

If all boxes are ticked and bundles still do not arrive at the nest,
consult the transport-specific sections in `docs/manual-testing.md`
(sections 6–8).












