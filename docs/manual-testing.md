# Manual testing runbook

This runbook covers end-to-end tests that cannot be automated in CI
because they require a real PAM stack, SSH daemon, and auditd instance.

Run this runbook before tagging any release.

---

## Prerequisites

- A fresh Debian or Ubuntu VM (virtualbox, KVM, or cloud instance)
- A second machine or VM to act as the nest
- SSH access to both
- The `mina` and `mina-nest` binaries built for the target architecture

---

## 1. Install and configure the agent

```bash
sudo cp mina /usr/local/bin/mina
sudo chmod 755 /usr/local/bin/mina

sudo cp mina.toml.example /etc/mina.toml
sudo $EDITOR /etc/mina.toml   # set ssh_destination or https_endpoint
```

Verify the config parses cleanly:
```bash
mina verify-config
# Expected: "Config OK"
```

---

## 2. Install PAM hooks

```bash
sudo mina install-pam
```

Expected changes:
- `/etc/profile.d/mina.sh` created
- `/etc/pam.d/sshd` contains two new lines:
  ```
  session optional pam_exec.so /usr/local/bin/mina session-open
  session optional pam_exec.so /usr/local/bin/mina session-close
  ```
- `/usr/lib/tmpfiles.d/mina.conf` created (ensures `/run/mina` exists on boot)

Verify hooks are reversible:
```bash
sudo mina uninstall-pam
# Confirm the above changes are cleanly removed
sudo mina install-pam
# Re-install for the rest of the runbook
```

---

## 3. Basic session capture

Open a new SSH session to the test machine. Run:

```bash
cd /tmp
vim /etc/hostname         # make a trivial edit and save
echo "test" > ./testfile.txt
systemctl status ssh
```

Log out. On the nest, verify the bundle appeared:

```bash
ls -la /var/mina/<hostname>/
# Expect: one directory named YYYY-MM-DD_HH-MM-SS_<user>

cat /var/mina/<hostname>/*/session.json
# Expect: correct user, source_ip, started_at, ended_at, files_captured >= 1

cat /var/mina/<hostname>/*/commands.log
# Expect: all four commands listed with timestamps

cat "/var/mina/<hostname>/*/files/etc/hostname"
# Expect: content of /etc/hostname as it was at session close
```

---

## 4. Binary file is not captured

```bash
cp /bin/ls /tmp/test_binary
vim /tmp/test_binary   # open it (vim will warn it's binary), quit without saving
```

Verify in session.json that `/tmp/test_binary` appears in `files_skipped`
with reason `binary file`, and does not appear under `files/`.

---

## 5. auditd fallback

If `auditd` and `pam_tty_audit` are available:

```bash
sudo mina install-audit
```

Repeat test 3. Verify that commands run inside a subshell or script
are still captured:

```bash
bash -c "vim /etc/hosts"
```

Verify `/etc/hosts` appears in the bundle.

Then disable auditd to test shell-hook fallback:
```bash
sudo systemctl stop auditd
```

Repeat test 3. Commands should still be captured via `PROMPT_COMMAND`.

---

## 6. Transport failure and retry

Temporarily block outbound SSH from the test machine:
```bash
sudo iptables -A OUTPUT -p tcp --dport 22 -j DROP
```

Start a session, run a few commands, log out.

Verify in syslog (`journalctl -u mina` or `/var/log/syslog`):
- Transport failure is logged
- Session bundle is preserved locally under `/tmp/mina-staging/`

Restore connectivity:
```bash
sudo iptables -D OUTPUT -p tcp --dport 22 -j DROP
```

Trigger a retry (or wait for the next session) and verify the bundle
eventually arrives at the nest.

---

## 7. HTTPS transport (if configured)

Start the nest server on the nest machine:
```bash
mina-nest serve --dir /var/mina --port 8765
```

Update `/etc/mina.toml` on the test machine:
```toml
[nest]
transport = "https"
https_endpoint = "http://nest-ip:8765/ingest"   # plain HTTP for local testing only
```

Repeat test 3. Verify the bundle arrives at the nest via HTTP POST.

---

## 8. Cleanup

```bash
sudo mina uninstall-pam
sudo rm /usr/local/bin/mina
sudo rm /etc/mina.toml
```

Verify no PAM changes remain and the system SSH daemon still accepts logins.
