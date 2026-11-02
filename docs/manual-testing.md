# Manual testing runbook

This runbook covers end-to-end tests that cannot be automated in CI
because they require a real PAM stack, SSH daemon, and auditd instance.

Run this runbook before tagging any release.

---

## Prerequisites

- A fresh Debian or Ubuntu VM (virtualbox, KVM, or cloud instance)
- A second machine or VM to act as the nest (not needed for local transport tests)
- SSH access to both
- The `mina` and `mina-nest` binaries built for the target architecture

---

## 1. Install and configure the agent

```bash
sudo cp mina /usr/local/bin/mina
sudo chmod 755 /usr/local/bin/mina

sudo cp mina.toml.example /etc/mina.toml
sudo $EDITOR /etc/mina.toml   # set transport + destination (see below)
```

> **Note:** `mina verify-config` is not yet implemented. Check the config
> by hand — TOML syntax errors will surface at the first session close.

---

## 2. Install PAM hooks

```bash
sudo mina install-pam
```

This single command:
- Writes `/etc/mina.toml` from the bundled example (only if not already present)
- Copies `mina.sh.profile` to `/etc/profile.d/mina.sh`
- Writes `/usr/lib/tmpfiles.d/mina.conf` (`d /run/mina 1777 root root -`)
- Appends a guarded `pam_exec` block to `/etc/pam.d/sshd` (idempotent — safe to run twice)

It then prints a summary and a one-liner to activate `/run/mina` immediately
without rebooting:

```bash
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/mina.conf
# -- or, if tmpfiles is not available --
sudo mkdir -p /run/mina && sudo chmod 1777 /run/mina
```

**Verify the expected changes are in place:**

```bash
ls -la /run/mina               # should be drwxrwxrwt (1777)
ls /etc/profile.d/mina.sh      # should exist
grep -A4 "BEGIN mina" /etc/pam.d/sshd   # should show both pam_exec lines
cat /etc/mina.toml             # should be the example config
```

**Verify hooks are reversible:**

```bash
sudo mina uninstall-pam
# Confirm:
grep "BEGIN mina" /etc/pam.d/sshd  # should print nothing
ls /etc/profile.d/mina.sh          # should be gone
ls /usr/lib/tmpfiles.d/mina.conf   # should be gone
# /etc/mina.toml is deliberately preserved — re-install is clean
sudo mina install-pam              # should succeed again
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
# (with a _2, _3, … suffix if a session of the same user started in the same second)

cat /var/mina/<hostname>/*/session.json
# Expect: correct user, source_ip, started_at, ended_at, files_captured >= 1,
# "tty": "ssh", "shell_hook": true

cat /var/mina/<hostname>/*/commands.log
# Expect: all four commands, one per line as <UTC timestamp>\t<command>,
# e.g. 2026-10-30T14:03:46Z<TAB>cat /etc/hostname; the file ends in a newline

cat "/var/mina/<hostname>/*/files/etc/hostname"
# Expect: content of /etc/hostname as it was at session close
```

On the test machine, verify the staged copy is gone:

```bash
sudo stat -c '%a %U %n' /var/lib/mina/staging
# Expect: 700 root /var/lib/mina/staging
sudo find /var/lib/mina/staging -mindepth 2
# Expect: no output: a bundle is removed from staging once it has shipped
# (empty <hostname> directories may remain)
```

### Sessions without a shell

Run a command over SSH without a login shell, then copy a file with scp:

```bash
ssh <user>@<test-host> 'cat /etc/hostname'
scp ./somefile <user>@<test-host>:/tmp/
```

```bash
cat /var/mina/<hostname>/<newest>/session.json
# Without mina's audit rules (section 5 not done yet), for each of the two
# bundles: "tty": "ssh", "shell_hook": false, "command_source": "none",
# "audit_status": "rules-missing" (or "unavailable" without auditd),
# "commands_recorded": 0
cat /var/mina/<hostname>/<newest>/commands.log
# Expect: empty. Section 5 repeats this with auditd.
```

An interactive SSH login where you log out right away gives
`"shell_hook": true` and `"commands_recorded": 0`.

---

## 3a. Only login services open a session

The PAM lines may sit in a stack every service uses (Debian's
`common-session`, via `pam-auth-update`). Only the services in
`[session] pam_services` (default `["sshd", "login"]`) may open a session.

For the tests below, put the mina lines in a shared stack: install the
Debian package (`pam-auth-update`), or copy the `BEGIN mina` block from
`/etc/pam.d/sshd` into `/etc/pam.d/common-session` and
`/etc/pam.d/common-session-noninteractive` (remove it from `sshd` so it does
not run twice). Note the bundle count first:
`ls /var/mina/<hostname>/ | wc -l`.

**Console login.** Log in on the VM console (tty1), run `cat /etc/hostname`,
log out.

```bash
ls /var/mina/<hostname>/
# Expect: one new bundle for the console user
cat /var/mina/<hostname>/<newest>/session.json
# Expect: source_ip null, user = console user, "tty": "tty1" (or
# "/dev/tty1"), "shell_hook": true
cat /var/mina/<hostname>/<newest>/commands.log
# Expect: cat /etc/hostname
```

**`sudo -i` and `su -` inside SSH.** Open an SSH session and run:

```bash
echo before
sudo -i
cat /etc/hostname
exit
su - root          # or another account you know the password of: see below
echo inside-su
exit
echo after
ls /run/mina/      # while still logged in
```

```bash
# Expect while logged in: exactly one <pid>.session (the SSH session); no
# extra .session for sudo or su.
```

Log out.

```bash
ls /var/mina/<hostname>/
# Expect: exactly one new bundle (the SSH session)
cat /var/mina/<hostname>/<newest>/commands.log
# Expect: echo before, cat /etc/hostname, sudo -i, echo inside-su,
#         su - root, echo after. bash logs a command at the next prompt,
#         so `sudo -i` / `su - root` come after the commands typed inside
#         them; the inner `exit` is not logged.
cat /var/mina/<hostname>/<newest>/files/etc/hostname
# Expect: captured
```

`su - <otheruser>` (not root): that user cannot write the SSH user's
command log, so the commands typed as `<otheruser>` are not logged. Expect
no error message at the prompt, and the commands before and after the `su`
still in `commands.log`.

**cron produces no bundle.** Add a job that runs every minute:

```bash
echo '* * * * * root true' | sudo tee /etc/cron.d/mina-test
```

Wait two minutes, then remove it:

```bash
sudo rm /etc/cron.d/mina-test
ls /run/mina/
# Expect: no .session file left behind by cron (nor by systemd --user)
ls /var/mina/<hostname>/ | wc -l
# Expect: unchanged by cron (only the bundles of the tests above)
```

**Allowlist is configurable.** Set `pam_services = ["sshd"]` in
`[session]` of `/etc/mina.toml`, log in on the console and out again:
expect no new bundle. Restore the default afterwards. With
`/etc/mina.toml` temporarily moved away, SSH and console logins still
work and a `<pid>.session` file still appears in `/run/mina` (the default
allowlist is used); no bundle is shipped at logout without a config.

---

## 4. Binary file is not captured

```bash
cp /bin/ls /var/tmp/test_binary
vim /var/tmp/test_binary   # open it (vim will warn it's binary), quit without saving
ls /etc/ssh/               # a directory
cat /tmp/anything          # under skip_paths (/tmp)
cat /etc/no-such-file
```

Verify in session.json that `/var/tmp/test_binary` appears in
`files_skipped` with reason `binary file`, and does not appear under
`files/`; `/etc/no-such-file` is listed with reason `not found`.
`/etc/ssh/` and `/tmp/anything` are not listed at all. (`/var/tmp` because
`/tmp` is in the default `skip_paths`.)

---

## 5. Sessions without a shell, with auditd

Design: `docs/design/auditd-source.md`. Check first that `pam_loginuid`
runs before mina in both login stacks:

```bash
grep -n 'pam_loginuid\|common-session\|mina' /etc/pam.d/sshd /etc/pam.d/login
# Expect: pam_loginuid before `@include common-session` (where the package
# puts mina) or before the `# BEGIN mina` block (install-pam)
```

Install the rules:

```bash
sudo apt install auditd
sudo mina install-audit
# Expect: "wrote /etc/audit/rules.d/50-mina.rules (for x86_64)"
sudo auditctl -l | grep mina
# Expect: two rules (arch=b64 and arch=b32) with key=mina
sudo mina install-audit
# Expect: the same, no duplicate rules
```

**A command over SSH:**

```bash
ssh <user>@<test-host> 'cat /etc/hostname'
```

```bash
cat /var/mina/<hostname>/<newest>/session.json
# Expect: "shell_hook": false, "command_source": "auditd",
# "audit_status": "ok", and an "audit_session" equal to the ses= that
# `sudo ausearch -k mina -i | tail` shows for that login
cat /var/mina/<hostname>/<newest>/commands.log
# Expect exactly: bash -c 'cat /etc/hostname', then cat /etc/hostname
# (with the user's shell in place of bash). No run-parts/uname from motd,
# no mina lines.
ls /var/mina/<hostname>/<newest>/files/etc/hostname
# Expect: captured
```

**sudo, and what package scripts run:**

```bash
ssh <user>@<test-host> 'sudo -n cp /etc/hostname /etc/hostname.mina-test; sudo -n apt-get install -y --reinstall nano'
```

Expect in `commands.log`: the `sudo` lines, then `cp`, `apt-get`, `dpkg`
and what the maintainer scripts ran, as root. Note: with sudo's `use_pty`
(Debian's default) the commands under sudo cannot be traced to the
session's shell, so they yield **no** captured files; `files/` must not
contain anything from the package's maintainer scripts. Remove
`/etc/hostname.mina-test` afterwards.

**scp and sftp:**

```bash
scp ./somefile <user>@<test-host>:/tmp/
echo 'ls' | sftp <user>@<test-host>
```

Expect: `command_source: "auditd"`; `commands.log` shows the shell
starting `/usr/lib/openssh/sftp-server`, and `sftp-server` itself. No
files captured: what sftp-server writes is not visible in exec records.
With `Subsystem sftp internal-sftp` in sshd_config, no commands at all.

**Interactive sessions are unchanged:** repeat test 3. Expect
`"command_source": "shell-hook"`, `"audit_status": null`, and the same
`commands.log` as before.

**Rotation during a session:** open an interactive `ssh <user>@<test-host> bash`
(no login shell, so auditd is used), run `id`, then on the host
`sudo auditctl --signal rotate`, run `uname -a`, log out. Expect
`"audit_status": "ok"` and both commands.

**Rules not loaded:** `sudo auditctl -D`, then `ssh <user>@<test-host> true`.
Expect `"audit_status": "not-capturing"`. session-close waits up to
`wait_ms` for records that never come; the client does not notice, since
sshd lets it go before closing the PAM session. Reload with
`sudo augenrules --load`.

**auditd stopped:** `sudo systemctl stop auditd`, `ssh <user>@<test-host> true`.
Expect `"not-capturing"` (the kernel sends records elsewhere while auditd
is down). Start it again (`systemctl start auditd` does not reload the
rules after an `auditctl -D`; run `augenrules --load`).

When checking a bundle right after `ssh … cmd` returns, wait a few
seconds: sshd runs `session-close` after the client has disconnected.


**Removal:**

```bash
sudo mina uninstall-audit
# Expect: "removed /etc/audit/rules.d/50-mina.rules"
sudo auditctl -l | grep -c mina
# Expect: 0
ssh <user>@<test-host> true
# Expect in the bundle: "audit_status": "rules-missing", empty commands.log
```

Known limit: commands run in a tmux/screen session started in an earlier
login keep that login's audit session id, and are lost.

---

## 6. Transport failure and retry

Temporarily block outbound SSH from the test machine:
```bash
sudo iptables -A OUTPUT -p tcp --dport 22 -j DROP
```

Start a session, run a few commands, log out.

Verify in syslog (`journalctl -u mina` or `/var/log/syslog`):
- Transport failure is logged
- Session bundle is preserved locally under
  `/var/lib/mina/staging/<hostname>/` (it is the only copy; mina does not
  remove it when shipping failed)

Restore connectivity:
```bash
sudo iptables -D OUTPUT -p tcp --dport 22 -j DROP
```

Trigger a retry (or wait for the next session) and verify the bundle
eventually arrives at the nest.

---

## 7. Local transport

This test requires only the single VM — no nest machine needed.

Update `/etc/mina.toml`:
```toml
[nest]
transport = "local"
local_destination = "/var/mina"
```

Create the destination (Mina creates it automatically on first ship, but
pre-creating it lets you set ownership explicitly). Bundles hold copies of
files only root may read, so keep the nest closed to other users:
```bash
sudo install -d -m 0750 -o root -g adm /var/mina
```

Repeat test 3 (login, edit a file, logout).

Verify the bundle appeared locally:
```bash
ls -lt /var/mina/<hostname>/
# Expect: one directory named YYYY-MM-DD_HH-MM-SS_<user>

cat /var/mina/<hostname>/*/session.json
cat /var/mina/<hostname>/*/commands.log
```

Verify the bundle is read-only and private to root:
```bash
sudo find /var/mina/<hostname>/ -mindepth 1 -printf '%m %u %p\n'
# Expect: 500 root for every directory, 400 root for every file

# As a regular user (not in group adm), nothing is readable:
ls /var/mina/
# Expect: Permission denied
```

Verify no staging artefacts remain:
```bash
sudo ls -a /var/mina/<hostname>/
# Expect: only the final bundle directory; no .tmp_ prefixes
sudo find /var/lib/mina/staging -mindepth 2
# Expect: no output
```

Verify an unsafe staging directory is refused. Point `staging_dir` at a
directory a regular user could have prepared:
```bash
sudo install -d -m 1777 /srv/mina-staging-test
echo 'staging_dir = "/srv/mina-staging-test"' | sudo sh -c \
  'cat - /etc/mina.toml > /etc/mina.toml.new && mv /etc/mina.toml.new /etc/mina.toml'
```
Log in and out once more.
- Logout is not delayed or blocked
- syslog / `journalctl` shows `unsafe or unusable staging_dir` and
  `writable by group or other`
- No new bundle in `/var/mina/<hostname>/`, nothing in
  `/srv/mina-staging-test`

Repeat with `sudo ln -s /var/lib/mina/staging /srv/mina-staging-test`
(after `sudo rmdir /srv/mina-staging-test`): expect `is a symlink`. Remove
the `staging_dir` line and `/srv/mina-staging-test` afterwards.

---

## 8. HTTPS transport

`mina-nest` is not written yet, so this test uses nginx with client-cert
verification in front of a tiny endpoint that saves each body.

On the nest machine, make a throwaway CA, a server cert and a client cert
(use the nest's real name or IP as `NEST`):
```bash
NEST=nest.example.test
mkdir -p ~/mina-tls && cd ~/mina-tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca.key -out ca.pem -days 7 -subj /CN=mina-manual-test-ca
for n in server client; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout $n.key -out $n.csr -subj /CN=$n
done
printf 'subjectAltName=DNS:%s\n' "$NEST" > san.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -out server.pem -days 7 -extfile san.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -out client.pem -days 7
```

nginx site (`/etc/nginx/sites-enabled/mina-test`):
```nginx
server {
    listen 443 ssl;
    ssl_certificate        /root/mina-tls/server.pem;
    ssl_certificate_key    /root/mina-tls/server.key;
    ssl_client_certificate /root/mina-tls/ca.pem;
    ssl_verify_client      on;
    client_max_body_size   64m;
    location /ingest {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Client-DN $ssl_client_s_dn;
    }
}
```

Receiver that saves each body under its digest:
```bash
mkdir -p /tmp/mina-in && cd /tmp/mina-in && python3 - <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        name = self.headers["X-Mina-Bundle-Digest"].split("=", 1)[1]
        open(name + ".tar.gz", "wb").write(body)
        print(self.headers["X-Client-DN"], self.headers["User-Agent"], name)
        self.send_response(201); self.end_headers()
HTTPServer(("127.0.0.1", 8080), H).serve_forever()
EOF
```

Copy `ca.pem`, `client.pem`, `client.key` to `/etc/mina/` on the test
machine (key `0600 root`) and set:
```toml
[nest]
transport = "https"
https_endpoint    = "https://nest.example.test/ingest"
https_client_cert = "/etc/mina/client.pem"
https_client_key  = "/etc/mina/client.key"
https_ca_cert     = "/etc/mina/ca.pem"
```

Then check:

1. **Success.** Repeat test 3. The receiver prints `CN=client`,
   `mina/<version>` and a digest; `tar tzf <digest>.tar.gz` shows
   `<hostname>/<bundle>/session.json`, `commands.log`, `files/…`;
   `sha256sum` of the file equals the digest. Staging is empty.
2. **No client cert.** Comment out `https_client_cert` and
   `https_client_key`, log in and out: nginx answers 400, the bundle stays
   in `/var/lib/mina/staging/<hostname>/`. Restore the keys.
3. **Wrong CA.** Point `https_ca_cert` at any other PEM CA: session close
   fails with an unknown-issuer error; bundle kept. Restore it.
4. **Plain HTTP refused.** Set `https_endpoint = "http://…"`: session close
   fails with `must start with https://`; bundle kept. Restore it.
5. **Nest unreachable.** Stop nginx; time a logout: it returns within
   about 2 × 10 s (two connect attempts); bundle kept. Start nginx.
6. **Renewal picked up.** Issue a second client cert (`client2`) from the
   same CA, overwrite `/etc/mina/client.pem` and `client.key` with it,
   log in and out: the receiver prints `CN=client2`.
7. **Resend has the same digest.** Make the receiver sleep 70 s before
   answering (longer than the 60 s timeout), log in and out: two POSTs
   arrive with the same `X-Mina-Bundle-Digest`.

Clean up: remove the nginx site, `~/mina-tls`, `/tmp/mina-in` and the
`/etc/mina/` test files.

---

## 9. Cleanup

```bash
sudo mina uninstall-pam
# Expect: also "removed /etc/audit/rules.d/50-mina.rules" if section 5 ran

sudo rm /usr/local/bin/mina
sudo rm /etc/mina.toml
```

Verify no PAM changes remain and the system SSH daemon still accepts logins.
