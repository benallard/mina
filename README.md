# Mina

> *A quiet companion that watches over your admins' shoulders, takes notes, and reports back when the session is done.*

Mina is a lightweight, passive SSH session auditor for Linux fleets. It records who logged in, when, from where, what commands they ran, and captures a snapshot of every text file they touched — then ships the bundle to a central collector called the **nest**.

No agent UI. No database to maintain. No workflow changes for your admins. It just runs.

> Named after the myna bird — the watchful companion that sits on your shoulder, mimics everything it sees, and always finds its way home.

## Why Mina

Every ops team has the same problem: something breaks, someone fixed it, nobody documented what they did. Mina doesn't try to stop that — it just makes the documentation happen automatically, as a side effect of the work itself.

The audit trail also creates a gentle accountability nudge. When admins know their sessions are recorded and the touched files are archived, the bar for "I'll document it later" quietly rises.

Mina is **not** a security tool aimed at attackers. It is a **team hygiene tool** aimed at your own admins.

## How it works

```
SSH login
   │
   ▼
PAM session open hook
   │  records: user, source IP, timestamp, hostname
   ▼
Shell hook (PROMPT_COMMAND / trap DEBUG)
   │  or, without a login shell (ssh host cmd, scp, sftp),
   │  the exec records of auditd
   │  records: every command, timestamped
   ▼
PAM session close hook
   │  extracts: file paths mentioned in commands
   │  checks:   text files only (skips binaries)
   │  snapshots: content of each touched file
   │  bundles:  session.json + commands.log + files/
   ▼
Transport (SSH/rsync, HTTPS, or local — configured at install)
   │
   ▼
Nest  (central collector)
   └── hostname/
       └── 2025-06-01_14-32-05_alice/
           ├── session.json
           ├── commands.log
           └── files/
               ├── etc/nginx/nginx.conf
               └── opt/myapp/config.yml
```

## Session bundle format

**`session.json`**
```json
{
  "host": "web-prod-03",
  "user": "alice",
  "source_ip": "10.0.1.42",
  "tty": "ssh",
  "audit_session": 412,
  "started_at": "2025-06-01T14:32:05Z",
  "ended_at": "2025-06-01T14:47:22Z",
  "duration_seconds": 917,
  "shell_hook": true,
  "command_source": "shell-hook",
  "audit_status": null,
  "commands_truncated": false,
  "files_captured": 2,
  "commands_recorded": 34
}
```

`command_source` says where the commands came from:

- `shell-hook` — a login shell loaded mina's shell hook (`shell_hook:
  true`): the commands as typed.
- `auditd` — no login shell (`ssh host cmd`, scp, sftp): the programs the
  session ran, from auditd's exec records, scoped by the login's audit
  session id (`audit_session`). Needs auditd and `mina install-audit`.
- `none` — neither recorded anything. `audit_status` says why:
  `rules-missing` (run `mina install-audit`), `unavailable` (no auditd),
  `no-session-id` (no `pam_loginuid`), `not-capturing` (rules not loaded),
  or `error`. `ok` and `incomplete` go with `auditd`; `incomplete` means
  the start or the end of the session may be missing.

`commands_truncated` is set when more than `[audit] max_commands` came
from the audit log.

`tty` is `PAM_TTY` at session open, or `null` when unset. A console login
gives the terminal (`tty1`); sshd on Linux always gives `ssh`, with or
without a pty, so it does not tell interactive SSH sessions apart.

**`commands.log`**
```
2025-06-01T14:32:11Z	cd /etc/nginx
2025-06-01T14:32:15Z	vim nginx.conf
2025-06-01T14:39:02Z	nginx -t
2025-06-01T14:39:08Z	systemctl reload nginx
2025-06-01T14:41:30Z	vim /opt/myapp/config.yml
2025-06-01T14:47:20Z	systemctl restart myapp
```

One command per line: UTC timestamp, a tab, the command. A line break
inside a command is written as `\n`.

**`files/`** — each captured file stored at its mirrored path, content as-is at session close. Text files only; binaries are skipped silently.

## Requirements

**On monitored machines:**
- Linux with PAM (systemd-based distros: Debian, Ubuntu, RHEL, Rocky, Arch…)
- `auditd` — optional; needed to record the commands of sessions without
  a login shell (`ssh host cmd`, scp, sftp)
- Mina agent binary (single static Rust binary, no runtime dependencies)
- HTTPS transport only: the system CA store (`/etc/ssl/certs`, from
  `ca-certificates`), unless `https_ca_cert` points at the nest's CA

**On the nest:**
- Any Linux machine with SSH access and a writable directory, **or**
- A small HTTP endpoint (if using HTTPS transport), **or**
- A local directory on the monitored machine itself (if using local transport)
- No database, no special software

## Installation

### 1. Install the agent on each monitored machine

```bash
curl -Lo /usr/local/bin/mina https://github.com/benallard/mina/releases/latest/download/mina-linux-x86_64
chmod +x /usr/local/bin/mina
```

### 2. Configure

```bash
cp /usr/local/share/mina/mina.toml.example /etc/mina.toml
$EDITOR /etc/mina.toml
```

Minimal config:
```toml
[nest]
transport = "ssh"                        # "ssh", "https", or "local"
ssh_destination = "mina@nest.example.com:/var/mina"
# https_endpoint = "https://nest.example.com/ingest"
# local_destination = "/var/mina"        # local: nest on the same machine

[capture]
text_size_limit_kb = 512                 # skip files larger than this
skip_paths = ["/proc", "/sys", "/dev", "/tmp"]

[session]
pam_services = ["sshd", "login"]         # PAM services that open a session
```

### 3. Hook into PAM

```bash
mina install-pam
# Adds mina hooks to /etc/pam.d/sshd
# Reversible: mina uninstall-pam
```

Only the PAM services listed in `[session] pam_services` open a session
(SSH and the local console by default), even if the hooks sit in a stack
shared by all services such as Debian's `common-session`. Commands typed in
a `su -` or `sudo -i` shell go into the login session they were started from.

### 4. (Optional) Record sessions without a login shell

```bash
apt install auditd
mina install-audit
# Writes /etc/audit/rules.d/50-mina.rules and loads it.
# Reversible: mina uninstall-audit (uninstall-pam does it too)
```

`ssh host cmd`, scp and sftp start no login shell, so the shell hook never
sees their commands. With these rules, the kernel records every program a
logged-in user runs; at session close mina reads those of its session
from auditd's log. Interactive sessions keep using the shell hook. Files
are captured from these commands only for the session's own commands
(not what package scripts run) and only for editors and `cp`, `mv`,
`cat`, `tee`, `sed`, `awk`, `install`, `chmod`, `chown`.

The rules apply to every login on the host, cron jobs included. To leave
out a busy account (a CI runner logging in over SSH), add a rule before
mina's, e.g. in `/etc/audit/rules.d/40-mina-local.rules`:
`-a never,exit -F auid=<uid> -S execve,execveat`.

### 5. Set up the nest

**SSH transport:**
```bash
# On the nest machine
useradd -m -s /bin/bash mina
mkdir -p /var/mina
chown mina:mina /var/mina

# On each monitored machine — deploy a dedicated key
ssh-keygen -t ed25519 -f /etc/mina/nest_key -N ""
ssh-copy-id -i /etc/mina/nest_key.pub mina@nest.example.com
```

**HTTPS transport:**
```bash
# On the nest machine
sudo apt install gunicorn python3-werkzeug nginx
# then follow nest/README.md: gunicorn on a Unix socket, nginx on 443
```

The [nest receiver](nest/README.md) is a small Python WSGI app. In
production it runs under gunicorn on a Unix socket, behind nginx, which
terminates TLS and optionally requires client certificates; examples of the
systemd units and the nginx site are in `nest/examples/`. To try it out,
`python -m mina_nest` runs it on loopback with Werkzeug's development server.

## Browsing reports

Reports are plain directories — use whatever you already know:

```bash
# List recent sessions on a host
ls -lt /var/mina/web-prod-03/

# See what alice did
cat /var/mina/web-prod-03/2025-06-01_14-32-05_alice/commands.log

# Diff a captured config against current
diff /var/mina/web-prod-03/2025-06-01_14-32-05_alice/files/etc/nginx/nginx.conf \
     /etc/nginx/nginx.conf

# Find all sessions that touched nginx.conf
grep -rl "nginx.conf" /var/mina/*/session.json
```

A query CLI (`mina-cli`) is on the roadmap.

## Transport options

| Transport | How it works | Best for |
|---|---|---|
| **SSH / rsync** | Agent rsyncs the bundle to the nest over SSH at session close. Uses existing port 22, existing key infrastructure. | Most fleets — no new ports, no new services |
| **HTTPS POST** | Agent POSTs a tarball to a small HTTP endpoint on the nest. TLS only. | Fleets with strict egress rules, VPNs, or where SSH to a central host is blocked |
| **Local** | Agent copies the bundle into a local directory, readable by root only (files `0400`, directories `0500`). No network, no remote host. | Single-machine setups, air-gapped systems, or development / testing without a nest server |

Transport is selected at install time via `mina.toml`. Both SSH and HTTPS can coexist if you have mixed environments.

> **VPN / port-blocked environments:** use HTTPS transport. The nest endpoint can sit behind a reverse proxy (nginx, Caddy) on port 443, which passes through virtually all corporate firewalls and VPNs.

### HTTPS with mutual TLS

Many fleets already give every machine a client certificate (for package
repositories, VPNs, config management). Point Mina at it and the nest can
authenticate the machine — no extra secret to distribute:

```toml
[nest]
transport = "https"
https_endpoint    = "https://nest.example.com/ingest"
https_client_cert = "/etc/mina/client.crt"   # PEM, full chain leaf first
https_client_key  = "/etc/mina/client.key"   # unencrypted PEM key
https_ca_cert     = "/etc/mina/nest-ca.crt"  # optional: trust only this CA
```

- Cert and key are set together or not at all; without them Mina uses
  plain server-authenticated TLS. Plain `http://` is refused, and there is
  no option to skip verification.
- Without `https_ca_cert` the nest is verified against the system CA store.
- The files are read at every session close, so a certificate renewed on
  disk (by a timer, say) is used from the next logout on.
- Shipping happens at logout: at most 10 s to connect and 60 s per
  attempt, one retry. If both fail the bundle stays in `staging_dir`.

**Wire contract** for whatever receives the bundles: one `POST` to
`https_endpoint` with `Content-Type: application/gzip`,
`User-Agent: mina/<version>` and `X-Mina-Bundle-Digest: sha256=<hex>`. The
body is a gzip tar with exactly one `{hostname}/` holding exactly one
`{YYYY-MM-DD_HH-MM-SS}_{user}/` bundle. Any 2xx is success. The receiver
should unpack to a temporary place and rename into the nest, refuse
entries that leave the bundle directory, and treat a bundle whose name
*and* digest it already has as a resend (answer 2xx, keep one copy);
same name, different digest gets the `_2` suffix. Whether to trust the
self-reported `{hostname}` or derive it from the client certificate is
the receiver's policy.

> **Single-machine or air-gapped environments:** use local transport. Bundles land in `/var/mina` (or any configured path) on the same machine, owned by root, read-only. Create the nest closed to other users — `install -d -m 0750 -o root -g adm /var/mina` — since bundles hold copies of files only root may read. Pair with `logrotate` or a cron job to manage retention.


- **Real-time alerting** — Mina reports at session close, not live. Use Falco or auditd rules if you need live tripwires.
- **Binary file capture** — intentionally skipped. Avoids capturing secrets in keystores, large assets, compiled artifacts.
- **Prevent anything** — Mina is read-only and passive. It does not block commands or enforce policy.
- **Replace documentation** — it makes documentation easier, not automatic. The bundle is the raw material; a human still writes the change ticket.

## Security considerations

- The Mina agent runs as root (required for PAM hooks). The binary should be owned root, mode 755, and verified via checksum after install.
- Bundles can contain copies of root-only files (e.g. `/etc/shadow` after `cat /etc/shadow`). `session-close` runs with umask `077`, assembles bundles in `staging_dir` (default `/var/lib/mina/staging`, created `0700`) and removes them from there once shipped. It refuses a staging directory that is a symlink, not owned by root, or writable by group or other. Keep the nest restrictive too: `/var/mina` `0750 root:adm`.
- The nest SSH key should be **write-only**. Mina never needs to read from the nest. Enforce this in `~mina/.ssh/authorized_keys` with a forced command:

  ```
  command="rsync --server -vlogDtpre.iLsfxCIvu . /var/mina/",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... mina@agent
  ```

  The `command=` prefix means SSH will only ever execute that exact rsync invocation, regardless of what the connecting agent requests. The restriction flags (`no-port-forwarding` etc.) close any remaining escape hatches. With this in place, a compromised agent key can push new bundles but cannot read existing ones, cannot open a shell, and cannot tunnel traffic through the nest.
- With the HTTPS transport, use mutual TLS where you can, so the nest only accepts bundles from machines it knows. The nest's trust in a client certificate is only as strong as the protection of its key file on the machine.
- Session bundles may contain sensitive file contents. Secure the nest accordingly — treat it like a backup server.
- Mina does not record keystrokes: no `pam_tty_audit`. With auditd it reads exec records (program and arguments), never terminal input.

## Roadmap

- [ ] `mina-cli` — query and browse sessions from the command line
- [ ] Diff mode — store deltas once a baseline exists per host
- [ ] Digest emails — daily summary of sessions per host, mailed to a team address
- [ ] `tmux` / `screen` session attribution
- [ ] `sudo` pivot tracking (attribute files changed under sudo to the original user)
- [ ] Redaction rules — suppress capture of files matching path patterns (e.g. `*.key`, `*secret*`)

## Contributing

Mina is written in Rust. The codebase is intentionally small — the goal is a tool you can read and trust in an afternoon.

```
mina/
└── src/
    ├── main.rs          # CLI entrypoint + install helpers
    ├── pam_hook.rs      # PAM session open/close handlers
    ├── command_log.rs   # Shell hook + auditd sources, source choice
    ├── command_log/
    │   ├── auditd.rs      # audit record parser, session window
    │   └── audit_files.rs # auditd.conf, log rotation, rules

    ├── file_capture.rs  # Path extraction, text detection, snapshotting
    ├── bundle.rs        # session.json + archive assembly
    └── transport/
        ├── ssh.rs       # rsync-based shipper
        ├── https.rs     # HTTP POST shipper
        └── local.rs     # local filesystem shipper (read-only copy)
```

Python contributions welcome for parsing/analysis tooling under `tools/`.

## License

MIT
