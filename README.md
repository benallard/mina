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
   │  or auditd / pam_tty_audit if available
   │  records: every command, timestamped
   ▼
PAM session close hook
   │  extracts: file paths mentioned in commands
   │  checks:   text files only (skips binaries)
   │  snapshots: content of each touched file
   │  bundles:  session.json + commands.log + files/
   ▼
Transport (SSH/rsync or HTTPS — configured at install)
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
  "started_at": "2025-06-01T14:32:05Z",
  "ended_at": "2025-06-01T14:47:22Z",
  "duration_seconds": 917,
  "files_captured": 2,
  "commands_recorded": 34
}
```

**`commands.log`**
```
14:32:11  cd /etc/nginx
14:32:15  vim nginx.conf
14:39:02  nginx -t
14:39:08  systemctl reload nginx
14:41:30  vim /opt/myapp/config.yml
14:47:20  systemctl restart myapp
```

**`files/`** — each captured file stored at its mirrored path, content as-is at session close. Text files only; binaries are skipped silently.

## Requirements

**On monitored machines:**
- Linux with PAM (systemd-based distros: Debian, Ubuntu, RHEL, Rocky, Arch…)
- `auditd` — optional but recommended for more complete command capture
- Mina agent binary (single static Rust binary, no runtime dependencies)

**On the nest:**
- Any Linux machine with SSH access and a writable directory, **or**
- A small HTTP endpoint (if using HTTPS transport)
- No database, no special software

## Installation

### 1. Install the agent on each monitored machine

```bash
curl -Lo /usr/local/bin/mina https://github.com/yourorg/mina/releases/latest/download/mina-linux-x86_64
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
transport = "ssh"                        # or "https"
ssh_destination = "mina@nest.example.com:/var/mina"
# https_endpoint = "https://nest.example.com/ingest"

[capture]
text_size_limit_kb = 512                 # skip files larger than this
skip_paths = ["/proc", "/sys", "/dev", "/tmp"]
```

### 3. Hook into PAM

```bash
mina install-pam
# Adds mina hooks to /etc/pam.d/sshd (and sudo if desired)
# Reversible: mina uninstall-pam
```

### 4. (Optional) Enable auditd for deeper command capture

```bash
mina install-audit
# Adds pam_tty_audit rule and configures mina to harvest from auditd
# Falls back to shell hook if auditd is not available
```

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
mina-nest serve --dir /var/mina --port 8765
# Put it behind nginx/caddy with TLS for production use
```

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

Transport is selected at install time via `mina.toml`. Both can coexist if you have mixed environments.

> **VPN / port-blocked environments:** use HTTPS transport. The nest endpoint can sit behind a reverse proxy (nginx, Caddy) on port 443, which passes through virtually all corporate firewalls and VPNs.

## What Mina does not do

- **Real-time alerting** — Mina reports at session close, not live. Use Falco or auditd rules if you need live tripwires.
- **Binary file capture** — intentionally skipped. Avoids capturing secrets in keystores, large assets, compiled artifacts.
- **Prevent anything** — Mina is read-only and passive. It does not block commands or enforce policy.
- **Replace documentation** — it makes documentation easier, not automatic. The bundle is the raw material; a human still writes the change ticket.

## Security considerations

- The Mina agent runs as root (required for PAM hooks). The binary should be owned root, mode 755, and verified via checksum after install.
- The nest SSH key should be **write-only** (restrict to `rsync --server` in `authorized_keys`). Mina never needs to read from the nest.
- Session bundles may contain sensitive file contents. Secure the nest accordingly — treat it like a backup server.
- Mina does not capture passwords typed at prompts (auditd's `log_passwd=off` default is preserved).

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
├── src/
│   ├── main.rs          # CLI entrypoint + install helpers
│   ├── pam_hook.rs      # PAM session open/close handlers
│   ├── command_log.rs   # Shell hook + auditd harvester
│   ├── file_capture.rs  # Path extraction, text detection, snapshotting
│   ├── bundle.rs        # session.json + archive assembly
│   └── transport/
│       ├── ssh.rs       # rsync-based shipper
│       └── https.rs     # HTTP POST shipper
└── nest/
    └── main.rs          # Optional HTTPS nest endpoint
```

Python contributions welcome for parsing/analysis tooling under `tools/`.

## License

MIT
