# The nest (HTTPS receiver) — design

Date: 2026-11-03
Status: **draft**, for review. Nothing implemented yet.

## Intent

The agent's HTTPS transport is done (`docs/design/https-transport.md`).
What receives its POSTs is still `src/nest.rs`, a stub that prints "not
yet implemented". Until now, operators had to write their own receiver
against the wire contract.

This design makes the receiver real: a small Python WSGI app that takes
one bundle per request, checks it, and puts it into the nest directory
tree with the same guarantees the local transport gives — atomic, never
overwriting, `_2` on a clash. When the machine presents a client
certificate, the nest decides from that certificate which host directory
the bundle belongs to.

The agent and the nest have opposite jobs. The agent runs on every
monitored machine and must need nothing there; the nest runs on one
machine the operator chose and controls. So the agent stays a static
Rust binary, and the nest uses what that one machine already has:
Python, Werkzeug, gunicorn and nginx, all packaged by Debian.

## Goals

- `POST` of a bundle that meets the wire contract → the bundle appears
  in the nest as `{hostname}/{YYYY-MM-DD_HH-MM-SS}_{user}/`, complete or
  not at all, and the agent gets `201`.
- A resend of a bundle the nest already stored (same name, same digest)
  → `2xx`, still one copy.
- A different bundle with a name already taken → stored as `_2`, `_3`, …
- With mutual TLS: the host directory comes from the verified client
  certificate, through a mapping the operator configures.
- Without mutual TLS: the self-reported hostname is used, and the nest
  says so in its log for every bundle.
- Any upload that is not a well-formed bundle is refused with a 4xx
  before anything becomes visible in the nest.

## Non-goals

- Terminating TLS or verifying client certificates in Python. nginx does
  that; the nest reads its verdict from request headers.
- Querying, indexing, searching, listing or serving bundles back. The
  nest only writes. Reading is `ls`, `grep`, `diff` and `tools/`.
- Retention, rotation, compression of old bundles. `find -mtime` and
  cron, or logrotate-style tooling, outside the nest.
- Re-checking bundle content (UTF-8, size of captured files). The agent
  enforces that; a machine can only fill its own host directory anyway.
- Parsing `session.json`. The nest checks the layout of the tarball, not
  what is inside the files.
- Any authentication other than client certificates (tokens, basic
  auth). An operator can add those in nginx without the nest knowing.
- Receiving SSH or local-transport bundles. Those keep writing into the
  same tree directly; the nest app is not involved.
- Multipart uploads, chunked uploads without `Content-Length`, HTTP/2,
  resumable uploads.

## Anti-goals (failure even if it technically works)

- A tarball that writes anything outside the one bundle directory it
  claims: through `..`, an absolute path, a symlink, a hardlink, or a
  device file.
- A bundle that is visible in the nest before it is complete, or a
  `2xx` answer for a bundle that is not yet safely on disk. On `2xx` the
  agent deletes its staged copy; that answer is the nest taking over.
- A machine with a valid certificate writing into another machine's
  host directory.
- Anything deployment-specific in upstream code, defaults or docs: CA
  names, certificate subject formats, host naming schemes, paths of a
  particular organisation. Those live in the operator's config or in a
  private hook module.
- A database, an index file the nest depends on, or a daemon besides the
  WSGI workers.
- Growing into a web application: no HTML, no UI, no second endpoint
  that does something other than ingest.

## Constraints

From the root `AGENTS.md` (repo-wide):

- No database. The nest is a directory tree; the layout is the shared
  contract between agent, nest and every tool that reads it.
- No new ports: nginx on 443. gunicorn listens on a Unix socket (or
  loopback), never on a port the fleet reaches.
- Atomic from the nest's perspective: no partial bundle ever appears.

From `nest/AGENTS.md` (new, see that file):

- Python 3.13 (Debian 13 trixie). Runtime dependencies: the standard
  library and Werkzeug (trixie: `python3-werkzeug` 3.1) — only its
  `Request`, `Response`, `exceptions` and `test` modules. No Flask, no
  async, no ORM. gunicorn runs the app but is never imported by it.
- No multipart: the stdlib `cgi` module is gone in 3.13, and the body
  is raw `application/gzip` per the contract anyway.
- Tests run offline with Debian's packages only (`python3-pytest`,
  `python3-werkzeug`), so the Debian build can run them.

From the wire contract (`docs/design/https-transport.md`): see the
next section; the nest implements it as written there.

## Wire contract, from the receiving side

As fixed by the agent's design, with the nest's answers:

| Request | Nest answer |
|---|---|
| Method other than `POST` | `405` |
| No `Content-Length` | `411` |
| `Content-Length` above `max_upload_bytes` | `413` (Werkzeug `max_content_length`) |
| `Content-Type` not `application/gzip` | `415` |
| No `X-Mina-Bundle-Digest`, or not `sha256=<64 hex>` | `400` |
| Body's SHA-256 differs from the header | `400` |
| Not gzip, not tar, truncated, or not exactly one `{hostname}/{bundle}/` tree | `400` |
| Hostile entry (see "Hostile input") | `400` |
| Unpacked size or entry count over the limits | `413` |
| Client certificate required but not verified, or not mapped to a host | `403` |
| New bundle stored | `201` |
| Same name and digest already stored (resend) | `200` |
| Nest-side failure (disk full, hook raised, misconfiguration) | `500` |

Every non-2xx keeps the bundle in the agent's staging directory, so a
nest-side failure costs nothing but a later manual reship. The response
body is one line of plain text: on success the stored path relative to
the nest (`web-03/2026-11-03_10-15-00_alice_2`), on failure the reason.
The agent quotes the first 512 bytes of a failure body in its error, so
the reason ends up in the machine's syslog.

`X-Mina-Bundle-Digest` is required. The agent always sends it, and the
nest needs it for resends; a client that cannot compute a SHA-256 is not
a Mina agent.

## Design

### Layout of `nest/`

```
nest/
├── AGENTS.md
├── pyproject.toml
├── mina_nest/
│   ├── __init__.py     # make_app(config) -> WSGI app; app_from_env()
│   ├── config.py       # nest.toml → Config (tomllib), checked at startup
│   ├── ingest.py       # digest check, safe unpack, atomic publish, receipts
│   └── identity.py     # verified client cert → host directory name
├── tests/
│   ├── unit/           # Tier 1
│   └── integration/    # Tier 2
└── examples/
    ├── nest.toml       # commented config
    ├── nginx.conf      # site snippet: TLS, mTLS, headers, body size
    └── mina-nest.service
```

`make_app(config)` returns a plain WSGI callable: one function that
builds a Werkzeug `Request`, dispatches on method and path, and returns
a `Response` or raises from `werkzeug.exceptions`. No routing library;
there is one endpoint. `app_from_env()` reads the config file named by
`MINA_NEST_CONFIG` (default `/etc/mina/nest.toml`) and calls `make_app`;
gunicorn runs it as `gunicorn 'mina_nest:app_from_env()'`. Everything
that can be wrong in the config (nest dir missing, regex without a
`host` group, hook not importable, state dir on another filesystem)
fails at startup, not on the first request.

### Configuration

TOML, read with `tomllib`. Same format as the agent's `mina.toml`, a
separate file because it lives on another machine.

```toml
[nest]
dir = "/var/mina"

[limits]
max_upload_bytes   = 67108864    # compressed body; nginx client_max_body_size ≥ this
max_unpacked_bytes = 268435456   # sum of entry sizes
max_entries        = 10000

[identity]
# "client-cert": host directory from the certificate nginx verified.
# "self-reported": host directory from the tarball; logged as unauthenticated.
source = "client-cert"

# Headers nginx sets; the defaults match examples/nginx.conf.
verify_header = "X-SSL-Client-Verify"
dn_header     = "X-SSL-Client-DN"
# cert_header = "X-SSL-Client-Cert"   # optional: URL-escaped PEM, for hooks

# Exactly one of these when source = "client-cert":
dn_regex = '(?:^|,)CN=(?P<host>[^,]+)'
# mapper = "example_site.mina:host_from_cert"
```

Limits are the builder's to tune; the numbers above are a starting
point sized for bundles of a few hundred captured text files.

There is no default for `dn_regex` or `mapper`. Which part of a
certificate names a machine is policy, and a guessed default would be
exactly the deployment-specific assumption the anti-goals forbid.

### Request handling

For one `POST`:

1. **Check headers.** Method, `Content-Length`, `Content-Type`, digest
   header format. Werkzeug's `max_content_length` gives `413` before the
   body is read.
2. **Identity.** Decide where the bundle may go (see "Identity"); `403`
   here, before reading the body, if the certificate is missing or
   unmapped.
3. **Spool and hash.** Copy the body to a temporary file in the state
   directory while hashing it. Compare with `X-Mina-Bundle-Digest`. An
   unverified body is never unpacked.
4. **Unpack** into a fresh directory under `{state}/tmp/` (see "Hostile
   input"), counting entries and bytes as it goes.
5. **Publish** under the lock (see "Atomic publish and resends").
6. **Answer** `201` or `200`, after the data is on disk.

The spool file and the unpack directory are removed on every exit
path, success or failure.

### Hostile input

Every upload is treated as hostile, also with mTLS: a valid certificate
proves which machine sent the bundle, not that the machine is intact.

The unpacker reads the tarball with `tarfile` member by member and never
calls `extractall`. For each member, before anything is written:

- Type is a regular file or a directory. Symlinks, hardlinks, character
  and block devices, FIFOs, sparse and other GNU special entries → `400`.
- The name splits on `/` into non-empty components, none of them `.` or
  `..`, no leading `/`, valid UTF-8. Anything else → `400`.
- The first component is the hostname, the second the bundle name.
  Every member shares the same first two components; the only members
  with fewer are the `{hostname}` and `{hostname}/{bundle}` directory
  entries themselves. A second hostname, a second bundle, or a file at
  either of the two top levels → `400`.
- The hostname is a single safe path component: 1–253 bytes, letters,
  digits, `.`, `-`, `_`, not starting with `.` or `-`. The bundle name
  matches `YYYY-MM-DD_HH-MM-SS_` followed by a safe component (the user
  part may contain `_`, and an agent-side `_2` suffix is just part of
  it).
- Running totals of entries and declared sizes stay under the limits →
  `413` otherwise. Declared size is what `tarfile` reads, so this also
  bounds a gzip bomb.

Writing: directories with `mkdir`, files with
`os.open(…, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW)`, parents created
as needed inside the unpack directory. Because nothing but plain files
and directories is ever created there, no later member can be redirected
through a link; `O_EXCL` turns a duplicate member into an error. Tar
metadata (mode, owner, mtime) is ignored. Files and directories get
fixed read-only modes, as the local transport does (exact modes and
group: builder's call, documented in the README).

A failed member aborts the request; the partly filled unpack directory
is removed. Nothing has touched the nest tree yet.

### Identity

Two modes, chosen in config.

**`source = "client-cert"`.** nginx verifies the client certificate
against the operator's CA and passes `$ssl_client_verify` and
`$ssl_client_s_dn` (and optionally `$ssl_client_escaped_cert`) as
headers. The nest:

1. Requires the verify header to be `SUCCESS`, else `403`.
2. Maps the certificate to a host directory name:
   - `dn_regex`: `re.search` on the DN; the named group `host` is the
     answer. No match → `403`.
   - `mapper`: a `module:function` path, imported once at startup and
     called as `function(cert) -> str | None`, where `cert` carries `dn`
     and `pem` (`None` unless `cert_header` is configured). `None` →
     `403`. An exception → `500`: a broken hook must not lose bundles,
     and `500` leaves them in the agent's staging.
   The answer goes through the same hostname check as a self-reported
   name; a mapping that yields an unsafe name is a configuration error →
   `500`.
3. **Overrides** the tarball's hostname with the mapped one: the bundle
   is stored under `{mapped}/{bundle}/` whatever the tarball says.

Override rather than reject, because:

- Reject would turn a naming mismatch into lost audit trail. The
  agent's hostname comes from `/etc/hostname`; certificates often carry
  an FQDN, a different case, or an inventory name. A machine renamed
  before its certificate is reissued would have every bundle refused,
  and they pile up in staging where nobody looks.
- Override gives the same security. The only thing a machine controls
  is the self-reported name; ignoring it means a machine with a valid
  certificate can only ever write into the directory its certificate
  maps to.
- Mina records and reports; it does not block (root `AGENTS.md`). A
  mismatch is information, so the nest logs it as a warning and keeps
  it in the receipt (`reported_hostname`), where an operator can find
  it.

`session.json` inside the bundle is not modified: it still holds what
the machine said about itself. The nest never rewrites bundle content.

**`source = "self-reported"`.** The tarball's hostname is used after the
hostname check. Certificate headers are ignored, even if present. Every
bundle is logged with `identity=unauthenticated`. This is for fleets
without client certificates, and for trying the nest out.

The nest trusts the certificate headers only because nginx sets them.
That holds when nginx overwrites them on every request
(`proxy_set_header` does) and gunicorn is reachable only from nginx (a
Unix socket with restrictive permissions). Both are in
`examples/nginx.conf` and in the README; the manual runbook checks a
spoofed header.

Organisation-specific mapping stays out of the repo: a site writes its
own `mapper` module, installs it next to the nest (a site package, a
config-management file), and names it in `nest.toml`. Upstream ships
the hook mechanism and `dn_regex`, nothing more.

### State directory

The nest needs a little private state: a place to unpack on the same
filesystem as the tree (so publishing is a `rename`), a lock, and the
digest of each stored bundle (for resends). It keeps it in one hidden
directory inside the nest:

```
/var/mina/
├── .mina-nest/
│   ├── tmp/                          # spool files and unpack dirs
│   ├── lock                          # flock for publishing
│   └── receipts/{hostname}/{bundle}.json
└── {hostname}/{YYYY-MM-DD_HH-MM-SS}_{user}/…   # unchanged
```

A receipt is small JSON, written once next to its bundle:

```json
{"digest": "sha256=…", "received_at": "2026-11-03T10:15:02Z",
 "identity": "client-cert", "client_dn": "CN=…",
 "reported_hostname": "web-03", "remote_addr": "10.0.1.42"}
```

Why here and in this form:

- `{state}/tmp` inside the nest dir is on the nest's filesystem by
  construction, so `rename` is atomic; startup checks `st_dev` anyway.
- The documented layout is unchanged: `{hostname}` directories still
  hold only bundles. A leading `.` keeps the state out of shell globs
  (`/var/mina/*/…`), and a hostname may not start with `.`, so it can
  never clash with a host directory.
- The digest cannot be recomputed from an unpacked bundle (it is the
  digest of the agent's gzip stream), and putting it inside the bundle
  would make HTTPS bundles differ from SSH and local ones. A file per
  bundle, readable with `cat`, is not a database. If the receipts are
  deleted, the only loss is that a later resend of an old bundle is
  stored again as `_2`.
- Bundles shipped by the SSH or local transport have no receipt; they
  are simply bundles whose digest the nest does not know.

### Atomic publish and resends

After a successful unpack, with `{state}/lock` held (`fcntl.flock`, one
lock for the whole nest; unpacking happens outside it, publishing takes
milliseconds):

1. For `name`, `name_2`, `name_3`, … in `{nest}/{host}/`:
   - exists and its receipt has the same digest → resend: drop the
     unpacked copy, answer `200` with that path;
   - exists otherwise → next suffix;
   - does not exist → this is the target.
2. `fsync` the unpacked files, `rename` the unpack directory to the
   target, `fsync` `{nest}/{host}/`.
3. Write the receipt (temp file + `rename`), `fsync`.
4. Release the lock, answer `201`.

Check-then-rename under the lock, as the local transport does
(`fill_and_publish` in `src/transport/local.rs`), with the same cap on
attempts. The lock makes concurrent gunicorn workers safe against each
other, including two copies of the same resend arriving at once.

A crash between step 2 and 3 leaves a bundle without a receipt. The
bundle is complete; at worst a resend of it is stored again as `_2`.
That is the right side to fail on: duplicates are visible and harmless,
a missing bundle is neither. Leftovers in `{state}/tmp` after a crash
are never visible as bundles and can be removed when no request runs
(builder's call: at startup, or a tmpfiles rule).

### Logging

One line per request to stderr (gunicorn → journald): outcome, status,
host, stored name, digest, identity mode, DN or `unauthenticated`, and
on mismatch the reported hostname. Failures say which check refused the
upload. No bundle content in logs.

### What goes away

In the implementation step, not this one:

- `src/nest.rs` and the `mina-nest` `[[bin]]` in `Cargo.toml`.
- `--bin mina-nest` and the `mina-nest-linux-x86_64` artefacts in the
  `publish-dev` and `publish-release` jobs of `.github/workflows/ci.yml`,
  and the `mina-nest` row of the dev release notes.
- The `mina-nest serve --port 8765` instructions in `README.md`; the
  stub-receiver note and the throwaway Python receiver in section 8 of
  `docs/manual-testing.md`; `src/nest.rs` in `CONTRIBUTING.md`; item 15
  and step 10 in `STATUS.md`.

## Packaging

One Debian source package can build both halves:

- `mina` — `Architecture: any`, the Rust agent, as today.
- `mina-nest` — `Architecture: all`, built with pybuild on `nest/`
  (`--dir nest`, `pybuild-plugin-pyproject`). `Depends: python3,
  python3-werkzeug, gunicorn`; `Recommends: nginx` (any TLS-terminating
  proxy that sets the headers works). Ships the systemd unit, a
  `mina-nest` system user, `/etc/mina/nest.toml`, and the nginx snippet
  as an example, not an enabled site.

`nest/pyproject.toml` uses a build backend trixie packages
(setuptools), declares `werkzeug>=3.1` as its only dependency, and
`pytest` (and `ruff` for CI) as test/dev extras. The nest keeps its own
version in `pyproject.toml`, released together with the agent's.

The Debian packaging itself lives in the packaging repository, not here.

## Testing

Same three tiers as the agent (root `AGENTS.md`), in `nest/tests/`.

**Tier 1** (`tests/unit/`, no filesystem): pure logic.
- Member checks on `TarInfo` objects built in memory: every hostile
  type and name above refused, good members accepted.
- Hostname and bundle-name checks.
- Identity: `dn_regex` matches and misses, `host` group required, hook
  loading by dotted path, hook returning `None` or an unsafe name or
  raising.
- Config parsing: missing keys, both `dn_regex` and `mapper`, neither
  with `client-cert`, bad limits.
- Digest header parsing and comparison.

**Tier 2** (`tests/integration/`, a `tmp_path` nest): the full app
through `werkzeug.test.Client`, with tarballs built in the test the way
the agent builds them.
- Good bundle → `201`, exactly the expected tree, nothing left in
  `.mina-nest/tmp`, receipt written.
- Resend of the same body → `200`, still one copy. Different body,
  same name → `201` as `_2`; resend of that one → `200`.
- Hostile tarballs: `..`, absolute path, symlink, hardlink, device,
  FIFO, two hostnames, two bundles, file at host level, duplicate
  member, hostname starting with `.`, too many entries, too many bytes,
  a gzip bomb, not gzip, truncated gzip. Each → 4xx, and afterwards the
  nest tree is exactly as before.
- Header failures: wrong method, missing length, oversize body,
  wrong type, missing/malformed/mismatching digest.
- Identity: mapped host overrides the tarball's (receipt records the
  reported one); verify header not `SUCCESS` → `403`; unmapped DN →
  `403`; hook raising → `500`, nothing stored; self-reported mode
  ignores certificate headers.
- Failure in publish (e.g. host dir not writable) → `500`, no partial
  bundle.

**Tier 3** (`docs/manual-testing.md`, replacing the throwaway receiver
in section 8): the packaged nest behind nginx with a test CA, gunicorn
on a Unix socket.
- Real agent logout → bundle under the mapped host directory.
- No client cert, cert from another CA → rejected by nginx; cert
  without a mapping → `403`; bundle kept in staging.
- `curl` with a valid cert and a forged `X-SSL-Client-DN` header → the
  header nginx sets wins.
- `curl` replay of a saved tarball with its digest → `200`, no `_2`.
- gunicorn not reachable except through nginx.

**CI**: a second job in `.github/workflows/ci.yml` on stock
`ubuntu-latest`, `working-directory: nest`: set up Python 3.13, install
Werkzeug 3.1, pytest and ruff with pip, run `ruff check`,
`ruff format --check`, `pytest`. No system packages, no nginx.

## Left to the builder

Exact limits and their defaults, config key names, file and directory
modes of stored bundles, log line format, how `{state}/tmp` leftovers
are cleaned, whether `cert_header` is worth shipping in the example
nginx config, the ruff rule set, and the gunicorn worker count in the
example unit.
