# The nest (HTTPS receiver) — design

Date: 2026-11-03, updated 2026-11-06 to what was built
Status: **approved and mostly implemented** (`nest/`, PRs #17–#26).
Still planned: the `.mina-nest/` state directory with receipts (see
"State directory") and the Tier 3 runbook. Where the code went another
way than the first draft (environment instead of `nest.toml`, the mapper
hook as the only identity mapping), this document follows the code.

## Intent

The agent's HTTPS transport is done (`docs/design/https-transport.md`).
When this design was written, what received its POSTs was `src/nest.rs`,
a stub that printed "not yet implemented" (removed in #23), and
operators had to write their own receiver against the wire contract.

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
- Health or metrics endpoints. A check that the nest works is a test
  upload; counters per gunicorn worker would mislead anyway.
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
  particular organisation. Those live in the operator's configuration or
  in a private hook module.
- A database, an index file the nest depends on, or a daemon besides the
  WSGI workers.
- Growing into a web application: no HTML, no UI, no second endpoint
  that does something other than ingest.

## Constraints

From the root `AGENTS.md` (repo-wide):

- No database. The nest is a directory tree; the layout is the shared
  contract between agent, nest and every tool that reads it.
- No new ports: nginx on 443. gunicorn listens on a Unix socket, never
  on a port the fleet reaches.
- Atomic from the nest's perspective: no partial bundle ever appears.

From `nest/AGENTS.md`:

- Python 3.13 (Debian 13 trixie). Runtime dependencies: the standard
  library and Werkzeug (trixie: `python3-werkzeug` 3.1) — its `Request`,
  `Response`, `exceptions` and `test` modules, plus `serving` for the
  development server behind `python -m mina_nest`. No Flask, no
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
| Path other than `/ingest` | `404` |
| Method other than `POST` | `405` |
| `Content-Type` not `application/gzip` | `415` |
| No `Content-Length` | `411` |
| `Content-Length` above the upload limit | `413` |
| No `X-Mina-Bundle-Digest`, or not `sha256=<64 hex>` | `400` |
| Client certificate required but not verified, or not mapped to a host | `403` |
| Body's SHA-256 differs from the header | `400` |
| Not gzip, not tar, truncated, or not exactly one `{hostname}/{bundle}/` tree | `400` |
| Hostile entry or bad name (see "Hostile input") | `400` |
| Unpacked size or entry count over the limits | `413` |
| New bundle stored | `201` |
| Same name and digest already stored (resend) | `200` |
| Nest-side failure (disk full, mapper raised or misbehaved) | `500` |

The nest answers on `/ingest`; the agent's `https_endpoint` can be any
URL, and nginx maps it (`examples/nginx.conf` uses `location = /ingest`).

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
├── README.md
├── pyproject.toml
├── mina_nest/
│   ├── __init__.py     # MinaReceiver, create_app(), app_from_env(), main()
│   ├── __main__.py     # python -m mina_nest: Werkzeug development server
│   ├── config.py       # settings from the environment
│   ├── ingest.py       # safe unpack, atomic publish, resend markers
│   ├── names.py        # host and bundle directory names, one rule each
│   └── identity.py     # verified client cert → host directory name
├── tests/
│   ├── unit/           # Tier 1
│   └── integration/    # Tier 2
└── examples/
    ├── mina-nest.socket   # /run/mina-nest.sock, only nginx's user may connect
    ├── mina-nest.service  # gunicorn as mina-nest, environment, sandboxing
    └── nginx.conf         # site: TLS, optional mTLS, headers, body size
```

`create_app(nest_dir, *, max_upload_bytes, max_expanded_bytes, mapper)`
returns a plain WSGI callable that builds a Werkzeug `Request`, checks
path and method, and returns a `Response`. No routing library; there is
one endpoint. `app_from_env()` builds it from the environment (next
section); gunicorn runs it as `gunicorn 'mina_nest:app_from_env()'`.
`python -m mina_nest` runs the same app on Werkzeug's development server
for trying the nest out; it is not for production.

### Configuration

Environment variables, read when the app is built, so a bad value stops
gunicorn at startup instead of failing on the first upload. The service
unit sets them (`Environment=`); there is no configuration file.

| Variable | Default | Meaning |
|---|---|---|
| `MINA_NEST_DIR` | `/var/mina` | The nest directory |
| `MINA_IDENTITY_MAPPER` | unset | `module:function` mapping a certificate DN to a host (see "Identity") |
| `MINA_DEFAULT_MAX_UPLOAD_BYTES` | 64 MiB | Compressed body; nginx `client_max_body_size` must allow it |
| `MINA_DEFAULT_MAX_EXPANDED_BYTES` | 512 MiB | Sum of unpacked file sizes |
| `MINA_MAX_ARCHIVE_ENTRIES` | 100000 | Entries per archive |
| `MINA_HOST`, `MINA_PORT` | `127.0.0.1`, `8080` | `python -m mina_nest` only |

The first draft had a `nest.toml`. Environment variables won because
the nest has a handful of settings, all set in one place (the unit),
and a second file format on the nest machine buys nothing.

### Request handling

For one `POST`:

1. **Check headers.** Path, method, `Content-Type`, `Content-Length`
   against the upload limit, digest header format.
2. **Identity.** With a mapper, decide the host from the certificate
   headers (see "Identity"); `403` here, before reading the body, if
   the certificate is missing or unmapped.
3. **Read and hash.** Read the body (bounded by the upload limit) and
   compare its SHA-256 with `X-Mina-Bundle-Digest`. An unverified body
   is never unpacked. The body is held in memory: with the default
   limit and 4 workers that is at most 256 MiB; spooling to a file can
   come if bundles grow.
4. **Unpack** into a fresh `.mina-upload-*` directory in the nest (see
   "Hostile input"), counting entries and bytes as it goes, then fsync
   the unpacked files and directories.
5. **Publish** under the lock (see "Atomic publish and resends").
6. **Answer** `201` or `200`, after the data is on disk.

The unpack directory is removed on every exit path, success or failure.

### Hostile input

Every upload is treated as hostile, also with mTLS: a valid certificate
proves which machine sent the bundle, not that the machine is intact.

The unpacker reads the tarball with `tarfile` member by member and never
calls `extractall`. For each member, before anything is written:

- Type is a regular file or a directory. Symlinks, hardlinks, character
  and block devices, FIFOs and GNU sparse entries → `400`.
- The name splits on `/` into non-empty, printable components, none of
  them `.` or `..`, no leading `/`, no `\`. Anything else → `400`.
- The first component is the hostname, the second the bundle name.
  Every member shares the same first two components; the only members
  with fewer are the `{hostname}` and `{hostname}/{bundle}` directory
  entries themselves. A second hostname, a second bundle, or a file at
  either of the two top levels → `400`.
- Inside the bundle: `session.json` and `commands.log` as regular files
  (required), `files/` as a directory (optional: the agent omits it when
  it captured nothing), and nothing else at that level.
- The hostname follows `names.is_safe_hostname`: 1–253 characters,
  letters, digits, `.`, `-`, `_`, not starting with `.` or `-`. The
  bundle name follows `names.is_bundle_name`: `YYYY-MM-DD_HH-MM-SS_`
  and a non-empty user part, which is not narrowed further (site user
  names vary, and an agent-side `_2` suffix is part of it).
- Running totals of entries and sizes stay under the limits → `413`
  otherwise. The decompressed stream is bounded too, so a gzip bomb
  stops at the limit.

Writing: directories with `mkdir`, files with
`os.open(…, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW)`. Because nothing
but plain files and directories is ever created there, no later member
can be redirected through a link; `O_EXCL` turns a duplicate member into
an error. Tar metadata (mode, owner, mtime) is ignored: files get
`0640`, directories `0750`, owned by the nest's user.

A failed member aborts the request; the partly filled unpack directory
is removed. Nothing has touched the nest's host directories yet.

### Identity

The mapper decides. Without `MINA_IDENTITY_MAPPER`, every bundle is
filed under its self-reported hostname and logged as
`identity=unauthenticated`; certificate headers are not looked at.

With a mapper, nginx verifies the client certificate against the
operator's CA and passes `$ssl_client_verify` and `$ssl_client_s_dn` as
`X-SSL-Client-Verify` and `X-SSL-Client-DN`. The nest:

1. Requires `X-SSL-Client-Verify: SUCCESS`, else `403`. A DN without
   that verdict is never used.
2. Calls the mapper, `function(dn: str) -> str | None`, imported once
   when the app is built (an unloadable mapper stops the nest).
   - `None` or `""` → `403`: a certificate the site does not know.
   - An exception → `500`: a broken hook must not lose bundles, and
     `500` leaves them in the agent's staging.
   - Anything that is not a safe host name (same rule as above) → `500`:
     a configuration error, never a path.
3. **Overrides** the tarball's hostname with the mapped one: the bundle
   is stored under `{mapped}/{bundle}/` whatever the tarball says. There
   is no fallback to the tarball's hostname when a mapper is set.

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
  mismatch is information, so the nest logs it as a warning (and, once
  receipts exist, keeps it in the receipt).

`session.json` inside the bundle is not modified: it still holds what
the machine said about itself. The nest never rewrites bundle content.

The nest trusts the certificate headers only because nginx sets them.
That holds when nginx overwrites them on every request
(`proxy_set_header` does, also without mTLS) and gunicorn is reachable
only from nginx (the socket unit lets only nginx's user connect). Both
are in `examples/` and the README; the manual runbook is to check a
forged header.

Organisation-specific mapping stays out of the repo: a site writes its
own mapper module, puts it on the nest's `PYTHONPATH`, and names it in
`MINA_IDENTITY_MAPPER`. The first draft also had a `dn_regex` setting
for simple cases; it was dropped, since a three-line mapper does the
same and keeps one mechanism.

### State directory

**Today:** the nest keeps its bookkeeping next to the bundles:
`.mina-ingest.lock` and `.mina-upload-*` unpack directories in the nest
directory, and a `.{bundle}.mina-digest` marker beside each bundle in
its host directory. The markers are inside the host directories, which
the root `AGENTS.md` layout rule forbids. This is to be replaced.

**Planned:** one hidden directory inside the nest:

```
/var/mina/
├── .mina-nest/
│   ├── tmp/                          # unpack dirs
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

Why there and in this form:

- `.mina-nest/tmp` inside the nest dir is on the nest's filesystem by
  construction, so `rename` is atomic.
- The documented layout is unchanged: `{hostname}` directories hold
  only bundles. A leading `.` keeps the state out of shell globs
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

No nest runs in production yet, so the switch needs no migration.

### Atomic publish and resends

After a successful unpack, and after fsyncing the unpacked files and
directories, with the lock held (`fcntl.flock`, one lock for the whole
nest; unpacking happens outside it, publishing takes milliseconds):

1. For `name`, `name_2`, `name_3`, … in `{nest}/{host}/`:
   - exists and its digest marker has the same digest → resend: drop the
     unpacked copy, answer `200` with that path;
   - exists, or a marker for it exists → next suffix;
   - otherwise → this is the target.
2. `rename` the unpacked bundle to the target.
3. Write the digest marker (temp file, fsync, `rename`).
4. fsync `{nest}/{host}/`, release the lock, answer `201`. A host
   directory created for this bundle was fsynced into the nest directory
   before.

Check-then-rename under the lock, as the local transport does
(`fill_and_publish` in `src/transport/local.rs`), with the same cap on
attempts. The lock makes concurrent gunicorn workers safe against each
other, including two copies of the same resend arriving at once.

A crash between steps 2 and 3 leaves a bundle without a marker. The
bundle is complete; at worst a resend of it is stored again as `_2`.
That is the right side to fail on: duplicates are visible and harmless,
a missing bundle is neither. Leftover unpack directories after a crash
are never visible as bundles and can be removed when no request runs.

fsync happens only after validation, so a refused upload costs none.

### Logging

To stderr (gunicorn → journald):
- every stored bundle: `stored {host}/{name} identity=client-cert` or
  `identity=unauthenticated`; a warning naming the reported hostname
  when a certificate overrode it;
- every refused identity: a warning with the client address and reason;
- every `500`: the exception.

Other `4xx` refusals are answered with their reason but not logged; the
agent logs them on its side. No bundle content in logs.

## Packaging

One Debian source package can build both halves:

- `mina` — `Architecture: any`, the Rust agent, as today.
- `mina-nest` — `Architecture: all`, built with pybuild on `nest/`
  (`--dir nest`, `pybuild-plugin-pyproject`). `Depends: python3,
  python3-werkzeug, gunicorn`; `Recommends: nginx` (any TLS-terminating
  proxy that sets the headers works). Ships the socket and service
  units, a `mina-nest` system user, and the nginx site as an example,
  not an enabled site. With the package, the units' `PYTHONPATH` line
  goes away.

`nest/pyproject.toml` uses a build backend trixie packages
(setuptools), declares `werkzeug>=3.1,<4` as its only dependency, and
`pytest` (and `ruff` for CI) as test/dev extras. The nest keeps its own
version in `pyproject.toml`, released together with the agent's.

The Debian packaging itself lives in the packaging repository, not here.
Its `mina-nest` package still installs the removed Rust stub and has to
move to the above.

## Testing

Same three tiers as the agent (root `AGENTS.md`), in `nest/tests/`.

**Tier 1** (`tests/unit/`, no filesystem): pure logic.
- Path checks on archive member names.
- Host and bundle name rules (`test_names.py`).
- Identity: mapper loading by `module:function`, bad specs, the verify
  header, unmapped and unsafe answers, a raising mapper.

**Tier 2** (`tests/integration/`, a temporary nest): extraction directly
and the full app through `werkzeug.test.Client`, with tarballs built in
the test the way the agent builds them.
- Good bundle → `201`, exactly the expected tree; also without
  `files/`.
- Everything the bundle needs is fsynced before the rename publishes it,
  and the host and nest directories after.
- Resend of the same body → `200`, still one copy. Different body,
  same name → `201` as `_2`.
- Hostile tarballs: `..`, absolute path, symlink, hardlink, sparse
  member, duplicate member, file outside the bundle, unsafe hostname,
  non-agent bundle name, too many entries, too many bytes, a gzip bomb.
  Each → 4xx, and nothing stored.
- Header failures: wrong method, wrong type, oversize body, mismatching
  digest.
- Identity: mapped host overrides the tarball's; DN without a verified
  certificate → `403`; mapper set and no certificate → `403`; unmapped →
  `403`; unsafe mapped name or raising mapper → `500`, nothing written;
  bad `MINA_IDENTITY_MAPPER` → fails at startup.

**Tier 3** (`docs/manual-testing.md`, to be written; section 8 still
tests the agent against a throwaway receiver): the nest under gunicorn
behind nginx with a test CA, as in `examples/`.
- Real agent logout → bundle under the mapped host directory.
- No client cert, cert from another CA → rejected by nginx; cert
  without a mapping → `403`; bundle kept in staging.
- `curl` with a valid cert and a forged `X-SSL-Client-DN` header → the
  header nginx sets wins.
- `curl` replay of a saved tarball with its digest → `200`, no `_2`.
- gunicorn not reachable except through nginx.

**CI**: the `Nest (Python)` job in `.github/workflows/ci.yml` on stock
`ubuntu-latest`, in `nest/`: Python 3.13, Werkzeug 3.1, pytest and a
pinned ruff from pip; `ruff format --check`, `ruff check`, `pytest`. No
system packages, no nginx.

## Open

- The `.mina-nest/` state directory and receipts (above).
- The Tier 3 runbook section.
- The `mina-nest` Debian package (packaging repository).
- Spooling the body to a file instead of memory, if bundles grow.
