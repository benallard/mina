# nest/AGENTS.md

Rules for `nest/`, the server side of Mina. Read the root `AGENTS.md`
first: what Mina is and is not, no database, no new ports and the nest
layout apply here too. The agent-only rules there (static binary, PAM,
no async in the agent…) do not. It is short on purpose.

The design is in `docs/design/nest.md`.

## What the nest is

The nest receives session bundles over HTTPS and files them into the
nest directory tree. One request, one bundle, one atomic `rename`.

It sits behind nginx on the one machine the operator chose to collect
bundles. nginx terminates TLS and checks client certificates; the nest
checks everything else.

## What the nest is not

- **Not a query service.** No search, no listing, no download. Reading
  bundles is `ls`, `grep`, `diff` and `tools/`.
- **Not an index.** No database, no catalogue file the tree depends on.
- **Not an alerting system.** It logs what it received. Nothing more.
- **Not a UI.** No HTML, no second endpoint.
- **Not a janitor.** No retention, no rotation. It touches nothing
  outside the nest directory, and inside it only what it writes.

If a feature needs any of these, it belongs in `tools/` or outside Mina.

## Hard constraints

1. **Every upload is hostile.** Also with a valid client certificate:
   it proves which machine sent the bundle, not that the machine is
   intact. Only regular files and directories, only inside the one
   `{hostname}/{bundle}/` the tarball claims. No `..`, no absolute
   paths, no symlinks, hardlinks or devices, never `extractall`. Size
   and entry count are bounded. A refused upload leaves no trace in the
   tree.

2. **Identity comes from the verified certificate.** When client
   certificates are configured, the host directory is what the
   certificate maps to, and the hostname inside the tarball is ignored.
   Without them, the self-reported hostname is used and every bundle is
   logged as unauthenticated. Never mix the two silently.

3. **Atomic delivery.** Unpack on the nest's filesystem, `rename` into
   place, never overwrite, `_2`, `_3`, … on a clash, same name and digest
   is a resend. Answer `2xx` only once the bundle is on disk: on `2xx`
   the agent deletes its copy.

4. **Nothing deployment-specific upstream.** No CA names, subject
   formats, host naming schemes or paths of any organisation in code,
   defaults, examples or tests. A site's certificate-to-host mapping is
   a private Python module named in `MINA_IDENTITY_MAPPER` (the `mapper`
   hook).

5. **The wire contract is the interface.** The nest accepts exactly
   what "Wire contract" in `docs/design/https-transport.md` describes.
   That section is the one place agent and nest meet over the network;
   change it there, for both sides, or not at all.

## Stack

- **Python 3.13** (Debian 13 trixie). Stdlib plus **Werkzeug 3.1**,
  and of Werkzeug only `Request`, `Response`, `exceptions` and `test`,
  plus `serving` for the development server (`python -m mina_nest`),
  which is never the production path.
- **WSGI**, served by **gunicorn** (sync workers) on a Unix socket,
  behind **nginx** on 443. The app never imports gunicorn.
- No Flask, no async, no ORM, no database, no multipart.
- Config is via environment variables. Errors in it fail at startup.
- Locking is `fcntl.flock`; there is no other coordination between
  workers.
- New runtime dependencies must be packaged in Debian trixie, and need
  a reason that survives the root file's question: does this make Mina
  simpler to deploy, and harder to misuse?

## Layout

```
nest/
├── pyproject.toml
├── mina_nest/
│   ├── __init__.py     # create_app(), app_from_env(); HTTP → status codes
│   ├── __main__.py     # python -m mina_nest: development server only
│   ├── config.py       # environment-based settings
│   ├── ingest.py       # safe unpack, fsync, atomic publish, resend markers
│   ├── names.py        # host and bundle directory names, one rule each
│   └── identity.py     # client cert → host directory; the mapper hook
├── tests/
│   ├── unit/
│   └── integration/
└── examples/           # systemd socket and service units, nginx site
```

Keep the boundaries: `identity` knows nothing about tarballs, `ingest`
nothing about certificates or HTTP. `__init__` turns HTTP into calls to
the two and their results into status codes.

## Testing

Same three tiers as the agent.

- **Tier 1** (`tests/unit/`): pure logic, no filesystem — tar member
  checks on in-memory `TarInfo`, name checks, identity mapping, config
  parsing, digest parsing.
- **Tier 2** (`tests/integration/`): the whole app through
  `werkzeug.test.Client` against a `tmp_path` nest. Every hostile
  tarball case, every refused header, a resend, a `_2` clash, identity
  override and refusal. After each refused request, the tree is
  unchanged.
- **Tier 3** (`docs/manual-testing.md`): nginx, a test CA, the real
  agent, and a forged certificate header.

Tests need only `pytest` and Werkzeug, offline, so the Debian build can
run them.

### CI

A job of its own in `.github/workflows/ci.yml`, stock `ubuntu-latest`,
in `nest/`:

```
pytest              # Tier 1 + Tier 2
ruff check          # No warnings permitted
ruff format --check # Formatting is not negotiable
```

No nginx, no system packages, no root.
