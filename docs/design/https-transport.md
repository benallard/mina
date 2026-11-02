# HTTPS transport with optional mTLS — design

Date: 2026-11-02
Status: **approved and implemented** (2026-11-02). Smoke-tested against
nginx with client-certificate verification, and end to end (real PAM
logouts) on a Debian 13 host presenting a step-ca issued client
certificate; built and tested against Debian 13's packaged crates.

## Intent

Mina can already ship bundles over SSH (rsync) and to a local directory.
The HTTPS transport (`src/transport/https.rs`) is a stub. This design makes
it real, so a fleet that can reach the nest only over 443 can use Mina.

Many fleets already give every machine a client certificate (from an
internal CA, for package repositories, VPNs, config management…). The
transport can optionally present such a certificate, so the nest can
authenticate the machine with mutual TLS. That needs no new secret to be
distributed for Mina alone, and no new port.

## Goals

- `transport = "https"` ships a bundle in one HTTPS POST and reports
  success or failure like the other transports.
- Optional mTLS: the operator points Mina at an existing client
  certificate and key on the machine.
- Optional private trust anchor: the operator points Mina at a CA
  certificate to verify the nest with, instead of public roots.
- Config mistakes (plain `http://`, a cert without a key) give a clear
  error and never cost a session its bundle: it stays in staging.

## Non-goals

- The nest-side receiver. It is a separate step; this design only fixes
  the contract it must meet (see "Wire contract").
- Issuing, renewing or decrypting certificates. Mina only reads files
  that something else keeps up to date.
- Encrypted private keys. The key file must be unencrypted PEM.
- HTTP proxies, HTTP/2, streaming uploads, resumable uploads.
- Any assumption about what the certificate subject contains. Mapping a
  certificate to a nest directory is server policy.

## Anti-goals (failure even if it technically works)

- Any path where a bundle travels unencrypted, or where server
  verification can be switched off. There is no `insecure` option.
- A session logout that hangs because the nest is slow or unreachable.
- A new runtime dependency on the monitored machine (`curl`, OpenSSL,
  a CA bundle package). The agent stays a single static binary.
- Anything specific to one deployment's CA, paths or naming in upstream
  code, defaults or docs.

## Constraints (from AGENTS.md)

- 443 only; TLS only.
- No async. `ship()` is synchronous.
- No `unwrap()` in production paths; `anyhow` for errors.
- Atomic from the nest's perspective: the server must never expose a
  partial bundle. The client helps by sending the bundle as one body.
- Retry at least once: already done by `ship_with_retry`.
- Never block the shell exit indefinitely: bounded timeouts.
- CI must pass on stock `ubuntu-latest` with no extra setup.

## Configuration

New optional keys in `[nest]`, next to `https_endpoint`:

```toml
[nest]
transport = "https"
https_endpoint = "https://nest.example.com/ingest"

# Optional: present a client certificate (mutual TLS).
# Both or neither. PEM; the cert file may hold the full chain, leaf first.
# The key must be unencrypted (PKCS#8, PKCS#1 or SEC1 PEM).
# https_client_cert = "/etc/mina/client.crt"
# https_client_key  = "/etc/mina/client.key"

# Optional: verify the nest against this CA certificate (PEM, one or more
# certs) instead of the built-in public roots.
# https_ca_cert = "/etc/mina/nest-ca.crt"
```

Validation (my call): only when `transport = "https"`, in the same place
`build_transport` (src/main.rs) already checks `https_endpoint` is set.
That runs after the bundle is staged, so a bad setting keeps the bundle
in staging, the same as a failed ship. The `https_*` keys are ignored
for other transports, so a leftover key never breaks an `ssh` or `local`
machine. Put the checks in a function in `config.rs` (e.g.
`NestConfig::https_settings() -> Result<…>`) so they are unit-testable.

- `https_endpoint` is required and must parse as a URL with scheme
  `https`. (Closes STATUS.md Q9 and the TLS part of item 18.)
- `https_client_cert` and `https_client_key`: both set or both unset.

Paths are not checked for existence here; the files are read on each
ship (see "Freshness"). A `mina check-config` command that runs these
checks ahead of time is out of scope; it can come later.

`EXAMPLE_CONFIG` in `config.rs` and `mina.toml.example` gain the
commented keys above.

## Client behaviour

`HttpsTransport` holds the endpoint and the three optional paths.
On each `ship(bundle_root)`:

1. **Build the body.** A gzip-compressed tar of the bundle, with entries
   rooted at `{hostname}/{bundle_name}/…` — the last two components of
   `bundle_root`, exactly the layout the local transport writes. The
   hostname is what the machine reports about itself; the server decides
   whether to trust it.
2. **Load TLS material from disk.** Client cert chain and key (if
   configured) and CA (if configured) are read now, not at construction
   time. Missing or unparseable files fail this attempt with an error
   naming the file and the config key.
3. **POST** to `https_endpoint` with the body.
4. **Result.** Any 2xx is success. Anything else, including connection
   and TLS errors, is an `Err` carrying the status (and the first few
   hundred bytes of the response body, if any, for diagnosis).
   `ship_with_retry` already retries once. Redirects are never followed
   (a followed 3xx becomes a bodyless GET whose 2xx would look like
   success and delete the staged bundle), and no proxy is taken from the
   environment.

### Freshness

Client certificates on real fleets are short-lived and renewed by a
timer, often together with re-writing the key file. Reading the files on
every `ship()` means a renewal is picked up by the next session close
without restarting anything (there is nothing long-running to restart
anyway) and Mina never presents a pair it cached before a renewal.

### Timeouts

Builder's call on exact values; my starting point: 10 s to connect,
60 s for the whole request. With the one retry, the worst case stays
around two minutes. Note in the docs that this time is spent at logout.

### Trust anchors

- `https_ca_cert` set: trust only the certificates in that file. Needs
  nothing from the system.
- Unset: trust the system CA store (ureq's platform verifier, i.e.
  `/etc/ssl/certs` from `ca-certificates`). My call, forced by Debian:
  trixie does not package `webpki-roots`, so compiled-in roots are not
  an option for the Debian build, and one behaviour for both builds is
  simpler. Document it: a machine without `ca-certificates` must set
  `https_ca_cert`. This is data, not a runtime program, so it does not
  break the "no runtime dependencies" constraint in spirit; say so in
  the README rather than hide it.

## Wire contract (what the future server must accept)

- Method `POST`, to the configured URL (the path is the operator's).
- Headers: `Content-Type: application/gzip`, `Content-Length`,
  `User-Agent: mina/<version>`, and `X-Mina-Bundle-Digest: sha256=<hex>`
  of the body.
- Retries (my call): `ship_with_retry` may resend a bundle the server
  already stored (e.g. the connection dropped after the server wrote
  it). The digest lets the server tell that apart from a real
  same-second clash: same name *and* same digest → answer 2xx and keep
  the one copy; same name, different digest → `_2` suffix. For this the
  tarball must be byte-identical across attempts: entries in sorted
  order, normalised entry metadata (`tar::HeaderMode::Deterministic`:
  fixed mtime, uid/gid 0), fixed gzip header (no mtime/filename).
- Body: gzip tar; top level is exactly one directory `{hostname}`
  containing exactly one directory `{YYYY-MM-DD_HH-MM-SS}_{user}`, which
  holds `session.json`, `commands.log`, `files/…`.
- Success: any 2xx (suggested: `201 Created`). The client does not read
  the response body on success.
- The server is responsible for: verifying the client certificate if it
  wants mTLS; deciding which nest directory a bundle lands in (it may
  reject or override the self-reported hostname); unpacking to a
  temporary location and renaming into place; the `_2`, `_3`, … suffix
  on name clashes, and dedup of resends by digest (above); rejecting entries that escape the bundle directory
  (`..`, absolute paths, symlinks).

## Implementation choices (builder's, stated so they can be challenged)

- **Two builds must work.** Upstream CI builds with crates.io and
  `Cargo.lock`. The downstream Debian package targets **Debian 13
  (trixie)** and builds with `--link-from-system`: only crates Debian
  packages, at Debian's versions, with Debian's feature sets. Every new
  dependency must therefore resolve against trixie. Checked 2026-11-02
  (trixie): `ureq` 3.0.11, `rustls` 0.23.26 (ring provider),
  `rustls-pemfile` 2.2.0, `rustls-pki-types` 1.11.0,
  `rustls-platform-verifier` 0.5, `tar` 0.4.43, `flate2` 1.1.0,
  `sha2` 0.10.8, `url` 2.5.4. Not in trixie: `webpki-roots`.
- **HTTP client:** `ureq` 3, with requirement `"3.0"` and no API newer
  than 3.0.11. Use its own TLS config types (`ureq::tls::TlsConfig`,
  `ClientCert`, `RootCerts`, `parse_pem`) for loading PEM, so no extra
  PEM crate is needed directly. Rustls backend, ring provider, no
  `webpki-roots`. Pick `default-features = false` plus the smallest
  feature set that exists in both crates.io's and Debian's ureq; verify
  by building the Debian package in a trixie chroot (sbuild/pbuilder)
  before calling it done. Synchronous, pure Rust, handles EC and RSA
  keys. Alternatives rejected: `reqwest` (async runtime underneath),
  shelling out to `curl` (runtime dependency), raw `rustls` over
  `TcpStream` (re-implements HTTP for no gain).
- **Cert/key pre-check:** ureq 3.0.11 `expect()`s rustls'
  `with_client_auth_cert`, so a key that does not belong to the
  certificate panicked at connect time. The transport makes the same
  rustls call first and returns its refusal as an error. For that,
  `rustls` 0.23 (ring) is a direct dependency — the same crate ureq
  already pulls in.
- **Digest:** `sha2` 0.10 for `X-Mina-Bundle-Digest`.
- **Tarball:** `tar` + `flate2` crates, built in memory. Bundles are
  bounded by `text_size_limit_kb` per file and are small in practice; if
  that ever stops being true, switch to a temp file in `staging_dir`.
  Use deterministic entry metadata (no uid/gid names), regular files and
  directories only.
- **Crate versions:** the trixie versions above are the ceiling for
  features used; `Cargo.toml` requirements must accept them. Check
  licences (MIT/Apache-2.0/ISC).

## Testing

Tier 1 (unit, in-file):
- config validation: `http://` rejected, cert without key rejected, key
  without cert rejected, valid combinations accepted, stray `https_*`
  keys ignored for other transports;
- tarball builder: given a bundle dir, the archive contains exactly the
  expected entries under `{hostname}/{bundle}/`, and building twice
  gives identical bytes (same digest);
- TLS material loader: valid PEM chain/key load, missing file and
  garbage file give errors naming the path (uses `tempfile`, which is
  allowed in today's Tier 1 practice — builder to confirm with existing
  `local.rs` tests).

Tier 2: none new needed; `FakeTransport` already covers the lifecycle.
A loopback TLS server test is possible (certificates generated in-test)
but optional — builder's call, only if it runs on stock CI without
setup.

Tier 3 (`docs/manual-testing.md`): a new section with a throwaway CA
(`openssl` or `step`), nginx or Caddy requiring client certs in front of
a dummy endpoint that saves the body, and checks for: success; server
rejects a box with no or wrong cert; `http://` refused at config load;
nest unreachable → logout not blocked beyond the timeouts, bundle kept
in staging; certificate replaced on disk between two sessions → second
session uses the new one.

## Docs and status

- `README.md` / `mina.toml.example`: describe the three new keys.
- `docs/troubleshooting.md`: TLS errors (unknown CA, expired cert, key
  mismatch, server rejected the client cert).
- `STATUS.md`: item 14 → done; Q9 → fixed; item 18 partially.
- `CHANGES.md`: entry under the next version.
- AGENTS.md describes `mina-nest` as a Rust binary. The receiver may end
  up as a Python WSGI app behind a reverse proxy; that wording is for the
  server step to update, not this one.

## Left to the builder

Exact timeouts, crate versions, error wording, in-memory vs temp-file
tarball if sizes surprise, and whether to add the optional loopback test.
