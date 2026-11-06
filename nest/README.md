# Mina bundle receiver

This optional Werkzeug WSGI application accepts the gzip tar uploads sent by
Mina's HTTPS transport. It listens on loopback by default; terminate TLS and,
optionally, verify client certificates at Caddy, nginx, or Apache. Do not
expose the Werkzeug development server directly to a network.

## Production: gunicorn behind nginx

gunicorn runs the app with a few worker processes on a Unix socket that only
nginx can open; nginx terminates TLS (and client certificates, if you use
them) on 443. The `examples/` directory has the pieces:

- `mina-nest.socket`: the socket, `/run/mina-nest.sock`, owned by nginx's user
- `mina-nest.service`: gunicorn as the `mina-nest` user, with
  `'mina_nest:app_from_env()'`; `MINA_NEST_DIR` names the nest
- `nginx.conf`: the site, proxying `/ingest` to the socket

```sh
sudo apt install gunicorn python3-werkzeug nginx
sudo install -d /opt/mina-nest                 # until there is a package
sudo cp -r nest/mina_nest /opt/mina-nest/
sudo adduser --system --group --no-create-home mina-nest
sudo install -d -m 0750 -o mina-nest -g mina-nest /var/mina
sudo cp nest/examples/mina-nest.socket nest/examples/mina-nest.service /etc/systemd/system/
sudo systemctl enable --now mina-nest.socket
# then adapt nest/examples/nginx.conf into a site and reload nginx
```

systemd starts gunicorn on the first request. `systemctl reload mina-nest`
restarts the workers without dropping uploads in progress.

## Host identity from client certificates

Without further setup, a bundle is filed under the hostname the machine
reports inside it, and the nest logs it as `identity=unauthenticated`.

If nginx verifies client certificates, the nest can file each bundle under
the host the certificate belongs to instead. Write a function that turns a
certificate subject DN (as nginx's `$ssl_client_s_dn` gives it) into a host
directory name, or `None` for a certificate you do not recognise, and name
it in `MINA_IDENTITY_MAPPER`:

```python
# site_mina/identity.py, anywhere on the nest's PYTHONPATH
def host_from_dn(dn: str) -> str | None:
    ...
```

```ini
Environment=MINA_IDENTITY_MAPPER=site_mina.identity:host_from_dn
```

With a mapper set, every upload needs a certificate nginx verified
(`X-SSL-Client-Verify: SUCCESS`); the hostname inside the bundle is ignored,
and a mismatch is logged. No verified certificate, or `None` from the mapper,
gets `403`. A mapper that raises, or returns something that is not a plain
host name (letters, digits, `.`, `-`, `_`, not starting with `.` or `-`), gets
`500`, so the machine keeps its bundle and retries later. A mapper that cannot
be imported stops the nest at startup.

The nest trusts these headers because nginx sets them on every request (see
`examples/nginx.conf`) and only nginx can reach the socket. Keep both true.

## Try it locally

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./nest
sudo install -d -m 0750 -o mina -g mina /var/mina
python -m mina_nest --dir /var/mina --host 127.0.0.1 --port 8080
```

Configure Mina with an endpoint whose path is `/ingest`, for example
`https://nest.example.com/ingest`. Point the reverse proxy at
`http://127.0.0.1:8080/ingest`. TLS and any client-certificate policy belong
at the reverse proxy; the receiver itself does not terminate TLS or authenticate
certificates.

The receiver accepts uploads up to 64 MiB and archives up to 512 MiB expanded
by default. Use `--max-upload-mb` and `--max-expanded-mb` to raise or lower the
limits. Configure the reverse proxy's request-body limit to allow the same
upload size.

The receiver checks the body digest, accepts only the expected single-host,
single-bundle tar layout, and rejects links, special files, and unsafe paths.
It unpacks to a private temporary directory and atomically renames complete
bundles into the nest. A retry with the same bundle name and digest returns
success without creating a second copy; a different digest gets a `_2`, `_3`,
… suffix. Hidden digest markers in each host directory support this retry
deduplication and should be left in place.

For another WSGI server, `mina_nest.app_from_env()` builds the app from
`MINA_NEST_DIR`, and `mina_nest.create_app("/var/mina")` takes the directory
directly.

Run the app only behind a trusted TLS-terminating reverse proxy. Protect the
nest directory as sensitive audit data.
