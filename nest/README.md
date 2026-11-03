# Mina bundle receiver

This optional Werkzeug WSGI application accepts the gzip tar uploads sent by
Mina's HTTPS transport. It listens on loopback by default; terminate TLS and,
optionally, verify client certificates at Caddy, nginx, or Apache. Do not
expose the Werkzeug development server directly to a network.

## Run

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r nest/requirements.txt
sudo install -d -m 0750 -o mina -g mina /var/mina
python -m nest.receiver --dir /var/mina --host 127.0.0.1 --port 8080
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

For a production WSGI server, import the factory and point it at the nest:

```python
from nest.receiver import create_app

app = create_app("/var/mina")
```

Run the app only behind a trusted TLS-terminating reverse proxy. Protect the
nest directory as sensitive audit data.
