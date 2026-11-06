"""mina-nest: Werkzeug WSGI receiver for Mina's HTTPS bundle transport."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import logging
import os
import re
import tempfile
from pathlib import Path

from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.serving import run_simple
from werkzeug.wrappers import Request, Response

from mina_nest.config import (
    DEFAULT_MAX_EXPANDED_BYTES,
    DEFAULT_MAX_UPLOAD_BYTES,
    DIGEST_HEADER,
    get_host,
    get_max_expanded_mb,
    get_max_upload_mb,
    get_nest_dir,
    get_port,
)
from mina_nest.identity import (
    DN_HEADER,
    HostMapper,
    IdentityRefused,
    host_from_headers,
    mapper_from_env,
)
from mina_nest.ingest import (
    BundleTooLarge,
    InvalidBundle,
    ensure_host_directory,
    ensure_state_directory,
    extract_archive,
    publish_bundle,
)

LOGGER = logging.getLogger("mina.nest")

_DIGEST_RE = re.compile(r"sha256=[0-9a-f]{64}\Z")


class MinaReceiver:
    def __init__(
        self,
        nest_dir: str | os.PathLike[str],
        *,
        max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
        max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
        mapper: HostMapper | None = None,
    ) -> None:
        if max_upload_bytes <= 0 or max_expanded_bytes <= 0:
            raise ValueError("upload limits must be positive")
        self.nest_dir = Path(nest_dir).resolve()
        self.nest_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        self.state_dir = ensure_state_directory(self.nest_dir)
        self.max_upload_bytes = max_upload_bytes
        self.max_expanded_bytes = max_expanded_bytes
        # With a mapper, the host comes from the client certificate only.
        self.mapper = mapper

    def __call__(self, environ: dict, start_response) -> list[bytes]:
        request = Request(environ)
        try:
            response = self.handle(request)
        except RequestEntityTooLarge:
            response = Response("upload exceeds the configured limit\n", status=413)
        except BundleTooLarge as error:
            response = Response(f"bundle too large: {error}\n", status=413)
        except InvalidBundle as error:
            response = Response(f"invalid bundle: {error}\n", status=400)
        except Exception:
            LOGGER.exception("failed to receive Mina bundle")
            response = Response("failed to store bundle\n", status=500)
        return response(environ, start_response)

    def handle(self, request: Request) -> Response:
        if request.path != "/ingest":
            return Response("not found\n", status=404)
        if request.method != "POST":
            return Response(
                "method not allowed\n", status=405, headers={"Allow": "POST"}
            )
        if request.mimetype != "application/gzip":
            return Response("Content-Type must be application/gzip\n", status=415)
        if request.content_length is None:
            return Response("Content-Length is required\n", status=411)
        if request.content_length <= 0:
            return Response("request body is empty\n", status=400)
        if request.content_length > self.max_upload_bytes:
            return Response("upload exceeds the configured limit\n", status=413)

        value = request.headers.get(DIGEST_HEADER, "")
        if not _DIGEST_RE.fullmatch(value):
            return Response(
                f"{DIGEST_HEADER} must be sha256=<lowercase hex>\n", status=400
            )

        # Decide who is uploading before reading the body. IdentityError (a
        # broken mapper) becomes a 500, so the agent keeps the bundle.
        cert_hostname = None
        if self.mapper is not None:
            try:
                cert_hostname = host_from_headers(request.headers, self.mapper)
            except IdentityRefused as error:
                LOGGER.warning("refused upload from %s: %s", request.remote_addr, error)
                return Response(f"{error}\n", status=403)

        request.max_content_length = self.max_upload_bytes
        body = request.get_data(cache=False)

        if len(body) != request.content_length:
            return Response(
                "request body length does not match Content-Length\n", status=400
            )
        actual_digest = "sha256=" + hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(value, actual_digest):
            return Response("bundle digest does not match request body\n", status=400)

        with tempfile.TemporaryDirectory(dir=self.state_dir / "tmp") as temporary_name:
            temporary_root = Path(temporary_name)
            tarball_hostname, bundle_name = extract_archive(
                body, temporary_root, self.max_expanded_bytes
            )

            # Use cert-based hostname if available and different from tarball
            if cert_hostname is not None and cert_hostname != tarball_hostname:
                old_dir = temporary_root / tarball_hostname
                new_dir = temporary_root / cert_hostname
                old_dir.rename(new_dir)
                hostname = cert_hostname
            else:
                hostname = tarball_hostname

            host_directory = self.nest_dir / hostname
            ensure_host_directory(host_directory)
            bundle_directory = temporary_root / hostname / bundle_name
            # For the receipt: who delivered the bundle, as far as we know.
            # nginx sets X-Forwarded-For (examples/nginx.conf); gunicorn on
            # a Unix socket has no peer address of its own.
            if cert_hostname is None:
                identity, client_dn = "unauthenticated", None
            else:
                identity, client_dn = "client-cert", request.headers.get(DN_HEADER)
            details = {
                "identity": identity,
                "client_dn": client_dn,
                "reported_hostname": tarball_hostname,
                "remote_addr": request.headers.get("X-Forwarded-For")
                or request.remote_addr,
            }
            name, duplicate = publish_bundle(
                self.state_dir,
                host_directory,
                bundle_directory,
                bundle_name,
                actual_digest,
                details,
            )

        if cert_hostname is None:
            LOGGER.info("stored %s/%s identity=unauthenticated", hostname, name)
        elif cert_hostname != tarball_hostname:
            LOGGER.warning(
                "stored %s/%s identity=client-cert (bundle reported hostname %s)",
                hostname,
                name,
                tarball_hostname,
            )
        else:
            LOGGER.info("stored %s/%s identity=client-cert", hostname, name)

        status = 200 if duplicate else 201
        return Response(f"{hostname}/{name}\n", status=status, mimetype="text/plain")


def create_app(
    nest_dir: str | os.PathLike[str],
    *,
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
    mapper: HostMapper | None = None,
) -> MinaReceiver:
    return MinaReceiver(
        nest_dir,
        max_upload_bytes=max_upload_bytes,
        max_expanded_bytes=max_expanded_bytes,
        mapper=mapper,
    )


def app_from_env() -> MinaReceiver:
    """Build the app from the environment, for a WSGI server such as gunicorn:

    gunicorn 'mina_nest:app_from_env()'

    The nest directory is MINA_NEST_DIR (default /var/mina); the limits are
    those of mina_nest.config. MINA_IDENTITY_MAPPER, if set, names the
    client certificate mapper; a bad value fails here, at startup.
    """
    return create_app(get_nest_dir(), mapper=mapper_from_env())


def _positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description="Receive Mina HTTPS bundles")
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path(get_nest_dir()),
        help="Directory to store bundles (default: MINA_NEST_DIR or /var/mina)",
    )
    parser.add_argument(
        "--host",
        default=get_host(),
        help="Host to bind to (default: MINA_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=get_port(),
        help="Port to listen on (default: MINA_PORT or 8080)",
    )
    parser.add_argument(
        "--max-upload-mb",
        type=_positive_integer,
        default=get_max_upload_mb(),
        help="Maximum upload size in MB",
    )
    parser.add_argument(
        "--max-expanded-mb",
        type=_positive_integer,
        default=get_max_expanded_mb(),
        help="Maximum decompressed archive size in MB",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    application = MinaReceiver(
        args.dir,
        max_upload_bytes=args.max_upload_mb * 1024 * 1024,
        max_expanded_bytes=args.max_expanded_mb * 1024 * 1024,
        mapper=mapper_from_env(),
    )
    run_simple(args.host, args.port, application, threaded=True, use_reloader=False)
