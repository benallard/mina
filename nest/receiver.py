"""Werkzeug WSGI receiver for Mina's HTTPS bundle transport."""

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

from nest.archive import InvalidBundle, extract_archive
from nest.storage import ensure_host_directory, publish_bundle

LOGGER = logging.getLogger("mina.nest")
DIGEST_HEADER = "X-Mina-Bundle-Digest"
DEFAULT_MAX_UPLOAD_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_EXPANDED_BYTES = 512 * 1024 * 1024
_DIGEST_RE = re.compile(r"sha256=[0-9a-f]{64}\Z")


class MinaReceiver:
    def __init__(
        self,
        nest_dir: str | os.PathLike[str],
        *,
        max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
        max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
    ) -> None:
        if max_upload_bytes <= 0 or max_expanded_bytes <= 0:
            raise ValueError("upload limits must be positive")
        self.nest_dir = Path(nest_dir).resolve()
        self.nest_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        self.max_upload_bytes = max_upload_bytes
        self.max_expanded_bytes = max_expanded_bytes

    def __call__(self, environ: dict, start_response) -> list[bytes]:
        request = Request(environ)
        try:
            response = self.handle(request)
        except RequestEntityTooLarge:
            response = Response("upload exceeds the configured limit\n", status=413)
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
            return Response("method not allowed\n", status=405, headers={"Allow": "POST"})
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
            return Response(f"{DIGEST_HEADER} must be sha256=<lowercase hex>\n", status=400)

        request.max_content_length = self.max_upload_bytes
        body = request.get_data(cache=False)
        if len(body) != request.content_length:
            return Response("request body length does not match Content-Length\n", status=400)
        actual_digest = "sha256=" + hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(value, actual_digest):
            return Response("bundle digest does not match request body\n", status=400)

        with tempfile.TemporaryDirectory(
            prefix=".mina-upload-", dir=self.nest_dir
        ) as temporary_name:
            temporary_root = Path(temporary_name)
            hostname, bundle_name = extract_archive(
                body, temporary_root, self.max_expanded_bytes
            )
            host_directory = self.nest_dir / hostname
            ensure_host_directory(host_directory)
            bundle_directory = temporary_root / hostname / bundle_name
            name, duplicate = publish_bundle(
                self.nest_dir,
                host_directory,
                bundle_directory,
                bundle_name,
                actual_digest,
            )

        status = 200 if duplicate else 201
        return Response(f"{hostname}/{name}\n", status=status, mimetype="text/plain")


def create_app(
    nest_dir: str | os.PathLike[str],
    *,
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
) -> MinaReceiver:
    return MinaReceiver(
        nest_dir,
        max_upload_bytes=max_upload_bytes,
        max_expanded_bytes=max_expanded_bytes,
    )


def _positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description="Receive Mina HTTPS bundles")
    parser.add_argument("--dir", type=Path, default=Path("/var/mina"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--max-upload-mb", type=_positive_integer, default=64)
    parser.add_argument("--max-expanded-mb", type=_positive_integer, default=512)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    application = MinaReceiver(
        args.dir,
        max_upload_bytes=args.max_upload_mb * 1024 * 1024,
        max_expanded_bytes=args.max_expanded_mb * 1024 * 1024,
    )
    run_simple(args.host, args.port, application, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
