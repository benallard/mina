"""mina-nest: Werkzeug WSGI receiver for Mina's HTTPS bundle transport."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
import threading
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.serving import run_simple
from werkzeug.wrappers import Request, Response

from mina_nest.config import (
    DEFAULT_MAX_EXPANDED_BYTES,
    DEFAULT_MAX_UPLOAD_BYTES,
    DIGEST_HEADER,
    UPLOAD_TEMP_PREFIX,
    get_host,
    get_max_expanded_mb,
    get_max_upload_mb,
    get_nest_dir,
    get_port,
)
from mina_nest.ingest import (
    InvalidBundle,
    ensure_host_directory,
    extract_archive,
    publish_bundle,
)

LOGGER = logging.getLogger("mina.nest")

_DIGEST_RE = re.compile(r"sha256=[0-9a-f]{64}\Z")


# ---------------------------------------------------------------------------
# Metrics and Health Tracking
# ---------------------------------------------------------------------------


class MetricsTracker:
    """Thread-safe metrics tracking for the receiver."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.start_time = datetime.now(UTC)
        self.counters: dict[str, int] = defaultdict(int)
        self.timing: dict[str, list[float]] = defaultdict(list)
        self.bundle_sizes: list[int] = []

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric."""
        with self.lock:
            self.counters[metric] += value

    def record_timing(self, metric: str, duration: float) -> None:
        """Record a timing measurement."""
        with self.lock:
            self.timing[metric].append(duration)
            # Keep only the last 1000 measurements to prevent memory growth
            if len(self.timing[metric]) > 1000:
                self.timing[metric] = self.timing[metric][-1000:]

    def record_bundle_size(self, size: int) -> None:
        """Record a bundle size."""
        with self.lock:
            self.bundle_sizes.append(size)
            if len(self.bundle_sizes) > 1000:
                self.bundle_sizes = self.bundle_sizes[-1000:]

    def get_metrics(self) -> dict[str, Any]:
        """Get all metrics as a dictionary."""
        with self.lock:
            uptime = (datetime.now(UTC) - self.start_time).total_seconds()

            metrics = {
                "uptime_seconds": uptime,
                "start_time": self.start_time.isoformat(),
                "counters": dict(self.counters),
                "timing": {},
                "bundle_sizes": {
                    "count": len(self.bundle_sizes),
                    "avg_bytes": sum(self.bundle_sizes) / len(self.bundle_sizes)
                    if self.bundle_sizes
                    else 0,
                    "min_bytes": min(self.bundle_sizes) if self.bundle_sizes else 0,
                    "max_bytes": max(self.bundle_sizes) if self.bundle_sizes else 0,
                }
                if self.bundle_sizes
                else {"count": 0},
            }

            for metric, times in self.timing.items():
                if times:
                    metrics["timing"][metric] = {
                        "count": len(times),
                        "avg_seconds": sum(times) / len(times),
                        "min_seconds": min(times),
                        "max_seconds": max(times),
                    }

            return metrics

    def get_health(self) -> dict[str, Any]:
        """Get health status."""
        with self.lock:
            return {
                "status": "healthy",
                "timestamp": datetime.now(UTC).isoformat(),
                "uptime_seconds": (datetime.now(UTC) - self.start_time).total_seconds(),
            }


# Global metrics tracker instance
_metrics = MetricsTracker()


def get_metrics() -> MetricsTracker:
    """Get the global metrics tracker."""
    return _metrics


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

        # Handle health and metrics endpoints
        if request.path == "/health":
            return self._handle_health(request, start_response)
        if request.path == "/metrics":
            return self._handle_metrics(request, start_response)

        try:
            response = self.handle(request)
        except RequestEntityTooLarge:
            _metrics.increment("errors.upload_too_large")
            response = Response("upload exceeds the configured limit\n", status=413)
        except InvalidBundle as error:
            _metrics.increment("errors.invalid_bundle")
            response = Response(f"invalid bundle: {error}\n", status=400)
        except Exception:
            LOGGER.exception("failed to receive Mina bundle")
            _metrics.increment("errors.internal")
            response = Response("failed to store bundle\n", status=500)
        return response(environ, start_response)

    def _handle_health(self, request: Request, start_response) -> list[bytes]:
        """Handle /health endpoint."""
        if request.method != "GET":
            response = Response(
                "method not allowed\n", status=405, headers={"Allow": "GET"}
            )
            return response(request.environ, start_response)

        health = _metrics.get_health()
        response = Response(
            json.dumps(health, indent=2) + "\n",
            status=200,
            mimetype="application/json",
        )
        return response(request.environ, start_response)

    def _handle_metrics(self, request: Request, start_response) -> list[bytes]:
        """Handle /metrics endpoint."""
        if request.method != "GET":
            response = Response(
                "method not allowed\n", status=405, headers={"Allow": "GET"}
            )
            return response(request.environ, start_response)

        metrics = _metrics.get_metrics()
        response = Response(
            json.dumps(metrics, indent=2) + "\n",
            status=200,
            mimetype="application/json",
        )
        return response(request.environ, start_response)

    def handle(self, request: Request) -> Response:
        import time

        start_time = time.perf_counter()

        if request.path != "/ingest":
            _metrics.increment("requests.other")
            return Response("not found\n", status=404)
        if request.method != "POST":
            _metrics.increment("requests.method_not_allowed")
            return Response(
                "method not allowed\n", status=405, headers={"Allow": "POST"}
            )
        if request.mimetype != "application/gzip":
            _metrics.increment("requests.wrong_content_type")
            return Response("Content-Type must be application/gzip\n", status=415)
        if request.content_length is None:
            _metrics.increment("requests.missing_content_length")
            return Response("Content-Length is required\n", status=411)
        if request.content_length <= 0:
            _metrics.increment("requests.empty_body")
            return Response("request body is empty\n", status=400)
        if request.content_length > self.max_upload_bytes:
            _metrics.increment("requests.upload_too_large")
            return Response("upload exceeds the configured limit\n", status=413)

        value = request.headers.get(DIGEST_HEADER, "")
        if not _DIGEST_RE.fullmatch(value):
            _metrics.increment("requests.invalid_digest_header")
            return Response(
                f"{DIGEST_HEADER} must be sha256=<lowercase hex>\n", status=400
            )

        request.max_content_length = self.max_upload_bytes
        body = request.get_data(cache=False)
        _metrics.record_bundle_size(len(body))

        if len(body) != request.content_length:
            _metrics.increment("requests.length_mismatch")
            return Response(
                "request body length does not match Content-Length\n", status=400
            )
        actual_digest = "sha256=" + hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(value, actual_digest):
            _metrics.increment("requests.digest_mismatch")
            return Response("bundle digest does not match request body\n", status=400)

        with tempfile.TemporaryDirectory(
            prefix=UPLOAD_TEMP_PREFIX, dir=self.nest_dir
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

        elapsed = time.perf_counter() - start_time
        _metrics.record_timing("request_duration", elapsed)
        _metrics.increment("requests.success")
        if duplicate:
            _metrics.increment("bundles.duplicate")
        else:
            _metrics.increment("bundles.created")

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
    )
    run_simple(args.host, args.port, application, threaded=True, use_reloader=False)
