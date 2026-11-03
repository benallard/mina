"""Werkzeug WSGI receiver for Mina's HTTPS bundle transport."""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import hmac
import io
import logging
import os
import re
import stat
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import BinaryIO

from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.serving import run_simple
from werkzeug.wrappers import Request, Response

LOGGER = logging.getLogger("mina.nest")
DIGEST_HEADER = "X-Mina-Bundle-Digest"
DEFAULT_MAX_UPLOAD_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_MEMBER_READ = 64 * 1024
MAX_NAME_ATTEMPTS = 100
_DIGEST_RE = re.compile(r"sha256=[0-9a-f]{64}\Z")


class InvalidBundle(Exception):
    """The request body is not a valid Mina bundle archive."""


class BoundedReader:
    """Limit bytes decompressed from gzip and the size of individual reads."""

    def __init__(self, source: BinaryIO, limit: int) -> None:
        self.source = source
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = MAX_MEMBER_READ
        size = min(size, MAX_MEMBER_READ, self.limit - self.total + 1)
        if size <= 0:
            raise InvalidBundle("expanded archive exceeds the configured limit")
        data = self.source.read(size)
        self.total += len(data)
        if self.total > self.limit:
            raise InvalidBundle("expanded archive exceeds the configured limit")
        return data


def _safe_component(component: str) -> bool:
    return (
        component not in ("", ".", "..")
        and len(component) <= 255
        and "/" not in component
        and "\\" not in component
        and all(character.isprintable() for character in component)
    )


def _member_parts(member: tarfile.TarInfo) -> tuple[str, ...]:
    name = member.name
    if not name or name.startswith("/") or "\\" in name:
        raise InvalidBundle("archive contains an unsafe path")
    if member.isdir() and name.endswith("/"):
        name = name[:-1]
    if name.endswith("/"):
        raise InvalidBundle("archive contains an invalid path")
    parts = tuple(name.split("/"))
    if not all(_safe_component(part) for part in parts):
        raise InvalidBundle("archive contains an unsafe path")
    return parts


def _read_member(source: BinaryIO, destination: Path, size: int) -> None:
    try:
        with destination.open("xb") as output:
            remaining = size
            while remaining:
                try:
                    chunk = source.read(min(remaining, MAX_MEMBER_READ))
                except (OSError, EOFError, zlib.error) as error:
                    raise InvalidBundle("invalid compressed archive data") from error
                if not chunk:
                    raise InvalidBundle("archive member is truncated")
                try:
                    output.write(chunk)
                except OSError:
                    raise
                remaining -= len(chunk)
            output.flush()
        destination.chmod(0o640)
    except OSError:
        raise


def _extract_archive(
    body: bytes, temporary_root: Path, max_expanded_bytes: int
) -> tuple[str, str]:
    seen: dict[str, bool] = {}
    hostname: str | None = None
    bundle_name: str | None = None
    file_bytes = 0
    entry_count = 0
    try:
        compressed = gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb")
        bounded = BoundedReader(compressed, max_expanded_bytes)
        with tarfile.open(fileobj=bounded, mode="r|") as archive:
            for member in archive:
                entry_count += 1
                if entry_count > MAX_ARCHIVE_ENTRIES:
                    raise InvalidBundle("archive has too many entries")
                parts = _member_parts(member)
                relative = "/".join(parts)
                if relative in seen:
                    raise InvalidBundle("archive contains duplicate paths")

                if len(parts) == 1:
                    if hostname is not None or not member.isdir():
                        raise InvalidBundle("archive must contain one hostname directory")
                    hostname = parts[0]
                elif len(parts) == 2:
                    if (
                        hostname is None
                        or parts[0] != hostname
                        or bundle_name is not None
                        or not member.isdir()
                    ):
                        raise InvalidBundle("archive must contain one bundle directory")
                    bundle_name = parts[1]
                elif (
                    hostname is None
                    or bundle_name is None
                    or parts[:2] != (hostname, bundle_name)
                ):
                    raise InvalidBundle("archive entries must belong to one bundle")

                if len(parts) >= 3:
                    bundle_path = "/".join(parts[:2])
                    if bundle_path not in seen or not seen[bundle_path]:
                        raise InvalidBundle("archive is missing a parent directory")
                    relative_to_bundle = parts[2:]
                    if len(relative_to_bundle) == 1:
                        if relative_to_bundle[0] not in (
                            "session.json",
                            "commands.log",
                            "files",
                        ):
                            raise InvalidBundle("archive contains an unexpected bundle entry")
                        if relative_to_bundle[0] == "files":
                            if not member.isdir():
                                raise InvalidBundle("files entry must be a directory")
                        elif not member.isfile():
                            raise InvalidBundle("bundle log entries must be regular files")
                    elif relative_to_bundle[0] != "files":
                        raise InvalidBundle("archive entries must be under files/")

                    parent = "/".join(parts[:-1])
                    if parent not in seen or not seen[parent]:
                        raise InvalidBundle("archive is missing a parent directory")

                destination = temporary_root.joinpath(*parts)
                if member.isdir():
                    if member.size != 0:
                        raise InvalidBundle("directory entries must be empty")
                    destination.mkdir(mode=0o750)
                    seen[relative] = True
                elif member.isfile():
                    if member.size < 0 or member.size > max_expanded_bytes:
                        raise InvalidBundle("archive member exceeds the configured limit")
                    file_bytes += member.size
                    if file_bytes > max_expanded_bytes:
                        raise InvalidBundle("expanded archive exceeds the configured limit")
                    source = archive.extractfile(member)
                    if source is None:
                        raise InvalidBundle("could not read archive member")
                    _read_member(source, destination, member.size)
                    seen[relative] = False
                else:
                    raise InvalidBundle("archive contains a link or special file")

        while True:
            try:
                trailing = bounded.read(MAX_MEMBER_READ)
            except (OSError, EOFError, zlib.error) as error:
                raise InvalidBundle("invalid compressed archive data") from error
            if not trailing:
                break
            if any(trailing):
                raise InvalidBundle("archive contains data after its tar entries")
    except InvalidBundle:
        raise
    except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError) as error:
        raise InvalidBundle("invalid gzip tar archive") from error

    if hostname is None or bundle_name is None:
        raise InvalidBundle("archive does not contain a bundle")
    required = (
        f"{hostname}/{bundle_name}/session.json",
        f"{hostname}/{bundle_name}/commands.log",
        f"{hostname}/{bundle_name}/files",
    )
    if any(path not in seen for path in required):
        raise InvalidBundle("bundle is missing a required entry")
    if seen[required[0]] or seen[required[1]] or not seen[required[2]]:
        raise InvalidBundle("bundle has invalid required entries")
    return hostname, bundle_name


def _ensure_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o750)
    except FileExistsError:
        mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise OSError(f"{path} exists and is not a directory")


def _read_digest_marker(path: Path) -> str | None:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None


def _write_digest_marker(path: Path, digest: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".mina-digest-", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as marker:
            marker.write(digest + "\n")
            marker.flush()
            os.fsync(marker.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


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
            hostname, bundle_name = _extract_archive(
                body, temporary_root, self.max_expanded_bytes
            )
            host_directory = self.nest_dir / hostname
            _ensure_directory(host_directory)
            bundle_directory = temporary_root / hostname / bundle_name
            name, duplicate = self._publish(
                host_directory, bundle_directory, bundle_name, actual_digest
            )

        status = 200 if duplicate else 201
        return Response(f"{hostname}/{name}\n", status=status, mimetype="text/plain")

    def _publish(
        self,
        host_directory: Path,
        bundle_directory: Path,
        bundle_name: str,
        digest: str,
    ) -> tuple[str, bool]:
        lock_path = self.nest_dir / ".mina-ingest.lock"
        descriptor = os.open(
            lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        with os.fdopen(descriptor, "rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            for attempt in range(1, MAX_NAME_ATTEMPTS + 1):
                name = bundle_name if attempt == 1 else f"{bundle_name}_{attempt}"
                destination = host_directory / name
                marker = host_directory / f".{name}.mina-digest"
                if os.path.lexists(destination):
                    if (
                        destination.is_dir()
                        and not destination.is_symlink()
                        and _read_digest_marker(marker) == digest
                    ):
                        return name, True
                    continue
                if os.path.lexists(marker):
                    continue

                os.rename(bundle_directory, destination)
                _write_digest_marker(marker, digest)
                return name, False
            raise OSError(
                f"no free bundle name for {bundle_name} in {host_directory}"
            )


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
