"""Validation and safe extraction for Mina gzip tar bundles."""

from __future__ import annotations

import gzip
import io
import tarfile
import zlib
from pathlib import Path
from typing import BinaryIO

MAX_ARCHIVE_ENTRIES = 100_000
MAX_MEMBER_READ = 64 * 1024


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
    with destination.open("xb") as output:
        remaining = size
        while remaining:
            try:
                chunk = source.read(min(remaining, MAX_MEMBER_READ))
            except (OSError, EOFError, zlib.error) as error:
                raise InvalidBundle("invalid compressed archive data") from error
            if not chunk:
                raise InvalidBundle("archive member is truncated")
            output.write(chunk)
            remaining -= len(chunk)
        output.flush()
    destination.chmod(0o640)


def extract_archive(
    body: bytes, temporary_root: Path, max_expanded_bytes: int
) -> tuple[str, str]:
    """Validate and extract one Mina bundle into a fresh temporary directory."""
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
