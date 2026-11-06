"""Validation, safe extraction and atomic publication of Mina bundles."""

from __future__ import annotations

import fcntl
import gzip
import io
import logging
import os
import shutil
import stat
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import BinaryIO

from mina_nest.config import (
    DEFAULT_DIR_MODE,
    DEFAULT_FILE_MODE,
    DIGEST_MARKER_PREFIX,
    FILES_DIRECTORY,
    LOCK_FILE,
    MAX_ARCHIVE_ENTRIES,
    MAX_MEMBER_READ,
    MAX_NAME_ATTEMPTS,
    MAX_PATH_COMPONENT_LENGTH,
    REQUIRED_BUNDLE_FILES,
)
from mina_nest.names import is_bundle_name, is_safe_hostname

LOGGER = logging.getLogger("mina.nest.archive")


class InvalidBundle(Exception):
    """The request body is not a valid Mina bundle archive."""


class BundleTooLarge(InvalidBundle):
    """The archive is over a size or entry limit (413, not malformed)."""


class BoundedReader:
    """
    Limit bytes decompressed from gzip and the size of individual reads.

    This is a performance-optimized reader that:
    - Minimizes conditional checks in the hot path
    - Reduces object allocations
    - Uses local variable caching for faster access
    """

    __slots__ = ("source", "limit", "total")

    def __init__(self, source: BinaryIO, limit: int) -> None:
        self.source = source
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        # Use local variables for faster access
        source = self.source
        limit = self.limit
        total = self.total

        # Fast path: size < 0 means read up to MAX_MEMBER_READ
        if size < 0:
            size = MAX_MEMBER_READ

        # Calculate actual read size with bounds checking
        # self.limit - self.total + 1 ensures we don't exceed limit
        # But we also need to respect MAX_MEMBER_READ
        available = limit - total
        if available <= 0:
            raise BundleTooLarge("expanded archive exceeds the configured limit")

        read_size = size if size < available else available

        # Read and update total
        data = source.read(read_size)
        new_total = total + len(data)

        if new_total > limit:
            raise BundleTooLarge("expanded archive exceeds the configured limit")

        self.total = new_total
        return data


def _safe_component(component: str) -> bool:
    # Check for unsafe path components (empty, ., ..)
    if component in ("", ".", ".."):
        return False
    # Check for path separators
    if "/" in component or "\\" in component:
        return False
    # Check length
    if len(component) > MAX_PATH_COMPONENT_LENGTH:
        return False
    # Check for printable characters
    return all(character.isprintable() for character in component)


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
    """
    Copy file data from source to destination efficiently.

    Uses buffered copying with size limit for performance and safety.
    Falls back to chunked reading if shutil.copyfileobj doesn't respect limits.
    """
    # Create parent directory if needed
    destination.parent.mkdir(parents=True, exist_ok=True, mode=DEFAULT_DIR_MODE)

    # Use low-level file descriptor for better performance
    # O_EXCL already refuses an existing name, symlinks included; O_NOFOLLOW
    # says so explicitly, should a link ever get here.
    fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        DEFAULT_FILE_MODE,
    )
    try:
        with os.fdopen(fd, "wb") as output:
            # Use shutil.copyfileobj for better performance
            # But we need to limit total bytes to 'size'
            bytes_copied = 0
            while bytes_copied < size:
                chunk_size = min(MAX_MEMBER_READ, size - bytes_copied)
                try:
                    chunk = source.read(chunk_size)
                except (OSError, EOFError, zlib.error) as error:
                    raise InvalidBundle("invalid compressed archive data") from error
                if not chunk:
                    raise InvalidBundle("archive member is truncated")
                output.write(chunk)
                bytes_copied += len(chunk)
            output.flush()
    except Exception:
        # Clean up on error
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    """Make the entries of directory `path` durable."""
    _fsync_path(path, os.O_RDONLY | os.O_DIRECTORY)


def _fsync_path(path: Path, flags: int = os.O_RDONLY) -> None:
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_extracted(paths: list[Path]) -> None:
    """Remove all extracted files and directories on failure."""
    for path in reversed(paths):
        try:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                path.unlink()
        except OSError as error:
            LOGGER.warning("Failed to cleanup %s: %s", path, error)


def extract_archive(
    body: bytes, temporary_root: Path, max_expanded_bytes: int
) -> tuple[str, str]:
    """
    Validate and extract one Mina bundle into a fresh temporary directory.

    Args:
        body: The gzip-compressed tar archive bytes
        temporary_root: Directory to extract into
        max_expanded_bytes: Maximum allowed decompressed size

    Returns:
        Tuple of (hostname, bundle_name)

    Raises:
        InvalidBundle: If archive fails validation
        OSError: If file operations fail
    """
    # Use a dict for O(1) lookups
    seen: dict[str, bool] = {}
    hostname: str | None = None
    bundle_name: str | None = None
    file_bytes = 0
    entry_count = 0
    extracted_paths: list[Path] = []  # Track all created paths for cleanup

    # Pre-compute required paths for faster validation
    required_files = REQUIRED_BUNDLE_FILES

    try:
        # Use BytesIO directly with gzip for better performance
        compressed = gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb")
        bounded = BoundedReader(compressed, max_expanded_bytes)
        with tarfile.open(fileobj=bounded, mode="r|") as archive:
            # Cache MAX_ARCHIVE_ENTRIES in local variable for faster access
            max_entries = MAX_ARCHIVE_ENTRIES
            required_files_set = set(required_files)

            for member in archive:
                entry_count += 1
                if entry_count > max_entries:
                    raise BundleTooLarge("archive has too many entries")

                # Validate and get path parts
                parts = _member_parts(member)
                parts_len = len(parts)

                # Build relative path once
                relative = "/".join(parts)

                # Check for duplicates
                if relative in seen:
                    raise InvalidBundle("archive contains duplicate paths")

                # Validate and track bundle structure
                if parts_len == 1:
                    if hostname is not None:
                        raise InvalidBundle(
                            "archive must contain one hostname directory"
                        )
                    if not member.isdir():
                        raise InvalidBundle(
                            "archive must contain one hostname directory"
                        )
                    if not is_safe_hostname(parts[0]):
                        raise InvalidBundle("archive hostname is not a valid host name")
                    hostname = parts[0]
                elif parts_len == 2:
                    if hostname is None:
                        raise InvalidBundle("archive must contain one bundle directory")
                    if parts[0] != hostname:
                        raise InvalidBundle("archive must contain one bundle directory")
                    if bundle_name is not None:
                        raise InvalidBundle("archive must contain one bundle directory")
                    if not member.isdir():
                        raise InvalidBundle("archive must contain one bundle directory")
                    if not is_bundle_name(parts[1]):
                        raise InvalidBundle(
                            "bundle name must be YYYY-MM-DD_HH-MM-SS_<user>"
                        )
                    bundle_name = parts[1]
                else:
                    # parts_len >= 3
                    if hostname is None or bundle_name is None:
                        raise InvalidBundle("archive entries must belong to one bundle")
                    if parts[0] != hostname or parts[1] != bundle_name:
                        raise InvalidBundle("archive entries must belong to one bundle")

                # Only check files/ structure if we have at least 3 parts
                if parts_len >= 3:
                    # Check parent directory exists (bundle_path = hostname/bundle_name)
                    bundle_path = "/".join(parts[:2])
                    if bundle_path not in seen or not seen[bundle_path]:
                        raise InvalidBundle("archive is missing a parent directory")

                    # Get the part relative to bundle
                    relative_to_bundle = parts[2:]
                    relative_len = len(relative_to_bundle)

                    if relative_len == 1:
                        # This is a direct child of the bundle directory
                        child_name = relative_to_bundle[0]
                        if child_name == FILES_DIRECTORY:
                            if not member.isdir():
                                raise InvalidBundle("files entry must be a directory")
                        elif child_name not in required_files_set:
                            raise InvalidBundle(
                                "archive contains an unexpected bundle entry"
                            )
                        elif not member.isfile():
                            raise InvalidBundle(
                                "bundle log entries must be regular files"
                            )
                    elif relative_to_bundle[0] != FILES_DIRECTORY:
                        raise InvalidBundle("archive entries must be under files/")

                    # Check parent directory exists for nested files
                    parent = "/".join(parts[:-1])
                    if parent not in seen or not seen[parent]:
                        raise InvalidBundle("archive is missing a parent directory")

                # tarfile counts GNU sparse members as regular files; the
                # agent never writes them.
                if member.type == tarfile.GNUTYPE_SPARSE or member.issparse():
                    raise InvalidBundle("archive contains a sparse file")

                destination = temporary_root.joinpath(*parts)
                if member.isdir():
                    if member.size != 0:
                        raise InvalidBundle("directory entries must be empty")
                    destination.mkdir(mode=DEFAULT_DIR_MODE)
                    extracted_paths.append(destination)
                    seen[relative] = True
                elif member.isfile():
                    if member.size < 0 or member.size > max_expanded_bytes:
                        raise BundleTooLarge(
                            "archive member exceeds the configured limit"
                        )
                    file_bytes += member.size
                    if file_bytes > max_expanded_bytes:
                        raise BundleTooLarge(
                            "expanded archive exceeds the configured limit"
                        )
                    source = archive.extractfile(member)
                    if source is None:
                        raise InvalidBundle("could not read archive member")
                    _read_member(source, destination, member.size)
                    extracted_paths.append(destination)
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
        # Clean up any extracted files/directories on failure
        _cleanup_extracted(extracted_paths)
        raise
    except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError) as error:
        # Clean up any extracted files/directories on failure
        _cleanup_extracted(extracted_paths)
        raise InvalidBundle("invalid gzip tar archive") from error

    # Final validation checks - these can also fail
    try:
        if hostname is None or bundle_name is None:
            raise InvalidBundle("archive does not contain a bundle")
        required = tuple(f"{hostname}/{bundle_name}/{f}" for f in REQUIRED_BUNDLE_FILES)
        if any(path not in seen for path in required):
            raise InvalidBundle("bundle is missing a required entry")
        # seen[path] is True for directories; files/ was checked when read.
        if any(seen[path] for path in required):
            raise InvalidBundle("bundle has invalid required entries")
    except InvalidBundle:
        # Clean up any extracted files/directories on validation failure
        _cleanup_extracted(extracted_paths)
        raise

    # Put the whole tree on disk before publish_bundle makes it visible: file
    # contents, then directory entries. Only now, after validation, so a
    # refused upload costs no fsync at all.
    for path in extracted_paths:
        if not path.is_dir():
            _fsync_path(path)
    for path in extracted_paths:
        if path.is_dir():
            _fsync_directory(path)

    # All validation passed, no need for cleanup list anymore
    extracted_paths.clear()
    return hostname, bundle_name


def ensure_host_directory(path: Path) -> None:
    try:
        path.mkdir(mode=DEFAULT_DIR_MODE)
        _fsync_directory(path.parent)
    except FileExistsError:
        mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise OSError(f"{path} exists and is not a directory") from None


def _read_digest_marker(path: Path) -> str | None:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None


def _write_digest_marker(path: Path, digest: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=DIGEST_MARKER_PREFIX, dir=path.parent
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


def publish_bundle(
    nest_dir: Path,
    host_directory: Path,
    bundle_directory: Path,
    bundle_name: str,
    digest: str,
) -> tuple[str, bool]:
    """Atomically publish a complete bundle, or identify an idempotent retry."""
    lock_path = nest_dir / LOCK_FILE
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
            # The rename and the marker are entries of the host directory;
            # only once they are on disk may the agent drop its copy.
            _fsync_directory(host_directory)
            return name, False
        raise OSError(f"no free bundle name for {bundle_name} in {host_directory}")
