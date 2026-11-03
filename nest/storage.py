"""Atomic publication and retry deduplication for received bundles."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from pathlib import Path

MAX_NAME_ATTEMPTS = 100


def ensure_host_directory(path: Path) -> None:
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


def publish_bundle(
    nest_dir: Path,
    host_directory: Path,
    bundle_directory: Path,
    bundle_name: str,
    digest: str,
) -> tuple[str, bool]:
    """Atomically publish a complete bundle, or identify an idempotent retry."""
    lock_path = nest_dir / ".mina-ingest.lock"
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
        raise OSError(f"no free bundle name for {bundle_name} in {host_directory}")
