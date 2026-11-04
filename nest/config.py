"""Central configuration for Mina Nest receiver."""

from __future__ import annotations

import os
from typing import Final

# ---------------------------------------------------------------------------
# Archive limits
# ---------------------------------------------------------------------------

MAX_ARCHIVE_ENTRIES: Final = int(
    os.environ.get("MINA_MAX_ARCHIVE_ENTRIES", "100000")
)
"""Maximum number of entries allowed in a bundle archive."""

MAX_MEMBER_READ: Final = int(
    os.environ.get("MINA_MAX_MEMBER_READ", "65536")  # 64KB
)
"""Maximum bytes to read per chunk from archive members."""

# ---------------------------------------------------------------------------
# Upload/expansion limits (bytes)
# ---------------------------------------------------------------------------

DEFAULT_MAX_UPLOAD_BYTES: Final = int(
    os.environ.get("MINA_DEFAULT_MAX_UPLOAD_BYTES", "67108864")  # 64MB
)
"""Default maximum upload size in bytes."""

DEFAULT_MAX_EXPANDED_BYTES: Final = int(
    os.environ.get("MINA_DEFAULT_MAX_EXPANDED_BYTES", "536870912")  # 512MB
)
"""Default maximum decompressed archive size in bytes."""

# ---------------------------------------------------------------------------
# Storage/naming limits
# ---------------------------------------------------------------------------

MAX_NAME_ATTEMPTS: Final = int(
    os.environ.get("MINA_MAX_NAME_ATTEMPTS", "100")
)
"""Maximum attempts to find a unique bundle name."""

# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------

DEFAULT_DIR_MODE: Final = 0o750
"""Default mode for created directories."""

DEFAULT_FILE_MODE: Final = 0o640
"""Default mode for created files."""

# ---------------------------------------------------------------------------
# Digest header
# ---------------------------------------------------------------------------

DIGEST_HEADER: Final = "X-Mina-Bundle-Digest"
"""HTTP header name for bundle digest verification."""

# ---------------------------------------------------------------------------
# Path/Directory names
# ---------------------------------------------------------------------------

LOCK_FILE: Final = ".mina-ingest.lock"
"""Name of the ingest lock file."""

DIGEST_MARKER_PREFIX: Final = ".mina-digest-"
"""Prefix for digest marker temporary files."""

UPLOAD_TEMP_PREFIX: Final = ".mina-upload-"
"""Prefix for temporary upload directories."""

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

REQUIRED_BUNDLE_FILES: Final = ("session.json", "commands.log", "files")
"""Required entries in every bundle (in this exact order for validation)."""

UNSAFE_PATH_COMPONENTS: Final = frozenset(
    {"", ".", "..", "/", "\\"}
)
"""Path components that are never allowed."""

MAX_PATH_COMPONENT_LENGTH: Final = 255
"""Maximum length of a single path component."""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_max_upload_mb() -> int:
    """Get max upload size in MB from config or environment."""
    return DEFAULT_MAX_UPLOAD_BYTES // (1024 * 1024)


def get_max_expanded_mb() -> int:
    """Get max expanded size in MB from config or environment."""
    return DEFAULT_MAX_EXPANDED_BYTES // (1024 * 1024)


def get_nest_dir() -> str:
    """Get the default nest directory from environment or use /var/mina."""
    return os.environ.get("MINA_NEST_DIR", "/var/mina")


def get_host() -> str:
    """Get the default host from environment or use 127.0.0.1."""
    return os.environ.get("MINA_HOST", "127.0.0.1")


def get_port() -> int:
    """Get the default port from environment or use 8080."""
    port = os.environ.get("MINA_PORT", "8080")
    return int(port)
