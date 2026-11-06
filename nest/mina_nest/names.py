"""Names the nest accepts for host and bundle directories.

Both become path components directly under the nest directory, next to
the nest's own hidden bookkeeping, so they are checked on top of the
general path checks in ingest.py.
"""

from __future__ import annotations

import re

# Letters, digits, '.', '-', '_'; not starting with '.' or '-': no '..', no
# hidden names, nothing that reads as an option. 253 is DNS's limit.
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,252}")

# The agent's {YYYY-MM-DD_HH-MM-SS}_{user}, maybe with a _2, _3, … suffix
# (part of the user part here). The user part is not narrowed further:
# site usernames vary (alice@example.org), and ingest.py already refuses
# separators, control characters and over-long components.
_BUNDLE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_.+")


def is_safe_hostname(name: object) -> bool:
    """True if `name` can be used as a host directory name."""
    return isinstance(name, str) and _HOSTNAME_RE.fullmatch(name) is not None


def is_bundle_name(name: str) -> bool:
    """True if `name` has the agent's bundle name layout."""
    return _BUNDLE_RE.fullmatch(name) is not None
