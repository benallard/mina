"""Client certificate to host directory mapping for Mina Nest.

nginx verifies the client certificate and passes its verdict and the
subject DN as request headers (see examples/nginx.conf). A site maps the
DN to a host directory with its own Python callable, named in the
environment variable MINA_IDENTITY_MAPPER as 'module:function'. This keeps
all deployment-specific certificate handling out of Mina's core.

With a mapper configured, every upload must carry a verified certificate
that maps to a safe host name, or it is refused; the hostname inside the
tarball is then ignored. Without a mapper, the nest uses the tarball's
hostname and logs the bundle as unauthenticated. The two never mix.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable, Mapping

from mina_nest.names import is_safe_hostname

VERIFY_HEADER = "X-SSL-Client-Verify"
"""nginx's $ssl_client_verify: SUCCESS, NONE or FAILED:<reason>."""

DN_HEADER = "X-SSL-Client-DN"
"""nginx's $ssl_client_s_dn: the verified certificate's subject DN."""

MAPPER_ENV = "MINA_IDENTITY_MAPPER"

HostMapper = Callable[[str], str | None]
"""Takes a subject DN, returns the host directory name, or None if unknown."""


class IdentityRefused(Exception):
    """The client has no verified certificate that maps to a host (403)."""


class IdentityError(Exception):
    """The mapper failed or returned an unusable name (500: retry later)."""


def load_mapper(spec: str | None) -> HostMapper | None:
    """Import the mapper named by `spec` ('module:function').

    None or empty means no mapper. A spec that cannot be loaded raises, so a
    misconfigured nest fails at startup instead of on the first upload.
    """
    if not spec:
        return None
    module_path, _, name = spec.rpartition(":")
    if not module_path or not name:
        raise ValueError(f"{MAPPER_ENV} must be 'module:function', got {spec!r}")
    mapper = getattr(importlib.import_module(module_path), name, None)
    if not callable(mapper):
        raise ValueError(f"{MAPPER_ENV} {spec!r} is not a callable")
    return mapper


def mapper_from_env() -> HostMapper | None:
    """The mapper named in MINA_IDENTITY_MAPPER, if any."""
    return load_mapper(os.environ.get(MAPPER_ENV))


def host_from_headers(headers: Mapping[str, str], mapper: HostMapper) -> str:
    """The host directory for a request, from nginx's certificate headers.

    Raises IdentityRefused without a verified certificate or when the
    mapper does not know it, and IdentityError when the mapper fails or
    returns a name that is not safe as a directory name.
    """
    if headers.get(VERIFY_HEADER) != "SUCCESS":
        raise IdentityRefused("a verified client certificate is required")
    dn = headers.get(DN_HEADER)
    if not dn:
        raise IdentityRefused("the client certificate has no subject")
    try:
        host = mapper(dn)
    except Exception as error:
        raise IdentityError(f"identity mapper failed for {dn!r}") from error
    if host is None or host == "":
        raise IdentityRefused(f"client certificate {dn!r} is not mapped to a host")
    if not is_safe_hostname(host):
        raise IdentityError(f"identity mapper returned an unsafe host name {host!r}")
    return host
