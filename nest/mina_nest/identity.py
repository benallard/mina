"""Client certificate to host directory mapping for Mina Nest.

This module provides the identity mapping functionality that allows the nest
to determine the host directory from client certificates, overriding the
hostname inside the bundle tarball when certificates are configured.

The mapper is a pluggable Python callable, specified via the environment
variable MINA_IDENTITY_MAPPER in the format 'module:function'. This keeps
all deployment-specific certificate handling out of Mina's core.
"""

from __future__ import annotations

import importlib
import logging
import os
from typing import Callable

from werkzeug.wrappers import Request

LOGGER = logging.getLogger("mina.nest.identity")

HostMapper = Callable[[str], str]
"""Type for host mapper functions: takes a DN string, returns a hostname."""

_mapper: HostMapper | None = None


def _load_mapper() -> HostMapper | None:
    """Load the host mapper from MINA_IDENTITY_MAPPER environment variable.
    
    The value must be in the format 'module:callable', e.g. 'my_site.mapper:dn_to_host'.
    Returns None if not configured or loading fails.
    """
    global _mapper
    if _mapper is not None:
        return _mapper

    mapper_spec = os.environ.get("MINA_IDENTITY_MAPPER")
    if mapper_spec is None:
        return None

    try:
        module_path, func_name = mapper_spec.rsplit(":", 1)
    except ValueError:
        LOGGER.error(
            "MINA_IDENTITY_MAPPER must be in format 'module:function', got %s",
            mapper_spec,
        )
        return None

    try:
        module = importlib.import_module(module_path)
        mapper_func = getattr(module, func_name)
        if not callable(mapper_func):
            LOGGER.error("Mapper %s is not callable", mapper_spec)
            return None
        _mapper = mapper_func
        return _mapper
    except (ImportError, AttributeError) as error:
        LOGGER.error("Failed to load mapper %s: %s", mapper_spec, error)
        return None


def get_hostname(request: Request) -> str | None:
    """
    Get the hostname from client certificate using the configured mapper.

    Checks the request environment for the client certificate Distinguished
    Name (typically set by nginx as SSL_CLIENT_S_DN or HTTP_SSL_CLIENT_S_DN).

    Args:
        request: The Werkzeug request object

    Returns:
        The mapped hostname if a mapper is configured and a valid certificate
        DN is present, otherwise None.

    Note:
        When this returns a non-None value, the tarball's hostname should be
        ignored per the design: "the host directory is what the certificate
        maps to, and the hostname inside the tarball is ignored."
    """
    mapper = _load_mapper()
    if mapper is None:
        return None

    # Nginx with ssl_verify_client sets SSL_CLIENT_S_DN in the environment
    # When proxying via HTTP, it becomes HTTP_SSL_CLIENT_S_DN
    dn = request.environ.get("SSL_CLIENT_S_DN")
    if dn is None:
        dn = request.environ.get("HTTP_SSL_CLIENT_S_DN")

    if dn is None:
        LOGGER.debug("No client certificate DN in request")
        return None

    try:
        hostname = mapper(dn)
        if not hostname:
            LOGGER.warning("Mapper returned empty hostname for DN '%s'", dn)
            return None
        return hostname
    except Exception as error:
        LOGGER.warning("Host mapper failed for DN '%s': %s", dn, error)
        return None
