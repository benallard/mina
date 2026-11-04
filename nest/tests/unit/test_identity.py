"""Unit tests for the identity module."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from werkzeug.wrappers import Request


class IdentityMapperTests(unittest.TestCase):
    """Tests for identity mapper loading and hostname extraction."""

    def test_no_mapper_configured_returns_none(self) -> None:
        """When MINA_IDENTITY_MAPPER is not set, get_hostname returns None."""
        with mock.patch.dict(os.environ, {}, clear=True):
            # Force reimport without the env var
            import importlib

            import mina_nest.identity as identity_module

            importlib.reload(identity_module)
            from mina_nest.identity import get_hostname

            environ = {}
            request = Request(environ)
            self.assertIsNone(get_hostname(request))

    def test_no_cert_in_request_returns_none(self) -> None:
        """When no certificate DN is in the request, get_hostname returns None."""
        with mock.patch.dict(os.environ, {"MINA_IDENTITY_MAPPER": "nonexistent:func"}):
            import importlib

            import mina_nest.identity as identity_module

            importlib.reload(identity_module)
            from mina_nest.identity import get_hostname

            environ = {"REQUEST_METHOD": "POST"}
            request = Request(environ)
            self.assertIsNone(get_hostname(request))

    def test_mapper_loads_from_env(self) -> None:
        """Mapper is loaded from MINA_IDENTITY_MAPPER environment variable."""
        # Create a temporary module with a mapper function
        mapper_code = """
def my_mapper(dn):
    return "mapped-host"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(mapper_code)
            mapper_path = f.name

        try:
            # Add to path and set environment
            module_name = Path(mapper_path).stem
            sys.path.insert(0, str(Path(mapper_path).parent))

            env = {"MINA_IDENTITY_MAPPER": f"{module_name}:my_mapper"}
            with mock.patch.dict(os.environ, env, clear=False):
                import importlib

                import mina_nest.identity as identity_module

                importlib.reload(identity_module)
                from mina_nest.identity import get_hostname

                environ = {
                    "REQUEST_METHOD": "POST",
                    "SSL_CLIENT_S_DN": "CN=test.example.com",
                }
                request = Request(environ)
                hostname = get_hostname(request)
                self.assertEqual(hostname, "mapped-host")

        finally:
            if mapper_path in sys.path:
                sys.path.remove(str(Path(mapper_path).parent))
            os.unlink(mapper_path)

    def test_ssl_client_s_dn_header(self) -> None:
        """SSL_CLIENT_S_DN is read from request environment."""
        mapper_code = """
def my_mapper(dn):
    return dn
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(mapper_code)
            mapper_path = f.name

        try:
            module_name = Path(mapper_path).stem
            sys.path.insert(0, str(Path(mapper_path).parent))

            env = {"MINA_IDENTITY_MAPPER": f"{module_name}:my_mapper"}
            with mock.patch.dict(os.environ, env, clear=False):
                import importlib

                import mina_nest.identity as identity_module

                importlib.reload(identity_module)
                from mina_nest.identity import get_hostname

                dn = "CN=myhost.example.com,O=My Org"
                environ = {"REQUEST_METHOD": "POST", "SSL_CLIENT_S_DN": dn}
                request = Request(environ)
                hostname = get_hostname(request)
                self.assertEqual(hostname, dn)

        finally:
            if str(Path(mapper_path).parent) in sys.path:
                sys.path.remove(str(Path(mapper_path).parent))
            os.unlink(mapper_path)

    def test_http_ssl_client_s_dn_fallback(self) -> None:
        """HTTP_SSL_CLIENT_S_DN is used as fallback for proxied requests."""
        mapper_code = """
def my_mapper(dn):
    return dn
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(mapper_code)
            mapper_path = f.name

        try:
            module_name = Path(mapper_path).stem
            sys.path.insert(0, str(Path(mapper_path).parent))

            env = {"MINA_IDENTITY_MAPPER": f"{module_name}:my_mapper"}
            with mock.patch.dict(os.environ, env, clear=False):
                import importlib

                import mina_nest.identity as identity_module

                importlib.reload(identity_module)
                from mina_nest.identity import get_hostname

                dn = "CN=myhost.example.com"
                environ = {"REQUEST_METHOD": "POST", "HTTP_SSL_CLIENT_S_DN": dn}
                request = Request(environ)
                hostname = get_hostname(request)
                self.assertEqual(hostname, dn)

        finally:
            if str(Path(mapper_path).parent) in sys.path:
                sys.path.remove(str(Path(mapper_path).parent))
            os.unlink(mapper_path)

    def test_mapper_error_returns_none(self) -> None:
        """If mapper raises an exception, get_hostname returns None."""
        mapper_code = """
def broken_mapper(dn):
    raise ValueError("mapper error")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(mapper_code)
            mapper_path = f.name

        try:
            module_name = Path(mapper_path).stem
            sys.path.insert(0, str(Path(mapper_path).parent))

            env = {"MINA_IDENTITY_MAPPER": f"{module_name}:broken_mapper"}
            with mock.patch.dict(os.environ, env, clear=False):
                import importlib

                import mina_nest.identity as identity_module

                importlib.reload(identity_module)
                from mina_nest.identity import get_hostname

                environ = {"REQUEST_METHOD": "POST", "SSL_CLIENT_S_DN": "CN=test"}
                request = Request(environ)
                hostname = get_hostname(request)
                self.assertIsNone(hostname)

        finally:
            if str(Path(mapper_path).parent) in sys.path:
                sys.path.remove(str(Path(mapper_path).parent))
            os.unlink(mapper_path)

    def test_empty_hostname_from_mapper_returns_none(self) -> None:
        """If mapper returns empty string, get_hostname returns None."""
        mapper_code = """
def empty_mapper(dn):
    return ""
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(mapper_code)
            mapper_path = f.name

        try:
            module_name = Path(mapper_path).stem
            sys.path.insert(0, str(Path(mapper_path).parent))

            env = {"MINA_IDENTITY_MAPPER": f"{module_name}:empty_mapper"}
            with mock.patch.dict(os.environ, env, clear=False):
                import importlib

                import mina_nest.identity as identity_module

                importlib.reload(identity_module)
                from mina_nest.identity import get_hostname

                environ = {"REQUEST_METHOD": "POST", "SSL_CLIENT_S_DN": "CN=test"}
                request = Request(environ)
                hostname = get_hostname(request)
                self.assertIsNone(hostname)

        finally:
            if str(Path(mapper_path).parent) in sys.path:
                sys.path.remove(str(Path(mapper_path).parent))
            os.unlink(mapper_path)


if __name__ == "__main__":
    unittest.main()
