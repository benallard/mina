"""Tier 1: client certificate to host mapping, no filesystem."""

import os.path
import unittest

from mina_nest.identity import (
    IdentityError,
    IdentityRefused,
    host_from_headers,
    is_safe_hostname,
    load_mapper,
)

VERIFIED = {"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-DN": "CN=web-01,O=Fleet"}


def cn(dn: str) -> str | None:
    """A mapper of the kind a site writes: the CN, if any."""
    for part in dn.split(","):
        key, _, value = part.partition("=")
        if key == "CN":
            return value
    return None


class LoadMapperTests(unittest.TestCase):
    def test_unset_means_no_mapper(self) -> None:
        self.assertIsNone(load_mapper(None))
        self.assertIsNone(load_mapper(""))

    def test_loads_module_function(self) -> None:
        self.assertIs(load_mapper("os.path:basename"), os.path.basename)

    def test_bad_specs_raise(self) -> None:
        for spec, error in (
            ("no-colon", ValueError),
            (":function", ValueError),
            ("os.path:", ValueError),
            ("os:sep", ValueError),  # not callable
            ("os.path:no_such_function", ValueError),
            ("no_such_module_for_mina:f", ImportError),
        ):
            with self.subTest(spec=spec), self.assertRaises(error):
                load_mapper(spec)


class HostnameTests(unittest.TestCase):
    def test_safe(self) -> None:
        for name in ("web-01", "web-01.example.org", "WEB_01", "a", "x" * 253):
            with self.subTest(name=name):
                self.assertTrue(is_safe_hostname(name))

    def test_unsafe(self) -> None:
        for name in (
            "",
            ".",
            "..",
            "../x",
            "a/b",
            ".hidden",
            "-x",
            "a b",
            "a\x00b",
            "é",
            "x" * 254,
            None,
            42,
        ):
            with self.subTest(name=name):
                self.assertFalse(is_safe_hostname(name))


class HostFromHeadersTests(unittest.TestCase):
    def test_maps_verified_dn(self) -> None:
        self.assertEqual(host_from_headers(VERIFIED, cn), "web-01")

    def test_requires_success(self) -> None:
        for verify in (None, "NONE", "FAILED:certificate has expired", "success"):
            headers = {"X-SSL-Client-DN": "CN=web-01"}
            if verify is not None:
                headers["X-SSL-Client-Verify"] = verify
            with self.subTest(verify=verify), self.assertRaises(IdentityRefused):
                host_from_headers(headers, cn)

    def test_requires_dn(self) -> None:
        with self.assertRaises(IdentityRefused):
            host_from_headers({"X-SSL-Client-Verify": "SUCCESS"}, cn)

    def test_unmapped_is_refused(self) -> None:
        for result in (None, ""):
            with self.subTest(result=result), self.assertRaises(IdentityRefused):
                host_from_headers(VERIFIED, lambda dn, r=result: r)

    def test_unsafe_mapping_is_an_error(self) -> None:
        for result in ("../escape", "a/b", ".mina-nest", 7):
            with self.subTest(result=result), self.assertRaises(IdentityError):
                host_from_headers(VERIFIED, lambda dn, r=result: r)

    def test_failing_mapper_is_an_error(self) -> None:
        def broken(dn: str) -> str:
            raise KeyError(dn)

        with self.assertRaises(IdentityError) as context:
            host_from_headers(VERIFIED, broken)
        self.assertIsInstance(context.exception.__cause__, KeyError)


if __name__ == "__main__":
    unittest.main()
