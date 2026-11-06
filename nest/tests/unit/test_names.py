"""Tier 1: host and bundle directory names, no filesystem."""

import unittest

from mina_nest.names import is_bundle_name, is_safe_hostname


class HostnameTests(unittest.TestCase):
    def test_safe(self) -> None:
        for name in ("web-01", "web-01.example.org", "WEB_01", "unknown", "x" * 253):
            with self.subTest(name=name):
                self.assertTrue(is_safe_hostname(name))

    def test_unsafe(self) -> None:
        for name in (
            "",
            ".",
            "..",
            "../x",
            "a/b",
            ".mina-nest",
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


class BundleNameTests(unittest.TestCase):
    def test_agent_names(self) -> None:
        for name in (
            "2026-11-06_09-00-00_alice",
            "2026-11-06_09-00-00_alice_2",
            "2026-11-06_09-00-00_alice@example.org",
        ):
            with self.subTest(name=name):
                self.assertTrue(is_bundle_name(name))

    def test_not_agent_names(self) -> None:
        for name in (
            "bundle1",
            "2026-11-06_09-00-00",
            "2026-11-06_09-00-00_",
            "2026-11-06T09-00-00_alice",
            "26-11-06_09-00-00_alice",
            "２０２６-11-06_09-00-00_alice",
            "x2026-11-06_09-00-00_alice",
        ):
            with self.subTest(name=name):
                self.assertFalse(is_bundle_name(name))


if __name__ == "__main__":
    unittest.main()
