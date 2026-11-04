"""Tier 1: path validation of archive members, no filesystem."""

from __future__ import annotations

import unittest

from mina_nest.ingest import InvalidBundle


class PathComponentSecurityTests(unittest.TestCase):
    """Test the path component validation logic."""

    def test_safe_component_validation(self) -> None:
        """Test the _safe_component function logic through member validation."""
        from mina_nest.ingest import _safe_component

        # Valid components
        self.assertTrue(_safe_component("normal"))
        self.assertTrue(_safe_component("file123"))
        self.assertTrue(_safe_component("a"))
        self.assertTrue(_safe_component("A" * 255))

        # Invalid components
        self.assertFalse(_safe_component(""))
        self.assertFalse(_safe_component("."))
        self.assertFalse(_safe_component(".."))
        self.assertFalse(_safe_component("file/name"))
        self.assertFalse(_safe_component("file\\name"))
        self.assertFalse(_safe_component("a" * 256))  # Too long
        self.assertFalse(_safe_component("file\x00name"))  # Null byte
        self.assertFalse(_safe_component("file\x01name"))  # Control char

    def test_member_parts_validation(self) -> None:
        """Test the _member_parts function validation."""

        from mina_nest.ingest import _member_parts

        # Create mock TarInfo objects
        class MockTarInfo:
            def __init__(self, name, isdir=False):
                self.name = name
                self._isdir = isdir

            def isdir(self):
                return self._isdir

        # Valid paths
        member = MockTarInfo("host1/bundle1/files/test.txt")
        parts = _member_parts(member)
        self.assertEqual(parts, ("host1", "bundle1", "files", "test.txt"))

        # Paths with trailing slash
        member = MockTarInfo("host1/bundle1/", isdir=True)
        parts = _member_parts(member)
        self.assertEqual(parts, ("host1", "bundle1"))

        # Invalid paths should raise
        with self.assertRaises(InvalidBundle):
            member = MockTarInfo("")
            _member_parts(member)

        with self.assertRaises(InvalidBundle):
            member = MockTarInfo("/etc/passwd")
            _member_parts(member)

        with self.assertRaises(InvalidBundle):
            member = MockTarInfo("host1\\bundle1")
            _member_parts(member)

        with self.assertRaises(InvalidBundle):
            member = MockTarInfo("host1/../etc/passwd")
            _member_parts(member)

        with self.assertRaises(InvalidBundle):
            member = MockTarInfo("host1/bundle1/")
            _member_parts(member)


if __name__ == "__main__":
    unittest.main()
