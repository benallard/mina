"""Tests for archive validation against generic archive attacks."""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from mina_nest.ingest import extract_archive, InvalidBundle


class ArchiveSecurityTests(unittest.TestCase):
    """Test suite for archive security against common attacks."""

    def _create_archive_with(self, extra_members: list[tuple[str, bytes, int | None]] = None) -> bytes:
        """Helper to create a valid base archive with optional extra members."""
        if extra_members is None:
            extra_members = []
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            # Required directory structure
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)

            # Required files
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))

            # Add extra members if specified
            for path, contents, member_type in extra_members:
                member = tarfile.TarInfo(path)
                if member_type == "dir":
                    member.type = tarfile.DIRTYPE
                    member.size = 0
                elif member_type == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = contents.decode() if isinstance(contents, bytes) else contents
                    member.size = 0
                elif member_type == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = contents.decode() if isinstance(contents, bytes) else contents
                    member.size = 0
                else:
                    member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents) if member_type is None else io.BytesIO(b""))

        return outer.getvalue()

    def test_zip_bomb_decompression_limit(self) -> None:
        """Test that decompression bomb (zip bomb) is rejected by size limit."""
        # Create a highly compressible 50MB file
        compressible_data = b"\x00" * (50 * 1024 * 1024)
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1/bundle1/files/bomb.bin")
            member.size = len(compressible_data)
            outer_tar.addfile(member, io.BytesIO(compressible_data))

        body = outer.getvalue()
        # Set a small limit (10MB) - should reject the 50MB decompressed file
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=10 * 1024 * 1024)
            self.assertIn("exceeds the configured limit", str(context.exception))

    def test_too_many_entries(self) -> None:
        """Test that archives with too many entries are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # Add more than MAX_ARCHIVE_ENTRIES (100,000) files
            for i in range(100001):
                member = tarfile.TarInfo(f"host1/bundle1/files/file_{i}.txt")
                member.size = 1
                outer_tar.addfile(member, io.BytesIO(b"x"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024 * 1024)
            self.assertIn("too many entries", str(context.exception))

    def test_path_traversal_with_dotdot(self) -> None:
        """Test that path traversal with ../.. is rejected."""
        body = self._create_archive_with(
            extra_members=[
                ("host1/bundle1/files/../../../etc/passwd", b"root\n", None)
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("unsafe path", str(context.exception))

    def test_absolute_path_rejected(self) -> None:
        """Test that absolute paths are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("/etc/passwd")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"root\n"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("unsafe path", str(context.exception))

    def test_symlink_rejected(self) -> None:
        """Test that symlinks are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            link = tarfile.TarInfo("host1/bundle1/files/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            link.size = 0
            outer_tar.addfile(link)

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("link or special file", str(context.exception))

    def test_hardlink_rejected(self) -> None:
        """Test that hard links are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1/bundle1/files/file1.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"hello"))
            link = tarfile.TarInfo("host1/bundle1/files/link_to_file1")
            link.type = tarfile.LNKTYPE
            link.linkname = "file1.txt"
            link.size = 0
            outer_tar.addfile(link)

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("link or special file", str(context.exception))

    def test_backslash_in_path_rejected(self) -> None:
        """Test that backslashes in paths are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1\\bundle1\\files\\evil.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"evil\n"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("unsafe path", str(context.exception))

    def test_duplicate_paths_rejected(self) -> None:
        """Test that duplicate paths are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1/bundle1/files/test.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"hello"))
            member2 = tarfile.TarInfo("host1/bundle1/files/test.txt")
            member2.size = 5
            outer_tar.addfile(member2, io.BytesIO(b"world"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("duplicate paths", str(context.exception))

    def test_missing_required_files_rejected(self) -> None:
        """Test that archives missing required files are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            # Missing session.json!
            member = tarfile.TarInfo("host1/bundle1/commands.log")
            member.size = 9
            outer_tar.addfile(member, io.BytesIO(b"echo one\n"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("missing a required entry", str(context.exception))

    def test_file_outside_bundle_structure_rejected(self) -> None:
        """Test that files outside the expected bundle structure are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # This file is outside the bundle1 structure
            member = tarfile.TarInfo("host1/other/evil.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"evil\n"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("must belong to one bundle", str(context.exception))

    def test_valid_archive_accepted(self) -> None:
        """Test that a valid archive is accepted."""
        body = self._create_archive_with()
        with tempfile.TemporaryDirectory() as tmpdir:
            hostname, bundle_name = extract_archive(
                body, Path(tmpdir), max_expanded_bytes=1024 * 1024
            )
            self.assertEqual(hostname, "host1")
            self.assertEqual(bundle_name, "bundle1")
            # Verify files were created
            bundle_path = Path(tmpdir) / "host1" / "bundle1"
            self.assertTrue((bundle_path / "session.json").exists())
            self.assertTrue((bundle_path / "commands.log").exists())
            self.assertTrue((bundle_path / "files").is_dir())

    def test_member_exceeds_size_limit_rejected(self) -> None:
        """Test that individual members exceeding size limit are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # Add a file that exceeds the limit
            big_data = b"x" * (10 * 1024 * 1024)  # 10MB
            member = tarfile.TarInfo("host1/bundle1/files/big.bin")
            member.size = len(big_data)
            outer_tar.addfile(member, io.BytesIO(big_data))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("exceeds the configured limit", str(context.exception))

    def test_total_expanded_size_limit_rejected(self) -> None:
        """Test that total expanded archive size is enforced."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # Add multiple files that together exceed the limit
            for i in range(10):
                data = b"x" * (200 * 1024)  # 200KB each
                member = tarfile.TarInfo(f"host1/bundle1/files/big_{i}.bin")
                member.size = len(data)
                outer_tar.addfile(member, io.BytesIO(data))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                # Set limit to 1MB, but total files are ~2MB
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("exceeds the configured limit", str(context.exception))

    def test_directory_with_nonzero_size_rejected(self) -> None:
        """Test that directory entries with non-zero size are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            # Directory with non-zero size
            directory = tarfile.TarInfo("host1/bundle1/files/")
            directory.type = tarfile.DIRTYPE
            directory.size = 100  # Should be 0 for directories
            outer_tar.addfile(directory)
            for path, contents in {
                "host1/bundle1/session.json": b'{"user":"alice"}\n',
                "host1/bundle1/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("directory entries must be empty", str(context.exception))

    def test_cleanup_on_extraction_failure(self) -> None:
        """Test that extracted files are cleaned up when validation fails."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/bundle1/", "host1/bundle1/files/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            # Missing session.json - will cause validation to fail
            member = tarfile.TarInfo("host1/bundle1/commands.log")
            member.size = 9
            outer_tar.addfile(member, io.BytesIO(b"echo one\n"))
            # Add a file that should be cleaned up
            member = tarfile.TarInfo("host1/bundle1/files/test.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"hello"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            # Try to extract - should fail
            with self.assertRaises(InvalidBundle):
                extract_archive(body, tmpdir_path, max_expanded_bytes=1024 * 1024)
            
            # Verify no files/directories remain
            remaining = list(tmpdir_path.rglob("*"))
            # Filter out the temp dir itself
            remaining = [p for p in remaining if p != tmpdir_path]
            self.assertEqual(len(remaining), 0, f"Files left behind: {remaining}")


if __name__ == "__main__":
    unittest.main()
