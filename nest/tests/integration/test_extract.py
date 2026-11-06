"""Tests for archive validation against generic archive attacks."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from mina_nest.ingest import InvalidBundle, extract_archive


class ArchiveSecurityTests(unittest.TestCase):
    """Test suite for archive security against common attacks."""

    def _create_archive_with(
        self, extra_members: list[tuple[str, bytes, int | None]] = None
    ) -> bytes:
        """Helper to create a valid base archive with optional extra members."""
        if extra_members is None:
            extra_members = []
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            # Required directory structure
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)

            # Required files
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
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
                    member.linkname = (
                        contents.decode() if isinstance(contents, bytes) else contents
                    )
                    member.size = 0
                elif member_type == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = (
                        contents.decode() if isinstance(contents, bytes) else contents
                    )
                    member.size = 0
                else:
                    member.size = len(contents)
                outer_tar.addfile(
                    member,
                    io.BytesIO(contents) if member_type is None else io.BytesIO(b""),
                )

        return outer.getvalue()

    def test_zip_bomb_decompression_limit(self) -> None:
        """Test that decompression bomb (zip bomb) is rejected by size limit."""
        # Create a highly compressible 50MB file
        compressible_data = b"\x00" * (50 * 1024 * 1024)
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/bomb.bin")
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # Add more than MAX_ARCHIVE_ENTRIES (100,000) files
            for i in range(100001):
                member = tarfile.TarInfo(
                    f"host1/2026-11-02_10-00-00_al/files/file_{i}.txt"
                )
                member.size = 1
                outer_tar.addfile(member, io.BytesIO(b"x"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(
                    body, Path(tmpdir), max_expanded_bytes=1024 * 1024 * 1024
                )
            self.assertIn("too many entries", str(context.exception))

    def test_path_traversal_with_dotdot(self) -> None:
        """Test that path traversal with ../.. is rejected."""
        body = self._create_archive_with(
            extra_members=[
                (
                    "host1/2026-11-02_10-00-00_al/files/../../../etc/passwd",
                    b"root\n",
                    None,
                )
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            link = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/link")
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/file1.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"hello"))
            link = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/link_to_file1")
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1\\2026-11-02_10-00-00_al\\files\\evil.txt")
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/test.txt")
            member.size = 5
            outer_tar.addfile(member, io.BytesIO(b"hello"))
            member2 = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/test.txt")
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            # Missing session.json!
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/commands.log")
            member.size = 9
            outer_tar.addfile(member, io.BytesIO(b"echo one\n"))

        body = outer.getvalue()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(body, Path(tmpdir), max_expanded_bytes=1024 * 1024)
            self.assertIn("missing a required entry", str(context.exception))

    def test_bundle_without_files_directory_accepted(self) -> None:
        """The agent omits files/ when it captured nothing."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/2026-11-02_10-00-00_al/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/commands.log": b"",
                "host1/2026-11-02_10-00-00_al/session.json": b"{}\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))

        with tempfile.TemporaryDirectory() as tmpdir:
            result = extract_archive(
                outer.getvalue(), Path(tmpdir), max_expanded_bytes=1024 * 1024
            )
            self.assertEqual(result, ("host1", "2026-11-02_10-00-00_al"))
            self.assertFalse(
                (Path(tmpdir) / "host1/2026-11-02_10-00-00_al/files").exists()
            )

    def test_files_as_regular_file_rejected(self) -> None:
        """files/ is optional, but when present it must be a directory."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in ["host1/", "host1/2026-11-02_10-00-00_al/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/commands.log": b"",
                "host1/2026-11-02_10-00-00_al/files": b"x",
                "host1/2026-11-02_10-00-00_al/session.json": b"{}\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(InvalidBundle) as context:
                extract_archive(
                    outer.getvalue(), Path(tmpdir), max_expanded_bytes=1024 * 1024
                )
            self.assertIn("files entry must be a directory", str(context.exception))

    def test_file_outside_bundle_structure_rejected(self) -> None:
        """Test that files outside the expected bundle structure are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # This file is outside the 2026-11-02_10-00-00_al structure
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
            self.assertEqual(bundle_name, "2026-11-02_10-00-00_al")
            # Verify files were created
            bundle_path = Path(tmpdir) / "host1" / "2026-11-02_10-00-00_al"
            self.assertTrue((bundle_path / "session.json").exists())
            self.assertTrue((bundle_path / "commands.log").exists())
            self.assertTrue((bundle_path / "files").is_dir())

    def test_member_exceeds_size_limit_rejected(self) -> None:
        """Test that individual members exceeding size limit are rejected."""
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w:gz") as outer_tar:
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # Add a file that exceeds the limit
            big_data = b"x" * (10 * 1024 * 1024)  # 10MB
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/big.bin")
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
            }.items():
                member = tarfile.TarInfo(path)
                member.size = len(contents)
                outer_tar.addfile(member, io.BytesIO(contents))
            # Add multiple files that together exceed the limit
            for i in range(10):
                data = b"x" * (200 * 1024)  # 200KB each
                member = tarfile.TarInfo(
                    f"host1/2026-11-02_10-00-00_al/files/big_{i}.bin"
                )
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
            for path in ["host1/", "host1/2026-11-02_10-00-00_al/"]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            # Directory with non-zero size
            directory = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/")
            directory.type = tarfile.DIRTYPE
            directory.size = 100  # Should be 0 for directories
            outer_tar.addfile(directory)
            for path, contents in {
                "host1/2026-11-02_10-00-00_al/session.json": b'{"user":"alice"}\n',
                "host1/2026-11-02_10-00-00_al/commands.log": b"echo one\n",
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
            for path in [
                "host1/",
                "host1/2026-11-02_10-00-00_al/",
                "host1/2026-11-02_10-00-00_al/files/",
            ]:
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                outer_tar.addfile(directory)
            # Missing session.json - will cause validation to fail
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/commands.log")
            member.size = 9
            outer_tar.addfile(member, io.BytesIO(b"echo one\n"))
            # Add a file that should be cleaned up
            member = tarfile.TarInfo("host1/2026-11-02_10-00-00_al/files/test.txt")
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


def bundle_archive(
    host: str = "web-01",
    bundle: str = "2026-11-06_09-00-00_alice",
    sparse: bool = False,
) -> bytes:
    """A bundle as the agent builds it, with the given names."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for path in (f"{host}/", f"{host}/{bundle}/", f"{host}/{bundle}/files/"):
            directory = tarfile.TarInfo(path)
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)
        files = {
            f"{host}/{bundle}/commands.log": b"",
            f"{host}/{bundle}/files/etc-motd": b"hello\n",
            f"{host}/{bundle}/session.json": b"{}\n",
        }
        for path, contents in files.items():
            member = tarfile.TarInfo(path)
            member.size = len(contents)
            if sparse and path.endswith("etc-motd"):
                member.type = tarfile.GNUTYPE_SPARSE
            tar.addfile(member, io.BytesIO(contents))
    return output.getvalue()


class NameTests(unittest.TestCase):
    def extract(self, body: bytes) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            return extract_archive(body, Path(tmpdir), max_expanded_bytes=1 << 20)

    def test_agent_names_accepted(self) -> None:
        for host, bundle in (
            ("web-01", "2026-11-06_09-00-00_alice"),
            ("web-01.example.org", "2026-11-06_09-00-00_alice_2"),
            ("unknown", "2026-11-06_09-00-00_svc-backup"),
            ("db_1", "2026-11-06_09-00-00_alice@example.org"),
        ):
            with self.subTest(host=host, bundle=bundle):
                self.assertEqual(
                    self.extract(bundle_archive(host, bundle)), (host, bundle)
                )

    def test_unsafe_hostname_rejected(self) -> None:
        # A leading dot would sit next to the nest's own hidden files.
        for host in (".mina-nest", ".hidden", "-x", "a b", "é", "x" * 254):
            with self.subTest(host=host), self.assertRaises(InvalidBundle):
                self.extract(bundle_archive(host=host))

    def test_bundle_name_must_be_timestamp_and_user(self) -> None:
        for bundle in (
            "bundle1",
            "2026-11-06_09-00-00",
            "2026-11-06_09-00-00_",
            "2026-11-06 09-00-00_alice",
            "26-11-06_09-00-00_alice",
            "２０２６-11-06_09-00-00_alice",
            ".2026-11-06_09-00-00_alice",
        ):
            with self.subTest(bundle=bundle), self.assertRaises(InvalidBundle):
                self.extract(bundle_archive(bundle=bundle))

    def test_sparse_member_rejected(self) -> None:
        with self.assertRaises(InvalidBundle) as context:
            self.extract(bundle_archive(sparse=True))
        self.assertIn("sparse", str(context.exception))


if __name__ == "__main__":
    unittest.main()
