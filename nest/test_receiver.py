import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from werkzeug.test import Client
from werkzeug.wrappers import Response

from nest.receiver import create_app

BUNDLE = "2026-11-02_10-00-00_alice"


def archive(*, command_log: bytes = b"echo one\n", extra: tuple[str, bytes] | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for path in ("host1/", f"host1/{BUNDLE}/", f"host1/{BUNDLE}/files/"):
            directory = tarfile.TarInfo(path)
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)
        files = {
            f"host1/{BUNDLE}/session.json": b'{"user":"alice"}\n',
            f"host1/{BUNDLE}/commands.log": command_log,
        }
        if extra is not None:
            files[extra[0]] = extra[1]
        for path, contents in files.items():
            member = tarfile.TarInfo(path)
            member.size = len(contents)
            tar.addfile(member, io.BytesIO(contents))
    return output.getvalue()


class ReceiverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.nest = Path(self.temporary.name) / "nest"
        self.client = Client(create_app(self.nest), Response)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def post(self, body: bytes, digest: str | None = None):
        digest = digest or "sha256=" + hashlib.sha256(body).hexdigest()
        return self.client.post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={"X-Mina-Bundle-Digest": digest},
        )

    def test_receives_and_publishes_bundle(self) -> None:
        body = archive()
        response = self.post(body)

        self.assertEqual(response.status_code, 201)
        bundle = self.nest / "host1" / BUNDLE
        self.assertEqual((bundle / "commands.log").read_bytes(), b"echo one\n")
        self.assertEqual((bundle / "session.json").read_bytes(), b'{"user":"alice"}\n')
        self.assertTrue((bundle / "files").is_dir())
        self.assertEqual(
            (self.nest / "host1" / f".{BUNDLE}.mina-digest").read_text().strip(),
            "sha256=" + hashlib.sha256(body).hexdigest(),
        )

    def test_same_digest_retry_is_idempotent(self) -> None:
        body = archive()

        first = self.post(body)
        retry = self.post(body)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(
            sorted(path.name for path in (self.nest / "host1").iterdir()),
            [f".{BUNDLE}.mina-digest", BUNDLE],
        )

    def test_different_digest_gets_collision_suffix(self) -> None:
        first = self.post(archive())
        second = self.post(archive(command_log=b"echo two\n"))

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertTrue((self.nest / "host1" / f"{BUNDLE}_2").is_dir())

    def test_digest_mismatch_is_rejected(self) -> None:
        response = self.post(archive(), "sha256=" + "0" * 64)

        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.nest / "host1").exists())

    def test_archive_path_traversal_is_rejected(self) -> None:
        body = archive(extra=(f"host1/{BUNDLE}/files/../../escape", b"no"))

        response = self.post(body)

        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.nest.parent / "escape").exists())

    def test_archive_links_are_rejected(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            link = tarfile.TarInfo(f"host1/{BUNDLE}/files/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        response = self.post(output.getvalue())

        self.assertEqual(response.status_code, 400)

    def test_upload_limit_is_enforced(self) -> None:
        body = archive()
        client = Client(
            create_app(self.nest, max_upload_bytes=len(body) - 1), Response
        )

        response = client.post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={"X-Mina-Bundle-Digest": "sha256=" + hashlib.sha256(body).hexdigest()},
        )

        self.assertEqual(response.status_code, 413)

    def test_rejects_wrong_method_and_content_type(self) -> None:
        self.assertEqual(self.client.get("/ingest").status_code, 405)
        response = self.client.post("/ingest", data=b"not gzip")
        self.assertEqual(response.status_code, 415)


if __name__ == "__main__":
    unittest.main()
