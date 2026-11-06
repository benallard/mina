import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from werkzeug.test import Client
from werkzeug.wrappers import Response

from mina_nest import app_from_env, create_app

BUNDLE = "2026-11-02_10-00-00_alice"


def archive(
    *,
    command_log: bytes = b"echo one\n",
    extra: tuple[str, bytes] | None = None,
    with_files: bool = True,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        directories = ["host1/", f"host1/{BUNDLE}/"]
        if with_files:
            directories.append(f"host1/{BUNDLE}/files/")
        for path in directories:
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

    def test_bundle_without_captured_files_is_accepted(self) -> None:
        # The agent creates files/ only when it captured a file, which most
        # sessions do not.
        response = self.post(archive(with_files=False))

        self.assertEqual(response.status_code, 201)
        bundle = self.nest / "host1" / BUNDLE
        self.assertEqual(
            sorted(path.name for path in bundle.iterdir()),
            ["commands.log", "session.json"],
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
        client = Client(create_app(self.nest, max_upload_bytes=len(body) - 1), Response)

        response = client.post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={
                "X-Mina-Bundle-Digest": "sha256=" + hashlib.sha256(body).hexdigest()
            },
        )

        self.assertEqual(response.status_code, 413)

    def post_to(self, app, body: bytes):
        return Client(app, Response).post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={
                "X-Mina-Bundle-Digest": "sha256=" + hashlib.sha256(body).hexdigest()
            },
        )

    def test_expanded_size_limit_is_413(self) -> None:
        # Small compressed, large unpacked: too large, not malformed.
        body = archive(extra=(f"host1/{BUNDLE}/files/big", b"\0" * 8192))
        app = create_app(self.nest, max_expanded_bytes=4096)

        response = self.post_to(app, body)

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            [p.name for p in self.nest.iterdir() if not p.name.startswith(".")], []
        )

    def test_entry_limit_is_413(self) -> None:
        body = archive()
        with mock.patch("mina_nest.ingest.MAX_ARCHIVE_ENTRIES", 3):
            response = self.post_to(create_app(self.nest), body)

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            [p.name for p in self.nest.iterdir() if not p.name.startswith(".")], []
        )

    def test_rejects_wrong_method_and_content_type(self) -> None:
        self.assertEqual(self.client.get("/ingest").status_code, 405)
        response = self.client.post("/ingest", data=b"not gzip")
        self.assertEqual(response.status_code, 415)


class AppFromEnvTests(unittest.TestCase):
    def test_nest_dir_comes_from_the_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            nest = Path(temporary) / "nest"
            with mock.patch.dict(os.environ, {"MINA_NEST_DIR": str(nest)}):
                client = Client(app_from_env(), Response)
            body = archive()
            response = client.post(
                "/ingest",
                data=body,
                content_type="application/gzip",
                headers={
                    "X-Mina-Bundle-Digest": "sha256=" + hashlib.sha256(body).hexdigest()
                },
            )

            self.assertEqual(response.status_code, 201)
            self.assertTrue((nest / "host1" / BUNDLE / "session.json").is_file())


class IdentityTests(unittest.TestCase):
    """Tests for client certificate identity mapping."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.nest = Path(self.temporary.name) / "nest"

    def test_hostname_from_tarball_when_no_cert(self) -> None:
        """Without certificate mapping, hostname comes from tarball."""
        client = Client(create_app(self.nest), Response)
        body = archive()
        digest = "sha256=" + hashlib.sha256(body).hexdigest()
        response = client.post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={"X-Mina-Bundle-Digest": digest},
        )
        self.assertEqual(response.status_code, 201)
        self.assertIn(b"host1/", response.data)
        self.assertTrue((self.nest / "host1" / BUNDLE / "session.json").is_file())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def post(self, mapper: str, headers: dict[str, str]):
        """POST a bundle to an app built from the environment with `mapper`.

        `builtins:str` maps a DN to itself, so the DN names the host.
        """
        env = {"MINA_NEST_DIR": str(self.nest), "MINA_IDENTITY_MAPPER": mapper}
        with mock.patch.dict(os.environ, env):
            client = Client(app_from_env(), Response)
        body = archive()
        digest = "sha256=" + hashlib.sha256(body).hexdigest()
        return client.post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={"X-Mina-Bundle-Digest": digest, **headers},
        )

    def stored(self) -> list[str]:
        """Everything under the nest's parent, outside .mina-* bookkeeping."""
        root = self.nest.parent
        return sorted(
            str(path.relative_to(root))
            for path in root.rglob("*")
            if not any(part.startswith(".") for part in path.parts)
        )

    def test_hostname_from_certificate_overrides_tarball(self) -> None:
        response = self.post(
            "builtins:str",
            {"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-DN": "cert-host"},
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, f"cert-host/{BUNDLE}\n".encode())
        self.assertTrue((self.nest / "cert-host" / BUNDLE / "session.json").is_file())
        self.assertFalse((self.nest / "host1").exists())

    def test_dn_without_verified_certificate_is_refused(self) -> None:
        # Any client can send a DN header; only nginx's verdict counts.
        for headers in (
            {"X-SSL-Client-DN": "cert-host"},
            {"X-SSL-Client-Verify": "NONE", "X-SSL-Client-DN": "cert-host"},
            {"X-SSL-Client-Verify": "FAILED:x", "X-SSL-Client-DN": "cert-host"},
            {"SSL-Client-S-DN": "cert-host"},
        ):
            with self.subTest(headers=headers):
                response = self.post("builtins:str", headers)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(self.stored(), ["nest"])

    def test_mapper_configured_but_no_certificate_is_refused(self) -> None:
        # Never fall back to the tarball's hostname when a mapper is set.
        response = self.post("builtins:str", {})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored(), ["nest"])

    def test_unsafe_mapped_hostname_is_an_error_and_writes_nothing(self) -> None:
        for dn in ("../escape", "a/b", ".hidden", "..", "-x", "x" * 254, "a b"):
            with self.subTest(dn=dn):
                response = self.post(
                    "builtins:str",
                    {"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-DN": dn},
                )
                self.assertEqual(response.status_code, 500)
                self.assertEqual(self.stored(), ["nest"])

    def test_unmapped_certificate_is_refused(self) -> None:
        receiver = create_app(self.nest, mapper=lambda dn: None)
        body = archive()
        response = Client(receiver, Response).post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={
                "X-Mina-Bundle-Digest": "sha256=" + hashlib.sha256(body).hexdigest(),
                "X-SSL-Client-Verify": "SUCCESS",
                "X-SSL-Client-DN": "CN=unknown",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored(), ["nest"])

    def test_failing_mapper_is_an_error_not_a_fallback(self) -> None:
        def broken(dn: str) -> str:
            raise RuntimeError("directory unreachable")

        receiver = create_app(self.nest, mapper=broken)
        body = archive()
        response = Client(receiver, Response).post(
            "/ingest",
            data=body,
            content_type="application/gzip",
            headers={
                "X-Mina-Bundle-Digest": "sha256=" + hashlib.sha256(body).hexdigest(),
                "X-SSL-Client-Verify": "SUCCESS",
                "X-SSL-Client-DN": "CN=web-01",
            },
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.stored(), ["nest"])

    def test_bad_mapper_setting_fails_at_startup(self) -> None:
        for spec in ("no-colon", "no_such_module_for_mina:f", "os:sep"):
            with self.subTest(spec=spec):
                env = {"MINA_NEST_DIR": str(self.nest), "MINA_IDENTITY_MAPPER": spec}
                with (
                    mock.patch.dict(os.environ, env),
                    self.assertRaises((ValueError, ImportError)),
                ):
                    app_from_env()


if __name__ == "__main__":
    unittest.main()
