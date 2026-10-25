"""Core tests: no pytest needed, just run python -m unittest.

    cd gpgfs
    python -m unittest discover -s tests -v

Needs a working gpg (picked automatically); the tests generate their own
temporary key and do everything in temp directories, never touching ~/.gnupg.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gpgfs.cipher import GpgCipher, best_gpg  # noqa: E402
from gpgfs.config import ENV_PASSPHRASE  # noqa: E402
from gpgfs.davserver import make_server  # noqa: E402
from gpgfs.errors import (  # noqa: E402
    AlreadyExists,
    DirectoryNotEmpty,
    InvalidPath,
    NotFound,
)
from gpgfs.state import PlaintextCache, SizeCache  # noqa: E402
from gpgfs.vfs import TMP_PREFIX, Vfs  # noqa: E402

GPG = None
HOMEDIR = None
KEYID = None


def setUpModule() -> None:  # noqa: N802
    global GPG, HOMEDIR, KEYID
    GPG = best_gpg()
    try:
        subprocess.run([GPG, "--version"], capture_output=True, timeout=20, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise unittest.SkipTest(f"no usable gpg: {exc}") from exc

    HOMEDIR = tempfile.mkdtemp(prefix="gpgfs-test-home-")
    os.chmod(HOMEDIR, 0o700)
    proc = subprocess.run(
        [GPG, "--homedir", HOMEDIR, "--batch", "--pinentry-mode", "loopback",
         "--passphrase", "", "--quick-generate-key",
         "gpgfs test <test@gpgfs.invalid>", "default", "default", "never"],
        capture_output=True, timeout=180,
    )
    if proc.returncode != 0:
        raise unittest.SkipTest(
            "failed to generate test key: " + proc.stderr.decode("utf-8", "replace"))
    proc = subprocess.run(
        [GPG, "--homedir", HOMEDIR, "--batch", "--with-colons", "--list-secret-keys"],
        capture_output=True, timeout=60,
    )
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("sec:"):
            KEYID = line.split(":")[4]
            break
    if not KEYID:
        raise unittest.SkipTest("could not read the test key ID")


def tearDownModule() -> None:  # noqa: N802
    if HOMEDIR and os.path.isdir(HOMEDIR):
        subprocess.run([GPG, "--homedir", HOMEDIR, "--batch", "--kill", "all"],
                       capture_output=True, timeout=30)
        shutil.rmtree(HOMEDIR, ignore_errors=True)


class CountingCipher(GpgCipher):
    """Count decryptions to verify cache hits."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.decrypt_count = 0

    def decrypt_bytes(self, data: bytes) -> bytes:
        self.decrypt_count += 1
        return super().decrypt_bytes(data)


class GpgfsTestBase(unittest.TestCase):
    cipher_factory = GpgCipher

    def setUp(self) -> None:
        self.vault = tempfile.mkdtemp(prefix="gpgfs-vault-")
        self.state = tempfile.mkdtemp(prefix="gpgfs-state-")
        self.cipher = self.cipher_factory(
            recipients=[KEYID], gpg=GPG, homedir=HOMEDIR)
        self.size_cache = SizeCache(os.path.join(self.state, "sizes.sqlite"))
        self.vfs = Vfs(self.vault, self.cipher, self.size_cache, PlaintextCache())

    def tearDown(self) -> None:
        self.size_cache.close()
        shutil.rmtree(self.vault, ignore_errors=True)
        shutil.rmtree(self.state, ignore_errors=True)

    # Convenience assertions
    def assertExists(self, rel: str) -> None:  # noqa: N802
        self.assertTrue(self.vfs.exists(rel), f"{rel} should exist")

    def assertMissing(self, rel: str) -> None:  # noqa: N802
        self.assertFalse(self.vfs.exists(rel), f"{rel} should not exist")


class PathMappingTest(GpgfsTestBase):
    def test_normalize(self) -> None:
        self.assertEqual(Vfs.normalize("/a/b/c"), "a/b/c")
        self.assertEqual(Vfs.normalize("a//b/./c/"), "a/b/c")
        self.assertEqual(Vfs.normalize(""), "")
        self.assertEqual(Vfs.normalize("/"), "")

    def test_reject_traversal(self) -> None:
        for bad in ("../etc/passwd", "a/../../b", "a/\x00b", TMP_PREFIX + "x"):
            with self.assertRaises(InvalidPath):
                Vfs.normalize(bad)

    def test_filename_gets_gpg_suffix(self) -> None:
        self.vfs.mkdir("foo")
        self.vfs.write_file("foo/bar.txt", b"hello")
        on_disk = os.listdir(os.path.join(self.vault, "foo"))
        self.assertEqual(on_disk, ["bar.txt.gpg"])
        # Directory names stay in plaintext
        self.assertIn("foo", os.listdir(self.vault))

    def test_unreadable_missing(self) -> None:
        with self.assertRaises(NotFound):
            self.vfs.read_file("nope.txt")


class ReadWriteTest(GpgfsTestBase):
    def test_roundtrip_text(self) -> None:
        self.vfs.mkdir("docs")
        payload = "café content\nsecond line\n".encode("utf-8")
        entry = self.vfs.write_file("docs/a.txt", payload)
        self.assertEqual(entry.size, len(payload))
        self.assertEqual(self.vfs.read_file("docs/a.txt"), payload)
        self.assertEqual(self.vfs.stat("docs/a.txt").size, len(payload))

    def test_empty_file(self) -> None:
        self.vfs.write_file("empty.txt", b"")
        self.assertEqual(self.vfs.read_file("empty.txt"), b"")
        self.assertEqual(self.vfs.stat("empty.txt").size, 0)

    def test_binary_large(self) -> None:
        payload = bytes(range(256)) * 4096  # 1 MiB
        self.vfs.write_file("blob.bin", payload)
        self.assertEqual(self.vfs.read_file("blob.bin"), payload)

    def test_stream_roundtrip(self) -> None:
        payload = os.urandom(300_000)
        entry = self.vfs.write_stream("stream.bin", io.BytesIO(payload))
        self.assertEqual(entry.size, len(payload))
        collected = b"".join(self.vfs.iter_file("stream.bin"))
        self.assertEqual(collected, payload)

    def test_ciphertext_does_not_contain_plaintext(self) -> None:
        secret = b"TOP-SECRET-MARKER-9f3a"
        self.vfs.write_file("s.txt", secret)
        raw = open(os.path.join(self.vault, "s.txt.gpg"), "rb").read()
        self.assertNotIn(secret, raw)
        self.assertTrue(len(raw) > len(secret))

    def test_overwrite(self) -> None:
        self.vfs.write_file("x.txt", b"one")
        self.vfs.write_file("x.txt", b"two-two")
        self.assertEqual(self.vfs.read_file("x.txt"), b"two-two")

    def test_parent_missing(self) -> None:
        with self.assertRaises(NotFound):
            self.vfs.write_file("no/such/dir/a.txt", b"x")


class DirectoryTest(GpgfsTestBase):
    def test_listdir_and_stat(self) -> None:
        self.vfs.mkdir("d1")
        self.vfs.write_file("f1.txt", b"12345")
        self.vfs.write_file("d1/f2.txt", b"1234567890")
        root = {e.name: e for e in self.vfs.listdir("")}
        self.assertTrue(root["d1"].is_dir)
        self.assertEqual(root["f1.txt"].size, 5)
        child = {e.name: e for e in self.vfs.listdir("d1")}
        self.assertEqual(child["f2.txt"].size, 10)

    def test_hides_internal_files(self) -> None:
        self.vfs.mkdir("d")
        # Simulate internal temp files and the config file
        open(os.path.join(self.vault, "d", TMP_PREFIX + "abc"), "wb").write(b"x")
        open(os.path.join(self.vault, ".gpgfs.json"), "w").write("{}")
        names = [e.name for e in self.vfs.listdir("d")]
        self.assertEqual(names, [])

    def test_rmdir_non_empty(self) -> None:
        self.vfs.mkdir("d")
        self.vfs.write_file("d/a.txt", b"x")
        with self.assertRaises(DirectoryNotEmpty):
            self.vfs.rmdir("d")

    def test_mkdir_twice(self) -> None:
        self.vfs.mkdir("d")
        with self.assertRaises(AlreadyExists):
            self.vfs.mkdir("d")

    def test_walk(self) -> None:
        self.vfs.mkdir("a")
        self.vfs.mkdir("a/b")
        self.vfs.write_file("a/b/c.txt", b"deep")
        paths = {p for p, _ in self.vfs.walk("")}
        self.assertIn("a/b/c.txt", paths)


class RenameDeleteTest(GpgfsTestBase):
    def test_rename_file(self) -> None:
        self.vfs.write_file("a.txt", b"content")
        self.vfs.rename("a.txt", "b.txt")
        self.assertMissing("a.txt")
        self.assertEqual(self.vfs.read_file("b.txt"), b"content")

    def test_rename_dir(self) -> None:
        self.vfs.mkdir("src")
        self.vfs.write_file("src/f.txt", b"v")
        self.vfs.rename("src", "dst")
        self.assertMissing("src")
        self.assertEqual(self.vfs.read_file("dst/f.txt"), b"v")

    def test_rename_overwrite_denied(self) -> None:
        self.vfs.write_file("a.txt", b"a")
        self.vfs.write_file("b.txt", b"b")
        with self.assertRaises(AlreadyExists):
            self.vfs.rename("a.txt", "b.txt", overwrite=False)

    def test_copy(self) -> None:
        self.vfs.write_file("a.txt", b"copy-me")
        self.vfs.copy("a.txt", "c.txt")
        self.assertEqual(self.vfs.read_file("c.txt"), b"copy-me")
        self.assertEqual(self.vfs.read_file("a.txt"), b"copy-me")

    def test_delete(self) -> None:
        self.vfs.write_file("a.txt", b"x")
        self.vfs.delete("a.txt")
        self.assertMissing("a.txt")
        self.assertEqual([n for n in os.listdir(self.vault) if n.endswith(".gpg")], [])

    def test_delete_missing(self) -> None:
        with self.assertRaises(NotFound):
            self.vfs.delete("nope.txt")


class CachingTest(GpgfsTestBase):
    cipher_factory = CountingCipher

    def test_repeated_reads_hit_memory_cache(self) -> None:
        self.vfs.write_file("a.txt", b"payload")
        self.vfs.read_file("a.txt")
        first = self.cipher.decrypt_count
        self.vfs.read_file("a.txt")
        self.vfs.read_file("a.txt")
        self.assertEqual(self.cipher.decrypt_count, first,
                         "repeated reads should not decrypt again")

    def test_size_cache_avoids_decrypt(self) -> None:
        self.vfs.write_file("a.txt", b"0123456789")
        self.vfs.stat("a.txt")
        before = self.cipher.decrypt_count
        # Drop the in-memory cache, keep only the persistent size cache
        self.vfs.plain_cache.clear()
        self.assertEqual(self.vfs.stat("a.txt").size, 10)
        self.assertEqual(self.cipher.decrypt_count, before,
                         "the size cache should avoid decryption")

    def test_cache_invalidated_on_write(self) -> None:
        self.vfs.write_file("a.txt", b"aaaa")
        self.assertEqual(self.vfs.stat("a.txt").size, 4)
        self.vfs.write_file("a.txt", b"bbbbbbbb")
        self.assertEqual(self.vfs.stat("a.txt").size, 8)
        self.assertEqual(self.vfs.read_file("a.txt"), b"bbbbbbbb")


class SizeCacheNamespaceTest(unittest.TestCase):
    """One database file serves every vault, so keys must be scoped per vault."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="gpgfs-cache-")
        self.path = os.path.join(self.dir, "sizes.sqlite")
        self.one = SizeCache(self.path, namespace=os.path.join(self.dir, "vault-one"))
        self.two = SizeCache(self.path, namespace=os.path.join(self.dir, "vault-two"))

    def tearDown(self) -> None:
        self.one.close()
        self.two.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_same_relative_path_does_not_collide(self) -> None:
        self.one.put("notes.txt", 1, 10, 100)
        self.assertIsNone(self.two.get("notes.txt", 1, 10))
        self.two.put("notes.txt", 1, 10, 200)
        self.assertEqual(self.one.get("notes.txt", 1, 10), 100)
        self.assertEqual(self.two.get("notes.txt", 1, 10), 200)

    def test_drop_prefix_is_scoped(self) -> None:
        self.one.put("d/a.txt", 2, 20, 5)
        self.two.put("d/a.txt", 2, 20, 6)
        self.one.drop_prefix("d")
        self.assertIsNone(self.one.get("d/a.txt", 2, 20))
        self.assertEqual(self.two.get("d/a.txt", 2, 20), 6)


class ExposePlaintextTest(GpgfsTestBase):
    """With --expose-plaintext, an unencrypted file must stay unencrypted when moved or copied."""

    def setUp(self) -> None:
        super().setUp()
        self.vfs = Vfs(self.vault, self.cipher, self.size_cache, PlaintextCache(),
                       expose_plaintext=True)
        with open(os.path.join(self.vault, "plain.txt"), "wb") as fh:
            fh.write(b"plain body")

    def test_rename_keeps_plaintext_form(self) -> None:
        self.vfs.rename("plain.txt", "moved.txt")
        self.assertFalse(os.path.exists(os.path.join(self.vault, "moved.txt.gpg")))
        self.assertEqual(self.vfs.read_file("moved.txt"), b"plain body")

    def test_copy_keeps_plaintext_form(self) -> None:
        self.vfs.copy("plain.txt", "copy.txt")
        self.assertFalse(os.path.exists(os.path.join(self.vault, "copy.txt.gpg")))
        self.assertEqual(self.vfs.read_file("copy.txt"), b"plain body")

    def test_copy_onto_a_directory_is_rejected(self) -> None:
        self.vfs.mkdir("dir")
        with self.assertRaises(AlreadyExists):
            self.vfs.copy("plain.txt", "dir")


class SymmetricModeTest(unittest.TestCase):
    """Passphrase mode (needs no key at all)."""

    def setUp(self) -> None:
        self.vault = tempfile.mkdtemp(prefix="gpgfs-sym-")
        self.cipher = GpgCipher(passphrase="correct horse battery staple",
                                gpg=GPG, homedir=HOMEDIR)
        self.vfs = Vfs(self.vault, self.cipher, SizeCache(None), PlaintextCache())

    def tearDown(self) -> None:
        shutil.rmtree(self.vault, ignore_errors=True)

    def test_roundtrip(self) -> None:
        self.vfs.write_file("s.txt", b"symmetric secret")
        self.assertEqual(self.vfs.read_file("s.txt"), b"symmetric secret")

    def test_wrong_passphrase_fails(self) -> None:
        self.vfs.write_file("s.txt", b"data")
        wrong = GpgCipher(passphrase="wrong one", gpg=GPG, homedir=HOMEDIR)
        with open(os.path.join(self.vault, "s.txt.gpg"), "rb") as fh:
            blob = fh.read()
        with self.assertRaises(Exception):
            wrong.decrypt_bytes(blob)

    def test_passphrase_file_uses_plain_lf(self) -> None:
        """A CRLF passphrase file makes the effective passphrase end with \\r, which locks the
        vault to the platform that created it."""
        with self.cipher._passphrase_file() as path:
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), b"correct horse battery staple\n")

    def test_vault_readable_with_a_plain_lf_passphrase_file(self) -> None:
        blob = self.cipher.encrypt_bytes(b"portable across platforms")
        fd, path = tempfile.mkstemp(prefix="gpgfs-pw-", suffix=".txt")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"correct horse battery staple\n")
        try:
            proc = subprocess.run(
                [GPG, "--homedir", HOMEDIR, "--batch", "--yes", "--pinentry-mode", "loopback",
                 "--passphrase-file", path, "--decrypt"],
                input=blob, capture_output=True, timeout=60)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertEqual(proc.stdout, b"portable across platforms")


class WebDavTest(GpgfsTestBase):
    """Exercise the WebDAV interface with stdlib urllib to verify the protocol layer."""

    def setUp(self) -> None:
        super().setUp()
        self.vfs.mkdir("dir")
        self.server = make_server(self.vfs, host="127.0.0.1", port=0)
        import threading

        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _request(self, method: str, path: str, data: bytes | None = None,
                 headers: dict | None = None):
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def test_options(self) -> None:
        status, _, headers = self._request("OPTIONS", "/")
        self.assertEqual(status, 200)
        self.assertIn("1", headers.get("DAV", ""))

    def test_put_get(self) -> None:
        status, _, _ = self._request("PUT", "/dir/a.txt", b"dav-content")
        self.assertIn(status, (201, 204))
        status, body, headers = self._request("GET", "/dir/a.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"dav-content")
        self.assertEqual(headers["Content-Length"], "11")

    def test_chunked_put(self) -> None:
        # Write to the raw socket to simulate Transfer-Encoding: chunked
        import http.client

        port = self.server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        body = b"chunked-payload"
        conn.putrequest("PUT", "/dir/chunked.txt")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        conn.send(b"%x\r\n%s\r\n" % (len(body), body))
        conn.send(b"0\r\n\r\n")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertIn(resp.status, (201, 204))
        self.assertEqual(self.vfs.read_file("dir/chunked.txt"), body)

    def test_propfind_depth1(self) -> None:
        self.vfs.write_file("dir/x.txt", b"123")
        status, body, _ = self._request("PROPFIND", "/dir", headers={"Depth": "1"})
        self.assertEqual(status, 207)
        text = body.decode("utf-8")
        self.assertIn("/dir/", text)
        self.assertIn("/dir/x.txt", text)
        self.assertIn("<D:getcontentlength>3</D:getcontentlength>", text)

    def test_mkcol_and_delete(self) -> None:
        status, _, _ = self._request("MKCOL", "/newdir")
        self.assertEqual(status, 201)
        self.assertExists("newdir")
        status, _, _ = self._request("DELETE", "/newdir")
        self.assertEqual(status, 204)
        self.assertMissing("newdir")

    def test_move(self) -> None:
        self.vfs.write_file("dir/m.txt", b"move")
        status, _, _ = self._request(
            "MOVE", "/dir/m.txt",
            headers={"Destination": self.base + "/dir/n.txt", "Overwrite": "T"})
        self.assertIn(status, (201, 204))
        self.assertMissing("dir/m.txt")
        self.assertEqual(self.vfs.read_file("dir/n.txt"), b"move")

    def test_range_request(self) -> None:
        self.vfs.write_file("dir/r.txt", b"0123456789")
        status, body, headers = self._request(
            "GET", "/dir/r.txt", headers={"Range": "bytes=2-5"})
        self.assertEqual(status, 206)
        self.assertEqual(body, b"2345")
        self.assertIn("bytes 2-5/10", headers["Content-Range"])

    def test_404(self) -> None:
        status, _, _ = self._request("GET", "/missing.txt")
        self.assertEqual(status, 404)

    def test_failed_put_does_not_desync_the_connection(self) -> None:
        """An error leaves the request body unread; the connection must be closed, not reused."""
        import http.client
        import threading

        server = make_server(self.vfs, host="127.0.0.1", port=0, read_only=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
            conn.request("PUT", "/dir/blocked.txt", body=b"unread payload")
            first = conn.getresponse()
            first.read()
            self.assertEqual(first.status, 403)
            self.assertEqual(first.getheader("Connection"), "close")

            conn.request("GET", "/dir")
            second = conn.getresponse()
            second.read()
            self.assertEqual(second.status, 200)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_locked_write_rejected(self) -> None:
        self.vfs.write_file("dir/l.txt", b"v1")
        status, _, headers = self._request("LOCK", "/dir/l.txt",
                                           b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"/>')
        self.assertEqual(status, 200)
        token = headers.get("Lock-Token", "").strip("<>")
        self.assertTrue(token)
        status, _, _ = self._request("PUT", "/dir/l.txt", b"v2")
        self.assertEqual(status, 423, "writing to a locked file should return 423")
        status, _, _ = self._request("PUT", "/dir/l.txt", b"v2", headers={"If": f"({token})"})
        self.assertIn(status, (201, 204))
        self.assertEqual(self.vfs.read_file("dir/l.txt"), b"v2")


class UnmapDriveTest(unittest.TestCase):
    """Unmounting must not hang on an unresponsive redirector.

    Regression: Ctrl+C got stuck in net use /delete.
    """

    def setUp(self) -> None:
        from gpgfs import winmount

        self.winmount = winmount

    def test_drive_normalization(self) -> None:
        self.assertEqual(self.winmount._drive_str("z"), "Z:")
        self.assertEqual(self.winmount._drive_str(" z:\\ "), "Z:")

    def test_net_use_parsing_ignores_the_status_column(self) -> None:
        output = (
            "New connections will be remembered.\n\n"
            "Status       Local     Remote                    Network\n"
            "\n"
            "-------------------------------------------------------------------------------\n"
            "OK           Z:        \\\\server\\share            Microsoft Windows Network\n"
            "Unavailable  Y:        \\\\127.0.0.1@8765\\DavWWWRoot\n"
            "The command completed successfully.\n"
        )
        self.assertEqual(self.winmount._parse_net_use(output), [
            ("Z:", "\\\\server\\share"),
            ("Y:", "\\\\127.0.0.1@8765\\DavWWWRoot"),
        ])

    def test_dav_remote_detection(self) -> None:
        self.assertTrue(self.winmount.is_dav_remote("\\\\127.0.0.1@8765\\DavWWWRoot"))
        self.assertTrue(self.winmount.is_dav_remote("\\\\10.0.0.5@443\\DavWWWRoot\\"))
        self.assertFalse(self.winmount.is_dav_remote("\\\\server\\share"))
        self.assertFalse(self.winmount.is_dav_remote(""))

    def test_wedged_probe_does_not_hang(self) -> None:
        import threading

        release = threading.Event()
        started = time.monotonic()
        with mock.patch.object(self.winmount, "IS_WINDOWS", True), \
                mock.patch.object(self.winmount, "_remote_of",
                                  side_effect=lambda drive: release.wait(30)), \
                mock.patch.object(self.winmount, "_cancel_connection", return_value=True):
            try:
                result = self.winmount.unmap_drive("Z:", wait=0.1, timeout=0.2)
            finally:
                release.set()
        self.assertTrue(result, "a successful force-disconnect should be reported as success")
        self.assertLess(time.monotonic() - started, 15)

    def test_wedged_disconnect_returns_quickly(self) -> None:
        import threading

        release = threading.Event()
        started = time.monotonic()
        with mock.patch.object(self.winmount, "IS_WINDOWS", True), \
                mock.patch.object(self.winmount, "_cancel_connection",
                                  side_effect=lambda drive: release.wait(30)), \
                mock.patch.object(self.winmount, "_net_delete", return_value=True), \
                mock.patch.object(self.winmount, "_is_mapped", return_value=False):
            try:
                self.assertTrue(self.winmount.unmap_drive("Z:", wait=0, timeout=0.2))
            finally:
                release.set()
        self.assertLess(time.monotonic() - started, 10)

    def test_unmap_is_a_no_op_off_windows(self) -> None:
        with mock.patch.object(self.winmount, "IS_WINDOWS", False):
            self.assertFalse(self.winmount.unmap_drive("Z:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
