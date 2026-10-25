"""End-to-end protocol test: start ``gpgfs serve`` and drive it over HTTP.

    python scripts/protocol_test.py
    python scripts/protocol_test.py --keep --verbose

Needs no drive letter, so it runs on any platform. The Windows drive-level test is
``scripts/e2e_test.py``.
"""

from __future__ import annotations

import argparse
import http.client
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASSED = 0
FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [ok]  {name}" + (f"   {detail}" if detail else ""))
    else:
        FAILED += 1
        print(f"  [xx]  {name}" + (f"   {detail}" if detail else ""))


def free_port(host: str) -> int:
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return True
            except OSError:
                time.sleep(0.2)
    return False


class Client:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def request(self, method: str, path: str, body: bytes | None = None,
                headers: dict[str, str] | None = None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.getheaders()}
        finally:
            conn.close()


def run_checks(client: Client, vault: str) -> None:
    status, _, headers = client.request("OPTIONS", "/")
    check("OPTIONS advertises WebDAV", status == 200 and "1" in headers.get("dav", ""),
          headers.get("dav", ""))

    status, _, _ = client.request("MKCOL", "/dir")
    check("MKCOL creates a collection", status == 201, str(status))

    payload = b"hello over webdav\n"
    status, _, _ = client.request("PUT", "/dir/a.txt", payload)
    check("PUT creates a file", status in (201, 204), str(status))

    status, body, _ = client.request("GET", "/dir/a.txt")
    check("GET returns the plaintext", status == 200 and body == payload, str(status))

    ciphertext = os.path.join(vault, "dir", "a.txt.gpg")
    plaintext = os.path.join(vault, "dir", "a.txt")
    check("ciphertext is on disk and plaintext is not",
          os.path.isfile(ciphertext) and not os.path.exists(plaintext))
    with open(ciphertext, "rb") as fh:
        check("the stored bytes are not the plaintext", fh.read() != payload)

    status, _, headers = client.request("HEAD", "/dir/a.txt")
    check("HEAD reports the plaintext length",
          status == 200 and headers.get("content-length") == str(len(payload)),
          headers.get("content-length", "?"))

    status, body, _ = client.request("GET", "/dir/a.txt", headers={"Range": "bytes=0-4"})
    check("Range returns a partial body", status == 206 and body == payload[:5], str(status))

    status, body, _ = client.request("PROPFIND", "/dir", headers={"Depth": "1"})
    check("PROPFIND lists the file", status == 207 and b"a.txt" in body, str(status))

    destination = f"http://{client.host}:{client.port}/dir/b.txt"
    status, _, _ = client.request("MOVE", "/dir/a.txt", headers={"Destination": destination})
    check("MOVE renames the file", status in (201, 204), str(status))

    status, _, headers = client.request(
        "LOCK", "/dir/b.txt", b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"/>')
    token = headers.get("lock-token", "").strip("<>")
    check("LOCK returns a token", status in (200, 201) and bool(token), str(status))

    status, _, _ = client.request("PUT", "/dir/b.txt", b"blocked")
    check("a write without the lock token is rejected", status == 423, str(status))

    status, _, _ = client.request("PUT", "/dir/b.txt", b"updated", headers={"If": f"({token})"})
    check("a write with the lock token succeeds", status in (201, 204), str(status))

    status, _, _ = client.request("UNLOCK", "/dir/b.txt", headers={"Lock-Token": f"<{token}>"})
    check("UNLOCK releases the lock", status == 204, str(status))

    status, body, _ = client.request("GET", "/dir/b.txt")
    check("the updated content is readable", body == b"updated", str(status))

    status, _, _ = client.request("DELETE", "/dir/b.txt")
    check("DELETE removes the file", status == 204, str(status))

    status, _, _ = client.request("PROPFIND", "/dir/b.txt")
    check("a missing file answers 404", status == 404, str(status))

    status, _, _ = client.request("DELETE", "/dir")
    check("an empty collection can be deleted", status == 204, str(status))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keep", action="store_true", help="keep the temporary vault")
    parser.add_argument("--passphrase", default="protocol-test-passphrase")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    vault = tempfile.mkdtemp(prefix="gpgfs-protocol-")
    host = "127.0.0.1"
    port = free_port(host)
    command = [sys.executable, "-m", "gpgfs", "serve", vault,
               "--symmetric", "--passphrase", args.passphrase,
               "--host", host, "--port", str(port)]
    if args.verbose:
        command.append("-v")

    print("Command :", " ".join(command))
    print("Vault   :", vault)
    print("WebDAV  :", f"http://{host}:{port}/")
    print()

    log_path = os.path.join(tempfile.gettempdir(), "gpgfs-protocol-server.log")
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            if not wait_for_port(host, port):
                print("  [xx]  the server did not start")
                with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                    print(fh.read()[-2000:])
                return 1
            run_checks(Client(host, port), vault)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            if not args.keep:
                shutil.rmtree(vault, ignore_errors=True)

    print()
    print(f"{PASSED} checks passed, {FAILED} failed")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
