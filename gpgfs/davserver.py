"""WebDAV transport layer: exposes Vfs as a WebDAV namespace over HTTP.

Why WebDAV:
- Windows ships a WebDAV redirector (the WebClient service), so
  ``net use Z: http://127.0.0.1:<port>/`` gives you a real drive letter that any
  program (Explorer/Office/VSCode/command line) can reach transparently;
- no kernel driver and no administrator rights needed;
- macOS Finder, Linux gvfs/davfs2, and file managers on phones all support WebDAV natively.

It implements WebDAV Class 1 plus part of Class 2 (LOCK/UNLOCK), enough for the
Windows redirector and Office write needs.
"""

from __future__ import annotations

import base64
import email.utils
import html
import mimetypes
import socket
import sys as _sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from .errors import (
    AlreadyExists,
    DirectoryNotEmpty,
    GpgfsError,
    InvalidPath,
    IsADirectory,
    NotADirectory,
    NotFound,
    GpgError,
)
from .vfs import Entry, Vfs

DAV_NS = 'xmlns:D="DAV:" xmlns:Win32="urn:schemas-microsoft-com:"'
WIN32_FILE_ATTR_DIR = "00000010"
WIN32_FILE_ATTR_NORMAL = "00000080"


def _rfc1123(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)


def _iso8601(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _xml_escape(text: str) -> str:
    return html.escape(text, quote=False)


def _href(rel: str, is_dir: bool) -> str:
    quoted = urllib.parse.quote("/" + rel if rel else "/", safe="/")
    if is_dir and not quoted.endswith("/"):
        quoted += "/"
    return quoted


class LockManager:
    """Minimal LOCK bookkeeping, enough for Office/Word.

    Tokens are tracked per path so a write that does not present the token can be rejected.
    It is not an exclusive lock: a second LOCK on the same path is granted as well, because
    only one client (the redirector) is ever expected to talk to this server.
    """

    def __init__(self) -> None:
        self._locks: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def acquire(self, rel: str, timeout: int = 3600) -> str:
        token = f"opaquelocktoken:{uuid.uuid4()}"
        with self._lock:
            self._locks[token] = (rel, time.time() + timeout)
        return token

    def release(self, token: str) -> bool:
        with self._lock:
            return self._locks.pop(token, None) is not None

    def find(self, rel: str) -> str | None:
        now = time.time()
        with self._lock:
            for token, (path, expires) in list(self._locks.items()):
                if expires < now:
                    self._locks.pop(token, None)
                    continue
                if path == rel or rel.startswith(path + "/") or path.startswith(rel + "/"):
                    return token
        return None

    def token_for_path(self, rel: str) -> str | None:
        with self._lock:
            for token, (path, _) in self._locks.items():
                if path == rel:
                    return token
        return None


class _ContentReader:
    """Confines the request body to Content-Length so keep-alive is not over-read."""

    def __init__(self, rfile, length: int) -> None:
        self._rfile = rfile
        self._left = length

    def read(self, size: int = -1) -> bytes:
        if self._left <= 0:
            return b""
        if size is None or size < 0:
            size = self._left
        size = min(size, self._left)
        data = self._rfile.read(size)
        if not data:
            self._left = 0
            return b""
        self._left -= len(data)
        return data


class _ChunkedReader:
    """Parses an HTTP/1.1 chunked request body.

    The Windows WebDAV redirector uploads files with chunked transfer rather than
    Content-Length, so this must be supported, otherwise only empty content is read.
    """

    def __init__(self, rfile) -> None:
        self._rfile = rfile
        self._left = 0
        self._done = False

    def _readline(self) -> bytes:
        return self._rfile.readline(8192)

    def read(self, size: int = -1) -> bytes:
        if self._done:
            return b""
        if self._left == 0:
            line = self._readline()
            while line in (b"\r\n", b"\n"):
                line = self._readline()
            if not line:
                self._done = True
                return b""
            token = line.strip().split(b";", 1)[0].strip()
            try:
                self._left = int(token, 16)
            except ValueError:
                self._done = True
                return b""
            if self._left == 0:  # final chunk, trailers may follow
                while True:
                    trailer = self._readline()
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                self._done = True
                return b""
        if size is None or size < 0 or size > self._left:
            size = self._left
        data = self._rfile.read(size)
        if not data:
            self._done = True
            return b""
        self._left -= len(data)
        if self._left == 0:
            self._rfile.read(2)  # consume the trailing CRLF of the chunk
        return data


class _EmptyReader:
    def read(self, size: int = -1) -> bytes:
        return b""


class DavHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gpgfs"
    sys_version = ""

    # injected by make_server
    vfs: Vfs
    verbose: bool = False
    auth: tuple[str, str] | None = None
    locks: LockManager = LockManager()
    read_only: bool = False

    # ------------------------------------------------------------------- basics

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        if self.verbose:
            super().log_message(fmt, *args)

    def log_request(self, code="-", size="-") -> None:
        if self.verbose:
            super().log_request(code, size)

    def _send(self, code: int, body: bytes = b"", content_type: str | None = None,
              extra: dict[str, str] | None = None, length: int | None = None) -> None:
        self.send_response(code)
        if content_type:
            self.send_header("Content-Type", content_type)
        if code != 304:
            self.send_header("Content-Length", str(len(body) if length is None else length))
        self.send_header("Accept-Ranges", "bytes")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _send_multistatus(self, xml: str) -> None:
        self._send(207, xml.encode("utf-8"),
                   'application/xml; charset="utf-8"',
                   {"Cache-Control": "no-cache, no-store"})

    def _error(self, code: int, message: str = "") -> None:
        body = (message or self.responses.get(code, ("",))[0]).encode("utf-8")
        # A failed request may leave its body unread, and reusing the connection would make the
        # leftovers look like the next request, so say we are closing it.
        self.close_connection = True
        self._send(code, body, "text/plain; charset=utf-8", {"Connection": "close"})

    def _authorized(self) -> bool:
        if self.auth is None:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                raw = base64.b64decode(header[6:]).decode("utf-8")
                user, _, password = raw.partition(":")
            except Exception:
                return False
            if (user, password) == self.auth:
                return True
        self._send(401, b"authentication required", "text/plain",
                   {"WWW-Authenticate": 'Basic realm="gpgfs"'})
        return False

    def _rel(self) -> str:
        path = urllib.parse.urlsplit(self.path).path
        path = urllib.parse.unquote(path)
        return self.vfs.normalize(path)

    def _rel_from_url(self, url: str) -> str:
        path = urllib.parse.urlsplit(url).path
        return self.vfs.normalize(urllib.parse.unquote(path))

    def _body_reader(self):
        """Picks the right body reader based on Transfer-Encoding / Content-Length."""
        encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in encoding:
            return _ChunkedReader(self.rfile)
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            return _ContentReader(self.rfile, length)
        return _EmptyReader()

    def _read_body(self, limit: int = 4 * 1024 * 1024) -> bytes:
        reader = self._body_reader()
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            data = reader.read(65536)
            if not data:
                break
            chunks.append(data)
            total += len(data)
        return b"".join(chunks)

    def _handle(self, func, *args) -> None:
        if not self._authorized():
            return
        if self.verbose:
            interesting = ("Content-Length", "Transfer-Encoding", "Expect", "Depth",
                           "If", "Destination", "Overwrite", "User-Agent", "Range")
            detail = "  ".join(f"{k}={self.headers[k]}" for k in interesting
                               if self.headers.get(k))
            _sys.stderr.write(f">>> {self.command} {self.path}  {detail}\n")
            _sys.stderr.flush()
        try:
            func(*args)
        except _Locked as exc:
            self.close_connection = True
            self._error(423, f"resource is locked: /{exc}")
        except InvalidPath as exc:
            self._error(400, str(exc))
        except NotFound as exc:
            self._error(404, str(exc))
        except AlreadyExists as exc:
            self._error(412 if self.command == "MOVE" else 405, str(exc))
        except NotADirectory as exc:
            self._error(409, str(exc))
        except IsADirectory as exc:
            self._error(409, str(exc))
        except DirectoryNotEmpty as exc:
            self._error(409, str(exc))
        except GpgError as exc:
            self.close_connection = True
            self._error(500, f"gpg failed: {exc}")
        except GpgfsError as exc:
            self._error(400, str(exc))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
        except Exception as exc:  # pragma: no cover - last resort
            import traceback

            if isinstance(exc, OSError):
                traceback.print_exc()
                _sys.stderr.write(f"    [oserror] winerror={getattr(exc, 'winerror', None)} "
                                  f"errno={exc.errno} filename={exc.filename!r}\n")
            else:
                traceback.print_exc()
            # the request body may not be fully read; reusing this connection would
            # desync later requests, so closing it is safer
            self.close_connection = True
            self._error(500, f"internal error: {exc}")

    # --------------------------------------------------------- protocol methods

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        self.send_response(200)
        self.send_header("DAV", "1, 2")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header("Allow", "OPTIONS, GET, HEAD, PUT, POST, DELETE, "
                                  "PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header("Content-Length", "0")
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_PROPFIND(self) -> None:  # noqa: N802
        self._handle(self._propfind)

    def do_PROPPATCH(self) -> None:  # noqa: N802
        self._handle(self._proppatch)

    def do_GET(self) -> None:  # noqa: N802
        self._handle(self._get)

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle(self._get)

    def do_PUT(self) -> None:  # noqa: N802
        self._handle(self._put)

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle(self._delete)

    def do_MKCOL(self) -> None:  # noqa: N802
        self._handle(self._mkcol)

    def do_MOVE(self) -> None:  # noqa: N802
        self._handle(self._move)

    def do_COPY(self) -> None:  # noqa: N802
        self._handle(self._copy)

    def do_LOCK(self) -> None:  # noqa: N802
        self._handle(self._lock)

    def do_UNLOCK(self) -> None:  # noqa: N802
        self._handle(self._unlock)

    def do_POST(self) -> None:  # noqa: N802
        self._error(405, "POST is not supported")

    # ------------------------------------------------------------- implementation

    def _propfind(self) -> None:
        rel = self._rel()
        depth = (self.headers.get("Depth") or "1").strip().lower()
        self._read_body()  # discard the request body, allprop/propname need not be told apart

        entry = self.vfs.stat(rel)
        parts: list[str] = []
        if depth == "0":
            parts.append(self._response_xml(rel, entry))
        elif depth == "infinity":
            parts.append(self._response_xml(rel, entry))
            if entry.is_dir:
                for sub, sub_entry in self._walk_limited(rel, 8):
                    parts.append(self._response_xml(sub, sub_entry))
        else:  # depth 1
            parts.append(self._response_xml(rel, entry))
            if entry.is_dir:
                try:
                    for child in self.vfs.listdir(rel):
                        child_rel = f"{rel}/{child.name}" if rel else child.name
                        parts.append(self._response_xml(child_rel, child))
                except GpgfsError:
                    pass
        self._send_multistatus(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            f"<D:multistatus {DAV_NS}>" + "".join(parts) + "</D:multistatus>"
        )

    def _walk_limited(self, rel: str, max_depth: int) -> Iterator[tuple[str, Entry]]:
        """Limits traversal depth for depth: infinity so one request cannot scan a whole tree."""

        def rec(path: str, depth: int):
            if depth > max_depth:
                return
            try:
                children = self.vfs.listdir(path)
            except GpgfsError:
                return
            for child in children:
                child_path = f"{path}/{child.name}" if path else child.name
                yield child_path, child
                if child.is_dir:
                    yield from rec(child_path, depth + 1)

        yield from rec(rel, 1)

    def _response_xml(self, rel: str, entry: Entry) -> str:
        props = [
            f"<D:creationdate>{_iso8601(entry.ctime)}</D:creationdate>",
            f"<D:displayname>{_xml_escape(entry.name)}</D:displayname>",
            "<D:resourcetype>" + ("<D:collection/>" if entry.is_dir else "") + "</D:resourcetype>",
            f"<D:getcontentlength>{0 if entry.is_dir else entry.size}</D:getcontentlength>",
            f"<D:getetag>{_xml_escape(entry.etag)}</D:getetag>",
            f"<D:getlastmodified>{_rfc1123(entry.mtime)}</D:getlastmodified>",
            "<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>",
            "<D:lockdiscovery/>",
            f"<Win32:Win32FileAttributes>"
            f"{WIN32_FILE_ATTR_DIR if entry.is_dir else WIN32_FILE_ATTR_NORMAL}"
            f"</Win32:Win32FileAttributes>",
        ]
        if not entry.is_dir:
            ctype = mimetypes.guess_type(entry.name)[0] or "application/octet-stream"
            props.append(f"<D:getcontenttype>{ctype}</D:getcontenttype>")
        return (
            "<D:response>"
            f"<D:href>{_xml_escape(_href(rel, entry.is_dir))}</D:href>"
            "<D:propstat><D:prop>" + "".join(props) + "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
            "</D:response>"
        )

    def _proppatch(self) -> None:
        rel = self._rel()
        self.vfs.stat(rel)  # 404 if it does not exist
        body = self._read_body().decode("utf-8", "replace")
        # Properties are not applied to the vault; the one Office cares about is echoed back
        # with a 200 so the save can continue.
        props = ""
        if "Win32LastModifiedTime" in body:
            props = "<Win32:Win32LastModifiedTime/>"
        self._send_multistatus(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            f"<D:multistatus {DAV_NS}><D:response>"
            f"<D:href>{_xml_escape(_href(rel, self.vfs.is_dir(rel)))}</D:href>"
            f"<D:propstat><D:prop>{props or '<D:displayname/>'}</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
            "</D:response></D:multistatus>"
        )

    def _get(self) -> None:
        rel = self._rel()
        entry = self.vfs.stat(rel)

        if entry.is_dir:
            if self.command == "HEAD":
                self._send(200, b"", "text/html; charset=utf-8")
                return
            body = self._html_index(rel)
            self._send(200, body, "text/html; charset=utf-8")
            return

        etag = entry.etag
        if self.headers.get("If-None-Match") == etag:
            self._send(304, b"", None, {"ETag": etag})
            return

        ctype = mimetypes.guess_type(entry.name)[0] or "application/octet-stream"
        extra = {
            "ETag": etag,
            "Last-Modified": _rfc1123(entry.mtime),
            "Cache-Control": "no-cache",
        }
        data = self.vfs.read_file(rel)

        rng = self._parse_range(self.headers.get("Range"), len(data))
        if rng is None and self.headers.get("Range"):
            self._send(416, b"", "text/plain", {"Content-Range": f"bytes */{len(data)}"})
            return
        if rng is not None:
            start, end = rng
            chunk = data[start:end + 1]
            extra["Content-Range"] = f"bytes {start}-{end}/{len(data)}"
            self._send(206, chunk, ctype, extra)
            return

        if self.command == "HEAD":
            self._send(200, b"", ctype, extra, length=len(data))
            return
        self._send(200, data, ctype, extra)

    @staticmethod
    def _parse_range(header: str | None, total: int) -> tuple[int, int] | None:
        """Only single-range Range requests are handled, enough for Windows video/large images."""
        if not header or not header.startswith("bytes="):
            return None
        spec = header[len("bytes="):].split(",")[0].strip()
        start_s, _, end_s = spec.partition("-")
        try:
            if start_s == "":
                length = int(end_s)
                start = max(0, total - length)
                end = total - 1
            else:
                start = int(start_s)
                end = int(end_s) if end_s else total - 1
        except ValueError:
            return None
        end = min(end, total - 1)
        if start > end or start >= total:
            return None
        return start, end

    def _html_index(self, rel: str) -> bytes:
        rows = []
        if rel:
            parent = "/".join(rel.split("/")[:-1])
            rows.append(f'<li><a href="{_href(parent, True)}">../</a></li>')
        try:
            entries = self.vfs.listdir(rel)
        except GpgfsError:
            entries = []
        for e in sorted(entries, key=lambda x: (not x.is_dir, x.name.lower())):
            child = f"{rel}/{e.name}" if rel else e.name
            suffix = "/" if e.is_dir else ""
            size = "" if e.is_dir else _human_size(e.size)
            rows.append(f'<li><a href="{_href(child, e.is_dir)}">{_xml_escape(e.name)}'
                        f'{suffix}</a><span>{size}</span></li>')
        title = f"/{rel}" if rel else "/"
        doc = f"""<!doctype html>
<meta charset="utf-8"><title>gpgfs {html.escape(title)}</title>
<style>
 body{{font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;margin:2rem auto;max-width:52rem;color:#1f2328}}
 h1{{font-size:1.1rem;font-weight:600;border-bottom:1px solid #e5e7eb;padding-bottom:.6rem}}
 ul{{list-style:none;padding:0}} li{{display:flex;justify-content:space-between;padding:.35rem .2rem;border-bottom:1px solid #f2f4f7}}
 a{{color:#0969da;text-decoration:none}} a:hover{{text-decoration:underline}}
 span{{color:#8b949e;font-variant-numeric:tabular-nums}}
 code{{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}}
</style>
<h1>{html.escape(title)}</h1>
<p><code>net use Z: {html.escape(self._base_url())}</code> mounts it directly as a drive letter</p>
<ul>{''.join(rows) or '<li>(empty directory)</li>'}</ul>"""
        return doc.encode("utf-8")

    def _base_url(self) -> str:
        host = self.headers.get("Host") or f"127.0.0.1:{self.server.server_address[1]}"
        return f"http://{host}/"

    def _put(self) -> None:
        if self.read_only:
            self._error(403, "read-only mode")
            return
        rel = self._rel()
        if not rel:
            self._error(405, "cannot write root")
            return
        if self.vfs.is_dir(rel):
            self._error(409, "target is a directory")
            return
        self._check_lock(rel)
        existed = self.vfs.exists(rel)
        entry = self.vfs.write_stream(rel, self._body_reader())
        self._send(204 if existed else 201, b"", None, {"ETag": entry.etag})

    def _delete(self) -> None:
        if self.read_only:
            self._error(403, "read-only mode")
            return
        rel = self._rel()
        if not rel:
            self._error(403, "cannot delete root")
            return
        self._check_lock(rel)
        entry = self.vfs.stat(rel)
        if entry.is_dir:
            self.vfs.rmdir(rel)
        else:
            self.vfs.delete(rel)
        self._send(204)

    def _mkcol(self) -> None:
        if self.read_only:
            self._error(403, "read-only mode")
            return
        rel = self._rel()
        self._read_body()
        self.vfs.mkdir(rel)
        self._send(201)

    def _destination(self) -> str:
        dest = self.headers.get("Destination")
        if not dest:
            raise InvalidPath("missing Destination header")
        return self._rel_from_url(dest)

    def _move(self) -> None:
        if self.read_only:
            self._error(403, "read-only mode")
            return
        src = self._rel()
        dst = self._destination()
        overwrite = (self.headers.get("Overwrite") or "T").upper() != "F"
        existed = self.vfs.exists(dst)
        self.vfs.rename(src, dst, overwrite=overwrite)
        self._send(204 if existed else 201)

    def _copy(self) -> None:
        if self.read_only:
            self._error(403, "read-only mode")
            return
        src = self._rel()
        dst = self._destination()
        overwrite = (self.headers.get("Overwrite") or "T").upper() != "F"
        existed = self.vfs.exists(dst)
        self.vfs.copy(src, dst, overwrite=overwrite)
        self._send(204 if existed else 201)

    def _lock(self) -> None:
        rel = self._rel()
        body = self._read_body().decode("utf-8", "replace")
        owner = ""
        marker = "<D:owner>"
        if marker in body:
            owner = body.split(marker, 1)[1].split("</D:owner>", 1)[0]
        token = self.locks.acquire(rel)
        exists = self.vfs.exists(rel)
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            f"<D:prop {DAV_NS}><D:lockdiscovery><D:activelock>"
            "<D:locktype><D:write/></D:locktype>"
            "<D:lockscope><D:exclusive/></D:lockscope>"
            "<D:depth>infinity</D:depth>"
            f"<D:owner>{owner}</D:owner>"
            "<D:timeout>Second-3600</D:timeout>"
            f"<D:locktoken><D:href>{token}</D:href></D:locktoken>"
            f"<D:lockroot><D:href>{_xml_escape(_href(rel, False))}</D:href></D:lockroot>"
            "</D:activelock></D:lockdiscovery></D:prop>"
        )
        self._send(200 if exists else 201, xml.encode("utf-8"),
                   'application/xml; charset="utf-8"',
                   {"Lock-Token": f"<{token}>"})

    def _unlock(self) -> None:
        token = (self.headers.get("Lock-Token") or "").strip().strip("<>")
        self.locks.release(token)
        self._send(204)

    def _check_lock(self, rel: str) -> None:
        token = self.locks.find(rel)
        if token is None:
            return
        header = self.headers.get("If") or ""
        if token in header:
            return
        raise _Locked(rel)


class _Locked(GpgfsError):
    """Internal signal: the target is locked."""


class DavServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:  # pragma: no cover
        import sys

        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


def make_server(
    vfs: Vfs,
    host: str = "127.0.0.1",
    port: int = 0,
    auth: tuple[str, str] | None = None,
    verbose: bool = False,
    read_only: bool = False,
) -> DavServer:
    """Creates a WebDAV server (not started). port=0 means a random port."""

    class BoundHandler(DavHandler):
        pass

    BoundHandler.vfs = vfs
    BoundHandler.auth = auth
    BoundHandler.verbose = verbose
    BoundHandler.read_only = read_only
    BoundHandler.locks = LockManager()

    server = DavServer((host, port), BoundHandler)
    server.host = host
    server.port = server.server_address[1]
    return server


def run_server(server: DavServer, block: bool = True) -> None:
    """Starts the server; with block=False it runs on a background thread."""
    if block:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"
