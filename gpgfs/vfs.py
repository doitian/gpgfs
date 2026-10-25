"""Virtual filesystem core: map a "gpg ciphertext directory" to a "plaintext namespace".

    vault/foo/bar.txt.gpg   ->   virtual dir/foo/bar.txt

Conventions:
- Directory names stay plaintext and reuse the real directory directly.
- The file name with the ``.gpg`` suffix stripped serves as the virtual file name.
- A write keeps the on-disk form of its target: an existing file is replaced in place, a new
  one is created with the ``.gpg`` suffix.
- Temp files all start with ``.gpgfs-tmp-``, and any directory listing hides them.
"""

from __future__ import annotations

import os
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterator

from .cipher import GpgCipher
from .errors import (
    AlreadyExists,
    DirectoryNotEmpty,
    InvalidPath,
    IsADirectory,
    NotADirectory,
    NotFound,
)
from .state import PlaintextCache, SizeCache

GPG_SUFFIX = ".gpg"
TMP_PREFIX = ".gpgfs-tmp-"
CONFIG_NAME = ".gpgfs.json"
CHUNK = 256 * 1024

# On Windows, antivirus software and indexers briefly hold exclusive locks on files that were
# just written, making the immediate open / rename report EACCES or a sharing violation. So we
# uniformly do a few backoff retries here.
RETRY_ATTEMPTS = 10
RETRY_BASE_DELAY = 0.04


def _retry_op(func, *args):
    """Backoff retry for operations that may be briefly blocked by antivirus or indexers."""
    last: OSError | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return func(*args)
        except PermissionError as exc:
            last = exc
            time.sleep(RETRY_BASE_DELAY * (attempt + 1))
    raise last  # type: ignore[misc]


def _open_with_retry(path: str, mode: str):
    last: OSError | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return open(path, mode)
        except PermissionError as exc:
            last = exc
            time.sleep(RETRY_BASE_DELAY * (attempt + 1))
    raise last  # type: ignore[misc]


def _replace_with_retry(tmp: str, target: str) -> None:
    """Atomic replace; retry with backoff while the target is busy.

    As a last resort (another process holds the target open in a way that forbids replacement)
    the bytes are copied into the target in place, which is no longer atomic — that is only
    reachable on Windows with an open handle on the destination.
    """
    last: OSError | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            os.replace(tmp, target)
            return
        except PermissionError as exc:
            last = exc
            time.sleep(RETRY_BASE_DELAY * (attempt + 1))
    try:
        with open(tmp, "rb") as src, open(target, "wb") as dst:
            while True:
                block = src.read(CHUNK)
                if not block:
                    break
                dst.write(block)
            dst.flush()
            os.fsync(dst.fileno())
        os.unlink(tmp)
        return
    except OSError:
        raise last  # type: ignore[misc]


@dataclass
class Entry:
    """One entry in the virtual namespace."""

    name: str
    is_dir: bool
    size: int
    mtime: float
    ctime: float
    encrypted: bool = True

    @property
    def etag(self) -> str:
        return f'"{int(self.mtime * 1e7):x}-{self.size:x}"'


class Vfs:
    """Virtual view of an encrypted directory.

    Safe for concurrent use: both caches are internally locked. Concurrent writes to the same
    path are last-writer-wins, so the recorded plaintext size may belong to the earlier write.
    """

    def __init__(
        self,
        root: str,
        cipher: GpgCipher,
        size_cache: SizeCache | None = None,
        plain_cache: PlaintextCache | None = None,
        expose_plaintext: bool = False,
        size_workers: int = 8,
    ) -> None:
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise NotFound(f"Encrypted directory does not exist: {self.root}")
        self.cipher = cipher
        self.size_cache = size_cache or SizeCache(None)
        self.plain_cache = plain_cache or PlaintextCache()
        self.expose_plaintext = expose_plaintext
        self.size_workers = max(1, size_workers)

    # ------------------------------------------------------------------ path

    @staticmethod
    def normalize(rel: str) -> str:
        """Normalize a virtual path of any form into ``a/b/c`` (no leading or trailing slash).

        Rejects ``..`` and empty segments, to prevent escaping the encrypted directory.
        """
        if rel is None:
            rel = ""
        rel = rel.replace("\\", "/")
        parts: list[str] = []
        for seg in rel.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                raise InvalidPath("Path must not contain '..'")
            if "\x00" in seg:
                raise InvalidPath("Path contains an illegal character")
            if seg.startswith(TMP_PREFIX):
                raise InvalidPath("This file name is reserved by the system")
            parts.append(seg)
        return "/".join(parts)

    def _abs(self, rel: str) -> str:
        rel = self.normalize(rel)
        if not rel:
            return self.root
        return os.path.join(self.root, *rel.split("/"))

    def _split(self, rel: str) -> tuple[str, str]:
        rel = self.normalize(rel)
        if not rel:
            return "", ""
        parent, _, name = rel.rpartition("/")
        return parent, name

    def _real_for_read(self, rel: str) -> tuple[str, bool]:
        """Return (real path, whether it is an encrypted file)."""
        base = self._abs(rel)
        enc = base + GPG_SUFFIX
        if os.path.isfile(enc):
            return enc, True
        if self.expose_plaintext and os.path.isfile(base):
            return base, False
        if os.path.isdir(base):
            return base, False
        if os.path.isfile(base):
            # Real file exists but is not exposed by expose_plaintext -> invisible to the
            # virtual layer
            raise NotFound(f"File does not exist: /{self.normalize(rel)}")
        raise NotFound(f"File does not exist: /{self.normalize(rel)}")

    def _real_for_write(self, rel: str) -> tuple[str, bool]:
        """Decide which real file the write lands in. An existing plaintext file is overwritten
        in place, otherwise ``.gpg`` is written."""
        base = self._abs(rel)
        if self.expose_plaintext and os.path.isfile(base) and not os.path.exists(base + GPG_SUFFIX):
            return base, False
        return base + GPG_SUFFIX, True

    # ------------------------------------------------------------- metadata query

    def exists(self, rel: str) -> bool:
        try:
            self.stat(rel)
            return True
        except NotFound:
            return False

    def stat(self, rel: str) -> Entry:
        rel = self.normalize(rel)
        if not rel:
            st = os.stat(self.root)
            return Entry("", True, 0, st.st_mtime, st.st_ctime)
        parent, name = self._split(rel)
        base = self._abs(rel)
        if os.path.isdir(base):
            st = os.stat(base)
            return Entry(name, True, 0, st.st_mtime, st.st_ctime)
        enc = base + GPG_SUFFIX
        if os.path.isfile(enc):
            st = os.stat(enc)
            return Entry(name, False, self._pt_size(rel, st), st.st_mtime, st.st_ctime)
        if self.expose_plaintext and os.path.isfile(base):
            st = os.stat(base)
            return Entry(name, False, st.st_size, st.st_mtime, st.st_ctime, encrypted=False)
        raise NotFound(f"Does not exist: /{rel}")

    def is_dir(self, rel: str) -> bool:
        try:
            return self.stat(rel).is_dir
        except NotFound:
            return False

    def _pt_size(self, rel: str, st: os.stat_result) -> int:
        """Plaintext size: prefer a cache hit, otherwise decrypt once and put the contents into
        the in-memory cache along the way."""
        cached = self.size_cache.get(rel, st.st_mtime_ns, st.st_size)
        if cached is not None:
            return cached
        return len(self.read_file(rel))

    def listdir(self, rel: str) -> list[Entry]:
        rel = self.normalize(rel)
        base = self._abs(rel)
        if not os.path.isdir(base):
            raise NotADirectory(f"Not a directory: /{rel}")

        dirs: list[Entry] = []
        files: list[tuple[str, os.stat_result, bool]] = []
        with os.scandir(base) as it:
            for de in it:
                name = de.name
                if name.startswith(TMP_PREFIX) or name == CONFIG_NAME:
                    continue
                try:
                    is_dir = de.is_dir()
                except OSError:
                    continue
                if is_dir:
                    st = de.stat()
                    dirs.append(Entry(name, True, 0, st.st_mtime, st.st_ctime))
                elif name.endswith(GPG_SUFFIX) and len(name) > len(GPG_SUFFIX):
                    files.append((name[: -len(GPG_SUFFIX)], de.stat(), True))
                elif self.expose_plaintext:
                    st = de.stat()
                    files.append((name, st, False))

        entries = dirs + [
            Entry(n, False, 0 if enc else st.st_size, st.st_mtime, st.st_ctime, enc)
            for n, st, enc in files
        ]
        self._warm_sizes(rel, entries, {n: st for n, st, _ in files})
        return entries

    def _warm_sizes(self, parent: str, entries: list[Entry], stat_map: dict[str, os.stat_result]) -> None:
        """Fill in plaintext sizes in parallel while listing a directory (only files that miss
        the cache need decryption)."""
        pending: list[tuple[Entry, os.stat_result]] = []
        for e in entries:
            if e.is_dir or not e.encrypted:
                continue
            st = stat_map.get(e.name)
            if st is None:
                continue
            cached = self.size_cache.get(self._join(parent, e.name), st.st_mtime_ns, st.st_size)
            if cached is not None:
                e.size = cached
            else:
                pending.append((e, st))
        if not pending:
            return

        def work(item: tuple[Entry, os.stat_result]) -> None:
            e, st = item
            try:
                e.size = self._pt_size(self._join(parent, e.name), st)
            except Exception:
                # On decryption failure fall back to the ciphertext size, at least the listing
                # is not interrupted
                e.size = st.st_size

        workers = min(self.size_workers, len(pending))
        if workers <= 1:
            for item in pending:
                work(item)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(work, pending))

    @staticmethod
    def _join(parent: str, name: str) -> str:
        return f"{parent}/{name}" if parent else name

    def walk(self, rel: str = "") -> Iterator[tuple[str, Entry]]:
        """Recursive walk, yielding (relative path, Entry)."""
        for entry in self.listdir(rel):
            path = self._join(self.normalize(rel), entry.name)
            yield path, entry
            if entry.is_dir:
                yield from self.walk(path)

    # ------------------------------------------------------------------ read

    def read_file(self, rel: str) -> bytes:
        rel = self.normalize(rel)
        path, encrypted = self._real_for_read(rel)
        if not encrypted:
            if os.path.isdir(path):
                raise IsADirectory(f"Is a directory: /{rel}")
            with _open_with_retry(path, "rb") as fh:
                return fh.read()
        st = os.stat(path)
        key = (rel, st.st_mtime_ns, st.st_size)
        hit = self.plain_cache.get(key)
        if hit is not None:
            return hit
        if st.st_size == 0:
            self.size_cache.put(rel, st.st_mtime_ns, 0, 0)
            self.plain_cache.put(key, b"")
            return b""
        with _open_with_retry(path, "rb") as fh:
            blob = fh.read()
        plain = self.cipher.decrypt_bytes(blob)
        self.size_cache.put(rel, st.st_mtime_ns, st.st_size, len(plain))
        self.plain_cache.put(key, plain)
        return plain

    def iter_file(self, rel: str) -> Iterator[bytes]:
        """Streamed read (avoids pulling a large file into memory as a whole)."""
        rel = self.normalize(rel)
        path, encrypted = self._real_for_read(rel)
        if not encrypted:
            with _open_with_retry(path, "rb") as fh:
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        return
                    yield chunk
            return
        yield from self.cipher.decrypt_iter(path, CHUNK)

    # ------------------------------------------------------------------ write

    def write_file(self, rel: str, data: bytes) -> Entry:
        rel = self.normalize(rel)
        self._ensure_parent(rel)
        target, encrypted = self._real_for_write(rel)
        if encrypted:
            blob = self.cipher.encrypt_bytes(data)
        else:
            blob = data
        self._atomic_write(target, blob)
        self.plain_cache.invalidate(rel)
        st = os.stat(target)
        self.size_cache.put(rel, st.st_mtime_ns, st.st_size, len(data))
        return Entry(os.path.basename(rel), False, len(data), st.st_mtime, st.st_ctime, encrypted)

    def write_stream(self, rel: str, reader) -> Entry:
        """Write from a readable stream (used by WebDAV PUT). Plaintext goes through the pipe
        the whole way and never lands on disk."""
        rel = self.normalize(rel)
        self._ensure_parent(rel)
        target, encrypted = self._real_for_write(rel)
        counter = _CountingReader(reader)
        tmp = os.path.join(os.path.dirname(target), TMP_PREFIX + uuid.uuid4().hex)
        try:
            with _open_with_retry(tmp, "wb") as fh:
                if encrypted:
                    self.cipher.encrypt_stream(counter, fh)
                else:
                    while True:
                        chunk = counter.read(CHUNK)
                        if not chunk:
                            break
                        fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            _replace_with_retry(tmp, target)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        self.plain_cache.invalidate(rel)
        st = os.stat(target)
        self.size_cache.put(rel, st.st_mtime_ns, st.st_size, counter.count)
        return Entry(os.path.basename(rel), False, counter.count, st.st_mtime, st.st_ctime, encrypted)

    def _atomic_write(self, target: str, blob: bytes) -> None:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = os.path.join(os.path.dirname(target), TMP_PREFIX + uuid.uuid4().hex)
        try:
            with _open_with_retry(tmp, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            _replace_with_retry(tmp, target)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _ensure_parent(self, rel: str) -> None:
        parent, name = self._split(rel)
        if not name:
            raise InvalidPath("Illegal file name")
        if parent:
            base = self._abs(parent)
            if os.path.isfile(base + GPG_SUFFIX):
                raise NotADirectory(f"Parent path is a file: /{parent}")
            if not os.path.isdir(base):
                raise NotFound(f"Parent directory does not exist: /{parent}")

    # ------------------------------------------------------------ dir/delete/rename

    def mkdir(self, rel: str) -> Entry:
        rel = self.normalize(rel)
        if not rel:
            raise AlreadyExists("Root directory already exists")
        parent, name = self._split(rel)
        self._ensure_parent(rel)
        base = self._abs(rel)
        if os.path.exists(base) or os.path.isfile(base + GPG_SUFFIX):
            raise AlreadyExists(f"Already exists: /{rel}")
        os.mkdir(base)
        st = os.stat(base)
        return Entry(name, True, 0, st.st_mtime, st.st_ctime)

    def delete(self, rel: str) -> None:
        rel = self.normalize(rel)
        if not rel:
            raise InvalidPath("Cannot delete the root directory")
        base = self._abs(rel)
        if os.path.isdir(base):
            raise IsADirectory(f"Is a directory, use rmdir: /{rel}")
        if os.path.isfile(base + GPG_SUFFIX):
            _retry_op(os.unlink, base + GPG_SUFFIX)
        elif self.expose_plaintext and os.path.isfile(base):
            _retry_op(os.unlink, base)
        else:
            raise NotFound(f"Does not exist: /{rel}")
        self.size_cache.drop(rel)
        self.plain_cache.invalidate(rel)

    def rmdir(self, rel: str) -> None:
        rel = self.normalize(rel)
        if not rel:
            raise InvalidPath("Cannot delete the root directory")
        base = self._abs(rel)
        if not os.path.isdir(base):
            raise NotADirectory(f"Not a directory: /{rel}")
        # As long as a visible entry remains the directory counts as non-empty (hidden temp
        # files and the config do not matter)
        with os.scandir(base) as it:
            visible = [e.name for e in it
                       if not e.name.startswith(TMP_PREFIX) and e.name != CONFIG_NAME]
        if visible:
            raise DirectoryNotEmpty(f"Directory not empty: /{rel}")
        with os.scandir(base) as it:
            leftovers = [e.path for e in it]
        for path in leftovers:
            try:
                _retry_op(os.unlink, path)
            except OSError:
                pass
        os.rmdir(base)
        self.size_cache.drop_prefix(rel)

    def rename(self, src: str, dst: str, overwrite: bool = True) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        if not src or not dst:
            raise InvalidPath("Illegal path")
        if src == dst:
            return
        src_base = self._abs(src)
        self._ensure_parent(dst)
        dst_base = self._abs(dst)
        dst_exists = os.path.exists(dst_base) or os.path.isfile(dst_base + GPG_SUFFIX)
        if dst_exists and not overwrite:
            raise AlreadyExists(f"Target already exists: /{dst}")

        if os.path.isdir(src_base):
            if dst_exists:
                raise AlreadyExists(f"Target already exists: /{dst}")
            os.rename(src_base, dst_base)
            self.size_cache.drop_prefix(src)
            return

        src_real, encrypted = self._real_for_read(src)
        if os.path.isdir(dst_base):
            raise AlreadyExists(f"Target already exists: /{dst}")
        # Keep the on-disk form of the source: a plaintext file stays plaintext
        dst_real = dst_base + GPG_SUFFIX if encrypted else dst_base
        _retry_op(os.replace, src_real, dst_real)
        self.size_cache.drop(src)
        self.size_cache.drop(dst)
        self.plain_cache.invalidate(src)
        self.plain_cache.invalidate(dst)

    def copy(self, src: str, dst: str, overwrite: bool = True) -> None:
        """Server-side copy: ciphertext is copied directly (same key, no decrypt then
        re-encrypt)."""
        src = self.normalize(src)
        dst = self.normalize(dst)
        self._ensure_parent(dst)
        src_base = self._abs(src)
        dst_base = self._abs(dst)
        dst_exists = os.path.exists(dst_base) or os.path.isfile(dst_base + GPG_SUFFIX)
        if dst_exists and not overwrite:
            raise AlreadyExists(f"Target already exists: /{dst}")

        if os.path.isdir(src_base):
            if dst_exists:
                raise AlreadyExists(f"Target already exists: /{dst}")
            shutil.copytree(src_base, dst_base)
            return

        src_real, encrypted = self._real_for_read(src)
        if os.path.isdir(dst_base):
            raise AlreadyExists(f"Target already exists: /{dst}")
        dst_real = dst_base + GPG_SUFFIX if encrypted else dst_base
        shutil.copy2(src_real, dst_real)


class _CountingReader:
    """Wrap a readable stream and record how many bytes were read."""

    def __init__(self, reader) -> None:
        self._reader = reader
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        data = self._reader.read(size)
        if data:
            self.count += len(data)
        elif data is None:
            return b""
        return data
