"""Cache layer: works around two performance problems caused by
"ciphertext size != plaintext size".

1. Plaintext length cache (stored in sqlite): filesystem stat must report the
   plaintext size, but a gpg ciphertext differs in size from the plaintext, so
   the plaintext size is only known after decryption. The cache key is
   (relative path, ciphertext mtime, ciphertext size), so the entry is
   invalidated automatically whenever the ciphertext changes.
2. Plaintext content cache (in-memory LRU): avoids decrypting the same file
   over and over (editors usually stat and then read several times). Kept in
   memory only, never on disk, so plaintext is not written to the disk.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections import OrderedDict


class SizeCache:
    """Persistent cache of plaintext lengths.

    One database file serves every vault on the machine, so ``namespace`` (the vault path)
    is prepended to each key; without it, same-named files in different vaults would evict
    each other and lose their cached size.
    """

    def __init__(self, path: str | None, namespace: str | None = None) -> None:
        self.path = path
        self._namespace = (
            os.path.normcase(os.path.abspath(namespace)) + "\x00" if namespace else ""
        )
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS sizes ("
                " rel TEXT PRIMARY KEY,"
                " ct_mtime INTEGER NOT NULL,"
                " ct_size INTEGER NOT NULL,"
                " pt_size INTEGER NOT NULL)"
            )
            self._conn.commit()

    def _key(self, rel: str) -> str:
        return self._namespace + rel

    def get(self, rel: str, ct_mtime: int, ct_size: int) -> int | None:
        if self._conn is None:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT pt_size FROM sizes WHERE rel=? AND ct_mtime=? AND ct_size=?",
                (self._key(rel), ct_mtime, ct_size),
            ).fetchone()
        return int(row[0]) if row else None

    def put(self, rel: str, ct_mtime: int, ct_size: int, pt_size: int) -> None:
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO sizes(rel, ct_mtime, ct_size, pt_size) VALUES(?,?,?,?)"
                " ON CONFLICT(rel) DO UPDATE SET"
                " ct_mtime=excluded.ct_mtime, ct_size=excluded.ct_size,"
                " pt_size=excluded.pt_size",
                (self._key(rel), ct_mtime, ct_size, pt_size),
            )
            self._conn.commit()

    def drop(self, rel: str) -> None:
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute("DELETE FROM sizes WHERE rel=?", (self._key(rel),))
            self._conn.commit()

    def drop_prefix(self, prefix: str) -> None:
        """Drop all entries under a directory (used when renaming or deleting a directory)."""
        if self._conn is None:
            return
        key = self._key(prefix)
        with self._lock:
            self._conn.execute("DELETE FROM sizes WHERE rel=? OR rel LIKE ?",
                               (key, key.rstrip("/") + "/%"))
            self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            with self._lock:
                self._conn.close()
                self._conn = None


class PlaintextCache:
    """In-memory LRU cache of plaintext contents.

    - total size is capped by total_bytes
    - a single large file above max_item_bytes is not cached (so large files do
      not flush the whole cache)
    """

    def __init__(self, total_bytes: int = 256 * 1024 * 1024,
                 max_item_bytes: int = 64 * 1024 * 1024) -> None:
        self.total_bytes = total_bytes
        self.max_item_bytes = max_item_bytes
        self._lock = threading.Lock()
        self._data: OrderedDict[tuple, bytes] = OrderedDict()
        self._bytes = 0
        self.hits = 0
        self.misses = 0

    def get(self, key: tuple) -> bytes | None:
        with self._lock:
            value = self._data.get(key)
            if value is None:
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def put(self, key: tuple, value: bytes) -> None:
        if len(value) > self.max_item_bytes or len(value) > self.total_bytes:
            return
        with self._lock:
            old = self._data.pop(key, None)
            if old is not None:
                self._bytes -= len(old)
            self._data[key] = value
            self._bytes += len(value)
            while self._bytes > self.total_bytes and self._data:
                _, removed = self._data.popitem(last=False)
                self._bytes -= len(removed)

    def invalidate(self, rel: str) -> None:
        with self._lock:
            for key in [k for k in self._data if k[0] == rel]:
                self._bytes -= len(self._data.pop(key))

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._bytes = 0

    @property
    def size(self) -> int:
        return self._bytes

    def stats(self) -> str:
        return (f"plaintext cache {self._bytes / 1048576:.1f} MB / "
                f"{self.hits} hits / {self.misses} misses")
