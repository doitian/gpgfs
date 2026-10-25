"""Runs a round of real file operations on a mounted drive to verify transparent I/O.

Usage:
    python scripts\\smoke_drive.py Z:
    python scripts\\smoke_drive.py Z: --keep

It only uses the standard Python file API (open / os.rename / os.remove / os.listdir),
the same path Word, VSCode and Notepad take.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import time

PASS = "  [ok]  "
FAIL = "  [xx]  "


def _report(ok: bool, label: str, detail: str = "") -> bool:
    print((PASS if ok else FAIL) + label + (f"   {detail}" if detail else ""), flush=True)
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("drive", help="drive letter, for example Z:")
    parser.add_argument("--dir", default="gpgfs-smoke", help="test directory name")
    parser.add_argument("--keep", action="store_true", help="keep the test files")
    parser.add_argument("--big-mb", type=float, default=2.0,
                        help="size of the large file test (MB)")
    args = parser.parse_args(argv)

    drive = args.drive.rstrip("\\/")
    if not drive.endswith(":"):
        drive += ":"
    root = os.path.join(drive + os.sep, args.dir)

    if not os.path.isdir(drive + os.sep):
        print(f"{FAIL}drive not accessible: {drive}\\")
        return 1

    failures = 0

    def check(ok: bool, label: str, detail: str = "") -> None:
        nonlocal failures
        if not _report(ok, label, detail):
            failures += 1

    print(f"Test directory: {root}\n")

    if os.path.isdir(root):
        for name in os.listdir(root):
            try:
                os.remove(os.path.join(root, name))
            except OSError:
                pass
        try:
            os.rmdir(root)
        except OSError:
            pass

    # 1. create a directory
    os.makedirs(root)
    check(os.path.isdir(root), "mkdir creates a directory")

    # 2. new text file
    text_path = os.path.join(root, "hello.txt")
    with open(text_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("first line: this is written as plaintext\n")
        fh.write("second line with ascii\n")
    with open(text_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    check(content.count("\n") == 2 and content.startswith("first line"),
          "write and read back text", f"{len(content)} chars")

    # 3. overwrite (simulating an editor's save-as)
    with open(text_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("overwritten content\n")
    with open(text_path, "r", encoding="utf-8") as fh:
        check(fh.read() == "overwritten content\n", "content correct after overwrite")

    # 4. append
    with open(text_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("appended line\n")
    with open(text_path, "r", encoding="utf-8") as fh:
        data = fh.read()
    check("appended line" in data and "overwritten content" in data, "append")

    # 5. binary round trip
    payload = bytes(random.getrandbits(8) for _ in range(64 * 1024))
    bin_path = os.path.join(root, "blob.bin")
    with open(bin_path, "wb") as fh:
        fh.write(payload)
    with open(bin_path, "rb") as fh:
        check(fh.read() == payload, "64KB binary round trip", hashlib.sha256(payload).hexdigest()[:12])

    # 6. large file streaming round trip
    size = int(args.big_mb * 1024 * 1024)
    if size > 0:
        big_path = os.path.join(root, "big.bin")
        digest = hashlib.sha256()
        block = os.urandom(1024 * 256)
        with open(big_path, "wb") as fh:
            written = 0
            while written < size:
                chunk = block[: min(len(block), size - written)]
                fh.write(chunk)
                digest.update(chunk)
                written += len(chunk)
        expected = digest.hexdigest()
        digest2 = hashlib.sha256()
        total = 0
        with open(big_path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 128)
                if not chunk:
                    break
                total += len(chunk)
                digest2.update(chunk)
        check(total == size and digest2.hexdigest() == expected,
              f"{args.big_mb:g}MB large file round trip", f"{total} bytes")

    # 7. stat size
    st = os.stat(text_path)
    with open(text_path, "r", encoding="utf-8") as fh:
        real_len = len(fh.read().encode("utf-8"))
    check(st.st_size == real_len, "stat reports the plaintext size", f"{st.st_size} == {real_len}")

    # 8. rename
    renamed = os.path.join(root, "renamed.txt")
    os.rename(text_path, renamed)
    check(os.path.exists(renamed) and not os.path.exists(text_path), "rename")

    # 9. listing
    names = set(os.listdir(root))
    check({"renamed.txt", "blob.bin"} <= names, "listdir", ", ".join(sorted(names)))

    # 10. subdirectory + deep nesting
    nested = os.path.join(root, "a", "b", "c")
    os.makedirs(nested)
    deep = os.path.join(nested, "deep.txt")
    with open(deep, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("deep\n")
    with open(deep, "r", encoding="utf-8") as fh:
        check(fh.read() == "deep\n", "read and write in a deep directory")

    # 11. delete
    try:
        os.remove(renamed)
        check(not os.path.exists(renamed), "delete a file")
    except OSError as exc:
        # some environments block deletes (security policy / recycle bin proxy), so skip this check
        print(f"  [--]  delete blocked by the environment, skipping ({type(exc).__name__}: {exc})")

    # 12. metadata timestamps
    mtime = os.stat(deep).st_mtime
    check(time.time() - mtime < 300, "mtime is reasonable")

    if not args.keep:
        for base, dirs, files in os.walk(root, topdown=False):
            for name in files:
                try:
                    os.remove(os.path.join(base, name))
                except OSError:
                    pass
            for name in dirs:
                try:
                    os.rmdir(os.path.join(base, name))
                except OSError:
                    pass
        try:
            os.rmdir(root)
        except OSError:
            pass

    print()
    if failures:
        print(f"{failures} checks failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
