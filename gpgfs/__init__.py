"""GPGFS -- mounts a directory of gpg-encrypted files as a virtual directory
with transparent reads and writes.

How it works:
    encrypted vault directory        virtual directory (mount point)
    foo/bar.txt.gpg           <->    foo/bar.txt

Read -> decrypt on the fly; write -> encrypt on the fly. File names and the
directory layout stay in plaintext; only file contents are protected by gpg
(similar to gocryptfs "plaintextnames" mode).
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
