"""gpg invocation wrapper: handles both directions, "plaintext -> ciphertext"
and "ciphertext -> plaintext".

Design notes:
1. Data always goes through stdin/stdout pipes; plaintext never touches the
   disk (the only file written is the temporary passphrase file used for
   symmetric encryption).
2. Two encryption modes are supported:
   - Public-key mode (recommended): --recipient <KEYID>; on decryption
     gpg-agent handles the secret key / smartcard.
   - Symmetric mode: the passphrase is passed via --passphrase-file, using a
     temporary file (on Windows subprocess cannot pass a file descriptor with
     pass_fds, hence the temp file plus 0600 permissions).
3. Standard library only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from typing import Iterable, Sequence

from .errors import CipherNotConfigured, GpgError, GpgNotFound


class GpgCipher:
    """Wraps gpg into a byte-in / byte-out encryptor and decryptor."""

    def __init__(
        self,
        recipients: Sequence[str] = (),
        passphrase: str | None = None,
        gpg: str = "gpg",
        armor: bool = False,
        cipher_algo: str = "AES256",
        homedir: str | None = None,
        timeout: int = 600,
    ) -> None:
        self.recipients = [r for r in recipients if r]
        self.passphrase = passphrase
        self.gpg = gpg
        self.armor = armor
        self.cipher_algo = cipher_algo
        self.homedir = homedir
        self.timeout = timeout

    # --------------------------------------------------------------- basics

    @property
    def mode(self) -> str:
        if self.recipients:
            return "public-key"
        if self.passphrase is not None:
            return "symmetric"
        return "unconfigured"

    def describe(self) -> str:
        if self.mode == "public-key":
            return "public-key encryption -> " + ", ".join(self.recipients)
        if self.mode == "symmetric":
            return f"symmetric encryption -> {self.cipher_algo} (passphrase mode)"
        return "unconfigured (needs --recipient or a passphrase)"

    def _common_args(self) -> list[str]:
        args = [self.gpg, "--batch", "--yes", "--no-tty", "--quiet"]
        if self.homedir:
            args += ["--homedir", self.homedir]
        return args

    def _ensure_configured(self) -> None:
        if self.mode == "unconfigured":
            raise CipherNotConfigured(
                "No encryption mode specified: use --recipient <KEYID> (public-key mode) "
                "or provide a passphrase (symmetric mode)."
            )

    @contextmanager
    def _passphrase_file(self):
        """When a passphrase is needed, create a temporary passphrase file; otherwise yield None."""
        if self.passphrase is None:
            yield None
            return
        fd, path = tempfile.mkstemp(prefix="gpgfs-pass-", suffix=".txt")
        try:
            # Binary-exact newline: gpg reads the line as-is, so a Windows CRLF file would
            # make the effective passphrase "…\r" and the vault unreadable elsewhere.
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(self.passphrase)
                fh.write("\n")
            _tighten(path)
            yield path
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _encrypt_args(self, passfile: str | None) -> list[str]:
        args = self._common_args() + ["--output", "-"]
        if self.armor:
            args.append("--armor")
        if self.recipients:
            args += ["--trust-model", "always", "--encrypt"]
            for r in self.recipients:
                args += ["--recipient", r]
        else:
            args += ["--symmetric", "--cipher-algo", self.cipher_algo]
            if passfile:
                args += ["--pinentry-mode", "loopback", "--passphrase-file", passfile]
        return args

    def _decrypt_args(self, passfile: str | None) -> list[str]:
        args = self._common_args() + ["--output", "-", "--decrypt"]
        if passfile:
            args += ["--pinentry-mode", "loopback", "--passphrase-file", passfile]
        return args

    @staticmethod
    def _raise_from_stderr(stderr: str, returncode: int, action: str) -> None:
        text = (stderr or "").strip()
        hint = ""
        low = text.lower()
        if "no secret key" in low or "decryption failed" in low:
            hint = (" (the current gpg cannot find the matching secret key, or the "
                    "secret key needs a smartcard/passphrase)")
        elif "bad passphrase" in low or "inv_passphrase" in low:
            hint = " (incorrect passphrase)"
        elif "no public key" in low or "unusable public key" in low:
            hint = " (recipient public key does not exist)"
        raise GpgError(f"gpg {action} failed{hint}: {text or 'exit code ' + str(returncode)}",
                       stderr=text, returncode=returncode)

    def _check_available(self) -> None:
        exe = self.gpg
        if os.path.sep in exe or (os.path.altsep and os.path.altsep in exe):
            if not os.path.exists(exe):
                raise GpgNotFound(f"gpg does not exist: {exe}")
            return
        if shutil.which(exe) is None:
            raise GpgNotFound(
                f"{exe!r} not found in PATH; install GnuPG or point --gpg at an absolute path."
            )

    # ---------------------------------------------------- fixed-size interface

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt an in-memory buffer and return the ciphertext bytes."""
        self._ensure_configured()
        self._check_available()
        with self._passphrase_file() as pf:
            proc = subprocess.run(
                self._encrypt_args(pf),
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
        if proc.returncode != 0:
            self._raise_from_stderr(proc.stderr.decode("utf-8", "replace"),
                                    proc.returncode, "encryption")
        return proc.stdout

    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt an in-memory buffer.

        Convention: a zero-length ciphertext is treated as an "empty file"
        (possibly left behind by an interrupted write) and yields empty bytes
        directly, instead of letting gpg report an EOF error.
        """
        if not data:
            return b""
        self._check_available()
        with self._passphrase_file() as pf:
            proc = subprocess.run(
                self._decrypt_args(pf),
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
        if proc.returncode != 0:
            self._raise_from_stderr(proc.stderr.decode("utf-8", "replace"),
                                    proc.returncode, "decryption")
        return proc.stdout

    # ----------------------------------------------------------- streaming API

    def encrypt_stream(self, source, sink) -> int:
        """Encrypt source (a readable file object) and write the result to sink
        (a writable file object).

        Plaintext stays in the pipe the whole time and never hits the disk.
        Returns the number of ciphertext bytes written.
        """
        self._ensure_configured()
        self._check_available()
        written = 0
        with self._passphrase_file() as pf:
            proc = subprocess.Popen(
                self._encrypt_args(pf),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            err_chunks: list[bytes] = []

            def _drain_err() -> None:
                try:
                    err_chunks.append(proc.stderr.read())
                except Exception:  # pragma: no cover - extreme cases
                    pass

            err_thread = threading.Thread(target=_drain_err, daemon=True)
            err_thread.start()

            # stdin must be written while stdout is being read: writing one
            # direction alone until the pipe fills up (about 64KB) deadlocks
            def _pump_in() -> None:
                try:
                    while True:
                        chunk = source.read(1024 * 256)
                        if not chunk:
                            break
                        proc.stdin.write(chunk)
                    proc.stdin.close()
                except (BrokenPipeError, ValueError):
                    pass  # gpg exited early; the exit-code check will explain why

            feeder = threading.Thread(target=_pump_in, daemon=True)
            feeder.start()
            try:
                while True:
                    out = proc.stdout.read(1024 * 256)
                    if not out:
                        break
                    sink.write(out)
                    written += len(out)
            finally:
                proc.wait()
                feeder.join(timeout=5)
                err_thread.join(timeout=5)
                _close_pipes(proc)

        if proc.returncode != 0:
            stderr = b"".join(err_chunks).decode("utf-8", "replace")
            self._raise_from_stderr(stderr, proc.returncode, "encryption")
        return written

    def decrypt_stream(self, source, sink) -> int:
        """Decrypt source (a ciphertext file object or path) and write the result
        to sink. Returns the number of plaintext bytes."""
        self._check_available()
        written = 0
        with self._passphrase_file() as pf:
            stdin = subprocess.PIPE if not isinstance(source, str) else subprocess.DEVNULL
            if isinstance(source, str):
                args = self._decrypt_args(pf) + [source]
            else:
                args = self._decrypt_args(pf)
            proc = subprocess.Popen(
                args,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            err_chunks: list[bytes] = []

            def _drain_err() -> None:
                try:
                    err_chunks.append(proc.stderr.read())
                except Exception:  # pragma: no cover
                    pass

            err_thread = threading.Thread(target=_drain_err, daemon=True)
            err_thread.start()

            def _feed() -> None:
                try:
                    while True:
                        chunk = source.read(1024 * 256)
                        if not chunk:
                            break
                        proc.stdin.write(chunk)
                    proc.stdin.close()
                except (BrokenPipeError, ValueError):
                    pass

            feeder = None
            if stdin is subprocess.PIPE:
                feeder = threading.Thread(target=_feed, daemon=True)
                feeder.start()

            try:
                while True:
                    out = proc.stdout.read(1024 * 256)
                    if not out:
                        break
                    sink.write(out)
                    written += len(out)
            finally:
                proc.wait()
                if feeder:
                    feeder.join(timeout=5)
                err_thread.join(timeout=5)
                _close_pipes(proc)

        if proc.returncode != 0:
            stderr = b"".join(err_chunks).decode("utf-8", "replace")
            # partial plaintext may already be written; still treated as a
            # failure, and the caller decides how to handle it
            self._raise_from_stderr(stderr, proc.returncode, "decryption")
        return written

    def decrypt_iter(self, source, chunk: int = 256 * 1024):
        """Streaming decryption generator: yields plaintext chunks as it decrypts.

        source may be a ciphertext path string or ciphertext bytes.
        The subprocess is cleaned up automatically after exhaustion (or when the
        caller breaks out early).
        """
        self._check_available()
        with self._passphrase_file() as pf:
            if isinstance(source, (bytes, bytearray)):
                proc = subprocess.Popen(
                    self._decrypt_args(pf),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )

                def _feed_bytes() -> None:
                    try:
                        proc.stdin.write(bytes(source))
                        proc.stdin.close()
                    except (BrokenPipeError, ValueError):
                        pass

                threading.Thread(target=_feed_bytes, daemon=True).start()
                err_thread = threading.Thread(
                    target=lambda: proc.stderr.read(), daemon=True)
                err_thread.start()
            else:
                args = self._decrypt_args(pf) + [str(source)]
                proc = subprocess.Popen(
                    args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                err_chunks: list[bytes] = []

                def _drain() -> None:
                    try:
                        err_chunks.append(proc.stderr.read())
                    except Exception:  # pragma: no cover
                        pass

                err_thread = threading.Thread(target=_drain, daemon=True)
                err_thread.start()

            try:
                while True:
                    data = proc.stdout.read(chunk)
                    if not data:
                        break
                    yield data
            finally:
                try:
                    proc.stdout.close()
                except Exception:  # pragma: no cover
                    pass
                proc.wait()
                err_thread.join(timeout=5)
                _close_pipes(proc)
            if proc.returncode != 0 and not isinstance(source, (bytes, bytearray)):
                self._raise_from_stderr(b"".join(err_chunks).decode("utf-8", "replace"),
                                        proc.returncode, "decryption")

    # --------------------------------------------------- self-test / diagnosis

    def self_test(self) -> str:
        """Run one in-memory round trip to verify the encrypt/decrypt path works.
        Returns a human-readable description."""
        self._ensure_configured()
        probe = b"gpgfs self-test " + os.urandom(8).hex().encode()
        blob = self.encrypt_bytes(probe)
        back = self.decrypt_bytes(blob)
        if back != probe:
            raise GpgError("self-test failed: decrypted result differs from the original")
        return (f"encrypt/decrypt round trip OK "
                f"({len(blob)} ciphertext bytes / {len(probe)} plaintext bytes)")


def _tighten(path: str) -> None:
    """Tighten temp file permissions to the current user only, as far as possible."""
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - chmod semantics are limited on Windows
        pass


def _close_pipes(proc: subprocess.Popen) -> None:
    """Clean up: make sure all subprocess pipes are closed (otherwise fds leak
    and ResourceWarning is raised)."""
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except Exception:  # pragma: no cover
                pass


_GPGS = ("gpg", "gpg2", "gpg.exe")
_WINDOWS_DIRS = (
    r"C:\Program Files\GnuPG\bin",
    r"C:\Program Files (x86)\GnuPG\bin",
    r"C:\Program Files\Gpg4win\bin",
    r"C:\Program Files (x86)\Gpg4win\bin",
)
_resolved_gpg: dict[str, str] = {}


def _windows_registry_dirs() -> list[str]:
    """Look up the Gpg4win install directory in the registry (a standard install
    normally has it)."""
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:  # pragma: no cover
        return []
    found: list[str] = []
    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\GnuPG"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\GnuPG"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\GnuPG"),
    ]
    for hive, subkey in locations:
        try:
            key = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        with key:
            for value_name in ("Install Dir", "InstallDir", "Install Directory"):
                try:
                    value, _ = winreg.QueryValueEx(key, value_name)
                except OSError:
                    continue
                if value:
                    found.append(str(value))
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            key = winreg.OpenKey(
                hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\gpg.exe")
        except OSError:
            continue
        with key:
            try:
                exe, _ = winreg.QueryValueEx(key, "")
            except OSError:
                continue
            if exe:
                found.append(os.path.dirname(str(exe)))
    return found


def _scoop_dirs() -> list[str]:
    """gpg4win installed via Scoop (wildcard over the app directory)."""
    home = os.path.expanduser("~")
    dirs: list[str] = []
    apps = os.path.join(home, "scoop", "apps")
    if os.path.isdir(apps):
        try:
            for name in os.listdir(apps):
                if "gpg" in name.lower() or "gnupg" in name.lower():
                    candidate = os.path.join(apps, name, "current", "GnuPG", "bin")
                    if os.path.isdir(candidate):
                        dirs.append(candidate)
        except OSError:
            pass
    shims = os.path.join(home, "scoop", "shims")
    if os.path.isdir(shims):
        dirs.append(shims)
    return dirs


def gpg_candidates() -> list[str]:
    """List every possible gpg executable on the system (deduplicated, order preserved)."""
    seen: list[str] = []
    known: set[str] = set()

    def _add(path: str) -> None:
        if not path or not os.path.exists(path):
            return
        if os.path.isdir(path):
            path = os.path.join(path, "gpg.exe")
            if not os.path.exists(path):
                return
        key = os.path.normcase(os.path.realpath(path))
        if key in known:
            return
        known.add(key)
        seen.append(path)

    for name in _GPGS:
        _add(shutil.which(name) or "")
    if os.name == "nt":
        for base in _WINDOWS_DIRS:
            _add(base)
        for base in _windows_registry_dirs():
            _add(base)
        for base in _scoop_dirs():
            _add(base)
    return seen


def health_check(path: str, homedir: str | None = None) -> tuple[bool, str]:
    """Check whether a given gpg is usable (can read the keyring).
    Returns (healthy, explanation)."""
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot execute: {exc}"
    if proc.returncode != 0:
        return False, f"--version exit code {proc.returncode}"
    version = proc.stdout.decode("utf-8", "replace").splitlines()[0].strip()

    args = [path, "--batch", "--no-tty", "--list-secret-keys"]
    if homedir:
        args += ["--homedir", homedir]
    try:
        proc = subprocess.run(args, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"failed to read keys: {exc}"
    stderr = proc.stderr.decode("utf-8", "replace").lower()
    if proc.returncode != 0 or "keyboxd" in stderr or "error opening key db" in stderr:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        return False, (f"{version}; keyring unavailable "
                       f"({detail[0] if detail else 'unknown reason'})")
    return True, version


def best_gpg(preferred: str | None = None, homedir: str | None = None) -> str:
    """Pick a gpg that actually works.

    Priority: explicit argument > GPGFS_GPG environment variable > candidates
    that pass the health check > gpg on PATH.
    This picks the right one on machines with both Gpg4win and the MSYS2 gpg
    installed.
    """
    if preferred:
        return preferred
    env = os.environ.get("GPGFS_GPG")
    if env:
        return env
    cache_key = homedir or ""
    if cache_key in _resolved_gpg:
        return _resolved_gpg[cache_key]

    candidates = gpg_candidates()
    for candidate in candidates:
        ok, _ = health_check(candidate, homedir)
        if ok:
            _resolved_gpg[cache_key] = candidate
            return candidate
    result = candidates[0] if candidates else "gpg"
    _resolved_gpg[cache_key] = result
    return result



def gpg_version(gpg: str = "gpg") -> str:
    """Return the first line of the gpg version string, for doctor output."""
    try:
        proc = subprocess.run([gpg, "--version"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GpgNotFound(f"cannot execute {gpg}: {exc}") from exc
    if proc.returncode != 0:
        raise GpgNotFound(f"{gpg} --version returned {proc.returncode}")
    return proc.stdout.decode("utf-8", "replace").splitlines()[0].strip()


def list_secret_keys(gpg: str = "gpg", homedir: str | None = None) -> list[str]:
    """List the available secret keys (uid + keyid), used by doctor and interactive selection."""
    args = [gpg, "--batch", "--no-tty", "--list-secret-keys", "--keyid-format=long"]
    if homedir:
        args += ["--homedir", homedir]
    try:
        proc = subprocess.run(args, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    out = proc.stdout.decode("utf-8", "replace")
    keys: list[str] = []
    has_uid: list[bool] = []
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("sec"):
            token = next((t for t in stripped.split() if "/" in t), None)
            if token:
                keys.append(token.split("/", 1)[1])
                has_uid.append(False)
        elif stripped.startswith("uid") and keys and not has_uid[-1]:
            uid = stripped[3:].strip()
            if uid.startswith("["):
                uid = uid.split("]", 1)[-1].strip()
            keys[-1] = f"{keys[-1]}  {uid}"
            has_uid[-1] = True
    return keys
