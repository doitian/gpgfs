"""Windows drive-letter mapping: turn a DAV namespace into a real drive letter via the built-in
WebDAV redirector.

Key point: ``net use Z: http://127.0.0.1:PORT/`` needs no admin rights and no kernel driver;
after mapping it is an ordinary drive letter in Explorer, and any program can read and write it
transparently. Underneath it relies on the WebClient service (installed by default on Windows,
started on demand).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import re
import shutil
import string
import subprocess
import sys
import threading
import time

CREATE_NO_WINDOW = 0x08000000
IS_WINDOWS = sys.platform == "win32"
ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234

_TIMEOUT = object()


def _no_window() -> int:
    return CREATE_NO_WINDOW if IS_WINDOWS else 0


def _run(cmd: list[str], timeout: float = 60) -> subprocess.CompletedProcess:
    # stdin must be cut off: net.exe waits for console input forever when it needs to interact
    # (e.g. asking for a password on reconnect), which shows up on the command line as
    # "unmount hangs and does not move at all".
    return subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        creationflags=_no_window(),
    )


def _bounded(func, timeout: float):
    """Run func in a background thread, return ``_TIMEOUT`` on timeout.

    When the WebClient redirector is stuck waiting for a network response, both mpr.dll and
    net.exe block synchronously, and there is no reliable way to cancel, so the only option is
    to throw the call into the background and stop waiting.
    """
    box: list = []

    def target() -> None:
        try:
            box.append(func())
        except BaseException as exc:  # noqa: BLE001 - the caller decides how to handle it
            box.append(exc)

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if not box:
        return _TIMEOUT
    outcome = box[0]
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome


_MPR = None


def _mpr():
    """Lazily load mpr.dll (the Windows network redirector API)."""
    global _MPR
    if _MPR is None:
        mpr = ctypes.WinDLL("mpr", use_last_error=True)
        mpr.WNetGetConnectionW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        ]
        mpr.WNetGetConnectionW.restype = wintypes.DWORD
        mpr.WNetCancelConnection2W.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL]
        mpr.WNetCancelConnection2W.restype = wintypes.DWORD
        _MPR = mpr
    return _MPR


def _drive_str(value: str) -> str:
    """Normalize ``z`` / ``z:\\`` / ``Z:`` into ``Z:``."""
    value = value.strip().rstrip("\\/").upper()
    if len(value) == 1 and value.isalpha():
        value += ":"
    return value


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


# --------------------------------------------------------------------- service state

def webclient_state() -> str:
    """Return the WebClient service state: RUNNING / STOPPED / UNKNOWN."""
    if not IS_WINDOWS:
        return "N/A"
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi.OpenSCManagerW.restype = wintypes.HANDLE
        advapi.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        advapi.OpenServiceW.restype = wintypes.HANDLE
        advapi.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        advapi.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        advapi.CloseServiceHandle.argtypes = [wintypes.HANDLE]

        class SERVICE_STATUS(ctypes.Structure):
            _fields_ = [
                ("dwServiceType", wintypes.DWORD),
                ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD),
                ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD),
                ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD),
            ]

        scm = advapi.OpenSCManagerW(None, None, 0x0004)  # SC_MANAGER_CONNECT
        if not scm:
            return "UNKNOWN"
        service = None
        try:
            service = advapi.OpenServiceW(scm, "WebClient", 0x0004)  # SERVICE_QUERY_STATUS
            if not service:
                return "MISSING"
            status = SERVICE_STATUS()
            if not advapi.QueryServiceStatus(service, ctypes.byref(status)):
                return "UNKNOWN"
            return {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING"}.get(
                status.dwCurrentState, "UNKNOWN")
        finally:
            if service:
                advapi.CloseServiceHandle(service)
            advapi.CloseServiceHandle(scm)
    except Exception:
        return "UNKNOWN"


def file_size_limit() -> int | None:
    """Read the single-file size limit of the WebDAV redirector (50MB by default, admin rights
    are needed to change it)."""
    if not IS_WINDOWS:
        return None
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\WebClient\Parameters",
        )
        try:
            value, _ = winreg.QueryValueEx(key, "FileSizeLimitInBytes")
            return int(value)
        finally:
            key.Close()
    except OSError:
        return 50_000_000


# --------------------------------------------------------------------- drive operations

def _remote_of(drive: str) -> str | None:
    """Remote path the drive letter is currently mapped to; None if unmapped or the query fails."""
    if not IS_WINDOWS:
        return None
    drive = _drive_str(drive)
    try:
        mpr = _mpr()
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        rc = mpr.WNetGetConnectionW(drive, buf, ctypes.byref(size))
        if rc == ERROR_MORE_DATA:
            buf = ctypes.create_unicode_buffer(size.value)
            rc = mpr.WNetGetConnectionW(drive, buf, ctypes.byref(size))
        if rc != ERROR_SUCCESS or not buf.value:
            return None
        return buf.value
    except OSError:
        return None


def _is_mapped(drive: str) -> bool:
    if _remote_of(drive) is not None:
        return True
    return os.path.exists(drive + "\\")


def _cancel_connection(drive: str) -> bool:
    """Call mpr.dll to force-disconnect the mapping: no interactive prompt, and it does not
    depend on the server still answering."""
    if not IS_WINDOWS:
        return False
    try:
        return _mpr().WNetCancelConnection2W(_drive_str(drive), 0, True) == ERROR_SUCCESS
    except OSError:
        return False


def _net_delete(drive: str, timeout: float) -> bool:
    try:
        proc = _run(["net", "use", _drive_str(drive), "/delete", "/y"], timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


_DRIVE_LINE = re.compile(r"\b([A-Za-z]:)\s+(\\\\\S+)")
_DAV_REMOTE = re.compile(r"^\\\\[^\\]+@\d+\\DavWWWRoot\\?$", re.IGNORECASE)


def _parse_net_use(output: str) -> list[tuple[str, str]]:
    """Parse ``net use`` output.

    The first column is a Status ("OK", "Unavailable", or blank for WebDAV mappings), so the
    drive letter and remote path are matched anywhere in the line rather than by position.
    """
    result: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = _DRIVE_LINE.search(line)
        if match:
            result.append((match.group(1).upper(), match.group(2)))
    return result


def is_dav_remote(remote: str) -> bool:
    """True when the remote has the form the Windows redirector gives a WebDAV mapping,
    e.g. ``\\\\127.0.0.1@8765\\DavWWWRoot``."""
    return bool(_DAV_REMOTE.match((remote or "").strip()))


def mapped_drives() -> list[tuple[str, str]]:
    """Return [(drive letter, remote)], e.g. [("Z:", "\\\\127.0.0.1@8765\\DavWWWRoot")]."""
    if not IS_WINDOWS:
        return []
    try:
        proc = _run(["net", "use"], timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    return _parse_net_use(_decode(proc.stdout))


def is_drive_in_use(drive: str) -> bool:
    drive = _drive_str(drive)
    if _is_mapped(drive):
        return True
    return any(d == drive for d, _ in mapped_drives())


def pick_free_drive(preferred: str | None = None, start: str = "Z") -> str | None:
    """Pick a free drive letter, starting from preferred, otherwise search down from start."""
    if preferred:
        if not is_drive_in_use(preferred):
            return preferred.rstrip("\\/").upper()
        return None
    used = {d for d, _ in mapped_drives()}
    letters = string.ascii_uppercase
    begin = letters.index(start.upper())
    for letter in list(letters[begin::-1]):
        candidate = f"{letter}:"
        if candidate in used:
            continue
        if not os.path.exists(candidate + "\\"):
            return candidate
    return None


def map_drive(url: str, drive: str, wait: float = 8.0) -> str:
    """Map url to the given drive letter and return the letter in the form ``Z:``."""
    if not IS_WINDOWS:
        raise RuntimeError("Drive letter mapping is only available on Windows")
    drive = _drive_str(drive)
    proc = _run(["net", "use", drive, url, "/persistent:no"], timeout=60)
    if proc.returncode != 0:
        message = _decode(proc.stderr).strip() or _decode(proc.stdout).strip()
        raise RuntimeError(f"net use failed (exit code {proc.returncode}): {message}")

    # The redirector needs to establish a session on the first connection, wait a bit, then
    # confirm
    deadline = time.time() + wait
    while time.time() < deadline:
        if os.path.isdir(drive + "\\"):
            return drive
        time.sleep(0.25)
    # Do not leave a broken mapping behind: the caller only sees the exception, so the letter
    # would stay occupied with no registry entry pointing at it.
    unmap_drive(drive)
    raise RuntimeError(f"Drive letter {drive} is mapped but the directory is not accessible, "
                       f"check the WebClient service")


def _probe_mapped(drive: str, timeout: float) -> bool | None:
    """True/False when the redirector answers, None when it is wedged."""
    outcome = _bounded(lambda: _is_mapped(drive), min(timeout, 5.0))
    return None if outcome is _TIMEOUT else bool(outcome)


def unmap_drive(drive: str, wait: float = 5.0, timeout: float = 10.0) -> bool:
    """Disconnect the drive letter mapping.

    Every probe and disconnect attempt runs as a bounded background call: once the WebClient
    redirector stops answering there is no way to cancel a synchronous call, and hanging the
    CLI is worse than reporting failure. An unverifiable state counts as success only when the
    force-disconnect itself reported success.
    """
    if not IS_WINDOWS:
        return False
    drive = _drive_str(drive)
    if _probe_mapped(drive, timeout) is False:
        return True

    cancelled = False
    attempts = (lambda: _cancel_connection(drive), lambda: _net_delete(drive, timeout))
    for attempt in attempts:
        try:
            outcome = _bounded(attempt, timeout + 2)
        except subprocess.SubprocessError:
            outcome = False
        if outcome is True:
            cancelled = True
            break
        if _probe_mapped(drive, timeout) is False:
            return True

    deadline = time.time() + wait
    while True:
        state = _probe_mapped(drive, timeout)
        if state is False:
            return True
        if state is True or time.time() >= deadline:
            break
        time.sleep(0.2)
    return state is None and cancelled


def find_gpg_candidates() -> list[str]:
    """List the possible gpg executables on the system, for the doctor hints."""
    seen: list[str] = []
    for name in ("gpg", "gpg2", "gpg.exe"):
        path = shutil.which(name)
        if path and path not in seen:
            seen.append(path)
    if IS_WINDOWS:
        for base in (r"C:\Program Files (x86)\GnuPG\bin",
                     r"C:\Program Files\GnuPG\bin",
                     r"C:\Program Files\Gpg4win\bin"):
            candidate = os.path.join(base, "gpg.exe")
            if os.path.exists(candidate) and candidate not in seen:
                seen.append(candidate)
    return seen
