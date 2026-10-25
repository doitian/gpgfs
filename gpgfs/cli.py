"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from typing import Iterable

from . import __version__
from .cipher import GpgCipher, best_gpg, gpg_candidates, health_check, list_secret_keys
from .config import (
    CONFIG_NAME,
    ENV_PASSPHRASE,
    load_config,
    state_dir,
    write_vault_config,
)
from .davserver import make_server, run_server
from .errors import GpgNotFound, GpgfsError
from .state import PlaintextCache, SizeCache
from .vfs import GPG_SUFFIX, Vfs

REGISTRY = "mounts.json"


# ----------------------------------------------------------------- small helpers

def _out(text: str = "") -> None:
    print(text, flush=True)


def _ok(text: str) -> None:
    print(f"  [ok]  {text}", flush=True)


def _warn(text: str) -> None:
    print(f"  [!!]  {text}", flush=True)


def _bad(text: str) -> None:
    print(f"  [xx]  {text}", flush=True)


def _kv(key: str, value: str) -> None:
    print(f"  {key:<18}{value}", flush=True)


def _ignore_sigint() -> None:
    """Mask Ctrl+C during cleanup: unmounting already has a timeout fallback, and
    it should not be interrupted by a second keypress."""
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):  # pragma: no cover - only usable on the main thread
        pass


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def _registry_path() -> str:
    return os.path.join(state_dir(), REGISTRY)


def _registry_load() -> dict:
    try:
        with open(_registry_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _registry_save(data: dict) -> None:
    with open(_registry_path(), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _registry_add(drive: str, info: dict) -> None:
    data = _registry_load()
    data[drive.rstrip("\\/").upper()] = info
    _registry_save(data)


def _registry_drop(drive: str) -> None:
    data = _registry_load()
    if data.pop(drive.rstrip("\\/").upper(), None) is not None:
        _registry_save(data)


def _normalize_drive(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().upper().rstrip("\\/")
    if not value.endswith(":"):
        value += ":"
    return value


def build_vfs(cfg) -> Vfs:
    cipher = GpgCipher(
        recipients=cfg.recipients,
        passphrase=cfg.passphrase,
        gpg=cfg.gpg,
        armor=cfg.armor,
        cipher_algo=cfg.cipher_algo,
        homedir=cfg.homedir,
    )
    cache = SizeCache(cfg.cache_db, namespace=cfg.vault)
    plain = PlaintextCache()
    return Vfs(cfg.vault, cipher, cache, plain, expose_plaintext=cfg.expose_plaintext)


# --------------------------------------------------------------- subcommands

def cmd_init(args) -> int:
    """Write a vault config so later mounts need no cipher arguments."""
    cfg = load_config(args)
    data = {
        "version": 1,
        "mode": "public-key" if cfg.recipients else "symmetric",
    }
    if cfg.recipients:
        data["recipients"] = cfg.recipients
    if cfg.homedir:
        data["homedir"] = cfg.homedir
    if cfg.gpg != "gpg":
        data["gpg"] = cfg.gpg
    if cfg.armor:
        data["armor"] = True
    if cfg.cipher_algo and cfg.cipher_algo != "AES256":
        data["cipher_algo"] = cfg.cipher_algo
    if cfg.expose_plaintext:
        data["expose_plaintext"] = True

    vfs = build_vfs(cfg)
    report = vfs.cipher.self_test()
    path = write_vault_config(cfg.vault, data)
    _out(f"Config written: {path}")
    _ok(report)
    _out(f"\nYou can now run directly: gpgfs mount \"{cfg.vault}\"")
    return 0


def cmd_doctor(args) -> int:
    from . import winmount

    _out(f"gpgfs {__version__}   Python {sys.version.split()[0]}   {sys.platform}\n")

    _out("gpg")
    explicit = getattr(args, "gpg", None) or os.environ.get("GPGFS_GPG")
    candidates = [explicit] if explicit else gpg_candidates()
    if not candidates:
        _bad("gpg not found in PATH, please install GnuPG/Gpg4win")
    chosen = best_gpg(explicit, getattr(args, "homedir", None))
    for candidate in candidates:
        ok, detail = health_check(candidate, getattr(args, "homedir", None))
        mark = "  <- in use" if os.path.normcase(candidate) == os.path.normcase(chosen) else ""
        (_ok if ok else _bad)(f"{candidate}{mark}")
        _out(f"         {detail}")
    if explicit and not any(health_check(c, getattr(args, "homedir", None))[0]
                            for c in candidates):
        _warn("The explicitly given gpg is not usable, will still try it")

    keys = list_secret_keys(chosen, getattr(args, "homedir", None))
    if keys:
        _ok(f"{len(keys)} secret keys available")
        for key in keys[:6]:
            _kv("", key)
        if len(keys) > 6:
            _kv("", f"... {len(keys) - 6} more")
    else:
        _warn("No secret key found, decryption will fail in public-key mode")

    _out("\nWindows / WebDAV")
    if winmount.IS_WINDOWS:
        state = winmount.webclient_state()
        if state == "RUNNING":
            _ok("WebClient service is running (WebDAV redirector available)")
        elif state == "STOPPED":
            _warn("WebClient service is stopped, the system will start it on first mount; "
                  "if that fails run: sc start webclient")
        else:
            _warn(f"Unknown WebClient service state: {state}")
        limit = winmount.file_size_limit()
        if limit is not None:
            if limit < 200_000_000:
                _warn(f"WebDAV per-file limit {_human(limit)}"
                      f" (registry WebClient\\Parameters\\FileSizeLimitInBytes; "
                      "raise it as administrator for large files)")
            else:
                _ok(f"WebDAV per-file limit {_human(limit)}")
        mappings = winmount.mapped_drives()
        if mappings:
            _ok(f"{len(mappings)} network locations currently mapped")
            for drive, remote in mappings:
                _kv("", f"{drive} -> {remote}")
    else:
        _warn("Not a Windows platform, drive letter mapping unavailable; "
              "use `gpgfs serve` + a system WebDAV client")

    _out("\nCipher self-test")
    if getattr(args, "vault", None):
        try:
            cfg = load_config(args)
            vfs = build_vfs(cfg)
            _ok(vfs.cipher.describe())
            _ok(vfs.cipher.self_test())
        except SystemExit as exc:
            _warn(str(exc))
        except GpgfsError as exc:
            _bad(str(exc))
    else:
        _warn("No vault directory given, skipping")

    _out("\nConclusion")
    if winmount.IS_WINDOWS and winmount.webclient_state() in ("RUNNING", "STOPPED"):
        _ok("Ready to mount: gpgfs mount <vault> --recipient <KEYID>")
    else:
        _warn("Please resolve the issues marked [!!] / [xx] above")
    return 0


def cmd_mount(args) -> int:
    from . import winmount

    cfg = load_config(args)
    vfs = build_vfs(cfg)

    if not args.skip_check:
        try:
            report = vfs.cipher.self_test()
        except GpgfsError as exc:
            _bad(f"Self-test failed, aborted: {exc}")
            return 2
        _ok(report)

    entries = len(vfs.listdir(""))
    server = make_server(
        vfs,
        host=cfg.host,
        port=cfg.port,
        auth=cfg.auth,
        verbose=cfg.verbose,
        read_only=cfg.read_only,
    )
    run_server(server, block=False)
    url = f"http://{cfg.host}:{server.port}/"

    _out("")
    _kv("Vault", cfg.vault)
    _kv("Cipher", vfs.cipher.describe())
    _kv("Initial entries", f"{entries} (current directory only)")
    _kv("WebDAV", url)

    drive = None
    mapped = False
    if winmount.IS_WINDOWS and not args.no_drive:
        wanted = _normalize_drive(cfg.drive) or winmount.pick_free_drive()
        if not wanted:
            _warn("No free drive letter, falling back to WebDAV address only")
        else:
            try:
                drive = winmount.map_drive(url, wanted)
                mapped = True
                _kv("Mount point", f"{drive}\\")
            except RuntimeError as exc:
                _warn(str(exc))
                _warn("You can mount manually: net use Z: " + url)
    elif args.no_drive:
        _kv("Mount point", "(--no-drive, WebDAV address only)")

    if mapped and drive:
        _registry_add(drive, {
            "url": url,
            "pid": os.getpid(),
            "vault": cfg.vault,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        _out("")
        _ok(f"Mounted: {drive}\\  <->  {cfg.vault}")
        _out("     Files created or edited in this directory are encrypted automatically, "
             "reads are decrypted automatically.")
        _out("     Press Ctrl+C to unmount.")
    else:
        _out("")
        _ok("Service started, any WebDAV client can connect to the address above.")
        _out("     Press Ctrl+C to stop.")

    exit_code = 0
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        _out("\nUnmounting ...")
    except Exception:  # pragma: no cover
        exit_code = 1
    finally:
        _ignore_sigint()
        if mapped and drive:
            if winmount.unmap_drive(drive):
                _registry_drop(drive)
                _ok(f"Disconnected {drive}")
            else:
                _warn(f"Could not disconnect {drive}, you can run later: "
                      f"gpgfs unmount --drive {drive}")
        server.shutdown()
        server.server_close()
        _ok("Service stopped")
    return exit_code


def cmd_serve(args) -> int:
    args.no_drive = True
    return cmd_mount(args)


def cmd_unmount(args) -> int:
    from . import winmount

    registry = _registry_load()
    targets: list[str] = []
    if args.all:
        # Only gpgfs' own WebDAV mappings: force-disconnecting an unrelated SMB share would
        # drop whatever the user has open there.
        extras = [d for d, remote in winmount.mapped_drives()
                  if d not in registry and winmount.is_dav_remote(remote)]
        targets = sorted(registry) + extras
    elif args.drive:
        targets = [_normalize_drive(args.drive)]
    elif registry:
        targets = sorted(registry)
    else:
        _bad("No drive letter mounted by gpgfs found, specify one with --drive Z:")
        return 1
    if not targets:
        _bad("No drive letter mounted by gpgfs found, specify one with --drive Z:")
        return 1

    rc = 0
    for drive in targets:
        info = registry.get(drive, {})
        pid = info.get("pid")
        if pid and _pid_alive(pid) and _kill(pid):
            _ok(f"Ended mount process {pid}")
        if winmount.IS_WINDOWS and not winmount.unmap_drive(drive):
            _bad(f"Failed to disconnect {drive} (it may be locked by another program, "
                 "or WebClient is not responding)")
            _warn("Close the windows using that drive letter, then run: "
                  "sc stop webclient && sc start webclient")
            rc = 1
            continue
        if winmount.IS_WINDOWS:
            _ok(f"Disconnected {drive}\\")
        _registry_drop(drive)
    return rc


def _pid_alive(pid: int) -> bool:
    try:
        if sys.platform == "win32":
            proc = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                  capture_output=True, timeout=15)
            return str(pid) in proc.stdout.decode("utf-8", "replace")
        os.kill(pid, 0)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _process_name(pid: int) -> str:
    """Image name for a PID (Windows), or "" when it cannot be determined."""
    try:
        proc = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                              capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return ""
    text = proc.stdout.decode("utf-8", "replace").strip()
    if not text or text.upper().startswith("INFO:"):
        return ""
    return text.split(",")[0].strip('"')


def _kill(pid: int) -> bool:
    if sys.platform == "win32":
        name = _process_name(pid)
        if name and not name.lower().startswith(("python", "gpgfs")):
            _warn(f"PID {pid} is {name}, not a gpgfs process; leaving it alone")
            return False
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, timeout=15)
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def cmd_ls(args) -> int:
    cfg = load_config(args, need_cipher=True)
    vfs = build_vfs(cfg)
    rel = vfs.normalize(args.path or "")

    if not args.recursive:
        entries = vfs.listdir(rel)
        _print_entries(entries, "", args.long)
        return 0

    base = f"/{rel}" if rel else "/"
    _out(base)
    for path, entry in vfs.walk(rel):
        depth = path.count("/")
        indent = "  " * depth
        name = entry.name + ("/" if entry.is_dir else "")
        if args.long:
            size = "-" if entry.is_dir else _human(entry.size)
            stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.mtime))
            _out(f"{indent}{size:>9}  {stamp}  {name}")
        else:
            _out(f"{indent}{name}")
    return 0


def _print_entries(entries, prefix: str, long_format: bool) -> None:
    for entry in sorted(entries, key=lambda e: (not e.is_dir, e.name.lower())):
        name = entry.name + ("/" if entry.is_dir else "")
        if long_format:
            size = "-" if entry.is_dir else _human(entry.size)
            stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.mtime))
            _out(f"{size:>9}  {stamp}  {prefix}{name}")
        else:
            _out(prefix + name)


def cmd_cat(args) -> int:
    cfg = load_config(args)
    vfs = build_vfs(cfg)
    rel = vfs.normalize(args.path)
    entry = vfs.stat(rel)
    if entry.is_dir:
        _bad(f"Is a directory: /{rel}")
        return 1
    for chunk in vfs.iter_file(rel):
        sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    return 0


def cmd_put(args) -> int:
    cfg = load_config(args)
    vfs = build_vfs(cfg)
    rel = vfs.normalize(args.path)
    if args.file:
        with open(args.file, "rb") as fh:
            entry = vfs.write_stream(rel, fh)
    else:
        if sys.stdin.isatty():
            _warn("Reading content from standard input, press Ctrl+Z then Enter "
                  "(or Ctrl+D) to finish")
        entry = vfs.write_stream(rel, sys.stdin.buffer)
    _ok(f"Wrote /{rel} (plaintext {entry.size} bytes)")
    return 0


def cmd_rm(args) -> int:
    cfg = load_config(args)
    vfs = build_vfs(cfg)
    rel = vfs.normalize(args.path)
    entry = vfs.stat(rel)

    if entry.is_dir:
        if not args.recursive:
            _bad("Is a directory, -r required")
            return 1
        for path, sub in sorted(vfs.walk(rel), key=lambda x: -len(x[0])):
            if sub.is_dir:
                vfs.rmdir(path)
            else:
                vfs.delete(path)
        vfs.rmdir(rel)
        _ok(f"Deleted directory /{rel}")
    else:
        vfs.delete(rel)
        _ok(f"Deleted /{rel}")
    return 0


def cmd_mkdir(args) -> int:
    cfg = load_config(args)
    vfs = build_vfs(cfg)
    rel = vfs.normalize(args.path)
    vfs.mkdir(rel)
    _ok(f"Created directory /{rel}")
    return 0


def cmd_warm(args) -> int:
    """Pre-decrypt once and store every file's plaintext size in the cache (later
    directory listings then take milliseconds)."""
    cfg = load_config(args)
    vfs = build_vfs(cfg)
    total = 0
    for path, entry in vfs.walk(vfs.normalize(args.path or "")):
        if entry.is_dir:
            continue
        try:
            size = vfs.stat(path).size
            total += 1
            if args.verbose:
                _kv("", f"/{path}  {_human(size)}")
        except GpgfsError as exc:
            _warn(f"/{path}: {exc}")
    _ok(f"Warmed plaintext sizes for {total} files")
    return 0


def cmd_drives(args) -> int:
    from . import winmount

    state = winmount.webclient_state()
    _kv("WebClient", state)
    limit = winmount.file_size_limit()
    if limit:
        _kv("Per-file limit", _human(limit))
    registry = _registry_load()
    mappings = winmount.mapped_drives()
    if not mappings:
        _out("  (no mapped network drives)")
        return 0
    for drive, remote in mappings:
        owner = registry.get(drive, {})
        tag = f"  <- gpgfs {owner.get('vault', '')}" if owner else ""
        _kv(drive, remote + tag)
    return 0


# ---------------------------------------------------------------- parser

def _add_cipher_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Cipher options")
    group.add_argument("--recipient", action="append", metavar="KEYID",
                       help="recipient for public-key mode (repeatable)")
    group.add_argument("--symmetric", action="store_true",
                       help="symmetric encryption (passphrase mode)")
    group.add_argument("--passphrase", metavar="TEXT",
                       help="symmetric passphrase (ends up in shell history, "
                            "prefer an environment variable)")
    group.add_argument("--passphrase-file", metavar="PATH",
                       help="read the passphrase from a file (first line)")
    group.add_argument("--gpg", metavar="PATH", help="path to the gpg executable")
    group.add_argument("--homedir", metavar="DIR", help="gpg homedir")
    group.add_argument("--armor", action="store_true", help="emit ASCII armor")
    group.add_argument("--cipher-algo", default=None,
                       help="symmetric cipher algorithm (default AES256)")
    group.add_argument("--expose-plaintext", action="store_true",
                       help="also show unencrypted files already in the directory "
                            "(hidden by default)")


def _add_transport_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Mount options")
    group.add_argument("--drive", metavar="Z:", help="drive letter (auto-picked by default)")
    group.add_argument("--no-drive", action="store_true",
                       help="only provide the WebDAV address, do not map a drive letter")
    group.add_argument("--port", type=int, default=0,
                       help="WebDAV port (random by default)")
    group.add_argument("--host", default="127.0.0.1",
                       help="listen address (local machine only by default)")
    group.add_argument("--auth", metavar="USER:PASS", help="add Basic auth to WebDAV")
    group.add_argument("--read-only", action="store_true", help="mount read-only")
    group.add_argument("--skip-check", action="store_true",
                       help="skip the encrypt/decrypt self-test at startup")
    group.add_argument("-v", "--verbose", action="store_true",
                       help="log HTTP requests")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gpgfs",
        description="Mount a directory of gpg-encrypted files as a transparent "
                    "read/write virtual directory.",
        epilog="Example: gpgfs mount D:\\vault --recipient 0D7E3C93",
    )
    parser.add_argument("--version", action="version", version=f"gpgfs {__version__}")
    subs = parser.add_subparsers(dest="command", required=True)

    p_init = subs.add_parser("init", help="write the vault config "
                                          "(later mounts need no cipher arguments)")
    p_init.add_argument("vault")
    _add_cipher_args(p_init)
    p_init.set_defaults(func=cmd_init)

    p_doctor = subs.add_parser("doctor", help="check whether the environment is ready")
    p_doctor.add_argument("vault", nargs="?")
    p_doctor.add_argument("--gpg")
    p_doctor.add_argument("--homedir")
    p_doctor.add_argument("--recipient", action="append")
    p_doctor.add_argument("--symmetric", action="store_true")
    p_doctor.add_argument("--passphrase")
    p_doctor.add_argument("--passphrase-file")
    p_doctor.add_argument("--armor", action="store_true")
    p_doctor.add_argument("--cipher-algo")
    p_doctor.add_argument("--expose-plaintext", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    p_mount = subs.add_parser("mount", help="mount as a virtual drive letter")
    p_mount.add_argument("vault")
    _add_cipher_args(p_mount)
    _add_transport_args(p_mount)
    p_mount.set_defaults(func=cmd_mount)

    p_serve = subs.add_parser("serve", help="only start the WebDAV service, "
                                             "do not map a drive letter")
    p_serve.add_argument("vault")
    _add_cipher_args(p_serve)
    _add_transport_args(p_serve)
    p_serve.set_defaults(func=cmd_serve)

    p_unmount = subs.add_parser("unmount", help="unmount the virtual drive letter")
    p_unmount.add_argument("--drive")
    p_unmount.add_argument("--all", action="store_true")
    p_unmount.set_defaults(func=cmd_unmount)

    p_ls = subs.add_parser("ls", help="list the virtual directory")
    p_ls.add_argument("vault")
    p_ls.add_argument("path", nargs="?")
    p_ls.add_argument("-R", "--recursive", action="store_true")
    p_ls.add_argument("-l", "--long", action="store_true")
    _add_cipher_args(p_ls)
    p_ls.set_defaults(func=cmd_ls)

    p_cat = subs.add_parser("cat", help="output the decrypted content of a file")
    p_cat.add_argument("vault")
    p_cat.add_argument("path")
    _add_cipher_args(p_cat)
    p_cat.set_defaults(func=cmd_cat)

    p_put = subs.add_parser("put", help="encrypt-write a file")
    p_put.add_argument("vault")
    p_put.add_argument("path")
    p_put.add_argument("-f", "--file", help="read from a file (standard input by default)")
    _add_cipher_args(p_put)
    p_put.set_defaults(func=cmd_put)

    p_rm = subs.add_parser("rm", help="delete a file or directory")
    p_rm.add_argument("vault")
    p_rm.add_argument("path")
    p_rm.add_argument("-r", "--recursive", action="store_true")
    _add_cipher_args(p_rm)
    p_rm.set_defaults(func=cmd_rm)

    p_mkdir = subs.add_parser("mkdir", help="create a directory")
    p_mkdir.add_argument("vault")
    p_mkdir.add_argument("path")
    _add_cipher_args(p_mkdir)
    p_mkdir.set_defaults(func=cmd_mkdir)

    p_warm = subs.add_parser("warm", help="warm the plaintext size cache")
    p_warm.add_argument("vault")
    p_warm.add_argument("path", nargs="?")
    p_warm.add_argument("-v", "--verbose", action="store_true")
    _add_cipher_args(p_warm)
    p_warm.set_defaults(func=cmd_warm)

    p_drives = subs.add_parser("drives", help="show current network drive mappings")
    p_drives.set_defaults(func=cmd_drives)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return args.func(args)
    except GpgfsError as exc:
        _bad(str(exc))
        return 1
    except SystemExit as exc:
        if isinstance(exc.code, str):
            _bad(exc.code)
            return 1
        raise
