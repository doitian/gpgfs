"""End-to-end self-check: server + drive mapping + real file I/O in one process.

    python scripts\\e2e_test.py --vault D:\\my-vault
    python scripts\\e2e_test.py --vault .\\demo-vault --port 8901

It will:
1. start a temporary WebDAV server (random port)
2. map a free drive letter with net use
3. run a full set of file operations through the drive (reusing the smoke_drive.py checks)
4. unmap the drive and stop the server

Without --keep it does not touch existing files in the vault (the test only runs in
the new gpgfs-e2e directory).
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gpgfs import winmount  # noqa: E402
from gpgfs.cipher import GpgCipher  # noqa: E402
from gpgfs.config import Config  # noqa: E402
from gpgfs.davserver import make_server  # noqa: E402
from gpgfs.state import PlaintextCache, SizeCache  # noqa: E402
from gpgfs.vfs import Vfs  # noqa: E402

import smoke_drive  # noqa: E402


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    parser = argparse.ArgumentParser()
    parser.add_argument("--vault", required=True, help="initialized encrypted directory")
    parser.add_argument("--drive", help="drive letter to use (auto-picked by default)")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--keep", action="store_true", help="keep the test files")
    parser.add_argument("--big-mb", type=float, default=2.0)
    parser.add_argument("--passphrase", help="passphrase for a symmetric vault")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if not winmount.IS_WINDOWS:
        print("The end-to-end drive test is only available on Windows")
        return 1

    cfg = Config.from_vault(args.vault, passphrase=args.passphrase)
    cipher = GpgCipher(
        recipients=cfg.recipients, passphrase=cfg.passphrase, gpg=cfg.gpg,
        armor=cfg.armor, cipher_algo=cfg.cipher_algo, homedir=cfg.homedir,
    )
    vfs = Vfs(cfg.vault, cipher, SizeCache(None), PlaintextCache())

    server = make_server(vfs, host="127.0.0.1", port=args.port, verbose=args.verbose)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    drive = args.drive or winmount.pick_free_drive()
    if not drive:
        print("No free drive letter available")
        server.shutdown()
        return 1

    print(f"Cipher  : {vfs.cipher.describe()}")
    print(f"WebDAV  : {url}")
    print(f"Drive   : {drive}\n")

    mapped = False
    rc = 1
    try:
        winmount.map_drive(url, drive)
        mapped = True
        args_for_smoke = [drive, "--dir", "gpgfs-e2e", "--big-mb", str(args.big_mb)]
        if args.keep:
            args_for_smoke.append("--keep")
        rc = smoke_drive.main(args_for_smoke)
    finally:
        if mapped:
            winmount.unmap_drive(drive)
            print(f"\nUnmapped {drive}")
        server.shutdown()
        server.server_close()
        time.sleep(0.2)
    return rc


if __name__ == "__main__":
    sys.exit(main())
