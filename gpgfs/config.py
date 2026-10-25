"""Configuration resolution: command-line arguments > environment variables >
.gpgfs.json inside the vault > defaults."""

from __future__ import annotations

import getpass
import json
import os
import sys
from dataclasses import dataclass, field

from .cipher import best_gpg

CONFIG_NAME = ".gpgfs.json"
ENV_PASSPHRASE = "GPGFS_PASSPHRASE"
ENV_GPG = "GPGFS_GPG"


def state_dir() -> str:
    """Application state directory (caches, mount registry)."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        path = os.path.join(base, "gpgfs")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
        path = os.path.join(base, "gpgfs")
    os.makedirs(path, exist_ok=True)
    return path


@dataclass
class Config:
    vault: str
    recipients: list[str] = field(default_factory=list)
    passphrase: str | None = None
    gpg: str = "gpg"
    armor: bool = False
    cipher_algo: str = "AES256"
    homedir: str | None = None
    expose_plaintext: bool = False
    drive: str | None = None
    host: str = "127.0.0.1"
    port: int = 0
    auth: tuple[str, str] | None = None
    read_only: bool = False
    verbose: bool = False

    @property
    def state(self) -> str:
        return state_dir()

    @property
    def cache_db(self) -> str:
        return os.path.join(state_dir(), "sizes.sqlite")

    @classmethod
    def from_vault(cls, vault: str, passphrase: str | None = None) -> "Config":
        """Build a config directly from the vault's .gpgfs.json (for scripts and embedding)."""
        vault = os.path.abspath(os.path.expanduser(vault))
        if not os.path.isdir(vault):
            raise FileNotFoundError(vault)
        stored = read_vault_config(vault)
        cfg = cls(vault=vault)
        cfg.passphrase = passphrase
        cfg.recipients = list(stored.get("recipients") or [])
        cfg.homedir = stored.get("homedir")
        cfg.gpg = stored.get("gpg") or best_gpg(None, cfg.homedir)
        cfg.armor = bool(stored.get("armor", False))
        cfg.cipher_algo = stored.get("cipher_algo") or "AES256"
        cfg.expose_plaintext = bool(stored.get("expose_plaintext", False))
        return cfg


def read_vault_config(vault: str) -> dict:
    path = os.path.join(vault, CONFIG_NAME)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_vault_config(vault: str, data: dict) -> str:
    path = os.path.join(vault, CONFIG_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path


def resolve_passphrase(args) -> str | None:
    """Resolve the passphrase by priority: --passphrase > --passphrase-file >
    environment variable > interactive prompt."""
    value = getattr(args, "passphrase", None)
    if value:
        return value
    pfile = getattr(args, "passphrase_file", None)
    if pfile:
        with open(pfile, "r", encoding="utf-8") as fh:
            return fh.readline().rstrip("\r\n")
    env = os.environ.get(ENV_PASSPHRASE)
    if env:
        return env
    return None


def load_config(args, need_cipher: bool = True) -> Config:
    vault = os.path.abspath(os.path.expanduser(args.vault))
    if not os.path.isdir(vault):
        raise SystemExit(f"vault does not exist: {vault}")

    stored = read_vault_config(vault)
    cfg = Config(vault=vault)

    cfg.recipients = list(getattr(args, "recipient", None) or stored.get("recipients") or [])
    cfg.armor = bool(getattr(args, "armor", False) or stored.get("armor", False))
    cfg.cipher_algo = getattr(args, "cipher_algo", None) or stored.get("cipher_algo") or "AES256"
    cfg.homedir = getattr(args, "homedir", None) or stored.get("homedir")
    # gpg executable: explicit flag > vault config > automatically pick one
    # that can really read the keyring
    cfg.gpg = (getattr(args, "gpg", None) or stored.get("gpg")
               or best_gpg(None, cfg.homedir))
    cfg.expose_plaintext = bool(getattr(args, "expose_plaintext", False)
                                or stored.get("expose_plaintext", False))
    cfg.read_only = bool(getattr(args, "read_only", False))
    cfg.verbose = bool(getattr(args, "verbose", False))
    cfg.host = getattr(args, "host", None) or "127.0.0.1"
    cfg.port = int(getattr(args, "port", 0) or 0)
    cfg.drive = getattr(args, "drive", None)

    auth = getattr(args, "auth", None)
    if auth:
        user, _, password = auth.partition(":")
        cfg.auth = (user, password)

    cfg.passphrase = resolve_passphrase(args)

    if need_cipher and not cfg.recipients and cfg.passphrase is None:
        if stored.get("mode") == "symmetric" or getattr(args, "symmetric", False):
            if sys.stdin.isatty():
                cfg.passphrase = getpass.getpass("gpg passphrase: ")
            else:
                raise SystemExit(
                    "This vault uses symmetric encryption; provide a passphrase "
                    f"via --passphrase / the {ENV_PASSPHRASE} environment variable "
                    "/ --passphrase-file."
                )
        else:
            raise SystemExit(
                "No encryption mode specified. Use --recipient <KEYID> to set the "
                "recipient public key, or use --symmetric together with --passphrase "
                "for passphrase mode."
            )
    return cfg
