# gpgfs

Mount a **gpg-encrypted directory** as a **virtual drive that reads and writes transparently**.

```
Encrypted vault                   Virtual drive
  foo/bar.txt.gpg        <->      Z:\foo\bar.txt
```

- Open `Z:\foo\bar.txt` → gpg decrypts on the fly, you see plaintext
- Create / save / overwrite files under `Z:\` → gpg encrypts on the fly, `xxx.gpg` lands on disk
- Plaintext is never written to disk as a file (reads go through pipes end to end; only an in-memory cache)

```
┌───────────────────────┬────────────────────────────────────────┐
│  Any program: Explorer / Word / VS Code / cmd / git            │
└───────────────────────┬────────────────────────────────────────┘
                        │  plain file API: open("Z:\\foo\\bar.txt")
┌───────────────────────┴────────────────────────────────────────┐
│  Windows built-in WebDAV redirector (WebClient service)        │
└───────────────────────┬────────────────────────────────────────┘
                        │  HTTP + WebDAV (listens on 127.0.0.1 only)
┌───────────────────────┴────────────────────────────────────────┐
│  gpgfs                                                         │
│  GET  -> gpg --decrypt     PUT -> gpg --encrypt                │
│  virtual namespace <-> ciphertext dir + plaintext size cache   │
└───────────────────────┬────────────────────────────────────────┘
                        │  standard gpg ciphertext (readable by gpg directly)
┌───────────────────────┴────────────────────────────────────────┐
│  vault/foo/bar.txt.gpg                                         │
└────────────────────────────────────────────────────────────────┘
```

## Why WebDAV instead of FUSE/WinFsp

To make an ordinary program treat a directory as a real drive, Windows only offers two paths:

| Approach | Kernel driver | Administrator | Large files | Used here |
|---|---|---|---|---|
| WinFsp / Dokan + FUSE binding | Yes (kernel driver) | Yes | Unlimited | No |
| **Built-in WebDAV redirector** | **No** | **No** | Limited to 50MB | **Yes** |

`net use Z: http://127.0.0.1:<port>/` is handled by the Windows WebClient service: no install,
no elevation, and every program sees a normal network drive. The trade-off is the default
50MB per-file limit (see "Limitations").

## Quick start

```bash
# 0. Environment check: is gpg usable, is WebClient present, do we have keys
python -m gpgfs doctor

# 1. Initialize an encrypted directory (once)
mkdir D:\vault
python -m gpgfs init D:\vault --recipient 0D7E3C932608C8B1

# 2. Mount (arguments are remembered in .gpgfs.json, no need to repeat them)
python -m gpgfs mount D:\vault
#   [ok]  Mounted: Z:\  <->  D:\vault
#   Files created or edited in this directory are encrypted automatically, reads are decrypted automatically.
#   Press Ctrl+C to unmount.

# 3. Use it
echo hello > Z:\notes.txt
type Z:\notes.txt      # hello
dir D:\vault           # notes.txt.gpg
```

Symmetric passphrase mode (no keys involved, good for sync drives / backup disks):

```bash
python -m gpgfs mount D:\vault --symmetric --port 8899
#   gpg passphrase: ************
```

## Commands

| Command | Description |
|---|---|
| `doctor [vault]` | Health check: gpg candidates, usable secret keys, WebClient state, per-file limit, encrypt/decrypt self-test |
| `init <vault>` | Write the encryption parameters into `<vault>/.gpgfs.json` |
| `mount <vault>` | Start the server and map a drive (picks a free letter by default) |
| `serve <vault>` | Start only the WebDAV server, no drive mapping (for macOS/Linux/phones, or manual `net use`) |
| `unmount [--drive Z:] [--all]` | Unmap the drive and stop the matching process |
| `ls <vault> [path] [-R] [-l]` | Browse without mounting (decrypts to learn sizes) |
| `cat / put / rm / mkdir` | Read and write single files without mounting |
| `warm <vault>` | Pre-populate the plaintext size cache; listing big directories becomes instant |
| `drives` | Show current network drive mappings |

Frequently used mount options:

```
--drive Z:         Drive letter to use (picked automatically by default)
--no-drive         Only serve WebDAV, do not map a drive
--port 8899        Fixed port (random by default)
--read-only        Read-only mount
--auth user:pass   Add Basic auth to WebDAV (default: 127.0.0.1 only, no auth)
--expose-plaintext Also show unencrypted files that already exist in the directory
--recipient KEYID  Public-key mode recipient (repeatable)
--symmetric        Symmetric passphrase mode
--passphrase       Passphrase (prefer the GPGFS_PASSPHRASE environment variable)
--gpg PATH         Path to the gpg executable
--homedir DIR      Path to the gpg home directory
-v                 Log every HTTP request (for debugging)
```

## Installation

No third-party dependencies, standard library only (Python ≥ 3.9).

```bash
cd gpgfs
pip install -e .        # afterwards the gpgfs command is available
# or skip installing and use python -m gpgfs ...
```

The only external dependency is **gpg** (GnuPG 2.1+ or Gpg4win).
`doctor` searches PATH, the registry and Scoop for a gpg whose **key store actually works**
(important when both Gpg4win and an MSYS2 gpg are installed).

## Implementation notes

**Path mapping** (`gpgfs/vfs.py`)
- Directory names stay in plaintext; files gain or lose a `.gpg` suffix
- `..`, absolute paths and internal temp file names are always rejected
- Internal temp files `.gpgfs-tmp-*` and the config `.gpgfs.json` never appear in the virtual namespace

**Read**: hit the in-memory cache (keyed by `ciphertext mtime + ciphertext size`) → otherwise `gpg --decrypt` → plaintext lives in memory only.
**Write**: stream `gpg --encrypt` into a temp file in the same directory → `fsync` → `os.replace` for an atomic swap. If another process holds the target open so it cannot be replaced (Windows), it falls back to copying the bytes into the target, which is not atomic.

**The plaintext size problem**: `stat` must report the plaintext size, but gpg ciphertext is larger than the plaintext.
- Files written through the mount: the size is known at write time and recorded directly
- Foreign files: decrypt once to learn the size, store it in sqlite keyed by `(path, ciphertext mtime, ciphertext size)`; the entry expires automatically when the ciphertext changes
- Directory listings: files with unknown sizes are decrypted in parallel by a thread pool (8 workers by default), so one slow file does not stall the listing

**Windows compatibility**
- Creating or deleting files can hit `EACCES` when antivirus or the indexer briefly holds them; `os.replace`/`open` retry with backoff
- Supports the `Transfer-Encoding: chunked` uploads the redirector uses
- Supports `Range` requests (video/large image seeking), `ETag`/`Last-Modified`, and `LOCK/UNLOCK` (needed for Word saves)
- On error the connection is closed deliberately, so an unread request body cannot pollute a keep-alive connection

## Limitations (read this)

1. **50MB per-file limit**: the Windows WebDAV redirector defaults `FileSizeLimitInBytes` to 50000000.
   Larger files fail with `0x800700DF`. Raising it requires an administrator to edit
   `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\FileSizeLimitInBytes` (DWORD, bytes),
   then `net stop webclient && net start webclient`. `doctor` reports the current value.
2. **Performance is not local-disk level**: every read and write spawns a gpg process (~20–60ms overhead).
   Great for documents, source code and notes; unsuitable for databases, VM images, `node_modules`
   or any workload with many small files or heavy I/O.
3. **File names and directory structure are not encrypted**: only contents are. If file names are
   sensitive, this project does not fit (that is gocryptfs default mode territory).
4. **Plaintext enters the in-memory cache** (256MB total by default; files over 64MB are not cached).
   A memory dump, or a privileged process on the same machine, can see plaintext — the inherent
   cost of transparent reads and writes.
5. **Single writer**: access the vault only through the mount point. If you write the same file through
   both `gpgfs put` and the drive, last writer wins (there is no cross-process lock).

## Security model

Protected: file contents inside the vault (at rest), and those contents if the cloud storage or an
external disk is copied away.
Not protected: plaintext on the machine while the vault is mounted (it must exist in memory), file
names, file sizes, modification times, directory structure.

Key material is never touched: in public-key mode gpg-agent manages the secret key, so smartcards and
hardware tokens keep working; in symmetric mode the passphrase is handed to gpg through a temporary
passphrase file that is deleted immediately afterwards (Windows cannot pass file descriptors via `pass_fds`).

## Self-test and tests

```bash
# Unit tests (they generate a throwaway gpg key and never touch ~/.gnupg)
python -m unittest discover -s tests -v

# Protocol layer: server only, verify with curl / any WebDAV client
python -m gpgfs serve D:\vault --port 8899 -v
curl -X PROPFIND -H "Depth: 1" http://127.0.0.1:8899/

# End to end: server + drive mapping + a full round of file operations in one process
python scripts\e2e_test.py --vault D:\vault --big-mb 2

# Test an already mounted drive (runs the real file API against it)
python scripts\smoke_drive.py Z:
```

## Repository layout

```
gpgfs/
├─ gpgfs/
│  ├─ cipher.py      gpg subprocess wrapper (public-key/symmetric, streaming, passphrase file)
│  ├─ vfs.py         virtual namespace core: path mapping, read/write, rename, caches
│  ├─ state.py       plaintext size cache (sqlite) + plaintext content cache (in-memory LRU)
│  ├─ davserver.py   WebDAV server (PROPFIND/PUT/GET/LOCK/Range…)
│  ├─ winmount.py    net use drive mapping, WebClient diagnostics
│  ├─ config.py      config resolution (command line > environment > .gpgfs.json)
│  └─ cli.py         command line
├─ scripts/
│  ├─ e2e_test.py    end to end: server + drive + file operations
│  └─ smoke_drive.py exercise the real file API on a mounted drive
└─ tests/test_gpgfs.py
```
