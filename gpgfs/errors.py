"""Exception definitions."""


class GpgfsError(Exception):
    """Base class for all expected GPGFS errors."""


class GpgNotFound(GpgfsError):
    """No usable gpg executable found."""


class GpgError(GpgfsError):
    """The gpg subprocess returned a non-zero exit code."""

    def __init__(self, message: str, stderr: str = "", returncode: int = -1):
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


class CipherNotConfigured(GpgfsError):
    """Neither a recipient nor a passphrase is available, so encryption mode is undecided."""


class NotFound(GpgfsError):
    """The virtual path does not exist."""


class AlreadyExists(GpgfsError):
    """The target already exists."""


class IsADirectory(GpgfsError):
    """A file was expected, but the path is a directory."""


class NotADirectory(GpgfsError):
    """A directory was expected, but the path is a file."""


class DirectoryNotEmpty(GpgfsError):
    """The directory is not empty and cannot be removed."""


class InvalidPath(GpgfsError):
    """Invalid path (escapes the root, illegal characters, and so on)."""
