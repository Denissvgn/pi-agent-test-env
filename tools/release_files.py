"""File helpers shared by the release tools.

Release tools read and write files as bytes, so line endings and permission bits
survive a rewrite. A FileTransaction applies a group of writes and deletions; when
one of them fails, every change already made is undone from the bytes and modes
captured just before it was made. Nothing is left half-applied, and no temporary
file is left behind.
"""
import os
from pathlib import Path
import stat
import tempfile


class RollbackError(OSError):
    """A failed transaction could not restore every file it had changed."""


def read_exact(path: Path) -> tuple[bytes, int]:
    """Return (bytes, permission bits) of a regular file.

    Anything else (a symbolic link, a directory, a FIFO, a device) is refused before
    it is read, so a release tool never follows a link, blocks on or consumes
    non-regular input.
    """
    if path.is_symlink():
        raise OSError(f'{path.name} is a symbolic link, not a regular file')
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode):
        raise OSError(f'{path.name} is not a regular file')
    return path.read_bytes(), stat.S_IMODE(mode)


def _discard(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def stage_bytes(path: Path, data: bytes, mode: int) -> Path:
    """Write data to a new, uniquely named file beside path and return its name.

    The staged file has the given permission bits. The caller moves it into place
    with os.replace, so a reader sees either the old bytes or the new ones.
    """
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f'.{path.name}.', suffix='.tmp')
    staged = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staged, stat.S_IMODE(mode))
    except BaseException:
        _discard(staged)
        raise
    return staged


def _replace(data: bytes, path: Path, mode: int) -> None:
    staged = stage_bytes(path, data, mode)
    try:
        os.replace(staged, path)
    except BaseException:
        _discard(staged)
        raise


class FileTransaction:
    """Writes and deletions that either all take effect or are all undone.

    Each change records the state it replaces only after it has succeeded. If the
    block raises, the recorded states are restored newest first. A restoration that
    also fails is reported by name in RollbackError, and the others are still tried.
    """

    def __init__(self):
        self._undo: list[tuple[Path, tuple[bytes, int] | None]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is None:
            return False
        failures = self.rollback()
        if failures:
            raise RollbackError(f'{exc}; could not restore: ' + '; '.join(failures)) from exc
        return False

    def write(self, path: Path, data: bytes) -> None:
        original = read_exact(path) if path.exists() else None
        _replace(data, path, original[1] if original else 0o644)
        self._undo.append((path, original))

    def delete(self, path: Path) -> None:
        original = read_exact(path)
        os.unlink(path)
        self._undo.append((path, original))

    def rollback(self) -> list[str]:
        """Restore every recorded state; return one message per path that could not be restored."""
        failures = []
        while self._undo:
            path, original = self._undo.pop()
            try:
                if original is None:
                    _discard(path)
                else:
                    data, mode = original
                    _replace(data, path, mode)
            except OSError as exc:
                failures.append(f'{path.name}: {exc.strerror or exc}')
        return failures
