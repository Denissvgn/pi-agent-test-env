"""Host-side store for model-endpoint keys.

Resolution order for a key named NAME: environment variable NAME, then the
owner-only file <store>/NAME. The store lives in the user's config directory,
never inside a project or a child mount. Values are never printed; status shows
only a short SHA-256 fingerprint so a user can confirm which key is active.
"""
from __future__ import annotations
import getpass
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

NAME_RE = re.compile(r'[A-Z_][A-Z0-9_]*')
MAX_LEN = 4096


class SecretError(RuntimeError):
    pass


def default_store() -> Path:
    if os.environ.get('PI_LAB_SECRETS_DIR'):
        return Path(os.environ['PI_LAB_SECRETS_DIR']).expanduser()
    base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    new_dir = Path(base).expanduser() / 'pi-agent-test-env' / 'secrets'
    old_dir = Path(base).expanduser() / 'pi-agentic-development' / 'secrets'
    if not new_dir.exists() and old_dir.exists():
        return old_dir
    return new_dir


def _store(store) -> Path:
    return Path(store).expanduser() if store else default_store()


def check_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise SecretError(f'Invalid secret name {name!r}: use an environment-variable style name such as UNSLOTH_API_KEY')
    return name


def secret_path(name: str, store=None) -> Path:
    return _store(store) / check_name(name)


def clean_value(raw: str) -> str:
    value = (raw or '').strip()
    if not value:
        raise SecretError('Empty secret; nothing stored')
    if len(value) > MAX_LEN:
        raise SecretError(f'Secret longer than {MAX_LEN} characters; refusing')
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise SecretError('Secret contains whitespace or control characters; paste only the key itself')
    return value


def fingerprint(value: str) -> str:
    return 'sha256:' + hashlib.sha256(value.encode()).hexdigest()[:10]


def _check_file(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SecretError(f'Secret file must be a regular file, not a symlink: {path}')
    if hasattr(os, 'getuid') and st.st_uid != os.getuid():
        raise SecretError(f'Secret file is owned by another user: {path}')
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise SecretError(f'Secret file is readable by group/others; run: chmod 600 {path}')


def read_secret(name: str, store=None) -> str:
    path = secret_path(name, store)
    if not path.exists() and not path.is_symlink():
        return ''
    _check_file(path)
    return clean_value(path.read_text(encoding='utf-8'))


def write_secret(name: str, value: str, store=None) -> Path:
    value = clean_value(value)
    path = secret_path(name, store)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink():
        raise SecretError(f'Refusing symlinked secret directory: {directory}')
    os.chmod(directory, 0o700)
    tmp = directory / f'.{name}.{os.getpid()}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(value)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return path


def delete_secret(name: str, store=None) -> bool:
    path = secret_path(name, store)
    if path.exists() or path.is_symlink():
        path.unlink()
        return True
    return False


def has_terminal() -> bool:
    try:
        with open('/dev/tty'):
            return True
    except OSError:
        return False


def prompt_secret(name: str) -> str:
    """Hidden input from the controlling terminal; never from a pipe by accident."""
    if not has_terminal():
        raise SecretError('No interactive terminal for hidden input. Run the command in your own terminal, '
                          'or pipe the key with --stdin (for example from a password manager).')
    first = getpass.getpass(f'{name} (input hidden): ')
    second = getpass.getpass(f'Repeat {name}: ')
    if first.strip() != second.strip():
        raise SecretError('The two entries differ; nothing stored')
    return clean_value(first)


def resolve_secret(name: str, store=None) -> tuple[str, str]:
    """Return (value, source) where source is 'env', 'store', or '' when missing."""
    check_name(name)
    value = os.environ.get(name, '').strip()
    if value:
        return value, 'env'
    value = read_secret(name, store)
    if value:
        return value, 'store'
    return '', ''


def status(name: str, store=None) -> dict:
    path = secret_path(name, store)
    result = {'name': name, 'store_path': str(path), 'env_set': bool(os.environ.get(name, '').strip()),
              'store_present': path.exists(), 'store_ok': None, 'active_source': None, 'fingerprint': None}
    try:
        value, source = resolve_secret(name, store)
        if result['store_present']:
            result['store_ok'] = True
    except SecretError as exc:
        value, source = (os.environ.get(name, '').strip(), 'env') if result['env_set'] else ('', '')
        result['store_ok'] = False
        result['store_error'] = str(exc)
    result['active_source'] = source or 'missing'
    result['fingerprint'] = fingerprint(value) if value else None
    return result


def read_stdin_secret() -> str:
    if sys.stdin.isatty():
        raise SecretError('--stdin expects piped input; for typing, omit --stdin to get a hidden prompt')
    return clean_value(sys.stdin.read(MAX_LEN + 2))
