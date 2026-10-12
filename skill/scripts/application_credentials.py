"""Stage-scoped application credentials. Values never enter persistent configuration."""
import json
import os
from pathlib import Path
import re
import shutil
import stat

import secret_store
import stage_control as controls


class CredentialError(ValueError):
    reason = 'application-credentials'


def validate(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 8:
        raise CredentialError('application_secrets must map 1..8 PI_APP_* variables to host secret names')
    for name, reference in value.items():
        if not isinstance(name, str) or not re.fullmatch(r'PI_APP_[A-Z][A-Z0-9_]{0,56}', name):
            raise CredentialError('Application variables must use the PI_APP_* namespace')
        if not isinstance(reference, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]{0,63}', reference):
            raise CredentialError('Application credentials require named host-store references')
    return dict(value)


def read(reference, store):
    """Open the owner-only directory and file without following child symlinks."""
    directory = Path(store).expanduser()
    parent = fd = None
    try:
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CredentialError('Application secret store must be owner-only (0700)')
        fd = os.open(reference, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise CredentialError('Application secret must be an owner-only, singly linked regular file (0600)')
        with os.fdopen(fd, 'rb') as source:
            fd = None
            body = source.read(secret_store.MAX_LEN * 4 + 1)
        if len(body) > secret_store.MAX_LEN * 4:
            raise CredentialError('Application secret exceeds the size limit')
        value = secret_store.clean_value(body.decode('utf-8'))
        if len(value) < 16:
            raise CredentialError('Application credentials must contain at least 16 characters')
        return value
    except (OSError, UnicodeError, secret_store.SecretError):
        raise CredentialError('Missing, unreadable or insecure application secret reference: ' + reference) from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


def resolve(plan, endpoint, inference_key, store, project, runroot, in_place=False, forbidden_roots=()):
    assigned = [task for task in plan['agents'] if task.get('application_secrets')]
    if not assigned:
        return {}
    if in_place:
        raise CredentialError('Application credentials require an isolated snapshot; --in-place is unsupported')
    directory = Path(store).expanduser().resolve()
    for root in [Path(path).resolve() for path in (project, runroot, *forbidden_roots) if path is not None]:
        if directory == root or root in directory.parents:
            raise CredentialError('Application secret store must be outside projects, packages and experiment/run evidence')
    values = {}
    stages = {}
    for task in assigned:
        declarations = validate(task['application_secrets'])
        stages[task['name']] = {}
        for name, reference in declarations.items():
            if reference == endpoint['api_key_env']:
                raise CredentialError('Application credentials cannot reference the inference key')
            if reference not in values:
                values[reference] = read(reference, store)
            if inference_key and values[reference] == inference_key:
                raise CredentialError('Application and inference credentials must differ')
            if any(other != reference and value == values[reference] for other, value in values.items()):
                raise CredentialError('Distinct application references must contain distinct credentials')
            stages[task['name']][name] = values[reference]
    if Redactor([inference_key, *values.values()]).contains(json.dumps(plan, ensure_ascii=False).encode()):
        raise CredentialError('Literal credential found in the plan; references only are supported')
    return stages


class Redactor:
    """Single-pass exact-value and JSON-escaped redaction, including overlaps."""
    def __init__(self, values):
        patterns = set()
        for value in values:
            if value:
                patterns.add(value.encode())
                for ascii_only in (True, False):
                    patterns.add(json.dumps(value, ensure_ascii=ascii_only)[1:-1].encode())
        self.pattern = re.compile(b'|'.join(re.escape(p) for p in sorted(patterns, key=lambda p: (-len(p), p)))) if patterns else None
        self.overlap = max((len(p) for p in patterns), default=1) - 1

    def bytes(self, body):
        return self.pattern.sub(b'<REDACTED>', body) if self.pattern else body

    def contains(self, body):
        return bool(self.pattern and self.pattern.search(body))

    def value(self, value):
        if isinstance(value, str):
            return self.bytes(value.encode()).decode()
        if isinstance(value, dict):
            return {self.value(k): self.value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.value(v) for v in value]
        return value


def workspace_clean(workspace, redactor):
    """Bounded full-tree scan; reject aliases, special files and unknown coverage."""
    total = count = 0

    def scan(parent):
        nonlocal total, count
        with os.scandir(parent) as entries:
            for entry in entries:
                count += 1
                if count > 10000 or redactor.contains(os.fsencode(entry.name)):
                    return False
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    try:
                        if not scan(child):
                            return False
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    with os.fdopen(fd, 'rb') as source:
                        current = os.fstat(source.fileno())
                        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                            return False
                        # Preserve enough overlap to detect a value across read boundaries.
                        tail = b''
                        while True:
                            chunk = source.read(65536)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > 256 * 1024 * 1024 or redactor.contains(tail + chunk):
                                return False
                            tail = (tail + chunk)[-redactor.overlap:] if redactor.overlap else b''
                else:
                    return False
        return True

    root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return scan(root)
    finally:
        os.close(root)


def workspace_inspected_clean(workspace, redactor):
    """Inspection failures have the same fail-closed disposition as contamination."""
    try:
        return workspace_clean(workspace, redactor)
    except (OSError, RecursionError):
        return False


def purge_stage(runroot, desc):
    """Remove raw sessions, temporary material and outbox after writer cleanup only."""
    runroot = Path(runroot)
    stage_id = desc['stage_id']
    control = runroot / 'controls' / stage_id
    roots = (runroot, runroot / 'controls', control, runroot / 'children', runroot / 'children' / '.pi-lab')
    if not controls.valid_id(stage_id) or any(path.is_symlink() for path in roots):
        raise CredentialError('Unsafe sensitive stage cleanup root')
    ids = [stage_id]
    folder = control / 'segments'
    if folder.is_symlink():
        raise CredentialError('Unsafe sensitive segment directory')
    if folder.exists():
        for segment in folder.iterdir():
            if segment.is_symlink() or not controls.valid_id(segment.name):
                raise CredentialError('Unsafe sensitive segment identity')
            ids.append(segment.name)
            (segment / 'session.jsonl').unlink(missing_ok=True)
    for identifier in ids:
        path = runroot / 'children' / '.pi-lab' / identifier
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
    outbox = control / 'outbox'
    if outbox.is_symlink():
        outbox.unlink()
    elif outbox.exists():
        shutil.rmtree(outbox)


def finish(runroot, desc, values, inference_key, result, redaction_secrets=()):
    receipt = {'schema': 1, 'status': 'cleanup_unconfirmed', 'workspace': 'quarantined'}
    try:
        if result.get('cleanup_confirmed') is not True:
            return receipt
        purge_stage(runroot, desc)
        workspace = Path(runroot) / 'workspace'
        if Path(desc['workspace']) != workspace.resolve() or workspace.is_symlink():
            raise CredentialError('Application credentials require the owned snapshot workspace')
        clean = workspace_inspected_clean(workspace, Redactor([inference_key, *values.values(), *redaction_secrets]))
        if not clean:
            shutil.rmtree(workspace)
        receipt.update(status='removed', workspace='clean' if clean else 'discarded')
        return receipt
    except (OSError, CredentialError, RecursionError):
        return receipt


def recover(runroot):
    """After independently owned Docker cleanup, discard abandoned sensitive snapshots."""
    runroot = Path(runroot)
    for path in (runroot / 'stages').glob('*/application-credentials.json'):
        receipt = controls.read(path)
        if receipt.get('status') == 'removed':
            continue
        desc = controls.read(path.parent / 'descriptor.json')
        if desc['stage_id'] != path.parent.name:
            raise CredentialError('Sensitive recovery identity mismatch')
        purge_stage(runroot, desc)
        workspace = runroot / 'workspace'
        if workspace.is_symlink():
            raise CredentialError('Sensitive recovery workspace alias')
        if workspace.exists():
            shutil.rmtree(workspace)
        controls.atomic(path, {**receipt, 'status': 'removed', 'workspace': 'discarded', 'recovery': True})
