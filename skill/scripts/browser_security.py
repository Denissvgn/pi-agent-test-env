"""Explicit pinned Chromium user-namespace policy; never downgrade browser sandboxing."""
import hashlib
import os
from pathlib import Path
import shutil
import stat

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = '4b8214fc4971e06172938a1f1554ccff6647ee80'
SHA256 = 'a424392ea9e982712eda600d3502269d59c18b8d13287c1022097b55daef7621'
BASE_SHA256 = '514c38e72edc5363e87287ea87212211172c6c3251a974ca21ebfd05a56c7f5d'
POLICIES = ('docker-default', 'chromium-userns')


def selection(profile='core', policy='docker-default', platform=None, no_sandbox=False):
    if policy not in POLICIES:
        raise ValueError('Unknown browser sandbox policy')
    if policy == 'chromium-userns':
        if profile != 'browser' or no_sandbox or platform not in (None, 'linux/arm64'):
            raise ValueError('chromium-userns requires the sandbox-enabled native ARM64 browser profile')
        return {'policy': policy, 'sha256': SHA256, 'base_sha256': BASE_SHA256, 'upstream_commit': UPSTREAM}
    return {'policy': policy, 'sha256': None}


def verify(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128 * 1024:
            raise ValueError('Unsafe browser seccomp policy file')
        body = source.read(128 * 1024 + 1)
    if hashlib.sha256(body).hexdigest() != SHA256:
        raise ValueError('Pinned browser seccomp policy changed or is unavailable')
    return path


def for_args(args):
    return selection(getattr(args, 'profile', 'core'), getattr(args, 'browser_sandbox_policy', 'docker-default'),
                     getattr(args, 'platform', None), getattr(args, 'allow_browser_no_sandbox', False))


def freeze(args, destination):
    receipt = for_args(args)
    if receipt['policy'] == 'chromium-userns':
        source = verify(ROOT / 'assets/security/chromium-userns.json')
        destination = Path(destination)
        destination.mkdir(mode=0o700)
        path = destination / 'seccomp.json'
        shutil.copyfile(source, path); path.chmod(0o600)
        receipt['path'] = str(path.resolve())
    return receipt


def docker_options(args, workspace):
    selected = for_args(args)
    if selected['policy'] == 'docker-default':
        return []
    receipt = getattr(args, 'frozen_browser_security', None)
    if receipt:
        if any(receipt.get(k) != v for k, v in selected.items()):
            raise ValueError('Browser policy receipt does not match the selected contract')
        path = verify(receipt['path'])
    else:
        path = verify(ROOT / 'assets/security/chromium-userns.json')
    root = Path(workspace).resolve()
    if path.resolve() == root or root in path.resolve().parents:
        raise ValueError('Browser policy must have no writable project alias')
    return ['--security-opt', 'seccomp=' + str(path.resolve())]
