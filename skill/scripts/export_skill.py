#!/usr/bin/env python3
"""Export pi-agent-test-env skill into format-compatible archives for Claude Code, Codex, and universal harnesses."""
from __future__ import annotations
import argparse
import hashlib
import json
import stat
import re
import os
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
EXCLUDE_EXTS = {'.pyc'}
EXCLUDE_NAMES = {'.DS_Store'}
SKILL_NAME = 'pi-agent-test-env'
HARNESS_PATHS = {'claude': '.claude/skills', 'codex': '.agents/skills', 'antigravity': '.agents/skills'}
EXCLUDE_DIRS = {'__pycache__'}


def file_list(base: Path) -> list[Path]:
    result = []
    for p in sorted(base.rglob('*')):
        if any(d in p.relative_to(base).parts for d in EXCLUDE_DIRS) or p.name in EXCLUDE_NAMES:
            continue
        if p.is_symlink():
            raise ValueError(f'Package source contains a symlink: {p.relative_to(base)}')
        if p.is_file():
            rel = p.relative_to(base).as_posix()
            if any(d in p.parts for d in EXCLUDE_DIRS) or p.suffix in EXCLUDE_EXTS:
                continue
            result.append(p)
    return result


def update_manifest(base: Path) -> Path:
    manifest_path = base / 'MANIFEST.sha256'
    lines = []
    for p in file_list(base):
        rel = p.relative_to(base).as_posix()
        if rel == 'MANIFEST.sha256':
            continue
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f'{digest}  {rel}')
    manifest_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return manifest_path


def package_metadata(base: Path) -> dict:
    metadata = json.loads((base / 'skill.json').read_text(encoding='utf-8'))
    if metadata['name'] != SKILL_NAME or not re.fullmatch(r'\d+\.\d+\.\d+', metadata['version']):
        raise ValueError('Invalid package name/version')
    return metadata


def archive_specs(base: Path) -> dict[str, str]:
    version = package_metadata(base)['version']
    return {
        f'{SKILL_NAME}-{version}.zip': SKILL_NAME,
        f'{SKILL_NAME}.zip': SKILL_NAME,
        f'{SKILL_NAME}-claude.zip': f"{HARNESS_PATHS['claude']}/{SKILL_NAME}",
        f'{SKILL_NAME}-codex.zip': f"{HARNESS_PATHS['codex']}/{SKILL_NAME}",
        f'{SKILL_NAME}-antigravity.zip': SKILL_NAME,
    }


def require_external_destination(base: Path, destination: Path) -> None:
    source = base.resolve()
    resolved = destination.resolve()
    contained = resolved == source or source in resolved.parents
    if not contained:
        # Canonical spelling alone misses case aliases on filesystems such as
        # default APFS. Existing ancestors identify even new descendant outputs.
        source_info = source.stat()
        for ancestor in (resolved, *resolved.parents):
            try:
                info = ancestor.stat()
            except FileNotFoundError:
                continue
            if (info.st_dev, info.st_ino) == (source_info.st_dev, source_info.st_ino):
                contained = True
                break
    if contained:
        raise ValueError(f'Export destination must be outside the skill package: {destination}')


def build_zip(base: Path, dest: Path, prefix: str, *, claude_command: bool = False) -> Path:
    require_external_destination(base, dest)
    if dest.is_symlink():
        raise ValueError(f'Refusing linked archive destination: {dest}')
    with zipfile.ZipFile(dest, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for p in file_list(base):
            zf.write(p, f'{prefix}/{p.relative_to(base).as_posix()}')
        if claude_command:
            zf.writestr(f'.claude/commands/{SKILL_NAME}.md', CLAUDE_COMMAND)
    return dest


def build_universal_zip(base: Path, dest: Path) -> Path:
    return build_zip(base, dest, SKILL_NAME)


def build_claude_zip(base: Path, dest: Path) -> Path:
    return build_zip(base, dest, f"{HARNESS_PATHS['claude']}/{SKILL_NAME}", claude_command=True)


def build_codex_zip(base: Path, dest: Path) -> Path:
    return build_zip(base, dest, f"{HARNESS_PATHS['codex']}/{SKILL_NAME}")


CLAUDE_COMMAND = "Read the installed pi-agent-test-env/SKILL.md and follow its evaluation or coding-delegation workflow. Resolve scripts relative to that skill directory.\n"


def _install_target(root: Path, relative: str, *, source: Path | None = None) -> dict:
    """Create exclusively through no-follow directory descriptors; never replace."""
    result = {"target": str(root / relative), "status": "failed"}
    descriptors = []
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        parts = Path(relative).parts
        for part in parts[:-1]:
            try:
                os.mkdir(part, dir_fd=fd)
            except FileExistsError:
                pass
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        name = parts[-1]
        try:
            existing = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            correct = False
            if source is not None and stat.S_ISLNK(existing.st_mode):
                link = os.readlink(name, dir_fd=fd)
                correct = (root / relative).parent.joinpath(link).resolve() == source
            elif source is None and stat.S_ISREG(existing.st_mode):
                read_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                with os.fdopen(read_fd, 'r', encoding='utf-8') as stream:
                    correct = stream.read() == CLAUDE_COMMAND
            result['status'] = 'already-correct' if correct else 'conflict'
            return result
        if source is not None:
            os.symlink(str(source), name, target_is_directory=True, dir_fd=fd)
        else:
            write_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
            with os.fdopen(write_fd, 'w', encoding='utf-8') as stream:
                stream.write(CLAUDE_COMMAND)
        result['status'] = 'created'
    except FileExistsError as exc:
        result.update(status='conflict', reason=str(exc))
    except (OSError, ValueError, UnicodeError) as exc:
        result['reason'] = str(exc)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return result


def install_harness(base: Path, target_dir: Path, harness: str) -> list[dict]:
    source = base.resolve(strict=True)
    if not (source / 'SKILL.md').is_file():
        raise ValueError('Skill source must contain SKILL.md')
    root = target_dir.resolve(strict=True)
    outcomes = []
    for parent in tuple(HARNESS_PATHS) if harness == 'all' else (harness,):
        relative = f'{HARNESS_PATHS[parent]}/{SKILL_NAME}'
        outcome = _install_target(root, relative, source=source)
        outcome['harness'] = parent
        outcomes.append(outcome)
        if parent == 'claude':
            if outcome['status'] in ('created', 'already-correct'):
                command = _install_target(root, '.claude/commands/pi-agent-test-env.md')
            else:
                command = {'target': str(root / '.claude/commands/pi-agent-test-env.md'),
                           'status': 'failed', 'reason': 'Skill installation did not succeed; command not created'}
            command['harness'] = parent
            outcomes.append(command)
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', default=str(PROJECT_ROOT), help='Directory to write zip packages')
    parser.add_argument('--install', choices=[*HARNESS_PATHS, 'all'], help='Link skill into local project for specified harness')
    parser.add_argument('--target-dir', default=str(PROJECT_ROOT), help='Project directory to install into')
    args = parser.parse_args()

    try:
        out_dir = Path(args.output_dir).resolve()
        require_external_destination(ROOT, out_dir)
        target_dir = Path(args.target_dir).resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    # Step 1: Update SHA-256 Manifest
    manifest = update_manifest(ROOT)
    print(f"Updated checksum manifest: {manifest}")

    # Step 2: Build precisely the documented release packages.
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, prefix in archive_specs(ROOT).items():
        archive = build_zip(ROOT, out_dir / filename, prefix,
                            claude_command=filename == f'{SKILL_NAME}-claude.zip')
        print(f"Exported package: {archive}")

    # Step 3: Install/link if requested
    if args.install:
        installed = install_harness(ROOT, target_dir, args.install)
        for outcome in installed:
            print(json.dumps(outcome, sort_keys=True))
        if any(item['status'] not in ('created', 'already-correct') for item in installed):
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
