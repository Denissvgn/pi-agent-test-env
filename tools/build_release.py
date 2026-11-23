#!/usr/bin/env python3
"""Build fresh skill and clean source archives without publishing or installing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import zlib
import zipfile

sys.dont_write_bytecode = True
import check_package
from check_package import export_skill
from validation.validate_standard import checked_lock

REPO = Path(__file__).resolve().parents[1]


def git(directory, *args, input=None):
    result = subprocess.run(['git', '--no-optional-locks', *args], cwd=directory, input=input,
                            capture_output=True)
    if result.returncode:
        raise ValueError('Git inventory failed: ' + os.fsdecode(result.stderr).strip())
    return result.stdout


def checkout_root(repository):
    for parent in (repository, *repository.parents):
        if os.path.lexists(parent / '.git'):
            return parent
    return None


def tracked_exports(repository, root):
    prefix = repository.relative_to(root)
    names = git(repository, 'ls-files', '--cached', '-z').split(b'\0')
    paths = {prefix / os.fsdecode(name) for name in names if name}
    # Git archive also omits descendants of an export-ignored directory.
    entries = {entry for path in paths for entry in (path, *path.parents) if entry != Path('.')}
    query = b''.join(os.fsencode(entry) + b'\0' for entry in sorted(entries))
    attrs = git(root, 'check-attr', '--cached', '-z', '--stdin', 'export-ignore', input=query)
    fields = attrs.split(b'\0')[:-1]
    ignored = {Path(os.fsdecode(name)) for name, value in zip(fields[::3], fields[2::3], strict=True)
               if value == b'set'}
    return [root / path for path in paths if path not in ignored and ignored.isdisjoint(path.parents)]


def extracted_files(repository):
    for directory, dirs, names in os.walk(repository):
        root = Path(directory)
        excluded = {'.git', '__pycache__'}
        if root == repository:
            excluded.update({'.agents', '.codex', 'plans', 'reports', 'development', 'dist'})
        if root == repository / 'tools':
            excluded.add('release-hardening')
        dirs[:] = [name for name in dirs if name not in excluded]
        for name in dirs:
            if (root / name).is_symlink():
                raise ValueError(f'Invalid published source directory: {root / name}')
        for name in names:
            if name != '.DS_Store' and not name.endswith('.pyc'):
                yield root / name


def source_files(repository=REPO):
    repository = repository.resolve()
    root = checkout_root(repository)
    files = sorted(tracked_exports(repository, root) if root else extracted_files(repository))
    for path in files:
        if path.resolve() != path or not path.is_file():
            raise ValueError(f'Invalid published source file: {path}')
    checked_lock(repository / 'tools/validation')
    return files


def checkout_state(repository):
    if checkout_root(repository) is None:
        return {'commit': None, 'tree': None, 'dirty': None}, []
    commit, tree = git(repository, 'rev-parse', 'HEAD', 'HEAD^{tree}').decode().splitlines()
    others = git(repository, 'ls-files', '--others', '-z', '--', 'skill', 'tests', 'tools')
    stray = [os.fsdecode(name) for name in others.split(b'\0') if name]
    dirty = bool(stray or git(repository, 'status', '--porcelain=v1', '-z', '--untracked-files=normal'))
    return {'commit': commit, 'tree': tree, 'dirty': dirty}, stray


def package_inputs(source, published):
    contents = {path: path.read_bytes() for path in published if path.is_relative_to(source)}
    package = check_package.check(source, verify_manifest=False, contents=contents)
    manifest = ''.join(f'{digest}  {name}\n' for name, digest in package['files'].items()
                       if name != 'MANIFEST.sha256').encode()
    check_package.manifest(manifest)
    manifest_path = source / 'MANIFEST.sha256'
    current = contents[manifest_path] == manifest
    contents[manifest_path] = manifest
    return contents, package, current


def write_archive(destination, prefix, base, members, *, claude=False):
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, body in members.items():
            name = prefix + '/' + path.relative_to(base).as_posix()
            export_skill.write_entry(archive, path, name, data=body)
        if claude:
            export_skill.write_entry(archive, None, '.claude/commands/pi-agent-test-env.md',
                                     data=export_skill.CLAUDE_COMMAND.encode(), mode=0o600)


def changelog_entry(source):
    """Return the first `## ` heading's leading token, e.g. '4.9.0' or 'Unreleased'."""
    path = source/'CHANGELOG.md'
    if not path.is_file(): return None
    for line in path.read_text(encoding='utf-8').splitlines():
        if line.startswith('## '):
            parts = line[3:].split()
            return parts[0] if parts else None
    return None


def build(output, repository=REPO, *, candidate=False):
    repository = repository.resolve()
    source = repository/'skill'
    if output.is_symlink(): raise ValueError('Linked output directory refused')
    output = output.resolve()
    for input_root in (source,repository/'tests',repository/'tools'):
        if input_root.exists(): export_skill.require_external_destination(input_root,output)
    for ancestor in (output,*output.parents):
        if ancestor.is_symlink(): raise ValueError('Linked output directory refused')
    if output.exists(): raise ValueError('Choose a fresh output directory')
    root = checkout_root(repository)
    if candidate and root:
        try:
            export_skill.require_external_destination(root, output)
        except ValueError as exc:
            raise ValueError('Choose a candidate output directory outside the Git working tree') from exc
    state, stray = checkout_state(repository)
    if stray and not candidate:
        raise ValueError('Untracked or ignored release inputs: ' + ', '.join(stray))
    published = source_files(repository)
    contents, package, current_manifest = package_inputs(source, published)
    entry = changelog_entry(source)
    version = package['version']
    if not candidate:
        if not current_manifest:
            raise ValueError('Stale skill manifest; run export_skill.py --manifest-only')
        if state['dirty']:
            raise ValueError('Dirty Git working tree; commit changes or pass --candidate')
        if entry != version:
            raise ValueError(f'CHANGELOG top entry {entry!r} is not the package version; '
                             'bump the version or pass --candidate for an unpublishable build')
    publishable = entry == version and current_manifest and not state['dirty']
    export_skill.zip_timestamp()
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '315532800'))
    output.mkdir(parents=True, exist_ok=False)
    layouts = {}
    for name, prefix in export_skill.archive_specs(source).items():
        destination = output / name
        if prefix in layouts:
            shutil.copyfile(layouts[prefix], destination)
        else:
            write_archive(destination, prefix, source, contents, claude=name.endswith('-claude.zip'))
            layouts[prefix] = destination
    source_archive = output / f'pi-agent-test-env-source-{version}.zip'
    source_members = {path: contents.get(path) for path in published}
    write_archive(source_archive, 'pi-agent-test-env-source', repository, source_members)
    with (output/'SHA256SUMS').open('x') as stream:
        for path in sorted(output.glob('*.zip')):
            stream.write(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
    return {'status':'pass','version':version,'changelog_entry':entry,'publishable':publishable,
            **state, 'python_version':platform.python_version(), 'zlib_version':zlib.ZLIB_RUNTIME_VERSION,
            'source_date_epoch':epoch, 'output_directory':str(output),
            'package_files':package['file_count'],'source_files':len(published),
            'artifacts':[p.name for p in sorted(output.iterdir())], 'published':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',required=True,type=Path)
    parser.add_argument('--candidate',action='store_true',
                        help='Allow a verification build with pending changes or a stale manifest')
    args = parser.parse_args()
    try: result = build(args.output_dir,candidate=args.candidate)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'fail','reason':str(exc)})); return 2
    print(json.dumps(result,indent=2)); return 0


if __name__ == '__main__':sys.exit(main())
