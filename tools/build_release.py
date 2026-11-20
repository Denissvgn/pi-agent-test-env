#!/usr/bin/env python3
"""Build fresh skill and clean source archives without publishing or installing."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
import zlib

sys.dont_write_bytecode = True
import check_package
from check_package import export_skill
from validation.validate_standard import checked_lock

REPO = Path(__file__).resolve().parents[1]
# These local-only paths must also stay out of builds from unpacked sources.
PRIVATE_PATHS = {'.git', '.agents', '.codex', 'plans', 'reports', 'development',
                 'dist', 'tools/release-hardening'}


def in_checkout(repository):
    return any(os.path.lexists(parent/'.git') for parent in (repository, *repository.resolve().parents))


def git(repository, *args, input=None):
    result = subprocess.run(['git', '--no-optional-locks', '-C', repository, *args], input=input, capture_output=True)
    if result.returncode:
        raise ValueError('Git inventory failed: ' + os.fsdecode(result.stderr).strip())
    return result.stdout


def git_paths(repository, *args):
    return [Path(os.fsdecode(name)) for name in git(repository, 'ls-files', '-z', *args).split(b'\0') if name]


def tracked_source(repository):
    paths = set(git_paths(repository, '--cached'))
    # git archive prunes an export-ignored directory before visiting its children.
    ancestors = {parent for path in paths for parent in path.parents if parent != Path('.')}
    names = sorted(paths | ancestors)
    records = git(repository, 'check-attr', '--cached', '-z', '--stdin', 'export-ignore',
                  input=b''.join(os.fsencode(path) + b'\0' for path in names)).split(b'\0')[:-1]
    fields = iter(records)
    excluded = {Path(os.fsdecode(name)) for name, _, value in zip(fields, fields, fields, strict=True)
                if value == b'set'}
    return [path for path in paths if path not in excluded and excluded.isdisjoint(path.parents)]


def source_files(repository=REPO):
    checkout = in_checkout(repository)
    if checkout:
        paths = tracked_source(repository)
    else:
        # Extracted source archives have already had Git's export exclusions applied.
        paths = [path.relative_to(repository) for path in export_skill.file_list(repository)]
    root = repository.resolve()
    files = []
    for path in sorted(paths):
        if any(part.as_posix() in PRIVATE_PATHS for part in (path, *path.parents)):
            if checkout:
                raise ValueError('Private source path lacks export-ignore: ' + str(path))
            continue
        file = repository/path
        if file.resolve() != root/path or not file.is_file():
            raise ValueError('Invalid published source file: ' + str(path))
        files.append(file)
    validation = repository/'tools/validation'
    lock = checked_lock(validation)
    if any(validation/item['path'] not in files for item in lock['files']):
        raise ValueError('Published source lacks locked validation inputs')
    return files


def checkout_state(repository):
    if not in_checkout(repository):
        return {'commit': None, 'tree': None, 'dirty': None}, []
    commit = git(repository, 'rev-parse', '--verify', 'HEAD').decode().strip()
    tree = git(repository, 'rev-parse', commit + '^{tree}').decode().strip()
    # Without --exclude-standard, --others also reports ignored files.
    extras = git_paths(repository, '--others', '--', 'skill', 'tests', 'tools')
    dirty = bool(extras or git(repository, 'status', '--porcelain=v1', '-z', '--untracked-files=all'))
    return {'commit': commit, 'tree': tree, 'dirty': dirty}, extras


def package_inputs(source, files):
    paths = [path for path in files if path.is_relative_to(source)]
    package = check_package.check(source, verify_manifest=False, paths=paths)
    manifest = ''.join(f'{digest}  {name}\n' for name, digest in package['files'].items()
                       if name != 'MANIFEST.sha256').encode()
    return package, manifest


def write_files(archive, root, paths, prefix, manifest_path, manifest):
    for path in paths:
        export_skill.write_entry(archive, path, prefix + '/' + path.relative_to(root).as_posix(),
                                 data=manifest if path == manifest_path else None)


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
    state, extras = checkout_state(repository)
    if extras and not candidate:
        raise ValueError('Untracked or ignored build inputs: ' + ', '.join(map(str, extras)))
    published_source = source_files(repository)
    package, manifest = package_inputs(source, published_source)
    version = package['version']
    entry = changelog_entry(source)
    manifest_path = source/'MANIFEST.sha256'
    current_manifest = manifest_path.read_bytes() == manifest
    issues = []
    if entry != version:
        issues.append(f'CHANGELOG top entry {entry!r} is not the package version')
    if not current_manifest:
        issues.append('Stale skill manifest; run export_skill.py --manifest-only')
    if state['dirty']:
        issues.append('Dirty Git checkout')
    if issues and not candidate:
        raise ValueError('; '.join(issues) + '. Pass --candidate for an unpublishable build.')
    publishable = not issues
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    export_skill.zip_timestamp()
    output.mkdir(parents=True,exist_ok=False)
    skill_files = [source/name for name in package['files']]
    layouts = {}
    for name, prefix in export_skill.archive_specs(source).items():
        dest = output/name
        if prefix in layouts:
            shutil.copyfile(layouts[prefix], dest)
            continue
        layouts[prefix] = dest
        with zipfile.ZipFile(dest, 'w') as archive:
            write_files(archive, source, skill_files, prefix, manifest_path, manifest)
            if name.endswith('-claude.zip'):
                export_skill.write_entry(archive, None, '.claude/commands/pi-agent-test-env.md',
                                         data=export_skill.CLAUDE_COMMAND.encode(), mode=0o600)
    source_archive = output/f'pi-agent-test-env-source-{version}.zip'
    with zipfile.ZipFile(source_archive,'w') as archive:
        write_files(archive, repository, published_source, 'pi-agent-test-env-source', manifest_path, manifest)
    with (output/'SHA256SUMS').open('x') as stream:
        for path in sorted(output.glob('*.zip')):
            stream.write(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
    return {'status':'pass','version':version,'changelog_entry':entry,'publishable':publishable,
            **state, 'python_version':platform.python_version(), 'zlib_version':zlib.ZLIB_RUNTIME_VERSION,
            'source_date_epoch':int(epoch) if epoch is not None else None, 'output_directory':str(output),
            'package_files':package['file_count'],'source_files':len(published_source),
            'artifacts':[p.name for p in sorted(output.iterdir())], 'published':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',required=True,type=Path)
    parser.add_argument('--candidate',action='store_true',
                        help='Build tracked candidate inputs with an in-memory manifest, allowing local changes')
    args = parser.parse_args()
    try: result = build(args.output_dir,candidate=args.candidate)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'fail','reason':str(exc)})); return 2
    print(json.dumps(result,indent=2)); return 0


if __name__ == '__main__':sys.exit(main())
