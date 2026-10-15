#!/usr/bin/env python3
"""Build fresh skill and clean source archives without publishing or installing."""
import argparse
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import zipfile

sys.dont_write_bytecode = True
import check_package
from check_package import export_skill

REPO = Path(__file__).resolve().parents[1]
SOURCE_ROOT_FILES = ('README.md','CONTRIBUTING.md','LICENSE','.gitignore','.gitattributes')


def source_files(repository=REPO):
    files = [repository/name for name in SOURCE_ROOT_FILES]
    files.append(repository/'docs/design/parallel-agents.md')
    files.extend(repository/'docs/design'/name for name in ('indexed-inference-environments.md','indexed-inference-environments-implementation-plan.md'))
    files.extend(export_skill.file_list(repository/'skill'))
    files.extend(sorted((repository/'tests').glob('test_*.py')))
    if (repository/'tests/__init__.py').is_file(): files.append(repository/'tests/__init__.py')
    files.extend(repository/'tools'/name for name in ('build_release.py','verify_release.py','check_package.py','check_examples.py'))
    files.extend(sorted((repository/'tools/qualification').glob('*.py')))
    validation = repository/'tools/validation'
    spec = importlib.util.spec_from_file_location('published_standard_validation',validation/'validate_standard.py')
    validator = importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
    lock = validator.checked_lock()
    files.extend(validation/name for name in ('validate_standard.py','toolchain.lock.json'))
    files.extend(validation/item['path'] for item in lock['files'])
    for path in files:
        if path.is_symlink() or not path.is_file(): raise ValueError('Invalid published source file: '+str(path))
    return sorted(set(files))


def build(output, repository=REPO):
    source = repository/'skill'
    if output.is_symlink(): raise ValueError('Linked output directory refused')
    output = output.resolve()
    for input_root in (source,repository/'tests',repository/'tools'):
        if input_root.exists(): export_skill.require_external_destination(input_root,output)
    for ancestor in (output,*output.parents):
        if ancestor.is_symlink(): raise ValueError('Linked output directory refused')
    if output.exists(): raise ValueError('Choose a fresh output directory')
    check_package.check(source,verify_manifest=False)
    # Inventory the allowlisted source before creating output, so optional history never leaks.
    published_source = source_files(repository)
    export_skill.update_manifest(source)
    package = check_package.check(source)
    output.mkdir(parents=True,exist_ok=False)
    version = package['version']; universal = output/f'pi-agent-test-env-{version}.zip'
    export_skill.build_universal_zip(source,universal)
    shutil.copyfile(universal,output/'pi-agent-test-env.zip')
    shutil.copyfile(universal,output/'pi-agent-test-env-antigravity.zip')
    export_skill.build_claude_zip(source,output/'pi-agent-test-env-claude.zip')
    export_skill.build_codex_zip(source,output/'pi-agent-test-env-codex.zip')
    source_archive = output/f'pi-agent-test-env-source-{version}.zip'
    with zipfile.ZipFile(source_archive,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in published_source:
            archive.write(path,'pi-agent-test-env-source/'+path.relative_to(repository).as_posix())
    with (output/'SHA256SUMS').open('x') as stream:
        for path in sorted(output.glob('*.zip')):
            stream.write(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
    return {'status':'pass','version':version,'output_directory':str(output),
            'package_files':package['file_count'],'source_files':len(published_source),
            'artifacts':[p.name for p in sorted(output.iterdir())], 'published':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',required=True,type=Path)
    args = parser.parse_args()
    try: result = build(args.output_dir)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'fail','reason':str(exc)})); return 2
    print(json.dumps(result,indent=2)); return 0


if __name__ == '__main__':sys.exit(main())
