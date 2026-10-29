#!/usr/bin/env python3
"""Read-only installable package checks; no Docker, model or installation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'skill/scripts'))
import export_skill

INTERNAL_MARKERS = re.compile(r'\b(?:[BFR]\d{2}(?:[–-][BFR]?\d{2})?|AC\d{2}-\d{2}|Wave\s+\d+|wave-\d+|release-hardening|implementation pending)\b', re.IGNORECASE)
PRIVATE_PARTS = {'.git','.agents','.codex','tests','reports','plans','dist','development','__pycache__'}
REQUIRED_FILES = {'SKILL.md','skill.json','LICENSE','MANIFEST.sha256','scripts/pi_lab.py',
                  'runtime/worker.py','docker/Dockerfile','references/SECURITY.md',
                  'scripts/application_owner_cleanup.py','scripts/ownership_registry.py',
                  'references/APPLICATION-OWNER-CLEANUP.md','references/APPLICATION-OWNER-READER.md',
                  'references/OWNER-CLEANUP-COMPATIBILITY.md',
                  'assets/application-owner-reader-v1.json','assets/application-owner-reader-vectors-v1.json',
                  *('scripts/application_owner_legacy'+suffix+'.py' for suffix in
                    ('','_catalog','_controller','_launchers','_roots','_namespace','_protocol','_native','_discard','_publication'))}
REQUIRED_DIRECTORIES = {'scripts','runtime','assets','examples','docker','references'}


def require(condition, message):
    if not condition: raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'Linked package entry: '+str(path))
        if path.is_file():
            result[path.relative_to(root).as_posix()] = {'sha256':sha(path),'mode':path.stat().st_mode&0o777,'bytes':path.stat().st_size}
        elif path.is_dir():
            result[path.relative_to(root).as_posix()] = {'directory':True,'mode':path.stat().st_mode&0o777}
        else: raise ValueError('Special package entry: '+str(path))
    return result


def manifest(body):
    result = {}
    for line in body.decode().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        require(match is not None, 'Malformed checksum line')
        digest,name = match.groups()
        require(name not in result, 'Duplicate checksum entry: '+name)
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and '\\' not in name, 'Unsafe checksum path')
        result[name] = digest
    return result


def check(source, verify_manifest=True):
    source = source.resolve(strict=True)
    files = {p.relative_to(source).as_posix():p for p in export_skill.file_list(source)}
    require(REQUIRED_FILES <= files.keys(), 'Package lacks required entry/runtime/license files')
    require(all((source/name).is_dir() for name in REQUIRED_DIRECTORIES), 'Package lacks runtime resource directories')
    # Example subject tests are runtime acceptance inputs, unlike maintainer tests.
    for name,path in files.items():
        parts = Path(name).parts
        require(parts[0] not in PRIVATE_PARTS, 'Non-runtime directory shipped: '+name)
        require(not any(part in {'.git','reports','__pycache__'} for part in parts), 'Development output shipped: '+name)
        require(path.suffix not in {'.zip','.pyc','.log'} and path.name not in {'unit-results.txt','static-checks.json'}, 'Stored output shipped: '+name)
        if path.suffix in {'.md','.py','.mjs','.json'} or path.name == 'Dockerfile':
            match = INTERNAL_MARKERS.search(path.read_text())
            require(match is None, 'Internal development marker in '+name+': '+(match.group() if match else ''))
    metadata = export_skill.package_metadata(source)
    entry = (source/'SKILL.md').read_text()
    require(entry.startswith('---\nname: '+metadata['name']+'\n'), 'Skill frontmatter name mismatch')
    require('Package version: '+metadata['version']+'.' in entry, 'Entry version mismatch')
    hashes = {name:sha(path) for name,path in files.items()}
    if verify_manifest:
        rows = manifest((source/'MANIFEST.sha256').read_bytes())
        require(set(rows) == set(files)-{'MANIFEST.sha256'}, 'Incomplete or extra manifest coverage')
        require(all(rows[name] == hashes[name] for name in rows), 'Manifest differs from package bytes')
    for path in files.values():
        if path.suffix != '.md': continue
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',path.read_text()):
            if target.startswith(('http:','https:','#','mailto:')): continue
            relative = target.split('#',1)[0]
            require(not relative or (path.parent/relative).is_file(), 'Broken package link: '+str(path)+' -> '+target)
            if relative: require((path.parent/relative).resolve().is_relative_to(source), 'Link escapes installed package')
    return {'status':'pass','version':metadata['version'],'file_count':len(files),'manifest_entries':len(files)-1,
            'package_content_sha256':hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'files':hashes,'scope':'Complete runtime package; no internal planning or stored validation output.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=REPO/'skill')
    args = parser.parse_args()
    try: result = check(args.source)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'fail','reason':str(exc)})); return 1
    print(json.dumps(result,indent=2)); return 0


if __name__ == '__main__': sys.exit(main())
