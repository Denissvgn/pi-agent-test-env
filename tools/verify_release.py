#!/usr/bin/env python3
"""Verify complete clean archives and execute tests against extracted runtime bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
import check_package
import build_release
from check_package import require

REPO = Path(__file__).resolve().parents[1]


class VerificationCommandError(ValueError):
    def __init__(self,row):
        super().__init__('Verification command failed: '+str(row['command']))
        self.row=row


def run(argv,cwd,timeout=180):
    result = subprocess.run(argv,cwd=cwd,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1'),
                            capture_output=True,text=True,timeout=timeout)
    row = {'command':argv,'cwd':str(cwd),'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
    if result.returncode != 0: raise VerificationCommandError(row)
    return row


def safe_members(archive):
    infos=archive.infolist();names=[i.filename for i in infos]
    require(len(names)==len(set(names))==len({n.casefold() for n in names}),'Duplicate or case-aliased archive members')
    for info in infos:
        name=info.filename;path=PurePosixPath(name)
        require(name==info.orig_filename and name==path.as_posix() and '\\' not in name and '\0' not in name
                and not path.is_absolute() and path.parts and all(p not in ('..','.') and ':' not in p for p in path.parts),'Unsafe archive name')
        require(not info.is_dir() and stat.S_IFMT(info.external_attr>>16) in (0,stat.S_IFREG)
                and not info.flag_bits&1,'Linked/special/encrypted archive entry')
    return infos


def extract(path,destination,expected):
    with zipfile.ZipFile(path) as archive:
        infos=safe_members(archive)
        require({i.filename for i in infos}==set(expected),'Archive member set differs: '+path.name)
        for info in infos:
            record=expected[info.filename]
            require(info.file_size==record['bytes'],'Archive resource size mismatch')
            body=archive.read(info)
            require(hashlib.sha256(body).hexdigest()==record['sha256'],'Archive bytes differ: '+info.filename)
            require(stat.S_IMODE(info.external_attr>>16)==record['mode'],'Archive mode differs: '+info.filename)
            target=destination.joinpath(*PurePosixPath(info.filename).parts);target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:stream.write(body)
            target.chmod(record['mode'])


def verify(archives,report,repository=REPO):
    source=repository/'skill';archives=archives.resolve(strict=True);report=report.absolute()
    for root in (source.resolve(),archives):
        try: build_release.export_skill.require_external_destination(root,report)
        except ValueError as exc: raise ValueError('Report must be outside inputs') from exc
    require(not report.exists() and not report.is_symlink(),'Verification report must be a new file')
    package=check_package.check(source);version=package['version']
    source_before=check_package.inventory(source);archive_before=check_package.inventory(archives)
    source_zip=f'pi-agent-test-env-source-{version}.zip'
    layouts={f'pi-agent-test-env-{version}.zip':'pi-agent-test-env','pi-agent-test-env.zip':'pi-agent-test-env',
             'pi-agent-test-env-antigravity.zip':'pi-agent-test-env','pi-agent-test-env-codex.zip':'.agents/skills/pi-agent-test-env',
             'pi-agent-test-env-claude.zip':'.claude/skills/pi-agent-test-env'}
    sums=check_package.manifest((archives/'SHA256SUMS').read_bytes())
    require(set(sums)==set(layouts)|{source_zip} and set(archive_before)==set(sums)|{'SHA256SUMS'},'Unexpected published artifact set')
    require(all(check_package.sha(archives/n)==h for n,h in sums.items()),'Published checksums differ')
    require((archives/'pi-agent-test-env.zip').read_bytes()==(archives/f'pi-agent-test-env-{version}.zip').read_bytes()
            ==(archives/'pi-agent-test-env-antigravity.zip').read_bytes(),'Universal aliases are not byte-identical')
    result={'status':'pass','version':version,'archive_sha256':sums,'package':{k:v for k,v in package.items() if k!='files'},'layouts':[]}
    with tempfile.TemporaryDirectory(prefix='pi-published-verification-') as temporary:
        temp=Path(temporary).resolve();roots=[]
        for index,(name,prefix) in enumerate(layouts.items()):
            expected={prefix+'/'+n:r for n,r in source_before.items() if 'sha256' in r and n in package['files']}
            if name.endswith('-claude.zip'):
                body=build_release.export_skill.CLAUDE_COMMAND.encode()
                expected['.claude/commands/pi-agent-test-env.md']={'sha256':hashlib.sha256(body).hexdigest(),'mode':0o600,'bytes':len(body)}
            extract(archives/name,temp/str(index),expected);root=temp/str(index)/prefix
            check_package.check(root);roots.append(root)
            result['layouts'].append({'archive':name,'members':len(expected),'entry_sha256':check_package.sha(root/'SKILL.md')})
        result['standard_validation']=run([sys.executable,str(repository/'tools/validation/validate_standard.py'),*[str(p) for p in roots]],repository)
        clean_files=build_release.source_files(repository)
        expected={'pi-agent-test-env-source/'+p.relative_to(repository).as_posix():{'sha256':check_package.sha(p),'mode':p.stat().st_mode&0o777,'bytes':p.stat().st_size} for p in clean_files}
        extract(archives/source_zip,temp/'source',expected)
        checkout=temp/'source/pi-agent-test-env-source'
        require(check_package.inventory(checkout/'skill')==check_package.inventory(roots[0]),'Source and universal extracted packages differ')
        shutil.rmtree(checkout/'skill')
        shutil.move(str(roots[0]),str(checkout/'skill'))
        # Confirm published-source exclusions independently of the build's allowlist.
        for name in ('plans','reports','dist','development','BACKLOG.md','RELEASE_BACKLOG.md','tools/release-hardening'):
            require(not (checkout/name).exists(),'Internal planning/history shipped in source archive')
        before=check_package.inventory(checkout)
        result['unit_tests']=run([sys.executable,'-m','unittest','discover','-s','tests','-v'],checkout,timeout=600)
        match=re.search(r'Ran (\d+) tests in ([\d.]+)s',result['unit_tests']['stderr'])
        verdict=re.search(r'\nOK(?: \(skipped=(\d+)\))?\n',result['unit_tests']['stderr'])
        require(match is not None and verdict is not None,'Missing test-suite verdict')
        skipped=int(verdict[1] or 0)
        require(int(match[1])>skipped,'Test suite executed no non-skipped tests')
        result['tests_run']=int(match[1]);result['tests_skipped']=skipped;result['test_seconds']=float(match[2])
        result['examples']=run([sys.executable,str(checkout/'tools/check_examples.py'),'--source',str(checkout/'skill')],checkout)
        after=check_package.inventory(checkout);require(before==after,'Extracted source changed during tests/examples')
        result['extracted_inventory_before']=before;result['extracted_inventory_after']=after
        # The source archive itself contains a runnable publishing checker and pinned offline tooling.
        result['source_package_check']=run([sys.executable,str(checkout/'tools/check_package.py'),'--source',str(checkout/'skill')],checkout)
        require(after==check_package.inventory(checkout),'Extracted source changed during final check')
    require(source_before==check_package.inventory(source) and archive_before==check_package.inventory(archives),'Verifier changed source/archive inputs')
    result.update(source_unchanged=True,archives_unchanged=True,temporary_extractions_removed=True,
                  no_internal_planning_artifacts=True,published=False)
    report.parent.mkdir(parents=True,exist_ok=True)
    with report.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archives',required=True,type=Path);parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    try: result=verify(args.archives,args.report)
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired,zipfile.BadZipFile) as exc:
        value={'status':'fail','reason':str(exc)}
        if isinstance(exc,VerificationCommandError): value['failed_command']=exc.row
        print(json.dumps(value));return 2
    print(json.dumps({k:result[k] for k in ('status','version','tests_run','test_seconds','no_internal_planning_artifacts','published')},indent=2));return 0


if __name__=='__main__':sys.exit(main())
