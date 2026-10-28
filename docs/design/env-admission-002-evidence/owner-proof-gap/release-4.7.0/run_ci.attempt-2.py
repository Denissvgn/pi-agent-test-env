"""Isolated ARM64 CI driver; seed code/archives only, no host state or credentials."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import time
import zipfile


SEED = Path('/ci-seed')
WORK = Path('/home/node/ci-work')
REPORTS = WORK / 'reports'


def require(condition, message):
    if not condition:raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label, argv, cwd, timeout):
    stdout = REPORTS / (label + '.stdout')
    stderr = REPORTS / (label + '.stderr')
    started = time.monotonic()
    with stdout.open('x') as out, stderr.open('x') as err:
        try:
            result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1'),
                                    timeout=timeout, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    row = {'label': label, 'argv': argv, 'cwd': str(cwd), 'exit_code': code,
           'timeout_seconds': timeout, 'seconds': time.monotonic() - started,
           'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
    print(json.dumps({'job': label, 'exit_code': code, 'seconds': row['seconds']}), flush=True)
    return row


def main():
    WORK.mkdir(parents=True, exist_ok=False); REPORTS.mkdir()
    Path(os.environ['HOME']).mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {'status': 'RUNNING', 'jobs': [], 'real_model_requests': 0,
              'real_application_workflows': 0, 'live_registry_mounted': False,
              'docker_socket_mounted': False, 'platform': platform.platform(),
              'machine': platform.machine(), 'uid': os.getuid(), 'python': sys.version}
    try:
        require(os.getuid() != 0, 'CI must run as non-root')
        require(platform.machine() in ('aarch64', 'arm64'), 'Native ARM64 required')
        manifest = json.loads((SEED / 'candidate-input.json').read_text())
        report['candidate_commit'] = manifest['candidate_commit']; report['version'] = manifest['version']
        for name, expected in manifest['archive_sha256'].items():
            require(sha(SEED / 'archives' / name) == expected, 'Archive hash mismatch: ' + name)
        source = WORK / 'source'
        archive_path = SEED / 'archives' / ('pi-agent-test-env-source-' + manifest['version'] + '.zip')
        expected = manifest['source_files']
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist(); names = [i.filename for i in infos]
            require(len(names) == len(set(names)), 'Duplicate source members')
            require(set(names) == {'pi-agent-test-env-source/' + name for name in expected}, 'Source member mismatch')
            for info in infos:
                path = PurePosixPath(info.filename)
                require(path.as_posix() == info.filename and not path.is_absolute()
                        and all(part not in ('.', '..') for part in path.parts), 'Unsafe member')
                relative = '/'.join(path.parts[1:]); record = expected[relative]
                require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG), 'Linked source member')
                body = archive.read(info)
                require(len(body) == record['bytes'] and hashlib.sha256(body).hexdigest() == record['sha256'], 'Source hash mismatch')
                target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:stream.write(body)
                target.chmod(record['mode'])
        report['installed_candidate_files'] = len(expected)
        origin = "import sys,json;from pathlib import Path;r=Path(sys.argv[1]);sys.path[:0]=[str(r/'skill/scripts'),str(r/'skill/runtime')];import application_owner_cleanup as p;assert Path(p.__file__)==r/'skill/scripts/application_owner_cleanup.py';print(json.dumps({'owner_module_origin':str(p.__file__)}))"
        jobs = [
            ('origin', [sys.executable, '-I', '-B', '-c', origin, str(source)], 30),
            ('runtimes', [sys.executable, '-B', '-c', "import json,subprocess;print(json.dumps({p:subprocess.check_output([p,'--version'],text=True).strip() for p in ('python3','node','git','bash','ps')}))"], 30),
            ('package', [sys.executable, '-B', 'tools/check_package.py', '--source', 'skill'], 60),
            ('standard-self-test', [sys.executable, '-B', 'tools/validation/validate_standard.py', '--self-test'], 180),
            ('release-verification', [sys.executable, '-B', 'tools/verify_release.py', '--archives', str(SEED / 'archives'),
                                      '--report', str(REPORTS / 'release-verification.json'), '--test-timeout-seconds', '1800'], 2100),
        ]
        for label, argv, limit in jobs:
            row = run(label, argv, source, limit); report['jobs'].append(row)
            require(row['exit_code'] == 0, 'CI job failed: ' + label)
        verified = json.loads((REPORTS / 'release-verification.json').read_text())
        require(verified['status'] == 'pass' and verified['tests_skipped'] == 0, 'Release suite incomplete or skipped')
        report.update(status='PASS', tests=verified['tests_run'], skipped=verified['tests_skipped'],
                      test_seconds=verified['test_seconds'], layouts=len(verified['layouts']))
        for name, expected_hash in manifest['archive_sha256'].items():
            require(sha(SEED / 'archives' / name) == expected_hash, 'Archive changed during CI')
        for name, record in expected.items():
            require(sha(source / name) == record['sha256'], 'Candidate changed during CI')
        report['candidate_unchanged'] = True
    except BaseException as error:
        report.update(status='FAIL', failure_type=type(error).__name__, reason=str(error))
    (REPORTS / 'ci-result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(REPORTS / 'ci-result.json')}), flush=True)
    return 0 if report['status'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
