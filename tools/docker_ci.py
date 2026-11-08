#!/usr/bin/env python3
"""Run the offline maintainer checks in a bounded native Linux container.

The published source allowlist is staged into a fresh directory and mounted
read-only, so tests see exactly the files a source archive would contain and
cannot change them. The container has no network, no capabilities, a read-only
root filesystem, a private /tmp and fixed CPU/memory/process ceilings. The image
must provide python3 (3.10+) and node; tools/ci/Dockerfile builds one.

This qualifies the offline suite on one Python/platform. It does not provide the
synthetic read-only providers that the isolated owner-consumer tests need
(PI_SYNTHETIC_READER_PROVIDER) or the operation SDK container fixture, and it
makes no Docker-in-Docker, model or Pi call.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
import build_release
import check_package

REPO = Path(__file__).resolve().parents[1]
PLATFORMS = {'aarch64': 'linux/arm64', 'arm64': 'linux/arm64', 'x86_64': 'linux/amd64', 'amd64': 'linux/amd64'}


def docker(*argv, timeout=60):
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout, check=True).stdout.strip()


def stage(destination):
    for path in build_release.source_files(REPO):
        target = destination/path.relative_to(REPO)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    return destination


def container(image, platform, source, limits, argv, timeout):
    # --init keeps the test process off PID 1; some tests reject owner PID 1.
    name = 'pi-docker-ci-' + uuid.uuid4().hex[:12]
    command = ['docker', 'run', '--rm', '--init', '--name', name, '--platform', platform,
               '--network', 'none', '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', str(limits['cpus']),
               '--memory', limits['memory'], '--memory-swap', limits['memory'],
               '--pids-limit', str(limits['pids']),
               '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777',
               '--mount', f'type=bind,src={source},dst=/candidate,readonly', '--workdir', '/candidate',
               '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONNOUSERSITE=1',
               '--env', 'HOME=/tmp/ci-home', '--entrypoint', argv[0], image, *argv[1:]]
    started = time.monotonic(); finished = False
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr; finished = True
    except subprocess.TimeoutExpired as exc:
        code = 124
        stdout = exc.stdout.decode(errors='replace') if isinstance(exc.stdout, bytes) else exc.stdout or ''
        stderr = exc.stderr.decode(errors='replace') if isinstance(exc.stderr, bytes) else exc.stderr or ''
    finally:
        # A timed-out or interrupted client must not leave the container running.
        if not finished: subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=60)
    return {'command': argv, 'exit_code': code, 'seconds': round(time.monotonic() - started, 3),
            'stdout': stdout, 'stderr': stderr}


def run(image, report, *, platform=None, limits=None, timeout=1800):
    report = report.absolute()
    if report.exists() or report.is_symlink(): raise ValueError('Report must be a new file')
    if report.is_relative_to(REPO): raise ValueError('Report must be outside the repository')
    limits = limits or {'cpus': 2, 'memory': '4g', 'pids': 1024}
    platform = platform or PLATFORMS.get(docker('info', '--format', '{{.Architecture}}'))
    if platform not in PLATFORMS.values(): raise ValueError('Native linux/arm64 or linux/amd64 platform required')
    identity = json.loads(docker('image', 'inspect', image))[0]
    if identity['Os'] != 'linux' or PLATFORMS.get(identity['Architecture']) != platform:
        raise ValueError('Image must match the native platform; emulation is not a qualification')
    result = {'status': 'fail', 'image': image, 'image_id': identity['Id'], 'platform': platform,
              'limits': limits, 'network': 'none', 'source_read_only': True, 'jobs': []}
    with tempfile.TemporaryDirectory(prefix='pi-docker-ci-') as temporary:
        source = stage(Path(temporary).resolve()/'candidate')
        before = check_package.inventory(source)
        versions = container(image, platform, source, limits, ['sh', '-c', 'python3 --version; node --version'], 60)
        result['versions'] = versions['stdout'].split()
        minor = re.search(r'Python 3\.(\d+)', versions['stdout'])
        if versions['exit_code'] != 0 or minor is None or int(minor[1]) < 10:
            raise ValueError('Image must provide python3 3.10+ and node')
        jobs = [['python3', '-m', 'unittest', 'discover', '-s', 'tests'],
                ['python3', 'tools/check_package.py', '--source', 'skill'],
                ['python3', 'tools/check_examples.py', '--source', 'skill']]
        if int(minor[1]) >= 11: jobs.append(['python3', 'tools/validation/validate_standard.py', '--self-test'])
        for argv in jobs:
            row = container(image, platform, source, limits, argv, timeout)
            if argv[2:3] == ['unittest']:
                ran = re.search(r'Ran (\d+) tests? in ([\d.]+)s', row['stderr'])
                verdict = re.search(r'\n(OK|FAILED)(?: \((.*)\))?\n', row['stderr'])
                row.update(tests_run=int(ran[1]) if ran else None, verdict=verdict[0].strip() if verdict else None)
            result['jobs'].append(row)
        result['source_unchanged'] = check_package.inventory(source) == before
    result['status'] = 'pass' if result['source_unchanged'] and all(j['exit_code'] == 0 for j in result['jobs']) else 'fail'
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open('x') as stream: json.dump(result, stream, indent=2); stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--image', required=True, help='Local native image with python3 3.10+ and node')
    parser.add_argument('--report', required=True, type=Path, help='New JSON report path outside the repository')
    parser.add_argument('--platform', choices=sorted(set(PLATFORMS.values())), help='Defaults to the native daemon platform')
    parser.add_argument('--cpus', type=float, default=2.0)
    parser.add_argument('--memory', default='4g')
    parser.add_argument('--pids-limit', type=int, default=1024)
    parser.add_argument('--timeout-seconds', type=int, default=1800, help='Per-job ceiling, 60..3600')
    args = parser.parse_args()
    if not 60 <= args.timeout_seconds <= 3600: parser.error('--timeout-seconds must be within 60..3600')
    # Turn SIGTERM into an exception so container cleanup in finally blocks runs.
    signal.signal(signal.SIGTERM, lambda *unused: sys.exit(143))
    try:
        result = run(args.image, args.report, platform=args.platform, timeout=args.timeout_seconds,
                     limits={'cpus': args.cpus, 'memory': args.memory, 'pids': args.pids_limit})
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'fail', 'reason': str(exc)})); return 2
    summary = {k: result[k] for k in ('status', 'image', 'platform', 'versions', 'source_unchanged')}
    summary['jobs'] = [{'command': ' '.join(j['command']), 'exit_code': j['exit_code'], 'seconds': j['seconds'],
                        **({'tests_run': j['tests_run'], 'verdict': j['verdict']} if 'tests_run' in j else {})}
                       for j in result['jobs']]
    print(json.dumps(summary, indent=2)); return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__': sys.exit(main())
