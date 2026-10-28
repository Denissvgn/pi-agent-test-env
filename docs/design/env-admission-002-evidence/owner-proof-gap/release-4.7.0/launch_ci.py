"""Launch one bounded native ARM64 CI container with fresh private Docker storage."""
import json
from pathlib import Path
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = Path(__file__).resolve().parent
BASE = 'sha256:71d15ec40d8b1151ec7ff8b767fab90e60ab278d6af8aa249f8c0e0c21606ee0'


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def main():
    attempt = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    if not 1 <= attempt <= 10:raise ValueError('Invalid CI attempt')
    seed = (ROOT / 'dist/pi-owner-proof-4.7.0-ci' / ('seed-attempt-' + str(attempt))).resolve()
    result_root = ROOT / 'dist/pi-owner-proof-4.7.0-ci' / ('attempt-' + str(attempt))
    result_root.mkdir(parents=True, exist_ok=False)
    images = json.loads(docker('image', 'inspect', BASE, 'pi-owner-proof-ci:arm64-4.7.0'))
    base, image = images
    if any(v['Os'] != 'linux' or v['Architecture'] != 'arm64' for v in images):
        raise ValueError('Native Linux ARM64 image required')
    if image['Config'].get('User') != 'node' or image['Config'].get('Volumes'):
        raise ValueError('Non-root image without baked volumes required')
    if image['RootFS']['Layers'][:len(base['RootFS']['Layers'])] != base['RootFS']['Layers']:
        raise ValueError('CI derivative does not match the inspected package-owned base')
    identity = {'image_id': image['Id'], 'base_id': base['Id'], 'architecture': image['Architecture'],
                'os': image['Os'], 'user': image['Config']['User'], 'base_layers_match': True,
                'environment_names': [s.split('=', 1)[0] for s in image['Config'].get('Env', [])]}
    (EVIDENCE / 'ci-image.json').write_text(json.dumps(identity, indent=2) + '\n')
    token = uuid.uuid4().hex[:10]
    name = 'pi-owner-proof-ci-470-' + token
    volume = name + '-home'
    docker('volume', 'create', '--label', 'org.openai.codex.purpose=owner-proof-ci', volume)
    argv = ['create', '--name', name, '--platform', 'linux/arm64', '--network', 'none', '--read-only',
            '--init', '--user', '1000:1000', '--cap-drop=ALL', '--security-opt', 'no-new-privileges=true',
            '--cpus', '2', '--memory', '4g', '--memory-swap', '4g', '--pids-limit', '1024',
            '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=2147483648,mode=1777',
            '--mount', 'type=volume,src=' + volume + ',dst=/home/node',
            '--mount', 'type=bind,src=' + str(seed) + ',dst=/ci-seed,readonly',
            '--env', 'HOME=/home/node/ci-home', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--env', 'PYTHONNOUSERSITE=1', '--workdir', '/home/node', '--entrypoint', 'python3',
            image['Id'], '-B', '/ci-seed/run_ci.py']
    container = docker(*argv)
    spec = json.loads(docker('container', 'inspect', container))[0]
    record = {'container': container, 'name': name, 'volume': volume, 'create_argv': ['docker', *argv],
              'image_id': image['Id'], 'readonly_rootfs': spec['HostConfig']['ReadonlyRootfs'],
              'network_mode': spec['HostConfig']['NetworkMode'], 'memory': spec['HostConfig']['Memory'],
              'memory_swap': spec['HostConfig']['MemorySwap'], 'nano_cpus': spec['HostConfig']['NanoCpus'],
              'pids_limit': spec['HostConfig']['PidsLimit'], 'mounts': spec['Mounts'], 'candidate':json.loads((seed/'candidate-input.json').read_text())['candidate_commit']}
    (EVIDENCE / 'ci-container.json').write_text(json.dumps(record, indent=2) + '\n')
    (result_root / 'container.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'container': name, 'platform': 'linux/arm64', 'image_id': image['Id'],
                      'cpus': 2, 'memory': '4g', 'pids': 1024, 'network': 'none'}), flush=True)
    with (result_root / 'attach.stdout').open('x') as out, (result_root / 'attach.stderr').open('x') as err:
        try:
            result = subprocess.run(['docker', 'start', '--attach', name], stdout=out, stderr=err, timeout=2400)
            attached_code = result.returncode
        except subprocess.TimeoutExpired:
            docker('stop', '--time', '10', name); attached_code = 124
    state = json.loads(docker('container', 'inspect', name))[0]['State']
    (result_root / 'container-state.json').write_text(json.dumps(state, indent=2) + '\n')
    copied = subprocess.run(['docker', 'cp', name + ':/home/node/ci-work/reports', str(result_root / 'reports')],
                            capture_output=True, text=True, timeout=60)
    summary = {'attached_exit_code': attached_code, 'container_exit_code': state['ExitCode'],
               'oom_killed': state['OOMKilled'], 'reports_copy_exit_code': copied.returncode,
               'name': name, 'volume': volume, 'result_root': str(result_root)}
    (result_root / 'launch-result.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    # Explicit cleanup after evidence has been copied, targeting only this job.
    if copied.returncode == 0:
        docker('rm', name); docker('volume', 'rm', volume)
    return 0 if attached_code == state['ExitCode'] == copied.returncode == 0 and not state['OOMKilled'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
