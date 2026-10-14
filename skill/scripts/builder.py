"""Run image builds in a dedicated, resource-limited BuildKit container.

Never change the user's selected builder. Never fall back to unconstrained
`docker build`. The builder is parent-controlled infrastructure, not a Pi agent.
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
from resources import memory_bytes
import ownership_registry


def builder_options(name, limits, config_path, image, platform=None):
    return ['docker', 'buildx', 'create', '--name', name, '--driver', 'docker-container',
            *(['--platform',platform] if platform else []),
            '--driver-opt', 'image=' + image,
            '--driver-opt', 'cpu-period=100000',
            '--driver-opt', 'cpu-quota=' + str(int(limits['cpus'] * 100000)),
            '--driver-opt', 'memory=' + limits['memory'],
            '--driver-opt', 'memory-swap=' + limits['memory'],
            '--driver-opt', 'restart-policy=no', '--buildkitd-config', str(config_path)]


def verify_builder(data, limits):
    host = data.get('HostConfig', {})
    if host.get('CpuPeriod') != 100000 or host.get('CpuQuota') != int(limits['cpus'] * 100000):
        raise ValueError('BuildKit CPU quota was not applied; refusing the build')
    if host.get('Memory') != memory_bytes(limits['memory']) or host.get('MemorySwap') != memory_bytes(limits['memory']):
        raise ValueError('BuildKit memory/swap quota was not applied; refusing the build')
    return {'container_id': data['Id'], 'image_id': data['Image'],
            'cpu_period': host['CpuPeriod'], 'cpu_quota': host['CpuQuota'],
            'memory_bytes': host['Memory'], 'memory_swap_bytes': host['MemorySwap']}


def limited_build(args, dockerfile, context, command):
    """command is the host runner's checked subprocess helper; injected for tests."""
    command(['docker', 'buildx', 'version'])
    limits = args.resource_report['effective']['build']
    command(['docker','pull','--platform',args.platform,args.buildkit_image],timeout=300)
    buildkit=json.loads(command(['docker','image','inspect',args.buildkit_image]).stdout)[0]
    if buildkit.get('Os')+'/'+buildkit.get('Architecture')!=args.platform:
        raise ValueError('BuildKit image architecture differs from selected native platform; refusing bootstrap')
    name = 'pi-agentic-build-' + uuid.uuid4().hex[:12]
    registry=ownership_registry.CURRENT.get();registered=None
    if registry is not None:registered=registry.builder_intent(name,buildkit['Id'])
    created = False
    receipt = {'builder_name': name, 'limits': limits,'buildkit_image_id':buildkit['Id'],'platform':args.platform}
    try:
        with tempfile.TemporaryDirectory(prefix='pi-buildkit-') as folder:
            config = Path(folder) / 'buildkitd.toml'
            config.write_text('[worker.oci]\nmax-parallelism = ' + str(limits['max_parallelism']) + '\n')
            create = builder_options(name, limits, config, buildkit["Id"],args.platform)
            command(create, timeout=120)
            created = True
            command(['docker', 'buildx', 'inspect', '--bootstrap', name], timeout=300)
            # Docker-container driver creates node <builder>0. Fail closed if this
            # convention changes instead of running without verified host limits.
            runtime = json.loads(command(['docker', 'inspect', 'buildx_buildkit_' + name + '0']).stdout)[0]
            receipt['observed'] = verify_builder(runtime, limits)
            if registered is not None:
                registered['container_id']=runtime['Id'];registered['status']='running';registry.write(registered)
            argv = ['docker', 'buildx', 'build', '--builder', name, '--load',
                    '--platform', args.platform, '-t', args.image,
                    '--build-arg', 'BASE_IMAGE=' + args.base_image,
                    '--build-arg', 'PI_VERSION=' + args.pi_version,
                    '--build-arg', 'WITH_BROWSER=' + ('1' if args.profile == 'browser' else '0'),
                    '--build-arg', 'EXTRA_APT_PACKAGES=' + ' '.join(args.apt_package),
                    '-f', str(dockerfile), str(context)]
            receipt['argv'] = argv
            print('Building in a CPU/memory-limited BuildKit container; no project or API keys in build context.', file=sys.stderr)
            try:
                result = subprocess.run(argv, stdout=sys.stderr, stderr=sys.stderr,
                                        timeout=limits['timeout_seconds'])
            except subprocess.TimeoutExpired as exc:
                raise ValueError('Image build exceeded its wall-time budget; bounded builder is being removed') from exc
            if result.returncode:
                raise ValueError(f'Image build failed ({result.returncode}); no unrestricted build fallback')
        return receipt
    finally:
        if created:
            result = command(['docker', 'buildx', 'rm', '--force', name], timeout=120, required=False)
            if registered is not None and not result.returncode:
                if not registry.confirm_absent(registered):raise ValueError('Builder absence unconfirmed')
                registry.release(registered,True)
            if result.returncode:
                # Do not leave the build consuming resources merely because rm failed.
                command(['docker', 'stop', 'buildx_buildkit_' + name + '0'], timeout=30, required=False)
                raise ValueError(f'Builder cleanup failed; inspect/remove {name} before another run: {result.stderr.strip()}')
