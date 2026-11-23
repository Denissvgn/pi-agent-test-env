"""Run image builds in a dedicated, resource-limited BuildKit container.

Never change the user's selected builder. Never fall back to unconstrained
`docker build`. The builder is parent-controlled infrastructure, not a Pi agent.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid
from resources import memory_bytes
import ownership_registry

DOCKER_DIR = Path(__file__).resolve().parents[1] / 'docker'
PINS_FILE = DOCKER_DIR / 'pins.json'
BUNDLED_DOCKERFILE = DOCKER_DIR / 'Dockerfile'
PIN_FIELDS = ('base_image', 'buildkit_image')
PINNED_REFERENCE = re.compile(r'[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?@(sha256:[0-9a-f]{64})')


def load_pins(path=None):
    """The digest-pinned base and BuildKit references, the only place either is written."""
    path = path or PINS_FILE
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f'Cannot read the image pins {path}: {exc}') from exc
    if not isinstance(data, dict) or set(data) != {'schema', *PIN_FIELDS} or data['schema'] != 1:
        raise ValueError('The image pins must be schema 1 with exactly ' + ' and '.join(PIN_FIELDS))
    for field in PIN_FIELDS:
        if not isinstance(data[field], str) or PINNED_REFERENCE.fullmatch(data[field]) is None:
            raise ValueError(f'The image pin {field} must be name@sha256:digest')
    return {field: data[field] for field in PIN_FIELDS}


def digest_of(reference):
    """The sha256 digest a pinned reference names, or None for a reference without one."""
    match = re.search(r'@(sha256:[0-9a-f]{64})$', reference or '')
    return match.group(1) if match else None


def dockerfile_references(text):
    """Image references of the FROM instructions, exactly as written (stage names are not images)."""
    references = []
    lines = iter(text.splitlines())
    for line in lines:
        statement = line.strip()
        while statement.endswith('\\'):
            statement = statement[:-1].rstrip() + ' ' + next(lines, '').strip()
        words = statement.split()
        if not words or words[0].startswith('#') or words[0].upper() != 'FROM':
            continue
        arguments = [word for word in words[1:] if not word.startswith('--')]
        if arguments:
            references.append(arguments[0])
    return references


BASE_ARGUMENT_USE = re.compile(r'\$\{?BASE_IMAGE(?![A-Za-z0-9_])')


def resolve_base(args, dockerfile):
    """The base the build starts from, and where that knowledge comes from.

    The bundled Dockerfile starts from the pinned reference unless the caller names
    another. A project's own Dockerfile chooses its own FROM lines: its base image is
    never known here (`image` is None, `source` is `dockerfile`) and `references` lists
    its FROM references as written. A `--base-image` given with such a file is still
    forwarded as the BASE_IMAGE build argument, for files that consume it, but it is
    only a supplied `argument`; `argument_in_from` says whether a FROM line uses it.
    """
    explicit = getattr(args, 'base_image', None) or None
    if Path(dockerfile).resolve() == BUNDLED_DOCKERFILE.resolve():
        if explicit:
            return {'image': explicit, 'source': 'argument', 'references': None,
                    'argument': explicit, 'argument_in_from': None}
        return {'image': load_pins()['base_image'], 'source': 'pins', 'references': None,
                'argument': None, 'argument_in_from': None}
    references = dockerfile_references(Path(dockerfile).read_text(errors='replace'))
    return {'image': None, 'source': 'dockerfile', 'references': references, 'argument': explicit,
            'argument_in_from': any(BASE_ARGUMENT_USE.search(item) for item in references) if explicit else None}


def base_build_argument(base):
    """The BASE_IMAGE value forwarded to docker, or None when the build passes none."""
    return base['image'] or base['argument']


def buildkit_reference(args):
    return getattr(args, 'buildkit_image', None) or load_pins()['buildkit_image']


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
    base=resolve_base(args,dockerfile)
    buildkit_image=buildkit_reference(args)
    command(['docker','pull','--platform',args.platform,buildkit_image],timeout=300)
    buildkit=json.loads(command(['docker','image','inspect',buildkit_image]).stdout)[0]
    if buildkit.get('Os')+'/'+buildkit.get('Architecture')!=args.platform:
        raise ValueError('BuildKit image architecture differs from selected native platform; refusing bootstrap')
    name = 'pi-agentic-build-' + uuid.uuid4().hex[:12]
    registry=ownership_registry.CURRENT.get();registered=None
    if registry is not None:registered=registry.builder_intent(name,buildkit['Id'])
    created = False
    receipt = {'builder_name': name, 'limits': limits,'buildkit_image_id':buildkit['Id'],'platform':args.platform,
               'buildkit':{'image':buildkit_image,'digest':digest_of(buildkit_image),
                           'id':buildkit['Id'],'repo_digests':buildkit.get('RepoDigests') or []}}
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
                    *(['--build-arg', 'BASE_IMAGE=' + base_build_argument(base)] if base_build_argument(base) else []),
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
