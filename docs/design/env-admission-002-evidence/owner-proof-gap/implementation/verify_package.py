"""Retained offline extracted-package verification; no registry/integration calls."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise ValueError('Select a new report; earlier observations are immutable')
    repository = Path(__file__).resolve().parents[5]
    sys.path[:0] = [str(repository / 'skill/scripts'), str(repository / 'tools')]
    import check_package
    import export_skill
    import verify_release
    require = check_package.require
    source = repository / 'skill'
    original = check_package.check(source)
    inventory = check_package.inventory(source)
    with tempfile.TemporaryDirectory(prefix='owner-proof-package-') as temporary:
        root = Path(temporary).resolve()
        archive = export_skill.build_universal_zip(source, root / 'candidate.zip')
        expected = {'pi-agent-test-env/' + name: value for name, value in inventory.items()
                    if name in original['files']}
        verify_release.extract(archive, root / 'extracted', expected)
        package = root / 'extracted/pi-agent-test-env'
        checked = check_package.check(package)
        before = check_package.inventory(package)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        origin_code = (
            "import sys,json;from pathlib import Path;root=Path(sys.argv[1]);"
            "sys.path.insert(0,str(root/'scripts'));import application_owner_cleanup as m;"
            "assert Path(m.__file__)==root/'scripts/application_owner_cleanup.py';"
            "print(json.dumps({'module_origin':str(Path(m.__file__).relative_to(root))}))")
        commands = []
        def run(argv, timeout=30):
            result = subprocess.run(argv, cwd=root, env=env, text=True,
                                    capture_output=True, timeout=timeout)
            require(result.returncode == 0, 'Offline package verification failed: ' + result.stderr)
            commands.append({'argv': argv, 'exit_code': result.returncode})
            return result
        origin = run([sys.executable, '-I', '-B', '-c', origin_code, str(package)])
        for command in ('application-owner-inspect', 'application-owner-recover'):
            run([sys.executable, '-B', str(package / 'scripts/pi_lab.py'), command, '--help'])
        standard = run([sys.executable, '-B', str(repository / 'tools/validation/validate_standard.py'),
                        str(package), '--self-test'], timeout=120)
        syntax = []
        for name in ('application_owner_cleanup.py', 'application_client.py', 'ownership_registry.py',
                     'pi_lab.py', 'registry_diagnostics.py', 'registry_maintenance.py'):
            ast.parse((source / 'scripts' / name).read_text(), feature_version=(3, 10))
            syntax.append(name)
        require(check_package.inventory(package) == before, 'Extracted package changed')
        require(check_package.check(source)['files'] == original['files'], 'Package source changed')
        data = {'status': 'pass', 'package_files': checked['file_count'], 'manifest_entries': checked['manifest_entries'],
                'module_origin': json.loads(origin.stdout), 'commands': commands,
                'standard_validation': json.loads(standard.stdout), 'python_3_10_syntax_checked': syntax,
                'interpreter': sys.version, 'scope': 'Fresh extracted package; offline help/import/standards only',
                'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                'package_sources_unchanged': True, 'extracted_package_unchanged': True,
                'temporary_extraction_removed': True, 'live_registry_accessed': False,
                'native_qualification': False}
    with args.report.open('x') as output:
        json.dump(data, output, indent=2); output.write('\n')
    print(json.dumps({'status': data['status'], 'package_files': data['package_files'],
                      'offline_commands': len(commands), 'standard_checks': len(data['standard_validation']['checks'])}))


if __name__ == '__main__':
    main()
