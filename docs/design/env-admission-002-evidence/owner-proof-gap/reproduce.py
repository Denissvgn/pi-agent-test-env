"""Offline contract observations in temporary registries; no real owner proof.

This retained analysis fixture neither creates a cleanup overlay nor validates
the reported live records. External processes and PID observations are forbidden.
Copy this file and select a new output for any later candidate observation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock
import uuid


def observe(repository):
    sys.path.insert(0, str(repository / 'skill/scripts'))
    import ownership_registry as registry
    import registry_diagnostics as diagnostics
    import stage_control as controls

    observations = []
    with tempfile.TemporaryDirectory(prefix='owner-proof-contract-') as temporary:
        root = Path(temporary).resolve()
        for shape in ('failed_agent', 'helper_only', 'interrupted_agent_without_cid'):
            case = root / shape
            case.mkdir(mode=0o700)
            run = case / 'run'
            run.mkdir(mode=0o700)
            command = mock.Mock(side_effect=AssertionError('External command forbidden'))
            owner = registry.Registry(case / 'registry', command=command)
            argv = ['docker', 'run', '--name', 'pi-fixture-helper',
                    'sha256:' + 'a' * 64, '/opt/pi-lab/worker.py', 'check']
            helper, unused = owner.intent(argv, 'pi-fixture-helper', runroot=run)
            helper.update(application_helper=True, client_mode='application-execution',
                          private_store=str(run / 'application-helpers' / ('a' * 32)),
                          daemon='synthetic-daemon', status='released')
            if shape != 'interrupted_agent_without_cid':
                helper['container_id'] = 'b' * 64
            owner.write(helper)
            if shape != 'helper_only':
                stage_id = str(uuid.uuid4())
                stage = run / 'stages' / stage_id
                stage.mkdir(mode=0o700, parents=True)
                controls.atomic(stage / 'descriptor.json',
                                {'stage_id': stage_id, 'kind': 'agent', 'label': 'agent-1-participant'})
                controls.atomic(stage / 'application-credentials.json',
                                {'schema': 1, 'status': 'cleanup_unconfirmed', 'workspace': 'quarantined'})
                controls.atomic(stage / 'state.json',
                                {'schema': 2, 'status': 'finalized', 'cleanup_confirmed': False})
                output = run / 'agent-1-participant'
                output.mkdir(mode=0o700)
                controls.atomic(output / 'process.json', {'cleanup_confirmed': False})
            retained = {p: p.read_bytes() for p in case.rglob('*') if p.is_file()}
            assert registry._application_stage_pending(run) is True
            assert owner.validate_history([helper]) == []
            pending = {'status': 'intent', 'kind': 'network'}
            try:
                owner.validate_history([helper, pending])
            except registry.RegistryError as error:
                diagnostic = diagnostics.diagnostic(error)
            else:
                raise AssertionError('Pending dependent record incorrectly admitted')
            assert diagnostic['phase'] == 'application_cleanup'
            assert diagnostic['condition'] == 'application_cleanup_pending'
            assert all(p.read_bytes() == body for p, body in retained.items())
            # This tests the release predicate only. It does not attest that
            # this synthetic helper ever existed or was physically cleaned.
            helper['status'] = 'absent'
            owner.release(helper, True)
            assert helper['status'] == 'released'
            assert registry._application_stage_pending(run) is True
            command.assert_not_called()
            observations.append({'shape': shape, 'stage_cleanup_pending': True,
                                 'all_released_history_returns_without_ordinary_check': True,
                                 'pending_dependent_record_diagnostic': diagnostic,
                                 'validation_preserved_retained_bytes': True,
                                 'ordinary_release_accepts_sensitive_clean_boolean': True,
                                 'external_calls': 0})
    return observations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--report-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    bundle = args.report_directory
    manifest = json.loads((bundle / 'manifest.json').read_text())
    hashes = {}
    for name, expected in manifest['files'].items():
        assert name in ('issue.md', 'report.json', 'safe-owner-summary.json', 'physical-observations.json')
        actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        assert actual == expected, name
        hashes[name] = actual
    source_names = ('skill/scripts/ownership_registry.py', 'skill/scripts/application_client.py',
                    'skill/scripts/application_credentials.py', 'skill/scripts/application_execution.py',
                    'tools/qualification/application_diagnostic_cleanup.py',
                    'tools/qualification/application_operational_replay.py',
                    'tools/qualification/application_sdk_admission.py')
    with mock.patch.object(subprocess, 'run', side_effect=AssertionError('External process forbidden')), \
         mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('External process forbidden')), \
         mock.patch('os.kill', side_effect=AssertionError('PID observation forbidden')):
        cases = observe(repository)
    result = {'scope': 'Synthetic temporary-registry contract observation only',
              'python': sys.version, 'report_manifest_verified': hashes,
              'source_sha256': {name: hashlib.sha256((repository / name).read_bytes()).hexdigest()
                                for name in source_names},
              'reproducer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'cases': cases, 'live_registry_accessed': False,
              'downstream_modified': False, 'owner_proof_published': False,
              'native_integration_qualification': False}
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'report_payload_hashes_verified': len(hashes), 'synthetic_cases': len(cases),
                      'output': str(args.output), 'external_calls': 0}))


if __name__ == '__main__':
    main()
