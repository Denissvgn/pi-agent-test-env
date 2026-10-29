"""Synthetic inputs for acceptance regressions; no production rule registration.

Source text is data. A unit test may explicitly patch the installed catalog with
the reference family's identities to exercise binding predicates. Production
inputs cannot install a rule, and this family does not qualify a real history.
"""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tests.test_application_owner_legacy_fixtures import LegacyFixture
import application_owner_cleanup as cleanup


class AcceptanceFixture(LegacyFixture):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        authority = self.put('authority-observation.json', {
            'schema': 1, 'document_type': 'source_bound_authority_observation',
            'registry': self.record['registry'], 'generation': self.record['generation'],
            'launch_id': self.launch_id, 'binding': self.record['binding'],
            'issued_contexts': [], 'external_authority': 'none_issued',
            'producer': self.refs['controller-driver.py'],
        })
        controller = {'rule_id': 'supervised_controller_v1', 'rule_version': 1, 'originals': {
            'context': self.refs['controller-context.json'],
            'start': self.refs.get('controller-start.json', self.refs.get('worker-start.json')),
            'terminal': self.refs.get('controller-verification.json', self.refs.get('worker-terminal.json')),
            'producer': self.refs['controller-driver.py'], 'supervisor': self.refs['supervisor.py'],
            'source_binding': self.refs['source-bindings.json'], 'inputs': self.refs['emission-inputs.json'],
        }}
        launcher = {'launch_id': self.launch_id, 'rule_id': 'source_bound_launcher_v1',
            'rule_version': 1, 'originals': {
                'start': self.refs.get('launcher-start.json', self.refs.get('worker-start.json')),
                'terminal': self.refs.get('launcher-terminal.json', self.refs.get('worker-terminal.json')),
                'ledger': self.refs['ledger.json'], 'producer': self.refs['controller-driver.py'],
                'emitter': self.refs['emission_source.py'], 'source_binding': self.refs['source-bindings.json'],
                'inputs': self.refs['emission-inputs.json'],
            }}
        variant = self.scope + '_v1'
        witness = self.refs.get('descriptor.json', self.refs.get('diagnostic-terminal.json',
                                                                self.refs['source-bindings.json']))
        self.envelope = {'schema': 1, 'document_type': 'application_owner_legacy_evidence',
            'produced_at': '2026-10-28T00:00:00Z', 'subject': cleanup.subject(self.record),
            'variant': variant, 'cohort': 'application_owner_legacy_1', 'controller': controller,
            'launchers': [launcher], 'root': {'rule_id': variant, 'rule_version': 1,
                                           'originals': {'witness': witness}},
            'namespace': {'rule_id': 'retained_namespace_v1', 'rule_version': 1, 'originals': {
                'authority': authority, 'producer': self.refs['controller-driver.py'],
                'source_binding': self.refs['source-bindings.json']}}, 'unknowns': []}
        self.flush_envelope()

    def flush_envelope(self):
        self.put('legacy-evidence.json', self.envelope)

    def request(self):
        stages = [self.stage_id] if 'descriptor.json' in self.refs else []
        shape = 'interrupted' if self.gap == 'interrupted_worker_only' else 'agent' if stages else 'helper_only'
        return {'schema': 2, 'document_type': 'application_owner_cleanup_request',
            'method': 'legacy_derived_v1', 'subject': cleanup.subject(self.record), 'shape': shape,
            'variant': self.scope + '_v1', 'cohort': 'application_owner_legacy_1',
            'evidence': copy.deepcopy(self.refs['legacy-evidence.json']),
            'stages': stages, 'extra_private_roots': []}

    @staticmethod
    def family():
        """Test-owned semantic identity map; never supplied in a request."""
        # Deliberately fixed reviewed pins: changing fixture source must not
        # silently teach the test consumer to trust the changed semantics.
        return {'d411c5ab4697bf616a9313d72abdd33608b5098d696f72271b02682a3aeba574': {
            'family_id': 'supervised_source_v1',
            'supervisor_sha256': 'a5e68fd3f10bda22858d70c842be22d706244ca6598ba3609b5f784268a07487',
            'emitter_sha256': '0ec48642b6f9158688f4f36adaff50ccbf1491feebf6d06d5adbca6fdb726f6f',
            'variants': ('standard_workspace_v1', 'diagnostic_disposable_v1'),
            'binding_format': 'supervised_source_v1',
        }}

    def body(self, name):
        return json.loads(Path(self.refs[name]['path']).read_bytes())

    def rewrite(self, name, change):
        """Change one semantic premise and update all reference edges, not facts."""
        value = self.body(name); change(value)
        old = copy.deepcopy(self.refs[name]); target = Path(old['path'])
        new = self.put(name, value) if target.parent == self.originals else self.put_retained(name, target, value)
        self._rebind(old, new)

    def rewrite_bytes(self, name, data):
        old = copy.deepcopy(self.refs[name]); target = Path(old['path'])
        if target.parent == self.originals:new = self.put_raw(name, data)
        else:
            mode = target.stat().st_mode & 0o777; target.write_bytes(data); target.chmod(mode)
            new = {'path': str(target), 'sha256': hashlib.sha256(data).hexdigest()}; self.refs[name] = new
        self._rebind(old, new)

    def _rebind(self, old, new):
        replacements = {old['path']: new}
        for unused in range(len(self.refs) * 2):
            changed = False
            for key, ref in list(self.refs.items()):
                target = Path(ref['path'])
                if target.suffix != '.json':continue
                value = json.loads(target.read_bytes())
                def rebind(item):
                    if type(item) is dict:
                        if set(item) == {'path', 'sha256'} and item['path'] in replacements:
                            return copy.deepcopy(replacements[item['path']])
                        return {k: rebind(v) for k, v in item.items()}
                    if type(item) is list:return [rebind(v) for v in item]
                    return item
                updated = rebind(value)
                if updated == value:continue
                if target.parent == self.originals:
                    current = self.put(key, updated)
                else:
                    current = self.put_retained(key, target, updated)
                replacements[current['path']] = current; changed = True
            if not changed:break
        else:raise AssertionError('Synthetic reference graph did not converge')
        self.envelope = self.body('legacy-evidence.json')

    def bytes_snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob('*') if p.is_file()}


class LegacyContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for obj, name in ((subprocess, 'run'), (subprocess, 'Popen'), (os, 'kill')):
            patch = mock.patch.object(obj, name, side_effect=AssertionError('Native action forbidden in pure tests'))
            patch.start(); self.addCleanup(patch.stop)

    def build(self, name='case', **kwargs):
        return AcceptanceFixture(self.root / name, **kwargs)

    def exercise(self, fixture, request=None, *, analyze=False, known_family=True):
        api = importlib.import_module('application_owner_legacy')
        before = fixture.bytes_snapshot()
        method = api.analyze if analyze else api.prepare
        catalog = fixture.family() if known_family else {}
        with mock.patch.dict(api.SOURCE_FAMILIES, catalog, clear=True):
            try:
                return method(request or fixture.request(), fixture.record, fixture.related,
                              reader=cleanup.Reader())
            finally:
                self.assertEqual(fixture.bytes_snapshot(), before, 'Pure validation changed original inputs')

    def reject(self, fixture, request=None, *, known_family=True):
        with self.assertRaises(cleanup.ownership.RegistryError):
            self.exercise(fixture, request, known_family=known_family)

    def claim(self, result, obligation, launch_id=None):
        matches = [c for c in result['claims'] if c['obligation'] == obligation
                   and (launch_id is None or c['value'].get('launch_id') == launch_id)]
        self.assertEqual(len(matches), 1)
        return matches[0]
