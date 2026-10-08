"""Frozen pair ownership and legacy archive regressions; offline fixtures only."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest import mock

import test_experiments as fixtures
import agent_profiles
import experiments
import pi_lab as lab
import provenance


class PlanIdentityTests(fixtures.ExperimentFixture):
    def setUp(self):
        super().setUp()
        self.root = self.root.resolve()
        self.plan['agents'][0]['prompt'] = 'First case instructions.'
        self.plan['checks'][0]['scorer']['assets'][0]['target'] = 'nested/oracle.py'
        self.plan['checks'][0]['argv'] = ['python3', '/opt/pi-scorer/nested/oracle.py']
        other = copy.deepcopy(self.plan)
        other['agents'][0]['prompt'] = 'Second case instructions.'
        other['checks'][0]['scorer']['id'] = 'second-oracle'
        other['checks'][0]['scorer']['assets'][0]['source'] = 'other-scorer.py'
        self.write('plan.json', self.plan)
        self.write('other-plan.json', other)
        (self.root / 'other-scorer.py').write_text('second independent oracle\n')
        self.write('candidate-endpoint.json', {**self.endpoint, 'model': 'candidate-model'})
        shutil.copytree(fixtures.ROOT / 'assets/profiles/fixture-lookup', self.root / 'profile')
        self.definition['cases'].append({'name': 'case--x', 'project': 'project', 'plan': 'other-plan.json',
            'budgets': {'timeout_seconds': 6, 'max_turns': 5, 'max_total_tokens': 20000}})
        self.definition['variants'][1] = {'name': 'x--baseline', 'prompt_suffix': 'Candidate instruction ✓.',
            'endpoint': 'candidate-endpoint.json', 'agent_profile': 'profile/profile.json'}
        self.definition['repetitions'] = 2
        self.write('experiment.json', self.definition)

    def reseal(self, root):
        files = {'inputs/' + p: h for p, h in lab.tree_hashes(root / 'inputs', include_ignored=True).items()}
        for name in ('experiment.json', 'matrix.json'):
            files[name] = lab.tree_hashes(root / name, include_ignored=True)['.']
        lab.save(root / 'integrity.json', {'schema': 1, 'files': files, 'fingerprint': provenance.digest(files)})

    def frozen_bytes(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*')
                if p.is_file() and (p.is_relative_to(root / 'inputs') or p.name in
                                    ('integrity.json', 'experiment.json', 'matrix.json'))}

    def legacy(self, root, ambiguous=False):
        matrix = json.loads((root / 'matrix.json').read_text())
        plans = {c['plan']: (root / c['plan']).read_bytes() for c in matrix['cells']}
        for path in plans: (root / path).unlink()
        for cell in matrix['cells']:
            dest = 'inputs/plans/' + cell['case'] + '--' + cell['variant'] + '.json'
            lab.save(root / dest, json.loads(plans[cell['plan']]))
            cell['plan'] = dest
        lab.save(root / 'matrix.json', matrix)
        self.reseal(root)
        if ambiguous:
            self.assertLess(len({c['plan'] for c in matrix['cells']}), 4)

    def test_four_pairs_preserve_independently_specified_contract_and_repetitions(self):
        # The user-plan feature remains supported at preparation, but frozen
        # verification must never need to read the original prompt file again.
        prompt = self.root / 'case-prompt.txt'
        prompt.write_text(self.plan['agents'][0].pop('prompt'))
        self.plan['agents'][0]['prompt_file'] = 'case-prompt.txt'
        self.write('plan.json', self.plan)
        self.prepare()
        prompt.unlink()
        root = self.root / 'prepared'
        metadata, matrix = experiments.verify(root, lab)
        self.assertEqual(len(matrix['cells']), 8)
        self.assertEqual(len({c['plan'] for c in matrix['cells']}), 4)
        prompts = {
            ('case', 'baseline'): 'First case instructions.',
            ('case', 'x--baseline'): 'First case instructions.\n\nDeclared variant instruction:\nCandidate instruction ✓.',
            ('case--x', 'baseline'): 'Second case instructions.',
            ('case--x', 'x--baseline'): 'Second case instructions.\n\nDeclared variant instruction:\nCandidate instruction ✓.',
        }
        paths = {}
        for cell in matrix['cells']:
            pair = (cell['case'], cell['variant'])
            path = root / cell['plan']
            plan = json.loads(path.read_text())
            self.assertEqual(plan['agents'][0]['prompt'], prompts[pair])
            expected_uuid = uuid.uuid5(uuid.UUID(metadata['experiment_id']),
                'plan:' + json.dumps(list(pair), ensure_ascii=False, separators=(',', ':')))
            self.assertEqual(cell['plan'], f'inputs/plans/{expected_uuid}.json')
            self.assertEqual(paths.setdefault(pair, cell['plan']), cell['plan'])
            second = cell['case'] == 'case--x'
            expected_budget = {'timeout_seconds': 6 if second else 4,
                               'max_turns': 5 if second else 3, 'max_total_tokens': 20000 if second else 10000}
            self.assertEqual(cell['budgets'], expected_budget)
            for key, value in expected_budget.items(): self.assertEqual(plan['agents'][0][key], value)
            candidate = cell['variant'] == 'x--baseline'
            endpoint = json.loads((root / cell['endpoint']).read_text())
            self.assertEqual(endpoint['model'], 'candidate-model' if candidate else 'fixture-model')
            self.assertEqual(cell['agent_profile_id'], 'fixture-lookup' if candidate else 'builtin')
            profile = agent_profiles.load(root / cell['agent_profile'])
            self.assertEqual('fixture_lookup' in plan['agents'][0]['tools'], candidate)
            self.assertEqual('fixture_lookup' in plan['agents'][0]['require_tools'], candidate)
            scorer = plan['checks'][0]['scorer']
            self.assertEqual(scorer['id'], 'second-oracle' if second else 'fixture')
            self.assertEqual(plan['checks'][0]['argv'], ['python3', '/opt/pi-scorer/nested/oracle.py'])
            self.assertEqual(scorer['required_assertions'], ['value'])
            self.assertEqual(scorer['score_domain'], {'min': 0, 'max': 1, 'direction': 'higher', 'pass_threshold': 1})
            self.assertEqual(scorer['assets'], [{'source': f'../scorers/{cell["case"]}/0/nested/oracle.py',
                                               'target': 'nested/oracle.py'}])
            body = (path.parent / scorer['assets'][0]['source']).read_bytes()
            self.assertEqual(body, b'second independent oracle\n' if second else b'print("synthetic schema fixture only")\n')
            normalized = lab.validate_plan(plan, path.parent, profile)
            self.assertEqual(cell['plan_sha256'], provenance.digest(normalized))
            # Reconstruct the complete configuration from independently asserted
            # contents; never use the production plan filename helper.
            contract = copy.deepcopy(normalized['checks'][0]['scorer'])
            contract['assets'] = [{'target': 'nested/oracle.py', 'sha256': hashlib.sha256(body).hexdigest()}]
            oracle = [{'contract': contract, 'argv': ['python3', '/opt/pi-scorer/nested/oracle.py'],
                       'cwd': '.', 'network': 'none'}]
            configuration = {'source': metadata['source_receipts'][cell['case']], 'scorer': oracle,
                'endpoint': {k: v for k, v in endpoint.items() if k != 'api_key_env'}, 'plan': plan,
                'execution': {**metadata['execution'], 'resources': json.loads((root / 'inputs/resources.json').read_text())},
                'budgets': expected_budget, 'profile_sha256': agent_profiles.identity(profile),
                'runner_content_sha256': metadata['runner_content_sha256']}
            self.assertEqual(cell['scorer_identity'], provenance.digest(oracle))
            self.assertEqual(cell['configuration_digest'], provenance.digest(configuration))

    def test_injected_uuid_collision_rejects_before_plan_or_snapshot_writes(self):
        before = lab.tree_hashes(self.root, include_ignored=True)
        with mock.patch.object(experiments.uuid, 'uuid5', return_value=uuid.UUID(int=1)), \
             mock.patch.object(experiments.controls, 'atomic', wraps=experiments.controls.atomic) as writes, \
             mock.patch.object(lab, 'snapshot', wraps=lab.snapshot) as snapshots:
            with self.assertRaisesRegex(experiments.ExperimentError, 'collision'):
                self.prepare()
            writes.assert_not_called(); snapshots.assert_not_called()
        self.assertFalse((self.root / 'prepared').exists())
        self.assertEqual(before, lab.tree_hashes(self.root, include_ignored=True))
        self.assertEqual(list(self.root.glob('.experiment-prepare-*')), [])

    def test_rehashed_alias_repetition_missing_escape_and_hash_mismatch_reject(self):
        for fault in ('cross-pair', 'repetition', 'missing', 'escape', 'wrong-uuid', 'plan-hash', 'external-prompt'):
            with self.subTest(fault=fault):
                self.prepare(fault)
                root = self.root / fault
                matrix = json.loads((root / 'matrix.json').read_text()); cells = matrix['cells']
                if fault == 'cross-pair': cells[2]['plan'] = cells[0]['plan']
                elif fault == 'repetition':
                    other = 'inputs/plans/case--baseline.json'
                    if cells[0]['plan'] == other:
                        expected = uuid.uuid5(uuid.UUID(matrix['experiment_id']), 'plan:["case","baseline"]')
                        other = f'inputs/plans/{expected}.json'
                    shutil.copyfile(root / cells[0]['plan'], root / other)
                    cells[1]['plan'] = other
                elif fault == 'missing': (root / cells[0]['plan']).unlink()
                elif fault == 'escape': cells[0]['plan'] = '../plan.json'
                elif fault == 'wrong-uuid':
                    other = 'inputs/plans/' + str(uuid.uuid4()) + '.json'
                    shutil.copyfile(root / cells[0]['plan'], root / other)
                    cells[0]['plan'] = other
                elif fault == 'external-prompt':
                    plan = json.loads((root / cells[0]['plan']).read_text())
                    outside = self.root / 'outside-prompt.txt'
                    outside.write_text(plan['agents'][0].pop('prompt'))
                    plan['agents'][0]['prompt_file'] = str(outside)
                    lab.save(root / cells[0]['plan'], plan)
                else: cells[0]['plan_sha256'] = '0' * 64
                lab.save(root / 'matrix.json', matrix); self.reseal(root)
                before = self.frozen_bytes(root)
                if fault == 'external-prompt':
                    # Frozen plans always contain inline prompts. Normalizing an
                    # archive must never read a user-plan prompt_file on the host.
                    with mock.patch.object(lab.Path, 'read_text', side_effect=AssertionError('External prompt read attempted')) as reads:
                        with self.assertRaises(experiments.ExperimentError): experiments.verify(root, lab)
                        reads.assert_not_called()
                else:
                    with self.assertRaises((experiments.ExperimentError, lab.LabError)):
                        experiments.verify(root, lab)
                self.assertEqual(before, self.frozen_bytes(root))

    def test_maximum_slug_lengths_and_consecutive_hyphens_keep_specified_identity(self):
        self.definition['cases'][0]['name'] = 'a' + '-' * 63
        self.definition['cases'][1]['name'] = 'b' + '-' * 63
        self.definition['variants'][0]['name'] = 'c' + '-' * 63
        self.definition['variants'][1]['name'] = 'd' + '-' * 63
        self.definition['baseline'] = 'c' + '-' * 63
        self.write('experiment.json', self.definition); self.prepare()
        metadata, matrix = experiments.verify(self.root / 'prepared', lab)
        for cell in matrix['cells']:
            pair = [cell['case'], cell['variant']]
            expected = uuid.uuid5(uuid.UUID(metadata['experiment_id']), 'plan:' + json.dumps(pair, ensure_ascii=False, separators=(',', ':')))
            self.assertEqual(Path(cell['plan']).name, str(expected) + '.json')
            self.assertEqual(len(Path(cell['plan']).parts), 3)

    def test_failed_freezing_keeps_sources_oracles_and_destination_unpublished(self):
        before = lab.tree_hashes(self.root, include_ignored=True)
        original = experiments.scoring.freeze
        def failure(contract, path):
            original(contract, path)
            raise experiments.ExperimentError('injected failure after scorer copy')
        with mock.patch.object(experiments.scoring, 'freeze', side_effect=failure), self.assertRaises(experiments.ExperimentError):
            self.prepare()
        self.assertFalse((self.root / 'prepared').exists())
        self.assertEqual(list(self.root.glob('.experiment-prepare-*')), [])
        self.assertEqual(before, lab.tree_hashes(self.root, include_ignored=True))

    def test_unambiguous_legacy_archive_report_export_preserve_frozen_bytes(self):
        self.definition['cases'][1]['name'] = 'second'
        self.definition['variants'][1]['name'] = 'candidate'
        self.write('experiment.json', self.definition); self.prepare()
        root = self.root / 'prepared'; self.legacy(root)
        archive = self.root / 'extracted'; shutil.copytree(root, archive)
        # The original preparation path need not exist for archived inspection.
        shutil.rmtree(root)
        before = self.frozen_bytes(archive)
        experiments.verify(archive, lab)
        args = lab.parser().parse_args(['experiment-report', '--experiment', str(archive)])
        with contextlib.redirect_stdout(io.StringIO()): experiments.command(args, lab)
        first = {p: (archive / p).read_bytes() for p in ('trials.jsonl', 'comparison.json', 'comparison.md')}
        with contextlib.redirect_stdout(io.StringIO()): experiments.command(args, lab)
        self.assertEqual(first, {p: (archive / p).read_bytes() for p in first})
        self.assertEqual(before, self.frozen_bytes(archive))
        self.assertEqual(experiments.export_ledger(archive, lab)['cells'], 8)
        with self.assertRaisesRegex(experiments.ExperimentError, 'directory moved'):
            experiments.execute(archive, lab, resume=True, runner=mock.Mock())

    def test_ambiguous_legacy_archive_rejects_even_with_matching_integrity(self):
        self.prepare(); root = self.root / 'prepared'; self.legacy(root, ambiguous=True)
        before = self.frozen_bytes(root)
        with self.assertRaisesRegex(experiments.ExperimentError, 'alias'):
            experiments.verify(root, lab)
        self.assertEqual(before, self.frozen_bytes(root))

    def test_changed_runner_remains_a_strict_execution_gate(self):
        self.prepare(); root = self.root / 'prepared'
        original = experiments.provenance.execution
        def changed(*args, **kwargs):
            result = original(*args, **kwargs); result['runner_content_sha256'] = '0' * 64; return result
        with mock.patch.object(experiments.provenance, 'execution', side_effect=changed), \
             mock.patch.object(experiments, 'reserve_attempt') as reserve:
            with self.assertRaisesRegex(experiments.ExperimentError, 'Runner content changed'):
                experiments.execute(root, lab, resume=True, runner=mock.Mock())
            reserve.assert_not_called()


if __name__ == '__main__':
    unittest.main()
