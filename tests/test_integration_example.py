"""Profile experiment/assets/oracle fixtures; no real Pi/model qualification."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=(Path(__file__).resolve().parents[1] / 'skill');EXAMPLE=ROOT/'examples/integration-baseline'
sys.path.insert(0,str(ROOT/'scripts'))
import agent_profiles,comparisons,experiments,pi_lab as lab
spec=importlib.util.spec_from_file_location('integration_example_configure',EXAMPLE/'configure.py');configure=importlib.util.module_from_spec(spec);spec.loader.exec_module(configure)


class IntegrationExampleTests(unittest.TestCase):
    def test_four_cell_profiles_share_case_data_oracle_source_and_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);endpoint=root/'endpoint.json';endpoint.write_text(json.dumps({'base_url':'http://example.invalid/v1','model':'synthetic-model','context_window':32768,'max_tokens':4096,'api_key_env':'TEST_KEY'}))
            path=root/'definition.json';path.write_text(json.dumps(configure.definition('sha256:'+'a'*64)))
            d=experiments.validate(path,lab,endpoint);self.assertEqual([v['agent_profile']['id'] for v in d['variants']],['builtin','fixture-lookup'])
            table=json.loads((ROOT/'assets/profiles/fixture-lookup/fixtures.json').read_text())
            self.assertEqual(table,json.loads((EXAMPLE/'project/fixtures.json').read_text()));self.assertEqual(table,json.loads((EXAMPLE/'expected.json').read_text()))
            experiments.prepare(path,root/'experiment',lab,endpoint);metadata,matrix=experiments.verify(root/'experiment',lab)
            self.assertEqual(metadata['profile'],'explicit-agent-profiles');self.assertEqual(len(matrix['cells']),4)
            for cell in matrix['cells']:
                profile=agent_profiles.load(root/'experiment'/cell['agent_profile']);p=root/'experiment'/cell['plan']
                plan=lab.validate_plan(json.loads(p.read_text()),p.parent,profile)
                self.assertEqual('fixture_lookup' in plan['agents'][0]['tools'],cell['variant']=='fixture')
                self.assertEqual('fixture_lookup' in plan['agents'][0]['require_tools'],cell['variant']=='fixture')
                self.assertEqual(cell['scorer_identity'],matrix['cells'][0]['scorer_identity']);self.assertEqual(cell['budgets'],matrix['cells'][0]['budgets'])
            builtin=next(c for c in matrix['cells'] if c['variant']=='builtin');fixture=next(c for c in matrix['cells'] if c['variant']=='fixture')
            self.assertNotEqual(builtin['configuration_digest'],fixture['configuration_digest']);self.assertNotEqual(builtin['agent_profile_sha256'],fixture['agent_profile_sha256'])
            asset=root/'experiment/inputs/profiles/fixture/fixtures.json';asset.chmod(0o600);asset.write_text('{}')
            with self.assertRaisesRegex(ValueError,'changed'):experiments.verify(root/'experiment',lab)

    def test_real_local_artifact_oracle_correct_wrong_missing_extra_fields(self):
        expected=json.loads((EXAMPLE/'expected.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);env={'PATH':os.environ.get('PATH',''),'PI_LAB_RUN_ID':'synthetic','PI_LAB_ATTEMPT_ID':'synthetic'}
            for value,success in [(expected,True),({**expected,'extra':1},False),({'alpha':{}},False),(None,False)]:
                path=root/'answer.json'
                if value is None:path.unlink(missing_ok=True)
                else:path.write_text(json.dumps(value))
                result=subprocess.run([sys.executable,str(EXAMPLE/'oracle.py')],cwd=root,env=env,text=True,capture_output=True,timeout=3)
                self.assertEqual(result.returncode,0);data=json.loads(result.stdout)
                self.assertEqual(data['task_status']=='pass',success);self.assertEqual(data['test_counts']['discovered'],4)

    def test_requested_profile_without_observed_use_excludes_primary_eligibility(self):
        from test_comparisons import record,expected
        e=expected();e.update(profile_explicit=True,agent_profile_id='fixture-lookup',agent_profile_sha256='profile')
        r=record();r['provenance']['agent_profile']={'sha256':'profile'}
        r['agent_profile']={'observed_stages':[{'segments':[{'loading':'observed','use':'unverified'}]}]}
        self.assertTrue(comparisons.assessment(r,e,'declared')['scorable']);self.assertFalse(comparisons.assessment(r,e,'declared')['eligible'])
        r['agent_profile']['observed_stages'][0]['segments'][0]['use']='observed'
        self.assertTrue(comparisons.assessment(r,e,'declared')['eligible'])
