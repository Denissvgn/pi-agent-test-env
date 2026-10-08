"""Real local oracle and example inputs; no Docker/model-performance qualification."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=(Path(__file__).resolve().parents[1] / 'skill');EXAMPLE=ROOT/'examples/application-baseline'
sys.path.insert(0,str(ROOT/'scripts'))
import experiments
import pi_lab as lab
spec=importlib.util.spec_from_file_location('application_configure',EXAMPLE/'configure.py');configure=importlib.util.module_from_spec(spec);spec.loader.exec_module(configure)


class ApplicationExampleTests(unittest.TestCase):
    def test_complete_example_matrix_external_oracle_and_declared_variant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            endpoint=root/'endpoint.json';endpoint.write_text(json.dumps({'base_url':'http://example.invalid/v1','model':'synthetic-example','api_key_env':'TEST_KEY','context_window':32768,'max_tokens':4096}))
            definition=root/'definition.json';definition.write_text(json.dumps(configure.definitions('sha256:'+'a'*64)['baseline.experiment.json']))
            value=experiments.validate(definition,lab,endpoint)
            self.assertEqual(value['variants'][0]['prompt_suffix'],'');self.assertTrue(value['variants'][1]['prompt_suffix'])
            self.assertEqual(value['repetitions'],2);self.assertEqual(len(value['cases']),2)
            self.assertEqual(value['cases'][0]['scorer'],value['cases'][1]['scorer'])
            experiments.prepare(definition,root/'experiment',lab,endpoint)
            metadata,matrix=experiments.verify(root/'experiment',lab);self.assertEqual(len(matrix['cells']),8)
            for cell in matrix['cells']:
                path=root/'experiment'/cell['plan'];plan=lab.validate_plan(json.loads(path.read_text()),path.parent)
                self.assertTrue(all(Path(x['source']).resolve().is_relative_to((root/'experiment/inputs/scorers').resolve()) for x in plan['checks'][0]['scorer']['assets']))
                self.assertEqual(plan['agents'][0]['timeout_seconds'],5 if cell['case']=='cutoff' else 120)
                self.assertEqual(cell['scorer_identity'],matrix['cells'][0]['scorer_identity'])

    def run_oracle(self,implementation):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'slug.py').write_text(implementation)
            env={'PATH':os.environ.get('PATH',''),'PI_LAB_RUN_ID':'synthetic-run','PI_LAB_ATTEMPT_ID':'synthetic-attempt','PYTHONDONTWRITEBYTECODE':'1'}
            result=subprocess.run([sys.executable,str(EXAMPLE/'oracle.py')],cwd=root,env=env,text=True,capture_output=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)

    def test_oracle_measures_correctness_and_fails_unimplemented_or_casefold_bug(self):
        good="import re\ndef slugify(value):\n if not isinstance(value,str):raise TypeError('string required')\n return re.sub('[^a-z0-9]+','-',value.lower()).strip('-')\n"
        result=self.run_oracle(good);self.assertEqual(result['score'],1)
        self.assertEqual(result['test_counts'],{'discovered':8,'passed':8,'failed':0,'skipped':0})
        stub=self.run_oracle((EXAMPLE/'project/services/api/slug.py').read_text());self.assertEqual(stub['score'],0);self.assertEqual(stub['task_status'],'fail')
        buggy=self.run_oracle(good.replace('.lower()', '.casefold()'))
        self.assertEqual(buggy['score'],7/8);self.assertEqual(buggy['task_status'],'fail')
        self.assertFalse(next(x['passed'] for x in buggy['assertions'] if x['id']=='unicode-lower'))
        poison="import json\njson.loads=lambda body:[{'id':x} for x in ('words','runs-edges','empty','ascii-digits','unicode-lower','types','idempotent','separators')]\ndef slugify(value):\n if not isinstance(value,str):raise TypeError()\n return 'wrong'\n"
        self.assertLess(self.run_oracle(poison)['score'],1)

    def test_configuration_requires_exact_reviewed_receipt_and_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);receipt=root/'receipt.json';output=root/'definitions'
            receipt.write_text(json.dumps({'id':'sha256:'+'a'*64,'platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}))
            argv=[sys.executable,str(EXAMPLE/'configure.py'),'--image-receipt',str(receipt),'--output-dir',str(output)]
            result=subprocess.run(argv,text=True,capture_output=True,timeout=8);self.assertEqual(result.returncode,0,result.stderr)
            old=(output/'baseline.experiment.json').read_bytes()
            self.assertNotEqual(subprocess.run(argv,capture_output=True,timeout=8).returncode,0)
            self.assertEqual((output/'baseline.experiment.json').read_bytes(),old)
            for platform,version in [('linux/amd64','0.87.1'),('linux/arm64','1.0.2')]:
                receipt.write_text(json.dumps({'id':'sha256:'+'a'*64,'platform':platform,'capabilities':{'pi':version}}))
                args=[*argv[:-1],str(root/'unsupported')]
                self.assertNotEqual(subprocess.run(args,capture_output=True,timeout=8).returncode,0)
