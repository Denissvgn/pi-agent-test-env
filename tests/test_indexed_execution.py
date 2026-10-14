"""Real CLI negative admission, before Docker/endpoint work or child dispatch."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import indexed_execution
import parallel_dispatch
import os


class AdmissionTests(unittest.TestCase):
    def test_selected_unconventional_key_name_is_absent_in_a_real_host_child(self):
        with patch.dict(os.environ,{'SYNTHETIC_REFERENCE':'synthetic-private-value','PI_APP_PERSONA':'synthetic-actor-value'}):
            env=parallel_dispatch.worker_environment({'secret_variable_names':['SYNTHETIC_REFERENCE']})
            script="import os,json;print(json.dumps({k:k in os.environ for k in ['SYNTHETIC_REFERENCE','PI_APP_PERSONA']}))"
            reply=subprocess.run([sys.executable,'-c',script],env=env,text=True,capture_output=True,timeout=5)
            self.assertEqual(json.loads(reply.stdout),{'SYNTHETIC_REFERENCE':False,'PI_APP_PERSONA':False})
    def test_every_selected_key_is_admitted_and_checked_against_application_keys(self):
        first={'incarnation':'first','configuration':{'endpoint':{'model':'fixture-one'}}}
        second={'incarnation':'second','configuration':{'endpoint':{'model':'fixture-two'}}}
        class Catalog:
            store='synthetic-store'
            def admit(self,binding,session):return 'synthetic-'+binding['incarnation']+'-key'
        class Lab:ROOT=Path('/synthetic-runtime')
        with patch.object(indexed_execution.application_credentials,'resolve',return_value={}) as checked:
            entries,keys,assigned=indexed_execution.resolve(Catalog(),{'stage-a':first,'stage-b':second},'fixture',{'agents':[]},'/synthetic-project','/synthetic-run',Lab())
        self.assertEqual(set(keys),{'first','second'});self.assertEqual(checked.call_count,2)
        self.assertEqual({call.args[2] for call in checked.call_args_list},{'synthetic-first-key','synthetic-second-key'})
    def test_unknown_profile_seals_blocked_without_dispatch(self):
        repo=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            command=[sys.executable,str(repo/'skill/scripts/pi_lab.py'),'smoke','--inference-env','unknown',
                '--session','synthetic-session','--catalog-dir',str(root/'catalog'),'--results-dir',str(root/'runs'),
                '--lock-file',str(root/'operation.lock'),'--platform','linux/arm64']
            reply=subprocess.run(command,text=True,capture_output=True,timeout=10)
            self.assertEqual(reply.returncode,2,reply.stderr)
            value=json.loads(reply.stdout);self.assertEqual(value['status'],'BLOCKED')
            self.assertEqual(value['infrastructure']['reason'],'environment-not-found')
            self.assertEqual(value['invocation']['attempted_stages'],0)
            self.assertTrue(value['sealed']);self.assertFalse(list((root/'runs').rglob('segments/*.json')))

    def test_other_selected_key_in_model_metadata_rejects_before_application_or_dispatch(self):
        first={'incarnation':'first','configuration':{'endpoint':{'model':'synthetic-second-key'}}}
        second={'incarnation':'second','configuration':{'endpoint':{'model':'fixture-two'}}}
        class Catalog:
            store='synthetic-store'
            def admit(self,binding,session):return 'synthetic-'+binding['incarnation']+'-key'
        class Lab:ROOT=Path('/synthetic-runtime')
        with patch.object(indexed_execution.application_credentials,'resolve',side_effect=AssertionError('No dependent work')):
            with self.assertRaises(ValueError):indexed_execution.resolve(Catalog(),{'one':first,'two':second},'fixture',{'agents':[]},'/synthetic-project','/synthetic-run',Lab())


if __name__=='__main__':unittest.main()
