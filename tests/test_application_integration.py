"""Synthetic Pi/Docker adapter, real snapshots/deadlines/oracle; no model claim."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import uuid
ROOT=(Path(__file__).resolve().parents[1] / 'skill');EXAMPLE=ROOT/'examples/application-baseline'
sys.path.insert(0,str(ROOT/'scripts'))
import comparisons,experiments,pi_lab as lab,provenance,scoring
spec=importlib.util.spec_from_file_location('integration_configure',EXAMPLE/'configure.py');configure=importlib.util.module_from_spec(spec);spec.loader.exec_module(configure)


class ApplicationIntegrationTests(unittest.TestCase):
    def test_controlled_collection_reset_deadline_scores_assistance_and_report_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);project=base/'project';shutil.copytree(EXAMPLE/'project',project)
            original=(project/'services/api/slug.py').read_text()
            definition=configure.definitions('sha256:'+'a'*64)['baseline.experiment.json']
            for case in definition['cases']:case['project']=str(project)
            path=base/'definition.json';path.write_text(json.dumps(definition))
            endpoint=base/'endpoint.json';endpoint.write_text(json.dumps({'base_url':'http://example.invalid/v1','model':'test-model','api_key_env':'TEST_KEY','context_window':32768,'max_tokens':4096}))
            root=base/'experiment';experiments.prepare(path,root,lab,endpoint)
            observations=[]
            def runner(args,initial_record):
                args.lock_file=str(base/'host.lock')
                def body(a,attempt,smoke):
                    index=len(observations);record=attempt.record
                    workspace=attempt.root/'workspace';lab.snapshot(Path(a.project),workspace,[],10)
                    cwd=workspace/'services/api';observations.append((cwd/'slug.py').read_text())
                    self.assertEqual(observations[-1],original)
                    if index==0:(project/'services/api/slug.py').write_text('external original changed\n')
                    planpath=Path(a.plan);plan=lab.validate_plan(json.loads(planpath.read_text()),planpath.parent)
                    image={'id':a.image,'platform':a.platform,'capabilities':{'pi':'0.87.1'}}
                    record.update(workspace=str(workspace),image=image,fixture_origin='synthetic Pi/Docker adapter; real deadline/snapshot/oracle')
                    record['provenance']=provenance.execution(lab.load_endpoint(Path(a.endpoint)),image,lab.ROOT)
                    record['provenance'].update(snapshot_sha256=provenance.digest(lab.tree_hashes(workspace)),plan_sha256=provenance.digest(plan))
                    record['protected_inputs']['status']='unchanged'
                    if index==3:
                        record['infrastructure']['phase']='setup';raise lab.LabError('Controlled setup failure','synthetic_setup')
                    record['infrastructure'].update(status='ready',phase='agents')
                    record['invocation'].update(status='invalid' if index==1 else 'verified',attempted_stages=1)
                    if index==1:
                        process=lab.stream_run([sys.executable,'-c','import time;time.sleep(0.3)'],attempt.root/'synthetic-agent',0.05,'synthetic-deadline')
                        self.assertTrue(process['timed_out']);self.assertTrue(process['cleanup_confirmed']);record['termination'].update(reason='timeout',process_exit_code=124)
                    else:
                        good="import re\ndef slugify(value):\n if not isinstance(value,str):raise TypeError('string required')\n return re.sub('[^a-z0-9]+','-',value.lower()).strip('-')\n"
                        (cwd/'slug.py').write_text(good.replace('.lower()', '.casefold()') if index==5 else good)
                        helper=ROOT/'runtime/verify-unittest.py'
                        code="import os,runpy,sys;os.chdir(sys.argv[1]);sys.argv=[sys.argv[2],'--start-dir','tests'];runpy.run_path(sys.argv[0],run_name='__main__')"
                        process=lab.stream_run([sys.executable,'-c',code,str(cwd),str(helper)],attempt.root/'synthetic-agent',3,'synthetic-nested-check')
                        self.assertEqual(process['exit_code'],0)
                        record['termination'].update(reason='completed',process_exit_code=0)
                    record['agents']=[{'name':'synthetic-agent','process':process}]
                    if index==4:
                        context={'schema':2,'id':str(uuid.uuid4()),'intervention_id':str(uuid.uuid4()),'run_id':record['run_id'],'attempt_id':record['attempt_id'],'stage_id':str(uuid.uuid4()),'kind':'extend_budget','payload_sha256':'synthetic'}
                        lab.controls.audit(attempt.root,context,'accepted',fixture=True)
                    check=plan['checks'][0];contract=check['scorer'];parent=attempt.root/'scorers';parent.mkdir()
                    receipt=scoring.freeze(contract,parent/'0')
                    oracle=Path(receipt['root'])/'oracle.py'
                    argv=[sys.executable,'-c',"raise RuntimeError('Controlled scorer crash')"] if index==2 else [sys.executable,str(oracle)]
                    code="import os,subprocess,sys;os.chdir(sys.argv[1]);os.environ['PI_LAB_RUN_ID']=sys.argv[2];os.environ['PI_LAB_ATTEMPT_ID']=sys.argv[3];raise SystemExit(subprocess.call(sys.argv[4:]))"
                    scoreprocess=lab.stream_run([sys.executable,'-c',code,str(cwd),record['run_id'],record['attempt_id'],*argv],attempt.root/'independent-oracle',4,'synthetic-scorer')
                    result=scoring.evaluate(contract,receipt,scoreprocess,(attempt.root/'independent-oracle/stdout.jsonl').read_text(),record['run_id'],record['attempt_id'])
                    record['checks']=[{'name':'external-oracle','process':scoreprocess,'scorer':result}]
                    record['scoring'],record['task_result']=scoring.aggregate([result])
                    record['measurement']={'agent_process_seconds':process['elapsed_seconds'],'usage':{'categories':{}},'inference_seconds':None}
                with mock.patch.object(lab,'_execute_suite',side_effect=body):return lab.run_suite(args,initial_record=initial_record)
            result=experiments.execute(root,lab,runner=runner)
            self.assertEqual(result['completed_this_call'],8);self.assertEqual(len(observations),8)
            self.assertTrue(all(x==original for x in observations))
            args=lab.parser().parse_args(['experiment-report','--experiment',str(root)])
            with contextlib.redirect_stdout(io.StringIO()):experiments.command(args,lab)
            report=json.loads((root/'comparison.json').read_text());c=report['counts_totals']
            self.assertEqual({k:c[k] for k in ('planned','started','completed','scorable','eligible','successful','blocked','unscorable')},
                             {'planned':8,'started':8,'completed':8,'scorable':6,'eligible':4,'successful':3,'blocked':1,'unscorable':2})
            self.assertEqual(report['evidence_scope'],'contains_synthetic_fixtures')
            self.assertEqual(sum(g['cohorts']['assisted']['attempts'] for case in report['cases'] for g in case['variants'].values()),1)
            self.assertEqual(len((root/'trials.jsonl').read_text().splitlines()),8)
            self.assertEqual(experiments.execute(root,lab,resume=True,runner=runner)['completed_this_call'],0)
