"""Hand-computed projections, explicitly synthetic; never model-performance evidence."""
import copy
from pathlib import Path
import sys
import unittest
ROOT=(Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0,str(ROOT/'scripts'))
import comparisons


def expected():
    return {'scorer':{'scorer_id':'oracle','scorer_version':'1','scorer_sha256':'oracle-code','score_domain':{'min':0,'max':1,'direction':'higher','pass_threshold':1}},
            'endpoint_sha256':'endpoint','snapshot_sha256':'source','plan_sha256':'plan','runner_content_sha256':'runner','image':'image','platform':'linux/arm64'}


def record(score=1,status='PASS'):
    oracle=expected()['scorer']
    task='pass' if score==1 else 'fail'
    return {'schema':2,'document_type':'run_result','sealed':True,'status':status,'configuration_digest':'declared',
            'infrastructure':{'status':'ready'},'invocation':{'status':'verified'},'termination':{'reason':'completed'},
            'assistance':{'status':'autonomous'},'protected_inputs':{'status':'unchanged'},
            'scoring':{'status':'completed','results':[{**oracle,'status':'completed','score':score,'task_status':task}]},
            'task_result':{'status':task,'score':score},'image':{'id':'image','platform':'linux/arm64'},
            'provenance':{'configuration_sha256':'endpoint','snapshot_sha256':'source','plan_sha256':'plan','runner_content_sha256':'runner'}}


def row(variant,repetition,result=None,retry=None,started=False):
    attempts=[]
    if result is not None or started:attempts.append({'attempt_id':variant+str(repetition)+'-primary','attempt_index':1,'retry_of_attempt_id':None,'result_path':'runs/p/result.json','result':result})
    if retry is not None:attempts.append({'attempt_id':variant+str(repetition)+'-retry','attempt_index':2,'retry_of_attempt_id':attempts[0]['attempt_id'],'result_path':'runs/r/result.json','result':retry})
    return {'trial_id':variant+str(repetition),'case':'case','variant':variant,'repetition':repetition,'configuration_digest':'declared',
            'primary_attempt_id':attempts[0]['attempt_id'] if attempts else None,'attempts':attempts}


class ComparisonTests(unittest.TestCase):
    def test_manual_denominators_failures_retries_assistance_and_missing_candidate(self):
        clean=record();clean['measurement']={'agent_process_seconds':2,'usage':{'categories':{k:{'reported':v} for k,v in {'input':100,'output':10,'cache_read':20,'cache_write':0,'total':130}.items()}}}
        timeout=record(status='FAIL');timeout['termination']['reason']='timeout';timeout['invocation']['status']='invalid'
        invalid=record(status='FAIL');invalid['invocation']['status']='invalid'
        crash=record(status='FAIL');crash['scoring']['status']='error';crash['scoring']['results'][0]['status']='error';crash['task_result']={'status':'unknown','score':None}
        zero=record(0,'FAIL');zero['task_result']['test_counts']={'discovered':0,'passed':0,'failed':0,'skipped':0}
        blocked=record(status='BLOCKED');blocked['infrastructure']['status']='failed';blocked['invocation']['status']='not_started';blocked['scoring']['status']='skipped';blocked['task_result']={'status':'unknown','score':None}
        assisted=record(status='ASSISTED');assisted['assistance']['status']='assisted'
        failed=record(0,'FAIL')
        rows=[row('baseline',i,r) for i,r in enumerate([clean,timeout,invalid,crash,zero,blocked,assisted,failed])]
        rows[7]=row('baseline',7,failed,retry=record());rows.append(row('baseline',8))
        rows+=[row('candidate',0,record(0.5,'FAIL')),row('candidate',1,started=True),*[row('candidate',i) for i in range(2,9)]]
        report=comparisons.comparison({'experiment_id':'synthetic','name':'manual','baseline':'baseline','repetitions':9},rows,{r['trial_id']:expected() for r in rows})
        group=report['cases'][0]['variants']['baseline'];c=group['counts']
        self.assertEqual({k:c[k] for k in ('planned','started','completed','scorable','eligible','successful','blocked','cancelled','unscorable','retries','attempts')},
                         {'planned':9,'started':8,'completed':8,'scorable':6,'eligible':3,'successful':1,'blocked':1,'cancelled':0,'unscorable':3,'retries':1,'attempts':9})
        self.assertEqual(group['rates']['primary_success_planned'],{'numerator':1,'denominator':9,'value':1/9})
        self.assertEqual(group['rates']['artifact_success_scored']['value'],4/6)
        self.assertAlmostEqual(group['attributable_scores']['mean'],1/3)
        self.assertEqual(group['cohorts']['retries']['artifact_correct'],1)
        self.assertEqual(group['cohorts']['assisted']['artifact_correct'],1)
        self.assertEqual(group['primary_reported_usage']['total']['observed'],1);self.assertEqual(group['primary_reported_usage']['total']['missing'],8)
        self.assertEqual(group['primary_agent_end_to_end_seconds']['mean'],2);self.assertIsNone(group['inference_seconds'])
        pair=report['cases'][0]['pairs'][0];self.assertEqual(pair['eligible_pairs'],1);self.assertEqual(pair['planned_pairs'],9);self.assertEqual(pair['score_differences']['mean'],-0.5)
        candidate=report['cases'][0]['variants']['candidate']['counts'];self.assertEqual(candidate['incomplete'],1);self.assertEqual(candidate['not_started'],7)
        markdown=comparisons.markdown(report);self.assertIn('1/9',markdown);self.assertIn('4/6',markdown);self.assertIn('No significance',markdown)

    def test_cancelled_all_skipped_and_mismatched_contracts_do_not_become_model_success(self):
        cancelled=record(status='INTERRUPTED');cancelled['termination']['reason']='cancelled'
        skipped=record(0,'FAIL');skipped['task_result']['test_counts']={'discovered':3,'passed':0,'failed':0,'skipped':3}
        bad=record();bad['scoring']['results'][0]['scorer_sha256']='other'
        for r in (cancelled,skipped,bad):self.assertFalse(comparisons.assessment(r,expected(),'declared')['successful'])
        self.assertTrue(comparisons.assessment(cancelled,expected(),'declared')['artifact_correct'])
        self.assertFalse(comparisons.assessment(cancelled,expected(),'declared')['eligible'])
        self.assertFalse(comparisons.assessment(bad,expected(),'declared')['scorable'])
        for field in ('configuration_digest','image','provenance'):
            r=record()
            if field=='configuration_digest':r[field]='other'
            elif field=='image':r['image']['id']='other'
            else:r['provenance']['runner_content_sha256']='other'
            self.assertFalse(comparisons.assessment(r,expected(),'declared')['eligible'])

    def test_incompatible_oracles_prevent_pairing_and_empty_observations_remain_null(self):
        rows=[row('baseline',0,record()),row('candidate',0,record())]
        e={r['trial_id']:expected() for r in rows};e['candidate0']['scorer']['scorer_sha256']='other';rows[1]['attempts'][0]['result']['scoring']['results'][0]['scorer_sha256']='other'
        report=comparisons.comparison({'experiment_id':'synthetic','name':'manual','baseline':'baseline','repetitions':1},rows,e)
        pair=report['cases'][0]['pairs'][0];self.assertEqual(pair['eligible_pairs'],0);self.assertIsNone(pair['score_differences']['mean'])
        self.assertIsNone(comparisons.rate(0,0)['value']);self.assertIsNone(comparisons.stats([None,None])['mean'])
        self.assertIsNone(comparisons.stats([1])['sample_stddev'])
