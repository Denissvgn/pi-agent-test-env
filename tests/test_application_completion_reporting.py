"""A08 comparison/export fixtures; frozen callbacks, no execution qualification."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_completion
import comparisons
import indexed_reporting
import test_comparisons as fixtures


def safe(stage='secret-stage',status='complete'):
    return {'stage':stage,'status':status,'diagnostics':[] if status=='complete' else [{'code':'report_missing','count':1}],
        'diagnostics_truncated':False}


def application_record(status='incomplete'):
    record=fixtures.record(status='PASS' if status=='complete' else 'FAIL')
    record['application_execution']={'schema':1,'plan_sha256':'f'*64,'required_stages':['secret-stage']}
    record['application_completion']=application_completion.run_projection([safe(status=status)])
    record['application_completion_result']={'pointer':'/private/report','participant':'secret-actor',
        'receipt_ids':['private-receipt'],'payload':'private-payload'}
    return record


class CompletionExportTests(unittest.TestCase):
    def public(self,record,*,required=True):
        row={'case':'private-case','variant':'private-variant','repetition':0,
            'attempts':[{'attempt_index':1,'result':record}]}
        bindings={stage:{'incarnation':stage,'fingerprint':stage,'authority_id':stage} for stage in ('prep','secret-stage')}
        options={'required_application_stages':lambda row:('secret-stage',)} if required else {}
        return indexed_reporting.public_rows([row],lambda row:bindings,lambda row:['prep','secret-stage'],**options)

    def test_public_required_completion_uses_frozen_ordinals_and_no_private_diagnostics(self):
        record=application_record();public=self.public(record)
        value=public[0]['attempts'][0]['application_completion']
        self.assertEqual(value['stages'][0]['stage'],2)
        self.assertEqual(value['stages'][0]['status'],'incomplete')
        self.assertEqual(value['stages'][0]['diagnostics'],[{'code':'report_missing','count':1}])
        text=json.dumps(public)
        for private in ('secret-stage','private','secret-actor','receipt_ids','pointer','payload','plan_sha256'):
            self.assertNotIn(private,text)

    def test_missing_marker_projection_or_malformed_declared_data_is_not_legacy(self):
        mutations=[lambda r:r.pop('application_completion'),lambda r:r.pop('application_execution'),
            lambda r:r['application_execution'].update(extra='private-value'),
            lambda r:r['application_execution'].update(schema=True),
            lambda r:r['application_completion']['stages'][0].update(status='private-value'),
            lambda r:r['application_completion']['stages'][0]['diagnostics'][0].update(count=True),
            lambda r:r['application_completion']['stages'][0].update(expected='private-value')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                record=application_record();mutate(record);public=self.public(record)
                stage=public[0]['attempts'][0]['application_completion']['stages'][0]
                self.assertEqual(stage,{'stage':2,'status':'not_evaluated',
                    'diagnostics':[{'code':'stage_not_evaluated','count':1}],'diagnostics_truncated':False})
                self.assertNotIn('private-value',json.dumps(public))
        self.assertEqual(self.public(None)[0]['attempts'][0]['application_completion']['stages'][0]['status'],'not_evaluated')

    def test_malformed_marker_without_required_callback_has_only_fixed_public_identity(self):
        record={'application_execution':{'schema':1,'required_stages':['hostile-private'],'secret':'private-value'}}
        projected=indexed_reporting.application_projection(record,public=True)
        self.assertEqual(projected['stages'][0]['stage'],1)
        self.assertEqual(projected['stages'][0]['status'],'not_evaluated')
        self.assertNotIn('private',json.dumps(projected))

    def test_legacy_three_argument_export_has_no_application_fields(self):
        result=self.public(fixtures.record(),required=False)
        self.assertNotIn('application_completion',result[0]['attempts'][0])
        self.assertIsNone(indexed_reporting.application_projection(None))
        self.assertIsNone(indexed_reporting.application_projection({},required_stages=()))

    def report(self,primary,retry=None,*,required=True):
        rows=[fixtures.row('baseline',0,primary,retry=retry)]
        expected=fixtures.expected()
        if required:expected.update(application_stage_names=['secret-stage'],application_required_stages=['secret-stage'])
        return comparisons.comparison({'experiment_id':'controlled-fixture','name':'completion fixture',
            'baseline':'baseline','repetitions':1},rows,{rows[0]['trial_id']:expected})

    def test_private_comparison_preserves_primary_retry_and_original_denominators(self):
        primary=application_record();retry=application_record('complete')
        report=self.report(primary,retry);group=report['cases'][0]['variants']['baseline'];trial=group['trials'][0]
        self.assertEqual(trial['application_completion']['stages'][0]['status'],'incomplete')
        self.assertEqual([attempt['application_completion']['stages'][0]['status'] for attempt in trial['attempts']],['incomplete','complete'])
        for target in [trial,*trial['attempts']]:
            text=json.dumps(target['application_completion'])
            for private in ('private','receipt','payload','pointer','expected','participant'):self.assertNotIn(private,text)
        self.assertEqual({key:group['counts'][key] for key in ('planned','started','completed','scorable','artifact_correct','eligible','successful','retries','attempts')},
            {'planned':1,'started':1,'completed':1,'scorable':1,'artifact_correct':1,'eligible':1,'successful':0,'retries':1,'attempts':2})
        self.assertEqual(group['rates']['primary_success_planned']['denominator'],1)
        markdown=comparisons.markdown(report)
        self.assertIn('| Report status | Diagnostic counts |',markdown)
        self.assertIn('report_missing: 1',markdown)

    def test_private_missing_required_is_unavailable_and_legacy_markdown_unchanged(self):
        report=self.report(fixtures.record())
        self.assertEqual(report['cases'][0]['variants']['baseline']['trials'][0]['application_completion']['stages'][0]['status'],'not_evaluated')
        legacy=self.report(fixtures.record(),required=False)
        self.assertNotIn('application_completion',legacy['cases'][0]['variants']['baseline']['trials'][0])
        self.assertNotIn('Report status',comparisons.markdown(legacy))
        self.assertNotIn('Required report completion',comparisons.markdown(legacy))


if __name__=='__main__':unittest.main()
