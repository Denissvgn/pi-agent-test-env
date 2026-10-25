"""A10 strict ledger projections and unchanged historical denominators/bytes."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import comparisons
import indexed_reporting
import native_budget_reporting as reporting
import test_comparisons as comparison_fixture
import test_native_budget_controls as budget_fixture

CANARY='synthetic-private-native-nonce-abc123'


def process(**changes):
    value={'native_tool_manifest':{'schema':1,'tools':['bash','budget_status']},
           'native_tool_budget':budget_fixture.snapshot()}
    value.update(changes);return value


def record(value=None,name='implementer'):
    return {'agents':[{'name':name,'process':process() if value is None else value}]}


class NativeReportingTests(unittest.TestCase):
    def test_absent_native_fields_are_absent_not_zero_or_new_legacy_fields(self):
        self.assertIsNone(reporting.process_projection({'exit_code':0,'events':{'tool_calls':999}}))
        self.assertIsNone(reporting.record_projection({'agents':[{'name':'implementer','process':{'exit_code':0}}]}))
        self.assertIsNone(reporting.record_projection(None))

    def test_declared_missing_accounting_is_unavailable_without_inferred_phase(self):
        value=reporting.process_projection({'native_tool_manifest':{'schema':1,'tools':['bash','budget_status']}})
        self.assertEqual(value,{'accounting':'unavailable','budget':None,'error':'accounting_unavailable'})
        self.assertEqual(reporting.process_projection({},required=True),value)
        self.assertNotIn('phase',value);self.assertNotIn('charged',value)

    def test_exact_snapshot_keeps_unknown_execution_and_is_independent_copy(self):
        source=process();before=copy.deepcopy(source)
        result=reporting.process_projection(source)
        self.assertEqual(result['budget'],source['native_tool_budget']);self.assertIsNone(result['budget']['counts']['executed'])
        self.assertEqual(result['budget']['counts']['charged'],3);self.assertEqual(result['budget']['remaining_calls'],5)
        result['budget']['counts']['charged']=99
        self.assertEqual(source,before)

    def test_missing_or_untrusted_manifest_never_derives_tools_from_snapshot(self):
        for manifest in (None,{}, {'schema':True,'tools':['bash','budget_status']},
                         {'schema':1,'tools':['bash']},{'schema':1,'tools':['bash','budget_status','bash']},
                         {'schema':1,'tools':['budget_status',CANARY]},
                         {'schema':1,'tools':['budget_status'],'capability':CANARY},
                         {'schema':1,'tools':['budget_status']*65}):
            with self.subTest(manifest=manifest):
                value=reporting.process_projection(process(native_tool_manifest=manifest))
                self.assertIsNone(value['budget']);self.assertNotIn(CANARY,json.dumps(value))

    def test_unknown_fields_raw_values_and_inconsistent_counters_fail_closed(self):
        for mutation in ('extra','tool','counter','nonfinite','private-id'):
            source=process();budget=source['native_tool_budget']
            if mutation=='extra':budget['request']={'credential':CANARY}
            elif mutation=='tool':budget['per_tool'][CANARY]=budget['per_tool'].pop('bash')
            elif mutation=='counter':budget['counts']['charged']=999
            elif mutation=='nonfinite':budget['remaining_calls']=float('inf')
            else:budget['counts']['native_call_id']=CANARY
            with self.subTest(mutation=mutation):
                value=reporting.process_projection(source)
                self.assertEqual(value,reporting.unavailable());self.assertNotIn(CANARY,json.dumps(value))

    def test_accounting_unavailable_retains_valid_partial_counts_and_exact_phase(self):
        source=process(native_tool_budget=budget_fixture.snapshot(accounting='unavailable',phase='reporting'))
        value=reporting.process_projection(source)
        self.assertEqual(value['accounting'],'unavailable');self.assertEqual(value['error'],'accounting_unavailable')
        self.assertEqual(value['budget'],source['native_tool_budget']);self.assertIsNone(value['budget']['counts']['executed'])
        self.assertEqual(value['budget']['phase'],'reporting')

    def test_cleanup_error_retains_trusted_snapshot_but_unknown_errors_do_not_echo(self):
        value=reporting.process_projection(process(native_tool_budget_error='cleanup_unconfirmed'))
        self.assertEqual(value['accounting'],'unavailable');self.assertEqual(value['error'],'cleanup_unconfirmed')
        self.assertEqual(value['budget']['limits'],budget_fixture.NATIVE)
        for error in (CANARY,None,{'reason':CANARY}):
            value=reporting.process_projection(process(native_tool_budget_error=error))
            self.assertEqual(value,reporting.unavailable());self.assertNotIn(CANARY,json.dumps(value))

    def test_stage_boundaries_and_last_parent_snapshot_survive_without_event_recount(self):
        first=process();first['events']={'tool_calls':999};first['segments']=[{'native_tool_budget':{'charged':999}}]
        source={'agents':[{'name':'implementer','process':first},{'name':'reviewer','process':process(native_tool_budget=budget_fixture.snapshot(charged=4))}]}
        result=reporting.record_projection(source,stage_names=['implementer','reviewer'])
        self.assertEqual([stage['stage'] for stage in result['stages']],['implementer','reviewer'])
        self.assertEqual([stage['budget']['counts']['charged'] for stage in result['stages']],[3,4])
        self.assertEqual(result['scope'],'parent_ledger; runtime_qualification_separate')
        self.assertNotIn('segments',json.dumps(result));self.assertNotIn('999',json.dumps(result))

    def test_frozen_required_missing_stage_remains_explicitly_unavailable(self):
        result=reporting.record_projection(None,stage_names=['implementer','reviewer'],required_stages=['reviewer'])
        self.assertEqual(result['stages'],[{'stage':'reviewer',**reporting.unavailable()}])
        public=reporting.record_projection(None,stage_names=['implementer','reviewer'],required_stages=['reviewer'],public=True)
        self.assertEqual(public['stages'][0]['stage'],2)

    def test_duplicate_or_foreign_native_stages_do_not_silently_disappear(self):
        source=record();source['agents'].append(copy.deepcopy(source['agents'][0]))
        self.assertEqual(reporting.record_projection(source)['stages'][0]['budget'],None)
        source=record(name=CANARY)
        result=reporting.record_projection(source,stage_names=['implementer'],public=True)
        self.assertEqual(result['stages'][0]['budget'],None);self.assertNotIn(CANARY,json.dumps(result))

    def test_frozen_metadata_names_are_bounded_and_diagnostics_never_echo_them(self):
        for names in ([CANARY+'\n'],['a']*2,['a']*9,['a'*65],'not-an-array'):
            with self.assertRaises(reporting.NativeBudgetReportingError) as caught:reporting.record_projection({},stage_names=names)
            self.assertNotIn(CANARY,str(caught.exception))

    def test_application_stage_name_limit_is_preserved_in_private_and_public_reports(self):
        for length in (52, 64):
            name = 's' * length
            with self.subTest(length=length):
                result = reporting.record_projection(record(name=name), stage_names=[name], required_stages=[name])
                self.assertEqual(result['stages'][0]['stage'], name)
                self.assertEqual(result['stages'][0]['accounting'], 'available')
                public = reporting.record_projection(record(name=name), stage_names=[name], required_stages=[name], public=True)
                self.assertEqual(public['stages'][0]['stage'], 1)

    def test_same_parent_projection_across_standalone_serial_indexed_parallel(self):
        outputs=[]
        for mode in ('standalone','serial','indexed','parallel'):
            source=record();source['mode']=mode
            source['agents'][0]['process'].update(native_call_id=CANARY,cursor=CANARY,capability=CANARY,prompt=CANARY,
                                                 tools=[{'arguments':CANARY}],result={'nonce':CANARY})
            outputs.append(reporting.record_projection(source))
        self.assertTrue(all(value==outputs[0] for value in outputs))
        self.assertNotIn(CANARY,json.dumps(outputs))

    def public(self,result):
        row={'case':'private-case','variant':'private-variant','repetition':0,'attempts':[{'attempt_index':1,'result':result}]}
        binding={'incarnation':'private-incarnation','fingerprint':'private-fingerprint','authority_id':'private-authority'}
        return indexed_reporting.public_rows([row],lambda unused:{'implementer':binding},lambda unused:['implementer'])

    def test_indexed_public_export_uses_stage_ordinals_and_strips_all_private_fields(self):
        source=record();source.update(private_path=CANARY,credentials={'key':CANARY})
        result=self.public(source)
        value=result[0]['attempts'][0]['native_tool_budgets']
        self.assertEqual(value['stages'][0]['stage'],1);self.assertIsNone(value['stages'][0]['budget']['counts']['executed'])
        body=json.dumps(result)
        for secret in (CANARY,'private','implementer','native_call_id','nonce','cursor','capability','sha256'):
            self.assertNotIn(secret,body)

    def test_legacy_public_export_bytes_match_historical_shape(self):
        result=self.public({'status':'PASS','task_result':{'score':1}})
        expected=[{'schema':1,'document_type':'public_indexed_trial','cell':1,'case':'case-1','variant':'variant-1','repetition':0,
            'bindings':[{'stage':1,'binding':'binding-1','adapter':'chat-completions-v1'}],
            'attempts':[{'index':1,'status':'PASS','reason':None,'score':1,'reported_usage':{'input':None,'output':None,'cache_read':None,'cache_write':None,'total':None},'inference_seconds':None}],
            'scope':'Opaque labels apply only within this collection; provider capacity and inference timing unknown.'}]
        self.assertEqual(json.dumps(result,separators=(',',':')).encode(),json.dumps(expected,separators=(',',':')).encode())

    def test_public_frozen_required_stages_diagnose_wholly_omitted_process(self):
        row={'case':'private-case','variant':'private-variant','repetition':0,
             'attempts':[{'attempt_index':1,'result':{'status':'PASS'}}]}
        binding={'incarnation':'private-incarnation','fingerprint':'private-fingerprint','authority_id':'private-authority'}
        value=indexed_reporting.public_rows([row],lambda unused:{'implementer':binding},lambda unused:['implementer'],
            required_native_stages=lambda unused:['implementer'])
        stage=value[0]['attempts'][0]['native_tool_budgets']['stages'][0]
        self.assertEqual(stage,{'stage':1,**reporting.unavailable()})

    def test_legacy_comparison_bytes_match_pre_native_projection_golden(self):
        rows=[comparison_fixture.row('baseline',0,comparison_fixture.record(),retry=comparison_fixture.record()),
              comparison_fixture.row('baseline',1)]
        value=comparisons.summarize_group(rows,{row['trial_id']:comparison_fixture.expected() for row in rows})
        body=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
        # Captured from the pre-A10 implementation with this fixed synthetic
        # two-trial cohort, including one retry and one unstarted primary.
        self.assertEqual(hashlib.sha256(body).hexdigest(),'926703c57ff65b9b328c4acd820aae18c01ecc1378117f3d50e8bbd9ece14e8a')

    def test_comparison_retains_denominators_retry_policy_and_optional_stage_projection(self):
        legacy=comparison_fixture.record();native=copy.deepcopy(legacy);native.update(record())
        rows=[comparison_fixture.row('baseline',0,native,retry=native),comparison_fixture.row('baseline',1)]
        expected={row['trial_id']:comparison_fixture.expected() for row in rows}
        group=comparisons.summarize_group(rows,expected)
        legacyrows=[comparison_fixture.row('baseline',0,legacy,retry=legacy),comparison_fixture.row('baseline',1)]
        baseline=comparisons.summarize_group(legacyrows,expected)
        self.assertEqual(group['counts'],baseline['counts']);self.assertEqual(group['rates'],baseline['rates'])
        self.assertEqual(group['counts']['planned'],2);self.assertEqual(group['counts']['attempts'],2)
        self.assertEqual(group['trials'][0]['native_tool_budgets']['stages'][0]['budget']['counts']['charged'],3)
        self.assertIn('native_tool_budgets',group['trials'][0]['attempts'][1])
        self.assertNotIn('native_tool_budgets',group['trials'][1])

    def test_native_required_missing_primary_is_diagnosed_without_changing_denominator(self):
        rows=[comparison_fixture.row('baseline',0)]
        expected={'baseline0':{**comparison_fixture.expected(),'native_budget_stage_names':['implementer'],'native_budget_required_stages':['implementer']}}
        group=comparisons.summarize_group(rows,expected)
        self.assertEqual(group['counts']['planned'],1);self.assertEqual(group['counts']['not_started'],1)
        self.assertEqual(group['trials'][0]['native_tool_budgets']['stages'][0]['budget'],None)

    def test_markdown_adds_native_accounting_only_when_present(self):
        native=comparison_fixture.record();native.update(record(process(native_tool_budget_error='cleanup_unconfirmed')))
        rows=[comparison_fixture.row('baseline',0,native)]
        value=comparisons.comparison({'experiment_id':'fixture','name':'fixture','baseline':'baseline','repetitions':1},rows,{'baseline0':comparison_fixture.expected()})
        text=comparisons.markdown(value)
        self.assertIn('Parent ledger accounting',text);self.assertIn('Reserve calls',text);self.assertIn('cleanup_unconfirmed',text)
        self.assertNotIn(CANARY,text)


if __name__=='__main__':unittest.main()
