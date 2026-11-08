"""Typed and legacy handler limits are enforced before provider entry/lookup."""
import types
from unittest import TestCase,mock
from tests.test_operation_sdk_policy import example_policy
from operation_sdk import collect,worker,wire


class SDKHandlerBudgetTests(TestCase):
    def test_typed_stage_prompt_check_and_scorer_dimensions_are_operation_bounds(self):
        variants=[({'schema':1,'stages':[{},{}],'checks':[]},{}),
                  ({'schema':1,'stages':[{'prompt':'XX'}],'checks':[]},{'max_prompt_bytes':1}),
                  ({'schema':1,'stages':[],'checks':[{},{}]},{'max_plan_checks':1}),
                  ({'schema':1,'stages':[],'checks':[{'scorer':{'assets':[{}]}}]}, {'max_scorer_assets':0})]
        for value,limits in variants:
            p=example_policy();p['limits'].update(limits)
            admitted=types.SimpleNamespace(operation='plan_validate_source_v1',policy=lambda:p)
            provider=mock.Mock();provider.module.side_effect=AssertionError('provider before operation dimensions')
            with self.subTest(value=value):
                with self.assertRaises(wire.SDKError):worker._execute(provider,admitted,{'plan':value},[],-1)
                provider.module.assert_not_called()

    def test_legacy_does_not_increase_an_explicit_zero_dependency_read_count(self):
        from operation_sdk import source
        p=example_policy('plan_validate_legacy_v1');p['scope']['base']='/approved/project';p['limits']['max_read_refs']=0
        value={'schema':1,'agents':[{'prompt':'fake'}],'checks':[{'argv':['true']}]}
        profile=types.SimpleNamespace(builtin=lambda:{'kind':'builtin'})
        lab=types.SimpleNamespace(validate_plan=lambda *args,**kwargs:value)
        provider=types.SimpleNamespace(module=lambda name:profile if name=='agent_profiles'else lab)
        admitted=types.SimpleNamespace(operation='plan_validate_legacy_v1',policy=lambda:p)
        with mock.patch.object(source,'ApprovedReader',wraps=source.ApprovedReader)as readers:
            worker._legacy(provider,admitted,value,collect.Patterns([],p['limits']))
        self.assertEqual(readers.call_args.kwargs['max_files'],0)

    def test_overlapping_resource_never_replaces_a_narrow_dependency_cap(self):
        from operation_sdk import source
        p=example_policy('plan_validate_legacy_v1');p['scope']['base']='/opt/provider/assets'
        selected='/opt/provider/assets/prompt.txt'
        p['deployment']['resources']={'assets/prompt.txt':'a'*64}
        p['scope']['dependencies']=[dict(path=selected,sha256='a'*64,maximum_bytes=1,role='prompt')]
        value={'schema':1,'agents':[{'prompt_file':'prompt.txt'}],'checks':[{'argv':['true']}]}
        reader=mock.Mock(count=0)
        reader.read.side_effect=lambda path,maximum:b'X'
        profile=types.SimpleNamespace(builtin=lambda:{'kind':'builtin'})
        lab=types.SimpleNamespace(validate_plan=lambda value,*args,**kwargs: {'schema':1,'agents':[{'prompt':'X'}],'checks':[]})
        provider=types.SimpleNamespace(module=lambda name:profile if name=='agent_profiles'else lab)
        admitted=types.SimpleNamespace(operation='plan_validate_legacy_v1',policy=lambda:p)
        with mock.patch.object(source,'ApprovedReader',return_value=reader)as readers:
            worker._legacy(provider,admitted,value,collect.Patterns([],p['limits']))
        self.assertEqual(readers.call_args.args[0][selected]['maximum_bytes'],1)
