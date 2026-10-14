"""Frozen parallel schema/capacity fixtures. No runtime or inference."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import parallel_contract as contract
import resources


def selected():
    return {'scheduler':contract.VERSION,'host_generation':1,'registry_aware_cohort':True,
            'max_trials':2,'max_stages':2,'max_pending':16,'queue_wait_seconds':300,'collection_timeout_seconds':14400,
            'aggregate':{'cpu_millis':2500,'memory_mib':3328,'pids_limit':1152},
            'gateway':{'resources':{'cpu_millis':250,'memory_mib':128,'pids_limit':64},
                       'max_inflight':1,'max_pending':4,'queue_wait_seconds':30,'request_timeout_seconds':180}}


class ContractTests(unittest.TestCase):
    def test_explicit_contract_is_copied_and_serial_does_not_gain_opt_in(self):
        value=selected();frozen=contract.validate(value);frozen['aggregate']['memory_mib']=64
        self.assertEqual(value['aggregate']['memory_mib'],3328)
        for invalid in (None,{},False):
            with self.assertRaises(contract.ParallelError):contract.validate(invalid)

    def test_unsupported_or_unbounded_modes_reject(self):
        for key,value in (('max_trials',3),('max_trials',True),('max_stages',1),('registry_aware_cohort',False),
                          ('host_generation',True),('scheduler','future'),('max_pending',0),('queue_wait_seconds',3601)):
            bad=selected();bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(contract.ParallelError):contract.validate(bad)
        bad=selected();bad['gateway']['max_inflight']=2
        with self.assertRaises(contract.ParallelError):contract.validate(bad)
        bad=selected();bad['gateway']['secret']='synthetic-secret'
        with self.assertRaises(contract.ParallelError):contract.validate(bad)

    def test_two_workers_and_helpers_must_fit_without_clamping(self):
        policy=resources.validate_policy({'runtime':{'cpus':1,'memory':'1536m','pids_limit':512,'jobs':1}})
        before=copy.deepcopy(policy)
        result=contract.admit_capacity(selected(),policy,{'NCPU':8,'MemTotal':8*1024**3})
        self.assertEqual(result['worker']['memory_mib'],1536);self.assertEqual(policy,before)
        policy['runtime']['memory']='2g'
        with self.assertRaisesRegex(contract.ParallelError,'do not fit'):
            contract.admit_capacity(selected(),policy,{'NCPU':8,'MemTotal':8*1024**3})
        with self.assertRaisesRegex(contract.ParallelError,'daemon budget'):
            contract.admit_capacity(selected(),before,{'NCPU':2,'MemTotal':4*1024**3})

    def test_queue_and_preflight_budgets_cover_a_long_but_bounded_other_request(self):
        value=selected();value['gateway']['queue_wait_seconds']=120
        self.assertEqual(contract.validate(value)['gateway']['max_inflight'],1)
        self.assertEqual(contract.preflight_limits(value),{'request_timeout_seconds':300,'container_timeout_seconds':330})
        value['gateway'].update(queue_wait_seconds=10,request_timeout_seconds=30)
        self.assertEqual(contract.preflight_limits(value),{'request_timeout_seconds':120,'container_timeout_seconds':150})
        for queue,request in ((601,600),(180,180),(True,180),(120,120)):
            value['gateway'].update(queue_wait_seconds=queue,request_timeout_seconds=request)
            with self.subTest(queue=queue,request=request),self.assertRaises(contract.ParallelError):contract.validate(value)


if __name__=='__main__':unittest.main()

from test_experiments import ExperimentFixture
import experiments
import pi_lab as lab


class SchemaTests(ExperimentFixture):
    def parallel(self):
        value=copy.deepcopy(self.definition);value['schema']=2;value['concurrency']=selected();value['budgets']['timeout_seconds']=300
        return value

    def test_serial_stays_serial_and_requires_explicit_new_schema(self):
        self.assertEqual(self.validate()['schema'],1)
        bad=copy.deepcopy(self.definition);bad['concurrency']=selected()
        with self.assertRaises(ValueError):self.validate(bad)
        bad=self.parallel();bad.pop('concurrency')
        with self.assertRaises(ValueError):self.validate(bad)

    def test_parallel_contract_and_matrix_are_frozen_and_execution_fail_closed(self):
        self.write('experiment.json',self.parallel());self.prepare()
        root=self.root/'prepared';metadata,matrix=experiments.verify(root,lab)
        self.assertEqual(metadata['schema'],2);self.assertEqual(matrix['schema'],2)
        self.assertEqual(metadata['concurrency'],selected())
        self.assertEqual(experiments.read_json(root/'state.json'),{'schema':2,'status':'prepared','active_attempts':{}})
        original=(root/'inputs/concurrency.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'cleanup bypass'):experiments.execute(root,lab,runner=lambda *a:None)
        self.assertEqual((root/'inputs/concurrency.json').read_bytes(),original)
        (root/'inputs/concurrency.json').chmod(0o600);(root/'inputs/concurrency.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'changed'):experiments.verify(root,lab)

    def test_parallel_rejects_multiple_upstream_models(self):
        value=self.parallel();self.write('different.json',{**self.endpoint,'model':'different-fixture'})
        value['variants'][1]['endpoint']='different.json'
        with self.assertRaisesRegex(ValueError,'one exact'):self.validate(value)

    def test_longer_queue_requires_room_in_every_frozen_stage(self):
        value=self.parallel();value['concurrency']['gateway']['queue_wait_seconds']=120
        with self.assertRaisesRegex(ValueError,'every Pi stage budget'):self.validate(value)
        value['budgets']['timeout_seconds']=600
        admitted=self.validate(value)
        self.assertEqual(admitted['concurrency']['gateway']['queue_wait_seconds'],120)
