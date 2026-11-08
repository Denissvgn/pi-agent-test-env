"""Client object models; these tests observe no actual SDK worker or deployment."""
import uuid
import os
import types
from unittest import TestCase,mock
from tests.test_operation_sdk_policy import example_policy,example_request,digest
from operation_sdk import policy,state,client,collect,wire,worker


class SDKClientModelTests(TestCase):
    def test_client_cannot_be_selected_by_an_ordinary_unverified_sibling_import(self):
        with self.assertRaises(wire.SDKError):client.Client()

    def test_prepared_policy_limits_and_deadline_are_immutable_snapshots(self):
        p=example_policy();p['input']['source_id']=str(uuid.uuid4());r=example_request(p)
        r.update(request_id=str(uuid.uuid4()),operation_id=str(uuid.uuid4()))
        admitted=policy.compile_admission(p,r,trusted_policy_sha256=digest(p),now_ns=100)
        record=state.reserve(admitted,100);session=client.Session(admitted,record)
        session.p['limits']['max_payload_bytes']=0
        session.limits['max_owned_fds']=0
        self.assertEqual(session.limits['max_payload_bytes'],p['limits']['max_payload_bytes'])
        self.assertEqual(session.limits['max_owned_fds'],p['limits']['max_owned_fds'])
        with self.assertRaises(AttributeError):session.deadline=1e100
        record.fail()

    def test_private_result_flags_cannot_be_mutated_and_public_envelopes_are_checked(self):
        limits=example_policy()['limits'];patterns=collect.Patterns(['accepted'],limits)
        result=client.Result(True,0,{'private':'fixture'}, {'handler_calls':1},patterns,65536)
        with self.assertRaises(AttributeError):result.accepted=False
        with self.assertRaises(AttributeError):result.code=99
        self.assertTrue(all(byte<32 for byte in result.public_wire()))
        with self.assertRaises(wire.SDKError):result.public_json({'accepted':True})
        self.assertEqual(result.public_json({'ok':True}),b'{"ok":true}')
        result.private()['private']='changed'
        self.assertEqual(result.private()['private'],'fixture')

    def test_precollection_refusal_cannot_claim_pattern_coverage_for_public_json(self):
        result=client.Result(False,1,None,{'collection':None},None,65536)
        with self.assertRaises(wire.SDKError):result.public_json({'ok':False})

    def test_mismatched_private_input_is_never_transferred_read_or_closed(self):
        p=example_policy();r=example_request(p)
        admitted=policy.compile_admission(p,r,trusted_policy_sha256=digest(p),now_ns=100)
        session=client.Session(admitted,None)
        with (mock.patch.object(client.os,'fstat',return_value=types.SimpleNamespace(st_dev=99,st_ino=99,st_uid=os.geteuid())),
              mock.patch.object(client.os,'read',side_effect=AssertionError('untransferred read')),
              mock.patch.object(client.native,'close',side_effect=AssertionError('untransferred close'))):
            with self.assertRaises(wire.SDKError):session._input(71)
        self.assertFalse(session._input_transferred);self.assertEqual(session._owned,{})

    def test_ready_cgroup_measurement_is_exact_and_typed(self):
        p=example_policy();deployment=p['deployment'];context='a'*64
        admitted=types.SimpleNamespace(operation=p['operation'],context_sha256=context,policy=lambda:p)
        session=client.Session(admitted,None);session._process=mock.Mock()
        session._process.observe.return_value={'pid':7}
        measured=dict(cpu_millicores=1000,memory_bytes=536870912,pids=128)
        value=dict(schema=1,kind='ready',context_sha256=context,operation=p['operation'],pid=7,
            runtime=dict(modules=deployment['runtime_modules'],files=deployment['runtime_files'],sizes=deployment['runtime_sizes'],
                         mapped_files=sorted(deployment['mapped_files']),python_sha256=deployment['python_sha256'],approval=False),
            limits=measured,sdk_files=deployment['consumer_files'],operational_approval=False,
            sdk_sources=[dict(path=deployment['consumer_root']+'/'+name,sha256=pin,code_filename=deployment['consumer_root']+'/'+name,
                              spec_origin=None if name=='__init__.py'else deployment['consumer_root']+'/'+name)
                         for name,pin in deployment['consumer_files'].items()],
            provider_sources=[dict(name=name,path=deployment['provider_root']+'/'+relative,
                code_filename=deployment['provider_root']+'/'+relative,spec_origin=deployment['provider_root']+'/'+relative,
                sha256=deployment['provider_files'][relative],loader_kind='verified_source')
                for name,relative in deployment['modules'].items()])
        with mock.patch.object(client.runtime,'cgroup_limits',return_value=measured):
            session._verify_ready(value)
            for invalid in(None,{**measured,'cpu_millicores':1001},{**measured,'pids':True}):
                with self.subTest(invalid=invalid),self.assertRaises(wire.SDKError):
                    session._verify_ready({**value,'limits':invalid})

    def test_native_receiver_identity_is_encoded_as_private_json_data(self):
        p=example_policy('secret_register_create_only_v1');p['deployment']['modules']={}
        p['scope'].update(store={'path':'/private/store','identity':[17,23]},
            coordination={'path':'/private/coord','identity':[17,24]},write_reference='APP_FAKE',value_contract='normalized_secret_1')
        r=example_request(p);admitted=policy.compile_admission(p,r,trusted_policy_sha256=digest(p),now_ns=100)
        native=mock.Mock(final_identity=(17,25,501,384,1,32),owned_fd_tokens=('value',))
        native.to_wire.return_value={'ack_ready':True}
        with mock.patch.object(worker.sys.modules['operation_sdk.secret_registration_primitive'],
                               'register_create_only',return_value=native):
            data,observation,identity=worker._execute(None,admitted,{'value':'fixture-value-0123456789'},[],71)
        body=wire.encode({'data':data,'native':observation,'final_identity':identity},4096)
        self.assertEqual(wire.decode(body,4096)['final_identity'],[17,25,501,384,1,32])
