"""Controlled interruption waits for caller handle ownership; no native effects."""
import ast,contextlib,json,os,stat,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent
REPO=HERE.parent

def load_helpers():
    tree=ast.parse((REPO/'tools/qualification/application_client.py').read_bytes())
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in
       {'_handoff_marker_value','_handoff_read','_participant_handle_handoff','_participant_handle_ready'}]
    class Refused(ValueError):pass
    def loads(body,max_bytes):
        if len(body)>max_bytes:raise Refused()
        def pairs(rows):
            d={}
            for k,v in rows:
                if k in d:raise Refused()
                d[k]=v
            return d
        def constant(value):raise Refused()
        return json.loads(body,object_pairs_hook=pairs,parse_constant=constant)
    def exact(value,fields,unused):
        if type(value)is not dict or set(value)!=fields:raise Refused()
    def valid_id(value):
        try:return type(value)is str and str(uuid.UUID(value))==value
        except ValueError:return False
    def directory(path):return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    class SyntheticOS:
        def __getattr__(self,name):return getattr(os,name)
        def getpid(self):return 177
    m=types.ModuleType('inert_handoff_helpers')
    m.__dict__.update(Path=Path,contextlib=contextlib,os=SyntheticOS(),stat=stat,
        QualificationError=Refused,controls=types.SimpleNamespace(valid_id=valid_id),
        preparation=types.SimpleNamespace(_directory=directory),c=types.SimpleNamespace(loads=loads,exact=exact))
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<inert-proposed-helpers>','exec'),m.__dict__)
    return m

class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='inert-handoff-proposal-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.m=load_helpers();self.events=[]
        self.ids=[str(uuid.uuid4())for _ in range(5)]
        q,run,attempt,stage,segment=self.ids
        self.manifest={'qualification_id':q}
        self.cell={'id':'N02-0.87.1-commit-and-interruption-b','group':'N02','scenario':'sensitive-participant-interruption','real_model':False}
        self.initial={'run_id':run,'attempt_id':attempt}
        self.desc={'kind':'agent','label':'agent-1-participant','run_id':run,'attempt_id':attempt,'stage_id':stage}
        self.binding={**self.initial,'stage_id':stage,'segment_id':segment}
        self.folder=self.root/'cells'/self.cell['id'];self.folder.mkdir(parents=True,mode=0o700)
        self.marker=self.folder/'participant-handoff.json';self.runroot=self.root/'results'/run
        self.descriptor={**self.desc,'schema':2,'workspace':str(self.runroot/'workspace'),'control':str(self.runroot/'controls'/stage)}
        self.state={'status':'running','segment_id':segment}
        self.meta={'active_stage.json':{'schema':2,'stage_id':stage,'label':'agent-1-participant'},
                   'descriptor.json':self.descriptor,'state.json':self.state}
        self.m._cell_args=lambda *args:types.SimpleNamespace(results_dir=str(self.root/'results'))
        self.m.read=lambda path,maximum:self.meta[Path(path).name]
        def atomic(path,value):
            self.events.append('publish')
            temp=path.with_name('.new-marker');temp.write_text(json.dumps(value));temp.chmod(0o600);os.replace(temp,path)
        self.m.atomic=atomic
        events=self.events
        class Coordinator:
            def mark_running(self):
                events.append('original_mark')
                if not self.p_owned:raise AssertionError('caller does not own handle')
                return 'original-return'
        self.coordinator_type=Coordinator;self.original=Coordinator.mark_running
        self.coordinator=Coordinator();self.coordinator.p_owned=True
        self.coordinator.desc=self.desc;self.coordinator.binding=self.binding
        self.fake_module=types.ModuleType('application_execution');self.fake_module.ApplicationCoordinator=Coordinator
        # Correctly scoped explicit patcher; restored by addCleanup without importing SDK.
        patcher=mock.patch.dict(sys.modules,{'application_execution':self.fake_module});patcher.start();self.addCleanup(patcher.stop)
    def value(self):return self.m._handoff_marker_value(self.manifest,self.cell,self.initial,self.desc,self.binding,177)
    def write(self,value=None):self.marker.write_text(json.dumps(self.value()if value is None else value));self.marker.chmod(0o600)
    def ready(self):return self.m._participant_handle_ready(self.root,self.manifest,self.cell,self.initial,177)
    def test_original_then_marker_and_restore(self):
        with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):
            self.assertEqual(self.coordinator.mark_running(),'original-return');self.assertTrue(self.ready())
        self.assertEqual(self.events,['original_mark','publish']);self.assertIs(self.coordinator_type.mark_running,self.original)
    def test_held_before_handoff_waits_then_one_intentional_signal(self):
        held=True;signals=[];sent=False
        def tick():
            nonlocal sent
            if held and not sent and self.ready():signals.append('SIGINT');sent=True
        tick();tick();self.assertEqual(signals,[])
        with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):self.coordinator.mark_running()
        tick();tick();self.assertEqual(signals,['SIGINT'])
    def test_actual_parent_trigger_waits_for_caller_handle_handoff(self):
        def condition(path):
            tree=ast.parse(path.read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_invoke_cell')
            return next(n.test for n in ast.walk(fn)if isinstance(n,ast.If)and isinstance(n.test,ast.BoolOp)
                and 'observed' in {x.id for x in ast.walk(n.test)if isinstance(x,ast.Name)})
        trigger=compile(ast.Expression(condition(REPO/'tools/qualification/application_client.py')),'<actual-parent-trigger>','eval')
        values={'observed':{'held':True,'identity_succeeded':True,'phase':'holding_after_identity'},
            'root':self.root,'manifest':self.manifest,'cell':self.cell,'initial':self.initial,
            'process':types.SimpleNamespace(pid=177),'_participant_handle_ready':self.m._participant_handle_ready}
        self.assertIs(eval(trigger,values),False)
        with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):self.coordinator.mark_running()
        self.assertIs(eval(trigger,values),True)
    def test_original_failure_no_marker_and_restoration(self):
        self.coordinator.p_owned=False
        with self.assertRaisesRegex(AssertionError,'caller does not own handle'):
            with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):self.coordinator.mark_running()
        self.assertFalse(self.marker.exists());self.assertIs(self.coordinator_type.mark_running,self.original)
    def test_publication_primary_preserved_and_restoration(self):
        error=OSError('synthetic publication error')
        def fail(*args):raise error
        self.m.atomic=fail
        with self.assertRaises(OSError)as got:
            with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):self.coordinator.mark_running()
        self.assertIs(got.exception,error);self.assertIs(self.coordinator_type.mark_running,self.original)
    def test_body_cancellation_restores_hook(self):
        error=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt)as got:
            with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):raise error
        self.assertIs(got.exception,error);self.assertIs(self.coordinator_type.mark_running,self.original)
    def test_non_scenario_has_no_hook_or_marker(self):
        other={**self.cell,'scenario':'omitted-report'}
        with self.m._participant_handle_handoff(self.root,self.manifest,other,self.initial):
            self.assertIs(self.coordinator_type.mark_running,self.original)
        self.assertFalse(self.marker.exists())
    def test_wrong_owner_run_stage_segment_refused(self):
        for key,value in [('owner_pid',178),('run_id',str(uuid.uuid4())),('stage_id',str(uuid.uuid4())),('segment_id',str(uuid.uuid4()))]:
            marker={**self.value(),key:value};self.write(marker)
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):self.ready()
    def test_wrong_active_stage_and_segment_state_refused(self):
        self.write();self.meta['active_stage.json']={**self.meta['active_stage.json'],'stage_id':str(uuid.uuid4())}
        with self.assertRaises(ValueError):self.ready()
        self.meta['active_stage.json']={'schema':2,'stage_id':self.ids[3],'label':'agent-1-participant'}
        self.meta['state.json']={**self.state,'segment_id':str(uuid.uuid4())}
        with self.assertRaises(ValueError):self.ready()
    def test_existing_stale_marker_not_overwritten(self):
        self.write({**self.value(),'run_id':str(uuid.uuid4())});before=self.marker.read_bytes()
        with self.assertRaises(ValueError):
            with self.m._participant_handle_handoff(self.root,self.manifest,self.cell,self.initial):self.coordinator.mark_running()
        self.assertEqual(self.marker.read_bytes(),before);self.assertIs(self.coordinator_type.mark_running,self.original)
    def test_unsafe_marker_mode_link_size_and_json_refused(self):
        self.write();self.marker.chmod(0o644)
        with self.assertRaises(ValueError):self.ready()
        self.marker.chmod(0o600);link=self.folder/'second-link';os.link(self.marker,link)
        with self.assertRaises(ValueError):self.ready()
        link.unlink();self.marker.write_bytes(b' '*4097)
        with self.assertRaises(ValueError):self.ready()
        self.marker.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):self.ready()
        self.marker.write_text('{"schema":NaN}')
        with self.assertRaises(ValueError):self.ready()
    def test_marker_only_closed_fields_no_keys(self):
        value=self.value();self.assertEqual(set(value),{'schema','document_type','qualification_id','cell_id','run_id','attempt_id','stage_id','segment_id','owner_pid','state'})
        self.assertNotIn('environment',value);self.assertNotIn('credential',value)

class StructuralTests(unittest.TestCase):
    def test_runtime_assignment_precedes_original_mark_running(self):
        p=REPO/'skill/scripts/pi_lab.py';t=ast.parse(p.read_bytes());node=next(n for n in t.body if isinstance(n,ast.FunctionDef)and n.name=='stream_run')
        assignment=next(n for n in ast.walk(node)if isinstance(n,ast.Assign)and any(isinstance(k,ast.Name)and k.id=='p'for k in n.targets)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and n.value.func.attr=='Popen')
        call=next(n for n in ast.walk(node)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='mark_running')
        self.assertLess(assignment.lineno,call.lineno)

if __name__=='__main__':unittest.main(verbosity=2)
