"""Closed startup diagnostics only; no HTTP, model, Docker or business actions."""
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_client as client
import application_client_service as service
import application_contracts as c
from tool_budgets import BudgetError
from test_application_client_authority import BaseFixture

SECRET='private-startup-canary-974261-secret'


class StartupDetailsTests(unittest.TestCase):
    def caught(self,program,filename):
        scope={'secret':SECRET,'c':c}
        try:exec(compile(program,filename,'exec'),scope)
        except Exception as error:return error
        self.fail('Controlled error did not occur')
    def assert_closed(self,result):
        self.assertEqual(set(result),{'schema','category','code','errno','frames','frames_truncated'})
        self.assertIn(result['category'],('contract','service','budget','os','other'))
        self.assertIn(result['code'],service.STARTUP_CODES|{'unknown'})
        self.assertLessEqual(len(result['frames']),12)
        for frame in result['frames']:
            self.assertEqual(set(frame),{'file','line'});self.assertIn(frame['file'],service.TRUSTED_CODE)
            self.assertIs(type(frame['line']),int);self.assertTrue(1<=frame['line']<=1000000)
        self.assertIs(type(result['frames_truncated']),bool)
        self.assertNotIn(SECRET,json.dumps(result));self.assertNotIn(str(ROOT),json.dumps(result))
    def test_secret_messages_locals_filenames_and_contract_pointers_never_serialize(self):
        error=self.caught('private_local={secret:secret}\nraise ValueError(secret)',str(ROOT/SECRET/'unknown-private-file.py'))
        result=service._startup_details(error);self.assert_closed(result)
        self.assertEqual(result['category'],'other');self.assertEqual(result['frames'],[]);self.assertTrue(result['frames_truncated'])
        error=self.caught('c.fail("/"+secret,secret)',str(ROOT/SECRET/'unknown.py'))
        result=service._startup_details(error);self.assert_closed(result)
        self.assertEqual((result['category'],result['code']),('contract','contract_invalid'))
        self.assertNotIn('pointer',result)
    def test_only_genuine_loaded_classes_have_closed_codes_and_errno_is_strict(self):
        for error,category,code in ((service.ServiceError('request_invalid'),'service','request_invalid'),
                (BudgetError('accounting_unavailable'),'budget','accounting_unavailable'),
                (type('ServiceError',(ValueError,),{'reason':'request_invalid'})(SECRET),'other','unknown'),
                (type('BudgetError',(ValueError,),{'reason':'accounting_unavailable'})(SECRET),'other','unknown'),
                (service.ServiceError(SECRET),'service','unknown')):
            result=service._startup_details(error);self.assert_closed(result)
            self.assertEqual((result['category'],result['code']),(category,code))
        for number,expected in ((errno.EACCES,errno.EACCES),(True,None),(10**9,None),(SECRET,None)):
            error=OSError();error.errno=number;error.filename=SECRET
            result=service._startup_details(error);self.assert_closed(result);self.assertEqual(result['errno'],expected)
    def test_total_walk_and_trusted_excerpt_are_bounded_without_source_or_function_names(self):
        filename=str(ROOT/'skill/runtime/application_client_service.py')
        program='def private_function_name(depth):\n private_local=secret\n if depth:return private_function_name(depth-1)\n raise ValueError(secret)\nprivate_function_name(200)'
        result=service._startup_details(self.caught(program,filename));self.assert_closed(result)
        self.assertEqual(len(result['frames']),12);self.assertTrue(result['frames_truncated'])
        self.assertNotIn('private_function_name',json.dumps(result));self.assertNotIn('private_local',json.dumps(result))
    def test_diagnostic_failure_and_overlarge_formatter_fall_back_to_original_constant(self):
        for change in (mock.patch.object(service,'_startup_details',side_effect=RuntimeError(SECRET)),
                       mock.patch.object(service,'_startup_details',return_value={'unsafe':SECRET*1000})):
            output=io.StringIO()
            with change,mock.patch.object(service.sys,'stderr',output):service._emit_startup_failure(ValueError(SECRET))
            self.assertEqual(json.loads(output.getvalue()),{'schema':1,'status':'blocked','reason':'client_start_failed'})
    def test_broken_write_or_flush_is_silenced_without_printing_original_context(self):
        class Broken:
            def __init__(self,write):self.write_fails=write
            def write(self,value):
                if self.write_fails:raise BrokenPipeError(SECRET)
            def flush(self):raise OSError(SECRET)
        for stream in (Broken(True),Broken(False)):
            with mock.patch.object(service.sys,'stderr',stream):
                self.assertFalse(service._emit_startup_failure(ValueError(SECRET)))
                self.assertIsNone(service.sys.stderr)


class FrozenMainFailureTests(BaseFixture):
    def setUp(self):
        super().setUp();self.code=self.root/('frozen-'+SECRET);self.code.mkdir(mode=0o700)
        self.identity=client.freeze_code(self.code)
    def run_failure(self,configuration,*,broken_stderr=False):
        argv=[sys.executable,'-I','-B',str(self.code/'runtime/application_client_service.py'),'--listen','127.0.0.1','--port','0']
        if broken_stderr:
            program='import os,runpy,sys;path=sys.argv[1];os.close(2);sys.argv=[path,"--listen","127.0.0.1","--port","0"];runpy.run_path(path,run_name="__main__")'
            argv=[sys.executable,'-I','-B','-c',program,str(self.code/'runtime/application_client_service.py')]
        result=subprocess.run(argv,input=c.canonical(configuration),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            cwd=self.root,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(self.root)},timeout=5)
        self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,b'')
        if broken_stderr:self.assertEqual(result.stderr,b'');return
        self.assertLessEqual(len(result.stderr),4096);self.assertNotIn(SECRET.encode(),result.stderr)
        value=json.loads(result.stderr);self.assertEqual((value['schema'],value['status'],value['reason']),(1,'blocked','client_start_failed'))
        self.assertEqual(set(value),{'schema','status','reason','diagnostic'})
        StartupDetailsTests.assert_closed(self,value['diagnostic'])
        return value['diagnostic']
    def configuration(self):
        authority,_=self.authority();evidence=self.root/'evidence';evidence.mkdir(mode=0o700)
        return c.loads(authority._bootstrap(evidence,self.identity))
    def test_actual_frozen_main_os_error_never_emits_secret_filename_or_message(self):
        configuration=self.configuration();configuration['evidence_root']=str(self.root/SECRET/'missing')
        diagnostic=self.run_failure(configuration)
        self.assertEqual((diagnostic['category'],diagnostic['code'],diagnostic['errno']),('os','unknown',errno.ENOENT))
        self.assertTrue(diagnostic['frames']);self.assertTrue(all(frame['file']=='runtime/application_client_service.py' for frame in diagnostic['frames']))
    def test_actual_frozen_main_recognizes_genuine_separately_imported_service_class(self):
        authority=self.configuration();authority['control_token']=SECRET
        configuration={'schema':1,'document_type':'application_execution_private_bootstrap','mode':'application-execution',
            'authority':authority,'state_root':str(self.root/'state'),'outputs_root':str(self.root/'evidence/outputs'),
            'budget_grants':[],'browser_admission':None,'sealed_inputs':[],'redaction_values':[]}
        diagnostic=self.run_failure(configuration)
        self.assertEqual((diagnostic['category'],diagnostic['code']),('service','request_invalid'))
        self.assertTrue(any(frame['file']=='runtime/application_execution_service.py' for frame in diagnostic['frames']))
    def test_actual_frozen_main_closed_stderr_exits_two_without_private_exception_context(self):
        configuration=self.configuration();configuration['evidence_root']=str(self.root/SECRET/'missing')
        self.run_failure(configuration,broken_stderr=True)


if __name__=='__main__':unittest.main()
