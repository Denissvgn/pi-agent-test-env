"""Real local lease/CLI negatives; no Docker, Pi participant, endpoint or secret access."""
import contextlib
import hashlib
import io
import json
import os
import select
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]/'skill'
sys.path.insert(0, str(ROOT/'scripts'))
import outcomes
import pi_lab as lab
import resources
from application_credentials import CredentialError

CANARY = 'synthetic-credential-123456'
PRIVATE_URL = 'https://private.example.invalid/v1?key='+CANARY


class AdmissionDiagnosticsTests(unittest.TestCase):
    def args(self, root, op='run'):
        project=root/'project';project.mkdir(exist_ok=True)
        (project/'input.txt').write_text('original')
        return lab.parser().parse_args([op,'--project',str(project),'--endpoint',str(root/'never-read.json'),
                                       '--lock-file',str(root/'lease'),'--results-dir',str(root/'results'),
                                       '--platform','linux/arm64'])

    def rejected(self, args, reason):
        output=io.StringIO()
        with mock.patch.object(lab,'_execute_suite') as dispatch, contextlib.redirect_stdout(output):
            self.assertEqual(lab.run_suite(args,smoke=args.op=='smoke'),2)
        dispatch.assert_not_called()
        result=json.loads(output.getvalue())
        self.assertEqual(result['infrastructure']['reason'],reason)
        self.assertEqual(result['infrastructure']['phase'],'admission')
        self.assertEqual(result['status'],'BLOCKED');self.assertTrue(result['sealed'])
        self.assertEqual(result['invocation'],{'status':'not_started','attempted_stages':0})
        self.assertEqual(result['scoring']['status'],'skipped');self.assertIsNone(result['task_result']['score'])
        self.assertIsNone(result['workspace']);self.assertEqual(result['agents'],[])
        self.assertLessEqual(len(result['infrastructure']['remedy']),384)
        self.assertNotIn(CANARY,output.getvalue());self.assertNotIn(PRIVATE_URL,output.getvalue())
        saved=lab.controls.read(Path(args.results_dir)/result['run_id']/'result.json')
        self.assertEqual(saved,result)
        self.assertEqual((Path(args.project)/'input.txt').read_text(),'original')
        return result

    def test_busy_run_and_smoke_are_sealed_without_dispatch_on_both_release_routes(self):
        for release in ('0.87.1','1.2.0'):
            for op in ('run','smoke'):
                with self.subTest(release=release,op=op),tempfile.TemporaryDirectory() as td:
                    args=self.args(Path(td),op);args.observed_pi_version=release
                    with resources.admission_lock(args.lock_file):
                        before=Path(args.lock_file).read_bytes()
                        result=self.rejected(args,'host-admission-busy')
                        self.assertEqual(Path(args.lock_file).read_bytes(),before)
                    self.assertEqual(result['infrastructure']['error_digest'],hashlib.sha256(resources.ADMISSION_FAILURES['host-admission-busy'][0].encode()).hexdigest())
                    with resources.admission_lock(args.lock_file):pass

    def test_invalid_policy_and_insecure_lock_are_distinct_nonsecret_outcomes(self):
        for fault in ('invalid-policy','insecure-lock','malformed-policy','missing-policy'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as td:
                root=Path(td);args=self.args(root);policy=root/'policy.json';target=root/'target'
                target.write_text(CANARY)
                reason='resource-policy-invalid'
                if fault=='invalid-policy':policy.write_text(json.dumps({'runtime':{'cpus':PRIVATE_URL}}));args.resources=str(policy)
                elif fault=='malformed-policy':policy.write_text('invalid '+PRIVATE_URL);args.resources=str(policy)
                elif fault=='missing-policy':args.resources=str(root/CANARY)
                else:Path(args.lock_file).symlink_to(target);reason='admission-lock-insecure'
                self.rejected(args,reason);self.assertEqual(target.read_text(),CANARY)

    def test_raw_details_only_survive_as_hash_and_sealed_accounting_cannot_change(self):
        for code in resources.ADMISSION_FAILURES:
            with self.subTest(code=code),tempfile.TemporaryDirectory() as td:
                attempt=outcomes.Attempt(self.args(Path(td)))
                error=resources.AdmissionError(code,PRIVATE_URL)
                attempt.fail(error);first=attempt.finalize()
                self.assertEqual(first['infrastructure']['reason'],code)
                self.assertEqual(first['infrastructure']['error_digest'],hashlib.sha256(PRIVATE_URL.encode()).hexdigest())
                self.assertNotIn(PRIVATE_URL,json.dumps(first));self.assertNotIn(CANARY,json.dumps(first))
                attempt.record['status']='PASS';attempt.fail(ValueError(CANARY))
                self.assertEqual(attempt.finalize(),first)

    def test_spoofed_text_and_attributes_cannot_create_catalog_authority(self):
        with tempfile.TemporaryDirectory() as td:
            attempt=outcomes.Attempt(self.args(Path(td)))
            error=ValueError(resources.ADMISSION_FAILURES['host-admission-busy'][0])
            error.reason='host-admission-busy';error.remedy=PRIVATE_URL
            attempt.fail(error);result=attempt.finalize()
            self.assertEqual(result['infrastructure']['reason'],'ValueError')
            self.assertNotIn('remedy',result['infrastructure'])
            self.assertNotIn(PRIVATE_URL,json.dumps(result))
        for code in (CANARY, None, []):
            with self.subTest(code=code),self.assertRaises(ValueError) as caught:
                resources.AdmissionError(code)
            self.assertNotIn(CANARY,str(caught.exception))
        error=resources.AdmissionError('host-admission-busy');error._admission_reason=PRIVATE_URL
        self.assertEqual(resources.admission_diagnostic(error),{'reason':'admission-error'})

    def test_invalid_wait_is_rejected_before_lock_creation(self):
        for wait in (-1,3601,True,float('nan'),float('inf'),PRIVATE_URL):
            with self.subTest(wait=wait),tempfile.TemporaryDirectory() as td:
                path=Path(td)/'lease'
                with self.assertRaises(resources.AdmissionError) as caught:
                    with resources.admission_lock(path,wait):self.fail('entered invalid lease')
                self.assertEqual(caught.exception.reason,'resource-policy-invalid');self.assertFalse(path.exists())

    def test_out_of_range_large_integer_policy_has_a_safe_reason_not_overflow(self):
        for policy in ({'runtime':{'cpus':10**400}},{'host_budget':{'cpu_fraction':10**400}}):
            with self.subTest(policy=policy),self.assertRaises(resources.AdmissionError) as caught:
                resources.validate_policy(policy)
            self.assertEqual(caught.exception.reason,'resource-policy-invalid')

    def test_memory_numeric_conversion_rejection_keeps_safe_policy_diagnostics(self):
        with mock.patch.object(resources,'int',side_effect=ValueError(PRIVATE_URL),create=True):
            with self.assertRaises(resources.AdmissionError) as caught:resources.memory_bytes('128m')
        self.assertEqual(caught.exception.reason,'resource-policy-invalid')
        self.assertNotIn(PRIVATE_URL,json.dumps(resources.admission_diagnostic(caught.exception)))
        if hasattr(sys,'get_int_max_str_digits') and sys.get_int_max_str_digits():
            with self.assertRaises(resources.AdmissionError) as caught:
                resources.memory_bytes('9'*(sys.get_int_max_str_digits()+1)+'m')
            self.assertEqual(caught.exception.reason,'resource-policy-invalid')

    def test_bounded_wait_expiry_and_success_preserve_exclusion(self):
        for released in (False,True):
            with self.subTest(released=released),tempfile.TemporaryDirectory() as td:
                path=Path(td)/'lease';holder=resources.admission_lock(path);holder.__enter__()
                def wait(_):
                    if released:holder.__exit__(None,None,None)
                with mock.patch.object(resources.time,'monotonic',side_effect=[0,0,1]),mock.patch.object(resources.time,'sleep',side_effect=wait) as sleep:
                    if released:
                        with resources.admission_lock(path,1):pass
                    else:
                        with self.assertRaises(resources.AdmissionError) as caught:
                            with resources.admission_lock(path,1):self.fail('entered busy lease')
                        self.assertEqual(caught.exception.reason,'host-admission-busy')
                sleep.assert_called_once_with(.1)
                if not released:holder.__exit__(None,None,None)
                with resources.admission_lock(path):pass

    def test_lock_access_errors_have_bounded_guidance_without_path_values(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(Path(td))
            with mock.patch.object(resources.os,'chmod',side_effect=PermissionError(PRIVATE_URL)):
                result=self.rejected(args,'admission-lock-unavailable')
            self.assertEqual(result['infrastructure']['error_digest'],hashlib.sha256(PRIVATE_URL.encode()).hexdigest())
            with resources.admission_lock(args.lock_file):pass

    def test_acquisition_and_metadata_os_errors_are_safe_before_yield(self):
        for operation in ('flock','seek','truncate','write','flush'):
            with self.subTest(operation=operation),tempfile.TemporaryDirectory() as td:
                path=Path(td)/'lease';error=OSError(PRIVATE_URL)
                with contextlib.ExitStack() as stack:
                    if operation=='flock':stack.enter_context(mock.patch.object(resources.fcntl,'flock',side_effect=error))
                    else:
                        handle=path.open('a+');self.addCleanup(handle.close)
                        proxy=mock.MagicMock(wraps=handle);proxy.__enter__.return_value=proxy
                        getattr(proxy,operation).side_effect=error
                        stack.enter_context(mock.patch.object(Path,'open',return_value=proxy))
                    with self.assertRaises(resources.AdmissionError) as caught:
                        with resources.admission_lock(path):self.fail('entered broken lease')
                self.assertEqual(caught.exception.reason,'admission-lock-unavailable')
                output=io.StringIO()
                with contextlib.redirect_stderr(output):self.assertEqual(lab.cli_failure(caught.exception),2)
                value=json.loads(output.getvalue());self.assertEqual(value['infrastructure']['reason'],'admission-lock-unavailable')
                self.assertNotIn(CANARY,output.getvalue());self.assertNotIn(PRIVATE_URL,output.getvalue())
                if operation!='flock':handle.close()
                with resources.admission_lock(path):pass

    def test_existing_credential_error_reason_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            attempt=outcomes.Attempt(self.args(Path(td)));error=CredentialError(PRIVATE_URL)
            error.reason=PRIVATE_URL
            attempt.fail(error);value=attempt.finalize()
            self.assertEqual(value['infrastructure']['reason'],'application-credentials')
            self.assertNotIn(PRIVATE_URL,json.dumps(value))

    def test_patch_admission_keeps_its_safe_failure_instead_of_unsafe_patch_wrapper(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);args=self.args(root);run=root/'run';run.mkdir()
            desc={'admission_lock_file':args.lock_file,'workspace':str(root/'workspace')}
            args.message=None;args.interrupt=False
            with resources.admission_lock(args.lock_file), \
                 mock.patch.object(lab,'find_run_dir',return_value=run), \
                 mock.patch.object(lab.controls,'resolve',return_value=(desc,{})):
                with self.assertRaises(resources.AdmissionError) as caught:lab._cmd_patch_session(args)
            self.assertEqual(caught.exception.reason,'host-admission-busy')

    def test_body_exception_is_not_reclassified_as_a_lock_failure(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'lease';error=OSError(PRIVATE_URL)
            with self.assertRaises(OSError) as caught:
                with resources.admission_lock(path):raise error
            self.assertIs(caught.exception,error)
            with resources.admission_lock(path):pass

    def test_same_user_exclusion_and_release_after_owner_process_death(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'lease'
            code="from resources import admission_lock;import sys\nwith admission_lock(sys.argv[1]):\n print('locked',flush=True)\n sys.stdin.read()\n"
            env={**os.environ,'PYTHONPATH':str(ROOT/'scripts'),'PYTHONDONTWRITEBYTECODE':'1'}
            with subprocess.Popen([sys.executable,'-c',code,str(path)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) as owner:
                try:
                    self.assertTrue(select.select([owner.stdout],[],[],5)[0],'owner never acquired lease')
                    self.assertEqual(owner.stdout.readline().strip(),'locked')
                    with self.assertRaises(resources.AdmissionError) as caught:
                        with resources.admission_lock(path):self.fail('overlapping lease')
                    self.assertEqual(caught.exception.reason,'host-admission-busy')
                finally:
                    owner.kill();owner.wait(timeout=5)
            with resources.admission_lock(path):pass
            self.assertTrue(path.exists())

    def test_nonrun_cli_admission_failures_are_machine_readable_without_raw_values(self):
        env={k:v for k,v in os.environ.items() if not k.startswith('PI_APP_') and k not in ('PI_API_KEY','PI_LAB_API_KEY')}
        env['PYTHONDONTWRITEBYTECODE']='1'
        for fault,reason in (('busy','host-admission-busy'),('policy','resource-policy-invalid'),('link','admission-lock-insecure')):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as td:
                root=Path(td);lock=root/'lease';target=root/'target';target.write_text(CANARY)
                argv=[sys.executable,str(ROOT/'scripts/pi_lab.py'),'ensure-image','--policy','reuse','--image','not-launched',
                      '--platform','linux/arm64','--lock-file',str(lock)]
                if fault=='link':lock.symlink_to(target)
                if fault=='policy':
                    policy=root/'policy';policy.write_text(PRIVATE_URL);argv+=['--resources',str(policy)]
                with resources.admission_lock(lock) if fault=='busy' else contextlib.nullcontext():
                    result=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')
                value=json.loads(result.stderr);self.assertEqual(value['document_type'],'admission_failure')
                self.assertEqual(value['infrastructure']['reason'],reason)
                self.assertNotIn(CANARY,result.stderr);self.assertNotIn(PRIVATE_URL,result.stderr)
                self.assertEqual(target.read_text(),CANARY)


if __name__ == '__main__':unittest.main()
