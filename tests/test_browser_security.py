"""Offline policy/admission tests; native Chromium observations are separate receipts."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'runtime'))
import browser_security as policy
import browser_sandbox
import pi_lab as lab
import worker

HTML = '<table id="sandbox-status">' + ''.join('<tr><td>'+k+'</td><td>'+v+'</td></tr>' for k,v in (
    ('Layer 1 Sandbox','Namespace'), ('PID namespaces','Yes'), ('Network namespaces','Yes'), ('Seccomp-BPF sandbox','Yes'))) + '</table>'


class PolicyTests(unittest.TestCase):
    def test_exact_pinned_delta_and_deny_by_default(self):
        directory = ROOT / 'assets/security'
        base = json.loads((directory/'moby-default.json').read_text())
        profile = json.loads((directory/'chromium-userns.json').read_text())
        self.assertEqual(hashlib.sha256((directory/'moby-default.json').read_bytes()).hexdigest(), policy.BASE_SHA256)
        self.assertEqual(profile['defaultAction'], 'SCMP_ACT_ERRNO')
        self.assertEqual(profile['syscalls'][:len(base['syscalls'])], base['syscalls'])
        self.assertEqual({k:v for k,v in profile.items() if k!='syscalls'}, {k:v for k,v in base.items() if k!='syscalls'})
        extra = profile['syscalls'][len(base['syscalls']):]
        self.assertEqual(len(extra), 10)
        self.assertEqual({name for row in extra for name in row['names']}, {'clone','unshare','chroot'})
        clones = [row for row in extra if row['names']==['clone']]
        self.assertEqual({row['args'][0]['valueTwo'] for row in clones}, {0x10000000,0x20000000,0x30000000,0x40000000,0x50000000,0x60000000,0x70000000})
        self.assertTrue(all(row['args'][0]['index']==0 and row['args'][0]['value']==0x7e020000 for row in clones))
        self.assertEqual({row['args'][0]['value'] for row in extra if row['names']==['unshare']}, {0x10000000,0x60000000})
        self.assertEqual(policy.verify(directory/'chromium-userns.json').name,'chromium-userns.json')

    def test_explicit_selection_and_no_unsafe_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            args=lab.parser().parse_args(['browser-check','--image','synthetic','--platform','linux/arm64'])
            self.assertEqual(policy.docker_options(args,Path(td)),[])
            for profile,platform,optout in (('core','linux/arm64',False),('browser','linux/amd64',False),('browser','linux/arm64',True)):
                with self.assertRaises(ValueError):policy.selection(profile,'chromium-userns',platform,optout)
            args.browser_sandbox_policy='chromium-userns'
            args.frozen_browser_security=policy.freeze(args,Path(td)/'policy')
            a=argparse.Namespace(platform='linux/arm64',uid=os.getuid(),gid=os.getgid(),memory='2g',cpus=2,pids_limit=512,
                                 allow_browser_no_sandbox=False,software_webgl=False,profile='browser',browser_sandbox_policy='chromium-userns',
                                 frozen_browser_security=args.frozen_browser_security)
            argv=lab.docker_args(a,'synthetic',Path(td)/'workspace',Path(td)/'control',Path(td)/'state','synthetic','none')
            for flag in ('--cap-drop=ALL','--security-opt=no-new-privileges=true','--read-only','--ipc=none','--platform'):
                self.assertIn(flag,argv)
            self.assertIn('seccomp='+args.frozen_browser_security['path'],argv)
            self.assertFalse(any('unconfined' in item or 'SYS_ADMIN' in item or item=='--privileged' for item in argv))
            Path(args.frozen_browser_security['path']).write_text('{}')
            with self.assertRaises(ValueError):policy.docker_options(args,Path(td)/'workspace')

    def test_policy_cannot_alias_a_writable_project_or_a_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);source=ROOT/'assets/security/chromium-userns.json'
            args=lab.parser().parse_args(['browser-check','--image','synthetic','--platform','linux/arm64','--browser-sandbox-policy','chromium-userns'])
            args.frozen_browser_security=policy.freeze(args,top/'project')
            with self.assertRaises(ValueError):policy.docker_options(args,top)
            path=Path(args.frozen_browser_security['path']);path.unlink();path.symlink_to(source)
            with self.assertRaises((ValueError,OSError)):policy.docker_options(args,top/'workspace')


class SandboxTests(unittest.TestCase):
    def test_actual_table_not_launch_flag_or_new_tab(self):
        self.assertTrue(browser_sandbox.observed(HTML)['namespace_and_seccomp_verified'])
        for html in ('<html>New Tab</html>', HTML.replace('Namespace','SUID'), HTML.replace('Yes','No'), '<p>PID namespaces Yes Seccomp-BPF sandbox Yes</p>'):
            self.assertFalse(browser_sandbox.observed(html)['namespace_and_seccomp_verified'])
        with self.assertRaises(ValueError):browser_sandbox.observed(HTML.replace('</table>','<tr><td>PID namespaces</td><td>No</td></tr></table>'))

    def test_worker_requires_dom_and_namespace_seccomp_observation(self):
        for report,ok in ((HTML,True),('<html>New Tab</html>',False)):
            with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{'TMPDIR':td,'CHROME_NO_SANDBOX':'0'}), mock.patch.object(worker,'chromium_path',return_value='/synthetic/chromium'), mock.patch.object(worker,'execute',side_effect=['<p id="probe">BROWSER_OK</p>',report]) as execute, contextlib.redirect_stdout(io.StringIO()):
                if ok:worker.browser()
                else:
                    with self.assertRaises(RuntimeError):worker.browser()
                self.assertEqual(execute.call_count,2)
                for call in execute.call_args_list:self.assertNotIn('--no-sandbox',call.args[0])
                self.assertIn('chrome://sandbox',execute.call_args_list[1].args[0])

    @unittest.skipUnless(shutil.which('node'),'Node is needed for the browser-options helper fixture')
    def test_helper_cannot_silently_disable_sandbox(self):
        source=ROOT/'runtime/browser-options.mjs'
        code="import fs from 'node:fs'; import {browserOptions} from "+json.dumps(source.as_uri())+"; const safe=browserOptions(); fs.rmSync(safe.userDataDir,{recursive:true}); for (const arg of ['--no-sandbox','--disable-namespace-sandbox','--disable-seccomp-filter-sandbox','--single-process']) { let rejected=false; try { browserOptions({args:[arg]}); } catch(e) { rejected=e.message.includes('Sandbox-disabling browser arguments'); } if(!rejected) process.exit(1); }"
        result=subprocess.run(['node','--input-type=module','-e',code],env={**os.environ,'CHROME_NO_SANDBOX':'0','PUPPETEER_EXECUTABLE_PATH':sys.executable},capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)


class AdmissionTests(unittest.TestCase):
    def test_key_free_admission_cannot_pass_without_sandbox_evidence(self):
        for valid in (True,False):
            with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
                top=Path(td);seen=[]
                stack.enter_context(mock.patch.object(lab,'require_host',return_value={'selected_platform':'linux/arm64'}))
                stack.enter_context(mock.patch.object(lab,'probe_image',return_value={'id':'synthetic'}))
                endpoint=stack.enter_context(mock.patch.object(lab,'endpoint_secret'))
                def stage(args,image,root,workspace,label,operation,**kwargs):
                    seen.append(kwargs)
                    lab.save(root/label/'stdout.jsonl',{'browser_dom_ok':True})
                    if valid:
                        with (root/label/'stdout.jsonl').open('a') as out:out.write(json.dumps({'browser_sandbox':{'namespace_and_seccomp_verified':True}})+'\n')
                    # stream JSONL is compact, unlike ordinary pretty JSON receipts.
                    rows=[{'browser_dom_ok':True}]+([{'browser_sandbox':{'namespace_and_seccomp_verified':True}}] if valid else [])
                    (root/label/'stdout.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows));(root/label/'stderr.log').write_text('')
                    return {'exit_code':0,'cleanup_confirmed':True}
                stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=stage));stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                code=lab.main(['browser-check','--image','synthetic','--platform','linux/arm64','--browser-sandbox-policy','chromium-userns','--results-dir',str(top/'runs'),'--lock-file',str(top/'lock')])
                self.assertEqual(code,0 if valid else 2);endpoint.assert_not_called()
                self.assertEqual(seen[0]['network'],'none');self.assertNotIn('secret',seen[0]);self.assertNotIn('application_secrets',seen[0])
                result=lab.controls.read(next((top/'runs').glob('browser-*/browser-admission.json')))
                self.assertFalse(result['credentials_supplied']);self.assertEqual(result['pi_participant_invocations'],0)


if __name__=='__main__':unittest.main()
