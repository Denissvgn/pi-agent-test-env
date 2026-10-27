"""The deployed helper bundle must close its local module dependency graph.

Only owned synthetic copies and a denied-effect host Node linker are used. No
Chromium configure input, Docker, SDK context, model, credentials or Original IO.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime'),str(ROOT/'tools/qualification')]
import application_client as client
import application_client_service as service
import application_sdk_admission as sdk

LEGACY_KEYS=frozenset(('runtime/application-browser-cdp.mjs','runtime/application_api.py',
    'runtime/application_browser.py','runtime/application_budget.py',
    'runtime/application_client_service.py','runtime/application_execution_service.py',
    'runtime/application_files.py','runtime/application_runtime_contracts.py',
    'runtime/native_budget_service.py','runtime/native_tool_contracts.py',
    'runtime/prompt_contract.py','runtime/release_contracts.py','scripts/application_contracts.py',
    'scripts/application_credentials.py','scripts/application_documents.py',
    'scripts/application_evidence.py','scripts/resources.py','scripts/secret_store.py',
    'scripts/stage_control.py','scripts/tool_budgets.py'))
BROWSER_OPTIONS='runtime/browser-options.mjs'
REGISTRY_DIAGNOSTICS='scripts/registry_diagnostics.py'
DRIVER='runtime/application-browser-cdp.mjs'
NODE_LINKER=r"""
import cp from 'node:child_process';import net from 'node:net';
import http from 'node:http';import https from 'node:https';import tls from 'node:tls';
import {syncBuiltinESMExports} from 'node:module';import {pathToFileURL} from 'node:url';
let effects=0;const deny=()=>{effects++;throw new Error('INERT_EFFECT_DENIED');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=deny;
net.createServer=deny;net.connect=deny;net.createConnection=deny;
http.request=deny;http.get=deny;https.request=deny;https.get=deny;tls.connect=deny;
globalThis.fetch=deny;syncBuiltinESMExports();
try {
  const module=await import(pathToFileURL(process.argv[1]).href);
  const valid=process.argv[3]==='present'&&typeof module.RENDERER_CHECKPOINT==='string';
  process.stdout.write(JSON.stringify({status:valid?'BUNDLE_LINKED':'UNEXPECTED_LINK',effects})+'\n');
  process.exitCode=valid&&effects===0?0:2;
} catch(error) {
  const expected=process.argv[3]==='missing'&&error.code==='ERR_MODULE_NOT_FOUND'&&error.url===pathToFileURL(process.argv[2]).href;
  process.stdout.write(JSON.stringify({status:expected?'EXPECTED_MISSING_DEPENDENCY':'UNEXPECTED_ERROR',effects})+'\n');
  process.exitCode=expected&&effects===0?0:2;
}
"""


def forbidden(*unused,**kw):raise AssertionError('pure_shape_must_not_observe_or_dispatch')


class BrowserBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='inert-browser-bundle-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve();self.root.chmod(0o700)
        self.code=self.root/'code'
        # Genuine production freezer, not a full-tree test mount or hand-built map.
        self.identity=client.freeze_code(self.code)

    def shape(self,identity):
        gate=object.__new__(sdk.AdmissionGate);gate.registry_root=self.root/'unopened-registry'
        key=str(uuid.uuid4())
        row={'schema':1,'launch_id':key,'generation':str(uuid.uuid4()),
            'registry':hashlib.sha256(str(gate.registry_root).encode()).hexdigest(),
            'status':'released','container':'inert-browser-helper','image':'sha256:'+'a'*64,
            'mounts':[],'daemon':'NONSECRET_SYNTHETIC_DAEMON','runroot':None,
            'binding':{},'application_helper':True,'client_mode':'application-execution',
            'code_identity':copy.deepcopy(identity)}
        with mock.patch('os.open',side_effect=forbidden),mock.patch('os.stat',side_effect=forbidden), \
             mock.patch('os.lstat',side_effect=forbidden),mock.patch('os.kill',side_effect=forbidden), \
             mock.patch('subprocess.Popen',side_effect=forbidden),mock.patch('socket.socket',side_effect=forbidden), \
             mock.patch.object(sdk,'digest',side_effect=forbidden):
            sdk.AdmissionGate._shape(gate,row,key)

    def link(self,expected):
        node=shutil.which('node');self.assertIsNotNone(node,'Node is required for the copied-bundle regression')
        env={'PATH':str(Path(node).parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],
             'TMPDIR':str(self.root),'LANG':'C.UTF-8'}
        process=None
        try:
            process=subprocess.Popen([node,'--input-type=module','-e',NODE_LINKER,
                 str(self.code/DRIVER),str(self.code/BROWSER_OPTIONS),expected],
                 cwd=self.code,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE,start_new_session=False)
            output,error=process.communicate(timeout=5)
            self.assertLessEqual(len(output)+len(error),8192)
            self.assertEqual(error,b'','unexpected nonsecret linker stderr')
            self.assertEqual(process.returncode,0,'copied-bundle linker assertion failed')
            self.assertEqual(json.loads(output),{'status':'BUNDLE_LINKED'if expected=='present'else'EXPECTED_MISSING_DEPENDENCY','effects':0})
        finally:
            if process is not None:
                if process.poll()is None:
                    process.kill();process.wait(timeout=2)
                self.assertIsNotNone(process.returncode)
                process.stdout.close();process.stderr.close()
                self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_genuine_freezer_includes_every_local_javascript_dependency(self):
        self.assertEqual(set(self.identity),LEGACY_KEYS|{BROWSER_OPTIONS,REGISTRY_DIAGNOSTICS})
        self.assertEqual(set(client.TRUSTED_CODE),set(self.identity))
        self.assertEqual({str(p.relative_to(self.code))for p in self.code.rglob('*')if p.is_file()},set(self.identity))
        for name,expected in self.identity.items():
            self.assertEqual(hashlib.sha256((self.code/name).read_bytes()).hexdigest(),expected)
            if name.endswith('.mjs'):
                for dependency in re.findall(r"from\s+['\"]([^'\"]+)['\"]",(self.code/name).read_text()):
                    if dependency.startswith('.'):
                        target=os.path.normpath(str(Path(name).parent/dependency))
                        self.assertIn(target,self.identity,'copied ESM dependency omitted from trusted identity')

    def test_copied_bundle_links_with_spawn_network_denied_and_no_configure(self):
        self.link('present')

    def test_missing_dependency_regression_fails_in_copied_bundle_not_whole_tree(self):
        (self.code/BROWSER_OPTIONS).unlink()
        self.link('missing')

    def test_original_sdk_accepts_only_exact_legacy_or_current_bundle_shapes(self):
        self.assertEqual(sdk.CODE_KEYS,LEGACY_KEYS)
        self.assertEqual(sdk.BROWSER_CODE_KEYS,LEGACY_KEYS|{BROWSER_OPTIONS})
        self.assertEqual(sdk.CURRENT_CODE_KEYS,LEGACY_KEYS|{BROWSER_OPTIONS,REGISTRY_DIAGNOSTICS})
        legacy={name:self.identity[name]for name in LEGACY_KEYS}
        browser={name:self.identity[name]for name in sdk.BROWSER_CODE_KEYS}
        self.shape(legacy);self.shape(browser);self.shape(self.identity)
        for fault in ('missing-old','extra','renamed','invalid-hash','bool-hash'):
            value=copy.deepcopy(self.identity)
            if fault=='missing-old':value.pop('runtime/application_api.py')
            elif fault=='extra':value['runtime/arbitrary-module.mjs']='a'*64
            elif fault=='renamed':value['runtime/other-browser-options.mjs']=value.pop(BROWSER_OPTIONS)
            elif fault=='invalid-hash':value[BROWSER_OPTIONS]='not-a-sha'
            else:value[BROWSER_OPTIONS]=True
            with self.subTest(fault=fault),self.assertRaises(sdk.AdmissionDenied):self.shape(value)

    def test_current_service_authenticates_added_dependency_without_weakening_hashes(self):
        # Genuine verifier checks the current public package paths. Legacy maps
        # remain historical SDK metadata, not acceptable current bootstraps.
        service.verify_code(self.identity)
        legacy={name:self.identity[name]for name in LEGACY_KEYS}
        with self.assertRaises(ValueError):service.verify_code(legacy)
        bad=copy.deepcopy(self.identity);bad[BROWSER_OPTIONS]='0'*64
        with self.assertRaises(ValueError):service.verify_code(bad)
        bad=copy.deepcopy(self.identity);bad[REGISTRY_DIAGNOSTICS]='0'*64
        with self.assertRaises(ValueError):service.verify_code(bad)
        browser={name:self.identity[name]for name in sdk.BROWSER_CODE_KEYS}
        with self.assertRaises(ValueError):service.verify_code(browser)

    def test_copied_python_bundle_requires_frozen_diagnostics_dependency(self):
        source="import sys; from pathlib import Path; root=Path(sys.argv[1]); sys.path[:0]=[str(root/'scripts'),str(root/'runtime')]; import application_client_service, registry_diagnostics; assert Path(registry_diagnostics.__file__).parent==root/'scripts'; print('COPIED_BUNDLE_IMPORTED')"
        def run():
            return subprocess.run([sys.executable,'-I','-B','-c',source,str(self.code)],
                                  capture_output=True,text=True,timeout=5,cwd=self.code)
        result=run();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'COPIED_BUNDLE_IMPORTED')
        (self.code/REGISTRY_DIAGNOSTICS).unlink()
        result=run();self.assertNotEqual(result.returncode,0)
        self.assertIn("No module named 'registry_diagnostics'",result.stderr)


if __name__=='__main__':unittest.main()
