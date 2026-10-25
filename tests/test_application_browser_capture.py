"""Controlled CDP DOM-tree checks; actual Chromium capture is a separate gate."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node required for controlled CDP predicate checks')
class BrowserCaptureTreeTests(unittest.TestCase):
    def test_closed_and_open_shadow_roots_cannot_hide_opaque_pixels(self):
        source = (ROOT / 'skill/runtime/application-browser-cdp.mjs').read_text()
        function = source[source.index('function safeScreenshotTree('):source.index('\nasync function nodeFor(')]
        script = '''import vm from 'node:vm';
const check=vm.runInNewContext(FUNCTION);
const node=(name,type=1,extra={})=>({nodeName:name,nodeType:type,...extra});
if(!check(node('#document',9,{children:[node('HTML'),node('INPUT',1,{shadowRoots:[node('#document-fragment',11,{shadowRootType:'user-agent',children:[node('SPAN')]})]})]})))throw Error('safe form tree rejected');
for(const shadowRootType of ['closed','open']){
 const root=node('#document',9,{children:[node('DIV',1,{shadowRoots:[node('#document-fragment',11,{shadowRootType,children:[node('canvas')]})]})]});
 if(check(root))throw Error('application shadow tree admitted');
}
if(check(node('svg')))throw Error('lowercase SVG admitted');
if(check({}))throw Error('untyped tree admitted');
if(check(node('#document',9,{children:Array.from({length:16385},()=>node('SPAN'))})))throw Error('oversized tree admitted');
console.log('bounded CDP shadow-tree predicate passed');
'''.replace('FUNCTION', repr('(' + function + ')'))
        result = subprocess.run(['node', '--input-type=module', '-e', script],
                                capture_output=True, text=True, timeout=10, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('predicate passed', result.stdout)


if __name__ == '__main__': unittest.main()
