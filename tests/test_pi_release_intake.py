"""Offline checks for the read-only Pi release intake tool.

A synthetic upstream repository and npm registry are served on loopback; no
test contacts GitHub or npm.
"""
import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import http.server
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / 'tools'))
import pi_release_intake as intake  # noqa: E402

BASE, TARGET = '7.1.0', '7.2.0'
BASE_COMMIT, TARGET_COMMIT, TAG_OBJECT = 'a' * 40, 'b' * 40, 'c' * 40
ARGS, LOCK = intake.CLI_ARGS, intake.LOCKFILE
READ = 'packages/coding-agent/src/core/tools/read.ts'
PACKAGE = 'packages/coding-agent/package.json'
AI, AGENT = intake.VALIDATOR_PACKAGES
TYPEBOX = {'version': '1.3.27', 'integrity': 'sha512-' + base64.b64encode(b'typebox').decode()}
TARBALL = b'synthetic package tarball'


def manifest(dependencies, **extra):
    return json.dumps({'dependencies': dependencies, **extra}).encode()


BASE_FILES = {
    ARGS: b'if (arg === "--mode") {} else if (arg === "--tools") {} else if (arg === "--no-mcp") {}\n',
    READ: b'export const read = 1;\n',
    PACKAGE: manifest({'@earendil-works/pi-ai': '7.1.0', 'undici': '8.10.2'}, engines={'node': '>=22.19.0'}),
    LOCK: json.dumps({'lockfileVersion': 3, 'packages': {'node_modules/typebox': TYPEBOX}}).encode(),
    AI: manifest({'typebox': '1.3.27'}),
    AGENT: manifest({'typebox': '1.3.27'}),
}
TARGET_FILES = {
    ARGS: b'if (arg === "--mode") {} else if (arg === "--tools") {} else if (arg === "--fresh") {}\n',
    READ: b'export const read = 2;\n',
    PACKAGE: manifest({'@earendil-works/pi-ai': '7.2.0', 'undici': '8.12.3'}, engines={'node': '>=22.19.0'}),
    LOCK: BASE_FILES[LOCK],
    AI: manifest({'@earendil-works/pi-schema': '7.2.0'}),
    AGENT: manifest({'@earendil-works/pi-schema': '7.2.0'}),
}
NOTES = '''## Release

### Breaking Changes

- Tool argument validation moved to a new schema package.

### Fixed

- Fixed the `grep` tool following a config file ([#2](https://example.invalid/2)).
- Fixed a Gemini thinking budget.
  Continued detail.
- Fixed `/tree` sessions in the TUI.
'''


def baseline():
    pins = {path: hashlib.sha256(BASE_FILES[path]).hexdigest() for path in (ARGS, READ, PACKAGE, LOCK)}
    return {'release': BASE, 'upstream_commit': BASE_COMMIT,
            'pins': {'native_tools': pins, 'application_runtime': {READ: pins[READ]}},
            'typebox': dict(TYPEBOX),
            'carried_over': {'required_flags': ['--mode', '--tools', '--no-mcp'],
                             'extra_cli_flags': ['--no-mcp'], 'settlement_aborted': 'required_boolean'}}


class World:
    """A synthetic upstream repository and npm registry on loopback."""

    def __init__(self):
        routes = self.routes = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                status, headers, body = routes.get(self.path, (404, {}, b'{}'))
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.root = f'http://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def json(self, path, value):
        self.routes[path] = (200, {'Content-Type': 'application/json'}, json.dumps(value).encode())

    def raw(self, path, body):
        self.routes[path] = (200, {}, body)

    def upstream(self):
        return intake.Upstream(github_api=self.root + '/api', github_raw=self.root + '/raw',
                               github_web=self.root + '/web', npm_registry=self.root + '/npm', proxies={})

    def populate(self, *, tarball=TARBALL, base_tag_commit=BASE_COMMIT, provenance_commit=TARGET_COMMIT):
        api = '/api/repos/earendil-works/pi/'
        self.json(api + f'git/ref/tags/v{BASE}', {'object': {'type': 'commit', 'sha': base_tag_commit}})
        self.json(api + f'git/ref/tags/v{TARGET}', {'object': {'type': 'tag', 'sha': TAG_OBJECT}})
        self.json(api + f'git/tags/{TAG_OBJECT}', {'object': {'type': 'commit', 'sha': TARGET_COMMIT}})
        for commit, files in ((BASE_COMMIT, BASE_FILES), (TARGET_COMMIT, TARGET_FILES)):
            for path, body in files.items():
                self.raw(f'/raw/earendil-works/pi/{commit}/{path}', body)
        self.json(api + f'contents/{intake.TOOLS_DIR}?ref={BASE_COMMIT}', [{'name': 'read.ts', 'type': 'file'}])
        self.json(api + f'contents/{intake.TOOLS_DIR}?ref={TARGET_COMMIT}',
                  [{'name': 'read.ts', 'type': 'file'}, {'name': 'search.ts', 'type': 'file'},
                   {'name': 'helpers', 'type': 'dir'}])
        self.json(api + 'releases?per_page=100&page=1', [
            {'tag_name': f'v{TARGET}', 'draft': False, 'prerelease': False, 'body': NOTES,
             'published_at': '2026-11-01T00:00:00Z', 'html_url': self.root + '/web/release'},
            {'tag_name': 'v7.2.0-rc.1', 'draft': False, 'prerelease': True, 'body': '- Fixed the `read` tool.'},
            {'tag_name': f'v{BASE}', 'draft': False, 'prerelease': False, 'body': '- Fixed the `edit` tool.'}])
        tarball_path = f'/npm/@earendil-works/pi-coding-agent/-/pi-coding-agent-{TARGET}.tgz'
        attestations_path = f'/npm/-/npm/v1/attestations/pi-coding-agent@{TARGET}'
        self.json(f'/npm/@earendil-works%2Fpi-coding-agent/{TARGET}', {
            'name': '@earendil-works/pi-coding-agent', 'version': TARGET, '_hasShrinkwrap': False,
            'dist': {'tarball': self.root + tarball_path, 'shasum': hashlib.sha1(TARBALL).hexdigest(),
                     'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(TARBALL).digest()).decode(),
                     'attestations': {'url': self.root + attestations_path}}})
        self.raw(tarball_path, tarball)
        statement = {'subject': [{'digest': {'sha512': hashlib.sha512(TARBALL).hexdigest()}}],
                     'predicate': {'buildDefinition': {
                         'externalParameters': {'workflow': {'repository': 'https://github.com/earendil-works/pi',
                                                             'ref': f'refs/tags/v{TARGET}', 'path': 'publish.yml'}},
                         'resolvedDependencies': [{'digest': {'gitCommit': provenance_commit}}]}}}
        self.json(attestations_path, {'attestations': [
            {'predicateType': 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1', 'bundle': {}},
            {'predicateType': 'https://slsa.dev/provenance/v1',
             'bundle': {'dsseEnvelope': {'payload': base64.b64encode(json.dumps(statement).encode()).decode()}}}]})


class PiReleaseIntakeTest(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        self.world.populate()

    def test_packet_reports_drift_contract_findings_and_an_unreviewed_draft(self):
        report, draft = intake.intake(self.world.upstream(), TARGET, baseline())
        files = {item['path']: item for item in report['pinned_files']}
        self.assertEqual({path: item['status'] for path, item in files.items()},
                         {ARGS: 'changed', READ: 'changed', PACKAGE: 'changed', LOCK: 'unchanged'})
        self.assertEqual(files[READ]['pinned_by'], ['application_runtime', 'native_tools'])
        self.assertTrue(files[READ]['diff'].endswith('#diff-' + hashlib.sha256(READ.encode()).hexdigest()))
        self.assertIsNone(files[LOCK]['diff'])
        self.assertEqual((report['base']['pins_reproduced'], report['target']['commit']), (5, TARGET_COMMIT))
        self.assertEqual(report['cli_flags'], {'added': ['--fresh'], 'removed': ['--no-mcp'],
                                               'missing_required': ['--no-mcp']})
        self.assertEqual(report['tools_directory'], {'added': ['search.ts'], 'removed': []})
        self.assertEqual((report['typebox']['status'], report['typebox']['base_reproduced']), ('undeclared', True))
        self.assertEqual(report['dependencies'][AI]['added'], {'@earendil-works/pi-schema': '7.2.0'})
        self.assertEqual(report['dependencies'][PACKAGE]['changed'], {'undici': ['8.10.2', '8.12.3']})
        self.assertEqual(report['dependencies'][PACKAGE]['lockstep'], ['@earendil-works/pi-ai'])
        npm = report['npm']
        self.assertEqual((npm['tarball_check'], npm['tarball_sha256']), ('match', hashlib.sha256(TARBALL).hexdigest()))
        self.assertEqual((npm['provenance']['commits'], npm['provenance']['signature']), ([TARGET_COMMIT], 'not verified'))
        severities = [item['severity'] for item in report['findings']]
        self.assertEqual((severities.count('blocking'), severities.count('contract')), (0, 2))
        self.assertEqual(severities, sorted(severities, key=intake.SEVERITIES.index))
        self.assertEqual([note['release'] for note in report['release_notes']], [TARGET])
        bullets = report['release_notes'][0]['bullets']
        self.assertEqual([bullet['relevant'] for bullet in bullets], [True, True, False, False])
        self.assertEqual(bullets[0]['topics'][:2], ['breaking', 'tools'])
        self.assertTrue(bullets[2]['text'].endswith('Continued detail.'))
        self.assertEqual(draft['status'], 'unreviewed-draft')
        self.assertEqual(draft['native_tool_contracts']['source_pins'][READ], hashlib.sha256(TARGET_FILES[READ]).hexdigest())
        self.assertEqual(draft['application_runtime_contracts']['source_pins'], {READ: hashlib.sha256(TARGET_FILES[READ]).hexdigest()})
        self.assertIsNone(draft['native_tool_contracts']['typebox'])
        self.assertEqual(draft['release_contracts']['carried_over_unreviewed'], baseline()['carried_over'])
        self.assertEqual(len(draft['open_items']), 2)
        packet = intake.render_packet(report)
        for expected in ('## Findings', f'git diff {BASE_COMMIT} {TARGET_COMMIT} --', '(#2)', 'TypeBox pin: undeclared'):
            self.assertIn(expected, packet)
        self.assertNotIn('example.invalid', packet)

    def test_main_writes_three_files_into_a_fresh_directory_only(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(intake, 'reviewed_baseline', return_value=baseline()):
            output = Path(temporary) / 'packet'
            argv = ['--release', 'v' + TARGET, '--base', BASE, '--output-dir', str(output)]
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(intake.main(argv, upstream=self.world.upstream()), 0)
            self.assertEqual(sorted(path.name for path in output.iterdir()),
                             ['draft-contract.json', 'intake.json', 'review-packet.md'])
            self.assertIn('0 blocking, 2 contract findings', stdout.getvalue())
            report = json.loads((output / 'intake.json').read_text(encoding='utf-8'))
            self.assertEqual(report['target']['release'], TARGET)
            self.assertEqual(set(report['repository_mentions']), {'code', 'docs'})
            fetches = len(self.world.routes)
            with redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(intake.main(argv, upstream=self.world.upstream()), 1)
            self.assertIn('fresh output directory', stderr.getvalue())
            self.assertEqual(len(self.world.routes), fetches)

    def test_identity_and_integrity_drift_is_blocking_and_exits_three(self):
        self.world.populate(tarball=b'tampered', base_tag_commit='d' * 40, provenance_commit='e' * 40)
        stale = baseline()
        stale['pins']['native_tools'][ARGS] = '0' * 64
        report, _ = intake.intake(self.world.upstream(), TARGET, stale)
        blocking = [item['text'] for item in report['findings'] if item['severity'] == 'blocking']
        for expected in ('not the reviewed commit', 'do not reproduce', 'does not match the registry integrity',
                         'npm provenance names commits', 'subject digest differs'):
            self.assertTrue(any(expected in text for text in blocking), expected)
        self.assertEqual(report['npm']['tarball_check'], 'mismatch')
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(intake, 'reviewed_baseline', return_value=stale), redirect_stdout(io.StringIO()):
            code = intake.main(['--release', TARGET, '--output-dir', str(Path(temporary) / 'packet')],
                               upstream=self.world.upstream())
        self.assertEqual(code, 3)

    def test_requests_stay_bounded_on_https_and_the_registry(self):
        for url in ('http://example.com/x', 'file:///etc/passwd', 'ftp://example.com/x', 'https://', None):
            with self.assertRaises(intake.IntakeError):
                intake.checked_url(url)
        self.assertEqual(intake.checked_url('http://127.0.0.1:9/x'), 'http://127.0.0.1:9/x')
        upstream = self.world.upstream()
        self.world.routes['/api/redirect'] = (302, {'Location': 'http://example.invalid/'}, b'')
        with self.assertRaisesRegex(intake.IntakeError, 'not HTTPS'):
            upstream.fetch(self.world.root + '/api/redirect', 100)
        with self.assertRaisesRegex(intake.IntakeError, 'outside'):
            upstream.registry_url('https://registry.example.invalid/package.tgz')
        self.world.raw('/raw/large', b'x' * 101)
        with self.assertRaisesRegex(intake.IntakeError, 'exceeds 100 bytes'):
            upstream.fetch(self.world.root + '/raw/large', 100)
        self.assertIsNone(upstream.source(BASE_COMMIT, 'packages/missing.ts'))
        with self.assertRaisesRegex(intake.IntakeError, 'HTTP 404'):
            upstream.fetch(self.world.root + '/api/absent', 100)

    def test_versions_and_output_location_are_checked_before_fetching(self):
        for text in ('7.2', '7.2.0-rc.1', '07.2.0', 'latest', None):
            with self.assertRaises(intake.IntakeError):
                intake.parse_version(text)
        upstream = self.world.upstream()
        with self.assertRaisesRegex(intake.IntakeError, 'not newer'):
            intake.intake(upstream, BASE, baseline())
        self.assertEqual(upstream.requests, 0)
        with self.assertRaisesRegex(intake.IntakeError, 'no reviewed contract'):
            intake.reviewed_baseline('0.0.1')
        for protected in ('skill', 'tests', 'tools'):
            with self.assertRaisesRegex(intake.IntakeError, 'outside'):
                intake._fresh_output(REPOSITORY / protected / 'intake-output')
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(intake.IntakeError, 'fresh output directory'):
                intake._fresh_output(temporary)

    def test_reviewed_baselines_come_from_the_runtime_contracts(self):
        releases = intake.release_contracts.RELEASES
        for release in releases:
            value = intake.reviewed_baseline(release)
            native = intake.native_tool_contracts.contract(release)
            application = intake.application_runtime_contracts.contract(release)
            self.assertEqual(value['pins'], {'native_tools': native['source_pins'],
                                             'application_runtime': application['source_pins']})
            self.assertEqual(value['typebox'], native['typebox'])
            self.assertRegex(value['upstream_commit'], '^[0-9a-f]{40}$')
            self.assertLessEqual(set(value['carried_over']['extra_cli_flags']),
                                 set(value['carried_over']['required_flags']))
        newest = intake.newest_reviewed()
        self.assertIn(newest, releases)
        self.assertTrue(all(intake.parse_version(release) <= intake.parse_version(newest) for release in releases))

    def test_cli_flags_and_release_note_topics(self):
        self.assertEqual(intake.cli_flags(b'arg === "--a" || arg === \'--b-c\' || `--d` "--A" "-x"'),
                         ['--a', '--b-c', '--d'])
        self.assertIsNone(intake.cli_flags(None))
        self.assertEqual(intake.classify('Fixed `--no-mcp` leaving MCP servers connected'), (['cli', 'extensions'], True))
        self.assertEqual(intake.classify('Fixed Gemini thinking levels'), (['models'], False))
        self.assertEqual(intake.classify('Fixed the `read` tool on Windows'), (['tools'], False))
        self.assertEqual(intake.classify('Updated the README'), ([], False))

    def test_repository_mentions_find_exact_release_literals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'skill/runtime').mkdir(parents=True)
            (root / 'skill/runtime/contracts.py').write_text("RELEASES = ('7.1.0',)\nOTHER = '17.1.0'\n")
            (root / 'skill/README.md').write_text('Pi 7.1.0.\nPi 7.1.01 and 7.1.0.5 differ.\n')
            (root / 'skill/MANIFEST.sha256').write_text('7.1.0\n')
            (root / 'tools/validation').mkdir(parents=True)
            (root / 'tools/validation/vendored.py').write_text("'7.1.0'\n")
            (root / 'tests').mkdir()
            (root / 'tests/data.bin').write_bytes(b'\xff\xfe7.1.0')
            found = intake.repository_mentions(root, BASE)
        self.assertEqual(found, {'code': [{'path': 'skill/runtime/contracts.py', 'lines': 1}],
                                 'docs': [{'path': 'skill/README.md', 'lines': 1}]})


if __name__ == '__main__':
    unittest.main()
