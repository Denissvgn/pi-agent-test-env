"""Unit tests for the pinned image inputs, the receipt's base and the validator-version probe.

Docker is mocked throughout. These tests build no image and run no browser.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'runtime'))
import pi_lab as lab
import builder
import release_contracts
import worker

REAL_PROBE_IMAGE = lab.probe_image
DIGEST = re.compile(r'@sha256:[0-9a-f]{64}$')
# Repositories whose images the runner starts from; each reference to one must carry a digest.
IMAGE_REFERENCE = re.compile(r'(?<![\w/.-])((?:docker\.io/)?(?:library/)?(?:node|moby/buildkit|debian|ubuntu|alpine)[:@][^\s\'"`)]*)')
LIMITS = {'cpus': 1.5, 'memory': '2g', 'max_parallelism': 1, 'timeout_seconds': 120}


def latest():
    return release_contracts.RELEASES[-1]


def pinned_capabilities(release=None, **validators):
    release = release or latest()
    entry = release_contracts.entry(release)
    found = {field: [entry[field]['version']] if entry[field] else [] for field in release_contracts.VALIDATOR_PACKAGES}
    found.update(validators)
    return {'pi': release, 'validators': found}


class PinTests(unittest.TestCase):
    def test_pins_file_names_both_images_by_digest(self):
        pins = builder.load_pins()
        self.assertEqual(set(pins), {'base_image', 'buildkit_image'})
        self.assertRegex(pins['base_image'], DIGEST)
        self.assertRegex(pins['buildkit_image'], DIGEST)
        self.assertIn('node:24-', pins['base_image'])

    def test_malformed_pins_are_refused(self):
        good = json.loads((ROOT / 'docker/pins.json').read_text())
        bad_values = [{**good, 'base_image': 'node:24-trixie-slim'},
                      {**good, 'buildkit_image': 'moby/buildkit@sha256:abc'},
                      {**good, 'schema': 2},
                      {k: v for k, v in good.items() if k != 'buildkit_image'},
                      {**good, 'extra': 'x'}]
        for value in bad_values:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'pins.json'
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    builder.load_pins(path)

    def test_no_image_is_named_by_a_mutable_tag_alone(self):
        for name in ('docker/Dockerfile', 'scripts/pi_lab.py', 'scripts/builder.py'):
            for number, line in enumerate((ROOT / name).read_text().splitlines(), 1):
                for reference in IMAGE_REFERENCE.findall(line):
                    self.assertRegex(reference, DIGEST, f'{name}:{number} names {reference} without a digest')
        for number, line in enumerate((ROOT / 'docker/Dockerfile').read_text().splitlines(), 1):
            words = line.split()
            if words and words[0].upper() == 'FROM':
                reference = [w for w in words[1:] if not w.startswith('--')][0]
                self.assertTrue(reference.startswith('${') or DIGEST.search(reference),
                                f'Dockerfile:{number} starts from {reference}')

    def test_the_search_notices_a_tag_only_reference(self):
        self.assertTrue(IMAGE_REFERENCE.findall("default='node:24-trixie-slim'"))
        self.assertTrue(IMAGE_REFERENCE.findall('ARG BASE_IMAGE=node:24-bookworm-slim'))
        self.assertTrue(IMAGE_REFERENCE.findall("'moby/buildkit:buildx-stable-1'"))

    def test_bundled_dockerfile_takes_its_base_from_the_build_argument(self):
        text = (ROOT / 'docker/Dockerfile').read_text()
        self.assertRegex(text, r'(?m)^ARG BASE_IMAGE$')
        self.assertRegex(text, r'(?m)^FROM \$\{BASE_IMAGE\}$')

    def test_no_pin_is_repeated_outside_the_pins_file(self):
        pins = builder.load_pins()
        for name in ('docker/Dockerfile', 'scripts/pi_lab.py', 'scripts/builder.py'):
            text = (ROOT / name).read_text()
            for value in pins.values():
                self.assertNotIn(digest_of(value), text, name)

    def test_the_release_campaign_qualifies_the_pinned_images(self):
        sys.path.insert(0, str(ROOT.parent / 'tools' / 'qualification'))
        import pi_release
        pins = builder.load_pins()
        self.assertEqual((pi_release.BASE, pi_release.BUILDKIT), (pins['base_image'], pins['buildkit_image']))
        for path in (ROOT.parent / 'tools').rglob('*.py'):
            self.assertIsNone(re.search(r'(?:node|buildkit)@sha256:', path.read_text()), path)


def digest_of(reference):
    return reference.rsplit('@', 1)[1]


class DockerfileReferenceTests(unittest.TestCase):
    def test_from_lines_are_listed_as_written(self):
        text = '\n'.join(['# FROM commented:out', 'ARG TAG=1', 'FROM --platform=$BUILDPLATFORM golang:1.22 AS build',
                          'RUN echo FROM nothing', 'from  scratch', 'FROM ${BASE_IMAGE} \\', '  AS final', 'FROM build'])
        self.assertEqual(builder.dockerfile_references(text), ['golang:1.22', 'scratch', '${BASE_IMAGE}', 'build'])

    def test_a_file_without_from_lists_nothing(self):
        self.assertEqual(builder.dockerfile_references('RUN true\n'), [])


class BuildTests(unittest.TestCase):
    def args(self, *extra):
        a = lab.parser().parse_args(['ensure-image', '--uid', '1000', '--pi-version', latest(), *extra])
        a.platform = 'linux/arm64'
        a.resource_report = {'effective': {'build': LIMITS}}
        return a

    def observed(self):
        return {'Id': 'container-fixture', 'Image': 'sha256:fixture', 'HostConfig': {
            'CpuPeriod': 100000, 'CpuQuota': 150000, 'Memory': 2 * 1024 ** 3, 'MemorySwap': 2 * 1024 ** 3}}

    def command(self, buildkit_digests):
        def run(argv, **kw):
            if argv[1:3] == ['image', 'inspect']:
                return argparse.Namespace(stdout=json.dumps([{'Id': 'sha256:buildkit-fixture', 'Os': 'linux',
                                                              'Architecture': 'arm64', 'RepoDigests': buildkit_digests}]))
            out = json.dumps([self.observed()]) if argv[1] == 'inspect' else ''
            return argparse.Namespace(returncode=0, stderr='', stdout=out)
        return mock.Mock(side_effect=run)

    def build(self, a, dockerfile):
        cmd = self.command(['moby/buildkit@sha256:' + 'b' * 64])
        with mock.patch.object(builder.subprocess, 'run', return_value=argparse.Namespace(returncode=0)):
            return builder.limited_build(a, dockerfile, dockerfile.parent, cmd), cmd

    def test_bundled_build_passes_the_pinned_base_and_pulls_the_pinned_buildkit(self):
        pins = builder.load_pins()
        receipt, cmd = self.build(self.args(), ROOT / 'docker/Dockerfile')
        self.assertIn('BASE_IMAGE=' + pins['base_image'], receipt['argv'])
        pulls = [c.args[0] for c in cmd.call_args_list if c.args[0][1] == 'pull']
        self.assertEqual(pulls, [['docker', 'pull', '--platform', 'linux/arm64', pins['buildkit_image']]])
        self.assertEqual(receipt['buildkit']['image'], pins['buildkit_image'])
        self.assertEqual(receipt['buildkit']['digest'], digest_of(pins['buildkit_image']))
        self.assertEqual(receipt['buildkit']['id'], 'sha256:buildkit-fixture')
        self.assertEqual(receipt['buildkit']['repo_digests'], ['moby/buildkit@sha256:' + 'b' * 64])

    def test_explicit_images_override_the_pins(self):
        base, buildkit = 'node@sha256:' + 'c' * 64, 'moby/buildkit@sha256:' + 'd' * 64
        receipt, cmd = self.build(self.args('--base-image', base, '--buildkit-image', buildkit), ROOT / 'docker/Dockerfile')
        self.assertIn('BASE_IMAGE=' + base, receipt['argv'])
        self.assertEqual(receipt['buildkit']['image'], buildkit)

    def test_own_dockerfile_is_passed_no_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('ARG BASE_IMAGE=elsewhere:1\nFROM ${BASE_IMAGE}\n')
            receipt, _ = self.build(self.args(), dockerfile)
        self.assertFalse([word for word in receipt['argv'] if word.startswith('BASE_IMAGE=')])

    def custom(self, text, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text(text)
            return self.build(self.args(*extra), dockerfile)[0]

    def test_an_explicit_base_is_still_forwarded_to_an_own_dockerfile(self):
        for text in ('FROM python:3.12-slim\n', 'ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n'):
            with self.subTest(text=text):
                receipt = self.custom(text, '--base-image', 'node@sha256:' + 'c' * 64)
                self.assertIn('BASE_IMAGE=node@sha256:' + 'c' * 64, receipt['argv'])

    def test_the_resolved_base_of_an_own_dockerfile_never_adopts_the_argument(self):
        argument = 'node@sha256:' + 'c' * 64
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            cases = [('FROM python:3.12-slim AS build\nFROM build\n', ['python:3.12-slim', 'build'], False),
                     ('ARG BASE_IMAGE=elsewhere:1\nFROM ${BASE_IMAGE}\n', ['${BASE_IMAGE}'], True),
                     ('ARG BASE_IMAGE\nFROM $BASE_IMAGE AS app\n', ['$BASE_IMAGE'], True),
                     ('ARG BASE_IMAGE_OTHER\nFROM ${BASE_IMAGE_OTHER}\n', ['${BASE_IMAGE_OTHER}'], False)]
            for text, references, used in cases:
                dockerfile.write_text(text)
                with self.subTest(text=text):
                    base = builder.resolve_base(self.args('--base-image', argument), dockerfile)
                    self.assertEqual((base['image'], base['source'], base['references']),
                                     (None, 'dockerfile', references))
                    self.assertEqual((base['argument'], base['argument_in_from']), (argument, used))
                    base = builder.resolve_base(self.args(), dockerfile)
                    self.assertEqual((base['image'], base['argument'], base['argument_in_from']), (None, None, None))

    def test_an_unreadable_pins_file_stops_the_build_before_docker(self):
        with mock.patch.object(builder, 'PINS_FILE', Path('/nonexistent/pins.json')), \
             mock.patch.object(builder.subprocess, 'run') as build:
            cmd = self.command([])
            with self.assertRaises(ValueError):
                builder.limited_build(self.args(), ROOT / 'docker/Dockerfile', ROOT / 'docker', cmd)
            build.assert_not_called()


class ReceiptTests(unittest.TestCase):
    def args(self, *extra):
        a = lab.parser().parse_args(['ensure-image', '--policy', 'build', '--uid', '1000',
                                     '--pi-version', latest(), *extra])
        a.platform = 'linux/arm64'
        return a

    def ensure(self, a, build_receipt=None):
        probe = {'id': 'sha256:unit', 'repo_digests': [], 'capabilities': {**pinned_capabilities(),
                                                                              'package_list_sha256': 'a' * 64}}
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', return_value=probe), \
             mock.patch.object(lab, 'limited_build', return_value=build_receipt or {'argv': ['fixture']}):
            return lab.ensure_image(a)

    def test_bundled_receipt_names_the_pinned_base_and_buildkit(self):
        pins = builder.load_pins()
        buildkit = {'image': pins['buildkit_image'], 'digest': digest_of(pins['buildkit_image']),
                    'id': 'sha256:buildkit-fixture', 'repo_digests': []}
        receipt = self.ensure(self.args(), {'argv': ['fixture'], 'buildkit': buildkit})
        self.assertEqual(receipt['base_image'], pins['base_image'])
        self.assertEqual(receipt['base_source'], 'pins')
        self.assertEqual(receipt['base_digest'], digest_of(pins['base_image']))
        self.assertIsNone(receipt['base_references'])
        self.assertEqual(receipt['buildkit'], buildkit)
        self.assertEqual(receipt['package_list_sha256'], 'a' * 64)
        self.assertEqual(receipt['id'], 'sha256:unit')

    def test_receipt_falls_back_to_the_pinned_buildkit_reference(self):
        receipt = self.ensure(self.args())
        pins = builder.load_pins()
        self.assertEqual(receipt['buildkit']['image'], pins['buildkit_image'])
        self.assertEqual(receipt['buildkit']['digest'], digest_of(pins['buildkit_image']))

    def test_receipt_of_an_own_dockerfile_has_no_base_image_and_lists_its_from_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM python:3.12-slim AS build\nFROM --platform=linux/arm64 node:24 AS final\n'
                                  'FROM final\n')
            receipt = self.ensure(self.args('--dockerfile', str(dockerfile)))
        self.assertIsNone(receipt['base_image'])
        self.assertEqual(receipt['base_source'], 'dockerfile')
        self.assertEqual(receipt['base_references'], ['python:3.12-slim', 'node:24', 'final'])
        self.assertIsNone(receipt['base_digest'])

    def test_explicit_base_is_recorded_as_an_argument(self):
        base = 'node@sha256:' + 'c' * 64
        receipt = self.ensure(self.args('--base-image', base))
        self.assertEqual((receipt['base_image'], receipt['base_source']), (base, 'argument'))
        self.assertEqual(receipt['base_digest'], digest_of(base))

    def test_an_argument_a_literal_from_ignores_is_not_the_base(self):
        argument = 'node@sha256:' + 'c' * 64
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM python:3.12-slim\n')
            receipt = self.ensure(self.args('--dockerfile', str(dockerfile), '--base-image', argument))
        self.assertIsNone(receipt['base_image'])
        self.assertIsNone(receipt['base_digest'])
        self.assertEqual(receipt['base_source'], 'dockerfile')
        self.assertEqual(receipt['base_references'], ['python:3.12-slim'])
        self.assertEqual(receipt['base_argument'], argument)
        self.assertIs(receipt['base_argument_in_from'], False)

    def test_an_argument_a_from_line_uses_is_supplied_but_the_base_stays_unknown(self):
        argument = 'node@sha256:' + 'c' * 64
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('ARG BASE_IMAGE=elsewhere:1\nFROM ${BASE_IMAGE}\n')
            receipt = self.ensure(self.args('--dockerfile', str(dockerfile), '--base-image', argument))
            plain = self.ensure(self.args('--dockerfile', str(dockerfile)))
        self.assertIsNone(receipt['base_image'])
        self.assertEqual((receipt['base_source'], receipt['base_references']), ('dockerfile', ['${BASE_IMAGE}']))
        self.assertEqual((receipt['base_argument'], receipt['base_argument_in_from']), (argument, True))
        self.assertEqual((plain['base_argument'], plain['base_argument_in_from']), (None, None))

    def test_reused_image_receipt_records_the_package_list_hash(self):
        a = lab.parser().parse_args(['ensure-image', '--policy', 'reuse', '--uid', '1000', '--image', 'unit:core'])
        probe = {'id': 'sha256:unit', 'capabilities': {**pinned_capabilities(), 'package_list_sha256': 'e' * 64}}
        with mock.patch.object(lab, 'require_host', return_value={}), mock.patch.object(lab, 'probe_image', return_value=probe):
            receipt = lab.ensure_image(a)
        self.assertEqual(receipt['package_list_sha256'], 'e' * 64)

    def test_the_parser_defaults_come_from_the_pins_not_from_a_tag(self):
        a = lab.parser().parse_args(['ensure-image', '--uid', '1000'])
        self.assertIsNone(a.base_image)
        self.assertIsNone(a.buildkit_image)


class ValidatorAdmissionTests(unittest.TestCase):
    def admit(self, capabilities):
        return lab.admit_image({'capabilities': capabilities})

    def test_installed_pins_are_admitted(self):
        for release in release_contracts.RELEASES:
            with self.subTest(release=release):
                self.assertEqual(self.admit(pinned_capabilities(release))['release'], release)

    def test_mismatched_typebox_is_rejected_as_image_incompatible(self):
        with self.assertRaises(lab.LabError) as caught:
            self.admit(pinned_capabilities(typebox=['1.3.28']))
        self.assertEqual(caught.exception.reason, 'image-incompatible')
        self.assertIn('typebox 1.3.28', str(caught.exception))
        self.assertIn('1.3.27', str(caught.exception))
        self.assertTrue(caught.exception.remedy)

    def test_mismatched_pi_schema_is_rejected_where_the_release_pins_it(self):
        pinned = [r for r in release_contracts.RELEASES if release_contracts.entry(r)['pi_schema']]
        self.assertTrue(pinned)
        with self.assertRaises(lab.LabError) as caught:
            self.admit(pinned_capabilities(pinned[-1], pi_schema=['1.5.1']))
        self.assertEqual(caught.exception.reason, 'image-incompatible')
        self.assertIn('pi-schema', str(caught.exception))

    def test_a_missing_or_extra_copy_is_rejected(self):
        entry = release_contracts.entry(latest())
        version = entry['typebox']['version']
        for found in ([], [version, '9.9.9']):
            with self.subTest(found=found), self.assertRaises(lab.LabError) as caught:
                self.admit(pinned_capabilities(typebox=found))
            self.assertEqual(caught.exception.reason, 'image-incompatible')

    def test_a_package_the_release_does_not_pin_is_not_checked(self):
        unpinned = [r for r in release_contracts.RELEASES if release_contracts.entry(r)['pi_schema'] is None]
        self.assertTrue(unpinned)
        self.assertEqual(self.admit(pinned_capabilities(unpinned[0], pi_schema=['0.0.1']))['release'], unpinned[0])

    def test_an_unreadable_report_is_rejected(self):
        with self.assertRaises(lab.LabError) as caught:
            self.admit({'pi': latest(), 'validators': 'typebox 1.3.27'})
        self.assertEqual(caught.exception.reason, 'image-incompatible')
        broken = pinned_capabilities()
        broken['validators']['typebox'] = None
        with self.assertRaises(lab.LabError):
            self.admit(broken)

    def test_an_unsupported_release_keeps_its_own_reason(self):
        with self.assertRaises(lab.LabError) as caught:
            self.admit({'pi': '0.0.1', 'validators': {}})
        self.assertEqual(caught.exception.reason, 'unsupported-pi-release')

    def test_the_reason_is_attributed_to_the_caller_and_has_a_remedy(self):
        import diagnostics
        import outcomes
        self.assertEqual(outcomes.blocked_attribution('image-incompatible'), 'configuration')
        self.assertIn('image-incompatible', diagnostics.REMEDIES)
        self.assertIn('`image-incompatible`', (ROOT / 'references/EVALUATION-CONTRACT.md').read_text())

    def test_registry_identities_are_unchanged_by_the_new_check(self):
        before = copy.deepcopy(release_contracts.snapshot())
        release_contracts.validate_validators(pinned_capabilities()['validators'], latest())
        self.assertEqual(release_contracts.snapshot(), before)


class LiveProbeTests(unittest.TestCase):
    """A fresh probe must carry the validator observation; saved receipts are read as before."""

    def probe(self, capabilities):
        """Run the real probe_image with only the Docker layer replaced by one probe answer."""
        def stream(argv, logdir, timeout, name, **kw):
            logdir.mkdir(parents=True, exist_ok=True)
            (logdir / 'stdout.jsonl').write_text(capabilities if isinstance(capabilities, str) else json.dumps(capabilities))
            return {'exit_code': 0}
        args = argparse.Namespace(profile='core', uid=1000, platform='linux/arm64', environment=None)
        with tempfile.TemporaryDirectory() as home, \
             mock.patch.object(lab.Path, 'home', return_value=Path(home)), \
             mock.patch.object(lab, 'image_info', return_value={'id': 'sha256:fresh', 'reference': 'unit:core'}), \
             mock.patch.object(lab, 'control_channels'), mock.patch.object(lab, 'state_dir'), \
             mock.patch.object(lab, 'docker_args', return_value=['docker', 'run']), \
             mock.patch.object(lab, 'stream_run', side_effect=stream):
            return REAL_PROBE_IMAGE(args, 'unit:core')

    def test_an_omitted_observation_is_refused(self):
        capabilities = pinned_capabilities()
        del capabilities['validators']
        with self.assertRaises(lab.LabError) as caught:
            self.probe(capabilities)
        self.assertEqual(caught.exception.reason, 'image-incompatible')
        self.assertIn('did not report', str(caught.exception))
        self.assertTrue(caught.exception.remedy)

    def test_a_malformed_observation_is_refused(self):
        good = pinned_capabilities()['validators']
        malformed = [None, 'typebox 1.3.27', [], {}, {'typebox': good['typebox']},
                     {**good, 'extra': []}, {**good, 'typebox': '1.3.27'}, {**good, 'pi_schema': None},
                     {**good, 'typebox': [1]}]
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(lab.LabError) as caught:
                self.probe({'pi': latest(), 'validators': value})
            self.assertEqual(caught.exception.reason, 'image-incompatible')

    def test_a_capability_report_that_is_not_an_object_is_refused(self):
        with self.assertRaises(lab.LabError) as caught:
            self.probe('[]')
        self.assertEqual(caught.exception.reason, 'image-incompatible')

    def test_correct_evidence_is_admitted(self):
        for release in release_contracts.RELEASES:
            with self.subTest(release=release):
                image = self.probe(pinned_capabilities(release))
                self.assertEqual(lab.admit_image(image)['release'], release)

    def test_a_version_mismatch_passes_the_probe_but_not_admission(self):
        image = self.probe(pinned_capabilities(typebox=['1.3.28']))
        with self.assertRaises(lab.LabError) as caught:
            lab.admit_image(image)
        self.assertEqual(caught.exception.reason, 'image-incompatible')
        self.assertIn('typebox 1.3.28', str(caught.exception))

    def test_ensure_image_does_not_admit_an_image_whose_probe_omits_the_evidence(self):
        capabilities = pinned_capabilities()
        del capabilities['validators']
        args = ReceiptTests().args()
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'limited_build', return_value={'argv': ['fixture']}), \
             mock.patch.object(lab, 'probe_image', side_effect=lambda a, i: self.probe(capabilities)):
            with self.assertRaises(lab.LabError) as caught:
                lab.ensure_image(args)
        self.assertEqual(caught.exception.reason, 'image-incompatible')

    def test_saved_receipts_without_the_observation_are_still_read(self):
        capabilities = pinned_capabilities()
        del capabilities['validators']
        self.assertEqual(lab.admit_image({'capabilities': capabilities})['release'], latest())
        self.assertEqual(lab.admit_image({'capabilities': {'pi': latest()}}, latest())['release'], latest())


class WorkerProbeTests(unittest.TestCase):
    def package(self, root, parts, name, version):
        folder = root.joinpath(*parts, 'node_modules', *name.split('/'))
        folder.mkdir(parents=True)
        (folder / 'package.json').write_text(json.dumps({'name': name, 'version': version}))

    def test_installed_versions_finds_hoisted_and_nested_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / 'lib'
            self.package(lib, [], 'typebox', '1.3.27')
            self.package(lib, ['node_modules', '@earendil-works', 'pi-coding-agent'], 'typebox', '1.3.28')
            self.package(lib, ['node_modules', '@earendil-works', 'pi-coding-agent'], '@earendil-works/pi-schema', '1.5.2')
            self.package(lib, [], 'typebox-extra', '2.0.0')
            root = lib / 'node_modules'
            self.assertEqual(worker.installed_versions(root, 'typebox'), ['1.3.27', '1.3.28'])
            self.assertEqual(worker.installed_versions(root, '@earendil-works/pi-schema'), ['1.5.2'])
            self.assertEqual(worker.installed_versions(root, 'absent'), [])

    def test_a_package_whose_name_differs_is_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / 'lib'
            self.package(lib, [], 'typebox', '1.3.27')
            (lib / 'node_modules/typebox/package.json').write_text(json.dumps({'name': 'other', 'version': '1.0.0'}))
            self.assertEqual(worker.installed_versions(lib / 'node_modules', 'typebox'), [])

    def test_validator_versions_follow_the_resolved_pi_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / 'lib'
            self.package(lib, [], 'typebox', '1.3.27')
            script = lib / 'node_modules/@earendil-works/pi-coding-agent/dist/cli.js'
            script.parent.mkdir(parents=True)
            script.write_text('')
            link = Path(tmp) / 'bin-pi'
            link.symlink_to(script)
            with mock.patch.object(worker.shutil, 'which', return_value=str(link)):
                found = worker.validator_versions()
        self.assertEqual(found, {'typebox': ['1.3.27'], 'pi_schema': []})

    def test_the_probe_reports_validators_and_the_package_list_hash(self):
        answers = {'node': 'v24.1.0', 'npm': '11.0.0', 'pi': latest(), 'git': 'git version 2', 'bash': 'GNU bash', 'rg': 'ripgrep 14'}
        def execute(argv, **kw):
            if argv[0] in answers:
                flags = ' '.join(release_contracts.contract(latest())['required_flags'])
                return flags if argv[1] == '--help' else answers[argv[0]]
            return 'unused'
        emitted = []
        with mock.patch.object(worker, 'execute', side_effect=execute), \
             mock.patch.object(worker.shutil, 'which', return_value='/usr/bin/x'), \
             mock.patch.object(worker, 'validator_versions', return_value=pinned_capabilities()['validators']), \
             mock.patch.object(worker, 'package_list_sha256', return_value='f' * 64), \
             mock.patch.object(worker, 'os_release', return_value={'version_codename': 'trixie'}), \
             mock.patch.object(worker, 'tmp_observation', return_value={}), \
             mock.patch.object(worker, 'emit', side_effect=emitted.append):
            worker.probe('core')
        self.assertEqual(emitted[0]['validators'], pinned_capabilities()['validators'])
        self.assertEqual(emitted[0]['package_list_sha256'], 'f' * 64)
        self.assertEqual(emitted[0]['os_release'], {'version_codename': 'trixie'})

    def test_package_list_hash_is_order_independent_and_absent_without_dpkg(self):
        with mock.patch.object(worker.shutil, 'which', return_value='/usr/bin/dpkg-query'), \
             mock.patch.object(worker, 'execute', return_value='ii \tb\t1\tarm64\nii \ta\t2\tarm64'):
            first = worker.package_list_sha256()
        with mock.patch.object(worker.shutil, 'which', return_value='/usr/bin/dpkg-query'), \
             mock.patch.object(worker, 'execute', return_value='ii \ta\t2\tarm64\nii \tb\t1\tarm64\n'):
            self.assertEqual(worker.package_list_sha256(), first)
        self.assertRegex(first, '^[0-9a-f]{64}$')
        with mock.patch.object(worker.shutil, 'which', return_value=None):
            self.assertIsNone(worker.package_list_sha256())

    def test_package_list_hash_is_of_the_sorted_installed_package_lines(self):
        import hashlib
        listing = 'ii \tzlib1g\t1:1.3\tarm64\nrc \told\t1\tarm64\nhi \tbash\t5.2\tarm64\nun \tgone\t\t'
        with mock.patch.object(worker.shutil, 'which', return_value='/usr/bin/dpkg-query'), \
             mock.patch.object(worker, 'execute', return_value=listing) as run:
            digest = worker.package_list_sha256()
        self.assertEqual(digest, hashlib.sha256(b'bash\t5.2\tarm64\nzlib1g\t1:1.3\tarm64').hexdigest())
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ['dpkg-query', '-W', '-f'])
        self.assertEqual(argv[3], '${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n')

    def test_unusable_dpkg_evidence_is_a_specific_error_never_a_digest(self):
        good = 'ii \ta\t1\tarm64'
        cases = {
            'installed row without a version': (good + '\nii \tb\t\tarm64', 'row 2.*installed package'),
            'installed row without an architecture': (good + '\nii \tb\t1', 'row 2.*installed package'),
            'installed row with an extra field': (good + '\nii \tb\t1\tarm64\textra', 'row 2.*installed package'),
            'row with no tabs': ('ii b 1 arm64', 'row 1.*status column'),
            'status column of the wrong width': (good + '\ni\tb\t1\tarm64', 'row 2.*status column'),
            'status garbage': ('synthetic version', 'row 1.*status column'),
            'empty output': ('', 'no installed packages'),
            'only removed packages': ('rc \told\t1\tarm64', 'no installed packages'),
        }
        for name, (listing, message) in cases.items():
            with self.subTest(name), \
                 mock.patch.object(worker.shutil, 'which', return_value='/usr/bin/dpkg-query'), \
                 mock.patch.object(worker, 'execute', return_value=listing):
                with self.assertRaisesRegex(RuntimeError, message):
                    worker.package_list_sha256()

    def test_a_stripped_final_row_for_a_package_that_is_not_installed_is_accepted(self):
        # execute() strips trailing blanks, so a last `un` row can arrive without its tabs.
        import hashlib
        with mock.patch.object(worker.shutil, 'which', return_value='/usr/bin/dpkg-query'), \
             mock.patch.object(worker, 'execute', return_value='ii \ta\t1\tarm64\nun \tgone'):
            digest = worker.package_list_sha256()
        self.assertEqual(digest, hashlib.sha256(b'a\t1\tarm64').hexdigest())


if __name__ == '__main__':
    unittest.main()
