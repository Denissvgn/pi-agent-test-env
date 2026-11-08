"""Explicit dependency seams preserve validation while bounding SDK reads."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
from unittest import TestCase, mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import pi_lab
import agent_profiles
from operation_sdk import collect, policy, source, wire, worker
from tests.test_operation_sdk_policy import digest, example_policy, example_request


def plan(schema=1):
    value = {'schema': schema, 'agents': [{'name': 'check', 'prompt_file': 'prompt.txt',
              'tools': ['read'], 'require_tools': ['read']}], 'checks': [{'argv': ['true']}]}
    if schema == 2: value['inference_bindings'] = 'external'
    return value


class LegacyReadSeamTests(TestCase):
    def test_prompt_dependency_is_bounded_before_read_and_schema2_recursion_preserves_reader(self):
        for schema in (1, 2):
            reads = []
            def reader(path, maximum):
                reads.append((str(path), maximum)); return b'Bounded fake prompt'
            with mock.patch.object(Path, 'read_text', side_effect=AssertionError('unguarded prompt read')):
                normalized = pi_lab.validate_plan(plan(schema), Path('/approved/project'),
                    external_bindings=True, dependency_reader=reader)
            self.assertEqual(reads, [('/approved/project/prompt.txt', 128 * 1024)])
            self.assertEqual(normalized['agents'][0]['prompt'], 'Bounded fake prompt')
            self.assertEqual(normalized['schema'], schema)

    def test_bad_prompt_relative_path_never_reaches_the_scoped_reader(self):
        for name in ('../outside', '/outside', 'prompt.txt\0'):
            value = plan(); value['agents'][0]['prompt_file'] = name
            reader = mock.Mock(side_effect=AssertionError('escaping private lookup'))
            with self.subTest(name=name), self.assertRaises(pi_lab.LabError):
                pi_lab.validate_plan(value, Path('/approved/project'), dependency_reader=reader)
            reader.assert_not_called()

    def test_profile_loader_uses_the_explicit_reader_without_an_unguarded_lookup(self):
        reads = []
        def reader(path, maximum):
            reads.append((str(path), maximum)); return json.dumps(agent_profiles.builtin()).encode()
        with (mock.patch.object(Path, 'is_symlink', side_effect=AssertionError('unguarded profile metadata')),
              mock.patch.object(Path, 'resolve', side_effect=AssertionError('unguarded profile resolution'))):
            result = agent_profiles.load(Path('/approved/profile.json'), reader=reader)
        self.assertEqual(result, agent_profiles.builtin())
        self.assertEqual(reads, [('/approved/profile.json', 1024 * 1024)])

    def test_project_metadata_is_a_separate_explicit_gate(self):
        normalized = pi_lab.validate_plan({'schema': 1, 'agents': [{'prompt': 'fake'}],
                                           'checks': [{'argv': ['true']}], 'required_paths': ['data']}, Path('/approved'))
        reader = mock.Mock(side_effect=lambda path, kind: str(path) in ('/approved/data', '/approved'))
        with (mock.patch.object(Path, 'exists', side_effect=AssertionError('unguarded project existence')),
              mock.patch.object(Path, 'resolve', side_effect=AssertionError('unguarded project resolution'))):
            pi_lab.check_project_contract(Path('/approved'), normalized, metadata_reader=reader)
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(reader.call_args_list[0].args, (Path('/approved/data'), 'exists'))


class NarrowDependencyCapTests(TestCase):
    """A narrower admitted cap binds fixed provider requests instead of refusing them."""
    def legacy(self, cap, prompt=b'Inspect the fixture', grant=4096):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve() / 'project'; project.mkdir(); os.chmod(project, 0o755)
            path = project / 'prompt.txt'; path.write_bytes(prompt)
            value = example_policy('plan_validate_legacy_v1')
            value['scope'].update(base=str(project), dependencies=[{'path': str(path), 'role': 'prompt',
                'sha256': hashlib.sha256(prompt).hexdigest(), 'maximum_bytes': grant}])
            value['limits'].update(max_dependency_file_bytes=cap, max_dependency_bytes=cap)
            admitted = policy.compile_admission(value, example_request(value),
                trusted_policy_sha256=digest(value), now_ns=100)
            provider = types.SimpleNamespace(module={'agent_profiles': agent_profiles, 'pi_lab': pi_lab}.__getitem__)
            with mock.patch.object(source.os, 'fstatvfs', return_value=mock.Mock(f_flag=os.ST_RDONLY)):
                return worker._legacy(provider, admitted, plan(), collect.Patterns([], value['limits']))

    def test_prompt_loads_when_cap_is_below_the_fixed_prompt_request(self):
        # pi_lab requests 128 KiB for every prompt file; policies may admit far less.
        for cap in (128 * 1024 - 1, 65536, 4096):
            with self.subTest(cap=cap):
                normalized, checks = self.legacy(cap)
                self.assertEqual(normalized['agents'][0]['prompt'], 'Inspect the fixture')
                self.assertEqual(checks['dependencies_read'], 1)

    def test_file_larger_than_its_grant_is_still_refused_not_truncated(self):
        with self.assertRaises(wire.SDKError):
            self.legacy(4096, grant=8)
