"""Explicit dependency seams preserve validation while bounding SDK reads."""
import json
from pathlib import Path
import sys
from unittest import TestCase, mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import pi_lab
import agent_profiles


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
