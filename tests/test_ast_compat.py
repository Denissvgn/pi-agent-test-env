"""Pinned source rendering remains exact without interpreter empty-list drift."""
import ast
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/qualification'))
from ast_compat import pinned_dump


class ASTCompatibilityTests(unittest.TestCase):
    def test_empty_field_rendering_matches_reviewed_format_without_mutating_input(self):
        tree = ast.parse('def f(): pass'); before = ast.dump(tree, include_attributes=False)
        fields = [(node, node._fields) for node in ast.walk(tree)]
        self.assertEqual(pinned_dump(tree), "Module(body=[FunctionDef(name='f', args=arguments(), body=[Pass()])])")
        self.assertEqual(ast.dump(tree, include_attributes=False), before)
        self.assertTrue(all(node._fields == original for node, original in fields))

    def test_semantic_mutations_never_normalize_to_the_original_pin(self):
        original = ast.parse('def f(x):\n if x > 0:\n  return [x]\n return []')
        for source in ('def f(x):\n if x >= 0:\n  return [x]\n return []',
                       'def f(x):\n if x > 0:\n  return [0]\n return []',
                       'def f(x):\n if x > 0:\n  return []\n return [x]'):
            with self.subTest(source=source):self.assertNotEqual(pinned_dump(original), pinned_dump(ast.parse(source)))


if __name__ == '__main__':
    unittest.main()
