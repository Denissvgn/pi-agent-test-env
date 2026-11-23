import argparse
import os
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'skill' / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import pi_lab


BUILTIN_COMMANDS = (
    'env', 'doctor', 'ensure-image', 'preflight', 'smoke', 'run', 'status', 'validate-plan',
    'extend-budget', 'steer', 'patch-session', 'secrets',
    'validate-experiment', 'experiment-prepare', 'experiment-run', 'experiment-resume',
    'experiment-export', 'experiment-report',
    'validate-agent-profile', 'browser-check', 'pr-review-gate',
    'compile-application-plan', 'registry-inspect', 'registry-recover',
    'application-owner-inspect', 'application-owner-recover', 'leftovers', 'cleanup',
)
EXPERIMENTAL_COMMANDS = {
    'compile-application-plan', 'registry-inspect', 'registry-recover',
    'application-owner-inspect', 'application-owner-recover', 'leftovers', 'cleanup',
}


class CommandHelpTests(unittest.TestCase):
    def test_all_subcommands_and_arguments_have_help(self):
        def check_parser(parser, path):
            with self.subTest(command=path):
                # Render the help so invalid argparse interpolation also fails.
                self.assertTrue(parser.format_help())
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    rows = action._get_subactions()
                    documented = {action.choices[row.dest] for row in rows}
                    with self.subTest(command=path):
                        missing = [name for name, child in action.choices.items() if child not in documented]
                        self.assertEqual(missing, [], 'Subcommands missing help')
                        self.assertEqual(action.metavar, 'COMMAND')
                    for row in rows:
                        with self.subTest(command=(*path, row.dest)):
                            self.assertTrue((row.help or '').strip(), 'Subcommand has empty help')
                            self.assertNotEqual(row.help, argparse.SUPPRESS, 'Subcommand help is hidden')
                    for name, child in action.choices.items():
                        check_parser(child, (*path, name))
                else:
                    with self.subTest(command=path, argument=action.option_strings or action.dest):
                        self.assertTrue((action.help or '').strip(), 'Argument has empty help')
                        self.assertNotEqual(action.help, argparse.SUPPRESS, 'Argument help is hidden')

        check_parser(pi_lab.parser(), ())

    def test_root_help_lists_builtin_commands_on_one_line_each(self):
        with patch.dict(os.environ, {'COLUMNS': '80'}):
            help_text = pi_lab.parser().format_help()

        self.assertIn('[-h] [--version] COMMAND ...', help_text)
        rows = re.findall(r'^    ([\w-]+) {2,}(\S.*)$', help_text, re.MULTILINE)
        builtin_rows = [(name, description) for name, description in rows if name in BUILTIN_COMMANDS]
        self.assertEqual(tuple(name for name, _ in builtin_rows), BUILTIN_COMMANDS)
        for name, description in builtin_rows:
            with self.subTest(command=name):
                self.assertEqual(description.endswith('(experimental)'), name in EXPERIMENTAL_COMMANDS)

    def test_help_describes_reviewed_pi_limits(self):
        root = pi_lab.parser()
        commands = next(action.choices for action in root._actions if isinstance(action, argparse._SubParsersAction))
        for name in ('run', 'smoke'):
            with self.subTest(command=name):
                self.assertIn('Every reviewed Pi release rejects process-exit.',
                              ' '.join(commands[name].format_help().split()))
        env_commands = next(action.choices for action in commands['env']._actions
                            if isinstance(action, argparse._SubParsersAction))
        self.assertIn('No reviewed Pi release accepts a numeric budget.',
                      ' '.join(env_commands['save'].format_help().split()))


if __name__ == '__main__':
    unittest.main()
