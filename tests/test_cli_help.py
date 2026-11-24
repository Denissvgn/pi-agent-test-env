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


NO_VALUE = 'the parser default is None or empty, and the text names what the code does instead'
HOST_VALUE = 'the parser default is computed from the host or resource policy at run time'
FLAG_OFF = 'a boolean flag whose off state the text describes in words'

# Stated defaults that do not name the parser's value. A "(default: ...)" clause
# whose first word does not state the parser default must be listed here with
# the reason it describes rather than states that default.
DESCRIPTIVE_DEFAULTS = {
    NO_VALUE: (
        'built-in profile', 'empty built-in profile', 'keep plan values', 'keep the timeout',
        'keep the token ceiling', 'keep the ceiling', 'keep the turn ceiling',
        'no extra packages', 'no explicit expectation', 'no named checks', 'no named reviewer',
        'no receipt file', 'no explicit level', 'no overrides', 'no retry', 'no additional images',
        'no revision check', 'the digest-pinned reference in docker/pins.json', 'Dockerfile directory',
        'bundled Dockerfile', 'PI_LAB_CATALOG_DIR or per-user catalog', 'PI_LAB_SECRETS_DIR or per-user store',
        'PI_LAB_SESSION', 'PI_LAB_SESSION, if set', 'leave session approvals in place',
        'saved endpoint', 'saved environment', 'saved environment, if present',
        'saved, session-confirmed environment', 'explicit endpoint or saved environment',
        'use the endpoint or saved environment', 'use the saved environment', 'baseline only',
        'built-in exclusions only', 'skip the scan', 'validate the plan on its own',
        'bindings from a schema-2 plan, or direct inference for a schema-1 plan',
        'hidden terminal prompt unless --from-file is set', 'endpoint key or PI_API_KEY',
        '--base-url', 'active stage', 'active stage selection', 'active stage, if any',
        'latest run in --results-dir', 'all runs', 'relative --file path or its basename',
    ),
    HOST_VALUE: (
        'resource policy', 'built-in resource policy', 'native Docker platform',
        'PI_LAB_LOCK_FILE or shared per-user lease', 'per-user runs directory',
        'host GID, or 1000 if unavailable', 'host UID, or 1000 if unavailable',
        '2 CPUs, 4 GiB, 256 PIDs, and 2 jobs for runtime. CPU and memory are capped at half '
        'the Docker allocation by default.',
    ),
    FLAG_OFF: (
        'require a key', 'verify before saving', 'check when confirmed', 'also test chat',
        'metadata only', 'skip it', 'inspect image metadata only', 'probe when a key is available',
        'fail without prompting', 'list models only', 'text only', 'use an isolated copy',
        'show helper records', 'keep the workspace', 'report only', 'full ledger',
        'queue without interrupting', 'skip scoring after cancellation', 'deny check networking',
        'deny setup networking', 'refuse both', 'no extra host mapping',
        'disabled unless requested by --reasoning-level', 'hidden terminal prompt unless --stdin is set',
        'keep the current selection',
    ),
}


def _literal_forms(default):
    """Spellings that state this parser default literally, compared case-insensitively."""
    if default is None:
        return {'none', 'unset'}
    if default is False:
        return {'off', 'disabled', 'false'}
    if default is True:
        return {'on', 'enabled', 'true'}
    if default in ('', []):
        return {'none', 'empty'}
    return {str(default)}


def _stated_defaults(parser, path=()):
    """Yield (command, action, clause) for each rendered "(default: ...)" clause, nested commands included."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from _stated_defaults(child, (*path, name))
            continue
        if isinstance(action, (argparse._HelpAction, argparse._VersionAction)) or not action.help:
            continue
        text = parser._get_formatter()._expand_help(action)
        for match in re.finditer(r'\(default: ([^)]*)\)', text):
            yield ' '.join(path) or 'pi_lab', action, match.group(1)


def _parser_at(path):
    parser = pi_lab.parser()
    for name in path:
        parser = next(action for action in parser._actions
                      if isinstance(action, argparse._SubParsersAction)).choices[name]
    return parser


def _action_and_help(path, option):
    parser = _parser_at(path)
    action = next(action for action in parser._actions if option in action.option_strings)
    return action, parser._get_formatter()._expand_help(action)


class StatedDefaultTests(unittest.TestCase):
    def test_stated_defaults_match_the_parser_or_are_listed_descriptions(self):
        listed = {clause for group in DESCRIPTIVE_DEFAULTS.values() for clause in group}
        problems, used = [], set()
        for command, action, clause in _stated_defaults(pi_lab.parser()):
            head = re.split(r'[,;]', clause, maxsplit=1)[0].strip().lower()
            if head in {form.lower() for form in _literal_forms(action.default)}:
                continue
            if clause in listed:
                used.add(clause)
                continue
            option = '/'.join(action.option_strings) or action.dest
            problems.append(f'{command} {option}: stated default "{clause}" does not match the parser default')
        self.assertEqual(problems, [])
        self.assertEqual(sorted(listed - used), [], 'Listed descriptions that no help text states')

    def test_named_options_state_the_parser_default(self):
        cases = [
            (('env', 'list'), '--json', 'off', False),
            (('env', 'inspect'), '--json', 'off', False),
            (('ensure-image',), '--pi-version', 'empty', ''),
            (('env', 'check'), '--platform', 'none', None),
        ]
        for path, option, stated, default in cases:
            with self.subTest(command=' '.join(path), option=option):
                action, help_text = _action_and_help(path, option)
                clause = re.search(r'\(default: ([^)]*)\)', help_text).group(1)
                self.assertEqual(clause.split(',')[0].split(';')[0].strip(), stated)
                self.assertEqual((type(action.default), action.default), (type(default), default))

    def test_browser_check_refuses_the_no_sandbox_flag_as_its_help_says(self):
        action, help_text = _action_and_help(('browser-check',), '--allow-browser-no-sandbox')
        self.assertIn('browser-policy-invalid', ' '.join(help_text.split()))
        args = pi_lab.parser().parse_args(['browser-check', '--image', 'pi-agent-tests:core',
                                           '--allow-browser-no-sandbox'])
        with self.assertRaises(pi_lab.LabError) as caught:
            pi_lab.browser_check(args)
        self.assertEqual(caught.exception.reason, 'browser-policy-invalid')
        self.assertIn('verified sandboxing', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
