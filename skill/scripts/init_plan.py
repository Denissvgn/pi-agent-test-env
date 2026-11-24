"""`init-plan`: write a validated plan for a project from one command.

The project kind picks the default check. Nothing here starts a container, runs
the check or contacts a model; the plan is only written after ``validate_plan``
accepts it, and an existing file is never overwritten.
"""
import json
import os
from pathlib import Path
import re
import shlex
import stat

from diagnostics import LabError

DEFAULT_OUTPUT = 'pi-plan.json'
TEMPLATE = 'python-feature.plan.json'
TASK_LIMIT = 100_000
PYTHON_MARKERS = ('pyproject.toml', 'setup.cfg', 'requirements.txt')
TEST_DIRECTORIES = ('tests', 'test', 'spec')
MANIFESTS = ('pyproject.toml', 'setup.cfg', 'requirements.txt', 'package.json', 'go.mod', 'Cargo.toml')
DEFAULT_CHECKS = {
    'node': ['node', '--test'],
    'go': ['go', 'test', './...'],
    'rust': ['cargo', 'test', '--offline'],
}
PYTHON_CHECK = ['python3', '/opt/pi-lab/verify-unittest.py', '--start-dir', 'tests']
AGENT_FIELDS = ('tools', 'require_tools', 'access', 'timeout_seconds', 'max_turns', 'max_total_tokens')
SHELL_OPERATORS = '|&;<>()'


def register(subparsers):
    parser = subparsers.add_parser(
        'init-plan', help='Write a validated plan for a project (never overwrites a file)')
    parser.add_argument('--project', required=True, metavar='DIR',
                        help='Project directory to write the plan for (required)')
    task = parser.add_mutually_exclusive_group(required=True)
    task.add_argument('--task', metavar='TEXT', help='Task text for the implementer (this or --task-file)')
    task.add_argument('--task-file', metavar='FILE',
                      help='Read the task text from this file; inside the project it is protected (this or --task)')
    parser.add_argument('--check', action='append', default=[], metavar='COMMAND',
                        help='Check command, split like a shell would quote it but never run through a shell; '
                             'repeatable (default: by project kind; required for a generic project)')
    parser.add_argument('--protect', action='append', default=[], metavar='PATH',
                        help='Project-relative path the agents must not change; repeatable '
                             '(tests/, test/, spec/ and the task file are always protected)')
    parser.add_argument('--no-reviewer', action='store_true',
                        help='Write only the implementer (default: also a read-only reviewer)')
    parser.add_argument('--output', metavar='FILE',
                        help=f'Write the plan here (default: ./{DEFAULT_OUTPUT}); an existing file is refused')
    parser.set_defaults(handler=handle)


def detect_kind(project: Path) -> str:
    if any((project / name).is_file() for name in PYTHON_MARKERS):
        return 'python'
    tests = project / 'tests'
    if tests.is_dir() and any(path.is_file() for path in tests.rglob('*.py')):
        return 'python'
    if (project / 'package.json').is_file():
        return 'node'
    if (project / 'go.mod').is_file():
        return 'go'
    if (project / 'Cargo.toml').is_file():
        return 'rust'
    return 'generic'


def default_check(project: Path, kind: str):
    if kind == 'python':
        return list(PYTHON_CHECK) if (project / 'tests').is_dir() else None
    return list(DEFAULT_CHECKS[kind]) if kind in DEFAULT_CHECKS else None


def split_check(text: str) -> list[str]:
    """Split a check into arguments as a shell would quote them, without a shell."""
    if not isinstance(text, str) or not text.strip():
        raise LabError('--check needs a command', 'check-invalid')
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "'":
            quote = None if char == "'" else quote
        elif char == '\\':
            index += 1
        elif quote == '"':
            if char == '"':
                quote = None
            elif char == '`' or text.startswith('$(', index):
                raise _shell_error(text)
        elif char in '\'"':
            quote = char
        elif char in SHELL_OPERATORS or char in '`\n\r' or text.startswith('$(', index):
            raise _shell_error(text)
        index += 1
    try:
        arguments = shlex.split(text)
    except ValueError as exc:
        raise LabError(f'--check {text!r} is not a valid command: {exc}', 'check-invalid') from None
    if not arguments:
        raise LabError('--check needs a command', 'check-invalid')
    if re.match(r'[A-Za-z_][A-Za-z0-9_]*=', arguments[0]):
        raise LabError(f'--check {text!r} starts with a variable assignment, which needs a shell; '
                       'checks are never run through a shell', 'check-shell-syntax')
    return arguments


def _shell_error(text):
    return LabError(f'--check {text!r} contains a shell operator (a pipe, redirect, list, substitution or '
                    'subshell); checks are never run through a shell. Pass one program and its arguments, '
                    'or repeat --check for several commands', 'check-shell-syntax')


def read_task(args, project: Path):
    """Return the task text and, when the task file is inside the project, its relative path."""
    if args.task is not None:
        text, relative = args.task, None
    else:
        path = Path(args.task_file).expanduser()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            raise LabError(f'--task-file cannot be read: {exc.strerror or exc}', 'task-invalid') from None
        with os.fdopen(fd, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise LabError('--task-file must be a regular file', 'task-invalid')
            body = source.read(TASK_LIMIT + 1)
        if len(body) > TASK_LIMIT:
            raise LabError(f'--task-file exceeds {TASK_LIMIT} bytes', 'task-invalid')
        try:
            text = body.decode('utf-8')
        except UnicodeError:
            raise LabError('--task-file is not UTF-8 text', 'task-invalid') from None
        resolved = path.resolve()
        relative = resolved.relative_to(project).as_posix() if resolved.is_relative_to(project) else None
    if not text.strip():
        raise LabError('The task text is empty', 'task-invalid')
    return text.strip(), relative


def protected_paths(project: Path, requested: list[str], task_relative, safe_relative) -> list[str]:
    paths = [name for name in TEST_DIRECTORIES if (project / name).is_dir()]
    for value in requested:
        name = safe_relative(value)
        if not (project / name).exists():
            raise LabError(f'--protect path does not exist in the project: {name}', 'protect-invalid')
        if not (project / name).resolve().is_relative_to(project):
            raise LabError(f'--protect path escapes the project: {name}', 'protect-invalid')
        paths.append(name)
    if task_relative is not None:
        paths.append(safe_relative(task_relative))
    return list(dict.fromkeys(paths))


def implementer_prompt(task: str, protected: list[str], checks: list[list[str]]) -> str:
    lines = [task, '']
    if protected:
        lines.append('Do not change these protected paths: ' + ', '.join(protected) + '.')
    lines.append('Use bash to run ' + ('this check:' if len(checks) == 1 else 'these checks:'))
    lines.extend(shlex.join(argv) for argv in checks)
    lines.append('Report the commands you actually ran and their results, and any remaining limitation. '
                 'Do not claim a check ran without invoking it.')
    return '\n'.join(lines)


def build_plan(lab, project: Path, args) -> tuple[dict, str]:
    kind = detect_kind(project)
    if args.check:
        checks = [split_check(text) for text in args.check]
    else:
        default = default_check(project, kind)
        if default is None:
            reason = ('a generic project has no default check' if kind == 'generic'
                      else 'a Python project without a tests/ directory has no default check')
            raise LabError(f'--check is required: {reason}. Pass --check COMMAND, '
                           'for example --check "pytest -q tests"', 'check-required')
        checks = [default]
    task, task_relative = read_task(args, project)
    protected = protected_paths(project, args.protect, task_relative, lab.safe_relative)
    template = json.loads((lab.ROOT / 'assets' / TEMPLATE).read_text(encoding='utf-8'))
    roles = {agent['name']: agent for agent in template['agents']}
    agents = [{'name': 'implementer', 'cwd': '.', 'prompt': implementer_prompt(task, protected, checks),
               **{field: roles['implementer'][field] for field in AGENT_FIELDS}}]
    if not args.no_reviewer:
        agents.append({'name': 'reviewer', 'cwd': '.',
                       'prompt': 'Read the task and the project independently and report concrete discrepancies '
                                 'and missing edge cases with file and line references. The project is read-only; '
                                 'do not change files. Treat another agent\'s claim as unverified and state '
                                 'any limitation.\n\nTask:\n' + task,
                       **{field: roles['reviewer'][field] for field in AGENT_FIELDS}})
    names = ['acceptance'] if len(checks) == 1 else [f'check-{i}' for i in range(1, len(checks) + 1)]
    plan = {
        'schema': 1,
        'name': re.sub(r'[^A-Za-z0-9._-]+', '-', project.name).strip('-') or 'project',
        'required_paths': list(protected),
        'protected_paths': list(protected),
        'setup': [],
        'agents': agents,
        'checks': [{'name': name, 'cwd': '.', 'argv': argv, 'network': 'none', 'timeout_seconds': 300}
                   for name, argv in zip(names, checks)],
    }
    return plan, kind


def write_new(path: Path, body: str):
    if not path.parent.is_dir():
        raise LabError(f'Output directory does not exist: {path.parent}', 'output-invalid')
    try:
        handle = open(path, 'x', encoding='utf-8')
    except FileExistsError:
        raise LabError(f'Output file already exists and is not overwritten: {path}; '
                       'choose another --output or remove it', 'output-exists') from None
    except OSError as exc:
        raise LabError(f'Output file cannot be created: {exc.strerror or exc}', 'output-invalid') from None
    try:
        with handle:
            handle.write(body)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def handle(args):
    import pi_lab as lab
    project = Path(args.project).expanduser()
    if not project.is_dir():
        raise LabError(f'--project is not a directory: {args.project}', 'project-invalid')
    project = project.resolve()
    output = Path(args.output or DEFAULT_OUTPUT).expanduser()
    output = output.parent.resolve() / output.name
    if output.exists() or output.is_symlink():
        raise LabError(f'Output file already exists and is not overwritten: {output}; '
                       'choose another --output or remove it', 'output-exists')
    plan, kind = build_plan(lab, project, args)
    checked = lab.validate_plan(plan, project)
    write_new(output, json.dumps(plan, indent=2) + '\n')
    print(f'Wrote {output}: a {kind} project, {len(checked["agents"])} agent(s), '
          f'{len(checked["checks"])} check(s).')
    for check in checked['checks']:
        print(f'  check {check["name"]}: {shlex.join(check["argv"])}')
    print('Protected paths: ' + (', '.join(checked['protected_paths']) or 'none'))
    manifests = [name for name in MANIFESTS if (project / name).is_file()]
    if manifests:
        print('Setup is empty. This project has a dependency manifest (' + ', '.join(manifests) +
              '): add setup steps that install its dependencies. The network is off for setup and '
              'checks unless a stage sets "network": "inherit" and the run allows it.')
    else:
        print('Setup is empty.')
    return 0
