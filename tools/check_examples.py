#!/usr/bin/env python3
"""Read-only packaged docs/parser/schema/syntax gate; no runtime/model execution.

Results go to stdout without changing source or storing output inside the skill.
Only CLI help and Node syntax subprocesses execute.
"""
import argparse
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]


def subprocess_check(argv, cwd):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=20)
    return {'command': argv, 'cwd': str(cwd), 'expected_exit_code': 0,
            'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def collect(source):
    source = source.resolve(strict=True)
    sys.path.insert(0, str(source / 'scripts'))
    import agent_profiles
    import experiments
    import outcomes
    import pi_lab

    errors, commands, links, helpers = [], [], [], []
    parser = pi_lab.parser()
    for path in [REPO / 'README.md', *sorted(source.rglob('*.md'))]:
        if '__pycache__' in path.parts:
            continue
        text = path.read_text()
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            if target.startswith(('http:', 'https:', '#', 'mailto:')):
                continue
            local = target.split('#', 1)[0]
            if local:
                exists = (path.parent / local).exists()
                links.append({'document': str(path), 'target': target, 'exists': exists})
                if not exists: errors.append(f'{path}: missing link {target}')
        for line in text.replace('\\\n', ' ').splitlines():
            if 'python3 ' not in line or 'pi_lab.py' not in line:
                continue
            command = line[line.index('python3 '):].split(' #', 1)[0].strip()
            if command.endswith(')') and '$(' in line:
                command = command[:-1]
            args = None
            try:
                tokens = shlex.split(command)
                if len(tokens) < 2 or not tokens[1].endswith('pi_lab.py'):
                    continue
                args = tokens[2:]
                if any(t.startswith('[') or t.endswith(']') for t in args):
                    continue # Explicit optional metasyntax, never shell execution.
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    parser.parse_args(args)
            except SystemExit as exc:
                if exc.code != 0: errors.append(f'{path}: CLI example {command}: exit {exc.code}')
            except ValueError as exc:
                errors.append(f'{path}: CLI example {command}: {exc}')
            if args is not None: commands.append({'document': str(path), 'arguments': args})
    for tool in json.loads((source / 'skill.json').read_text())['tools']:
        args = shlex.split(tool['command'])[2:]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(args)
        commands.append({'document': 'skill.json', 'arguments': args})

    def help_paths(current, prefix=()):
        yield prefix
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    yield from help_paths(child, (*prefix, name))

    for prefix in help_paths(parser):
        row = subprocess_check([sys.executable, str(source / 'scripts/pi_lab.py'), *prefix, '--help'], source)
        helpers.append(row)
        if row['exit_code'] != 0 or 'usage:' not in row['stdout']:
            errors.append('CLI help failed: ' + ' '.join(prefix))
    row = subprocess_check([sys.executable, str(source / 'scripts/export_skill.py'), '--help'], source)
    helpers.append(row)
    if row['exit_code'] != 0 or 'usage:' not in row['stdout']: errors.append('Exporter help failed')

    plans, profiles = [], []
    for path in sorted(source.rglob('*.plan.json')):
        profile = agent_profiles.load(source / 'assets/profiles/fixture-lookup/profile.json') if path.name == 'lookup.plan.json' else None
        pi_lab.validate_plan(json.loads(path.read_text()), path.parent, agent_profile=profile,external_bindings=path.name=='external.plan.json')
        plans.append(str(path.relative_to(source)))
    for relative in ('assets/profiles/builtin.json', 'assets/profiles/fixture-lookup/profile.json'):
        profile = agent_profiles.load(source / relative)
        profiles.append({'path': relative, 'id': profile['id'], 'sha256': agent_profiles.identity(profile)})
    outcome_examples = json.loads((source / 'references/outcome-examples.json').read_text())['examples']
    for example in outcome_examples:
        value = example['projection']
        if outcomes.status(value) != (value['status'], value['exit_code']):
            errors.append('Outcome projection mismatch: ' + example['example'])
        if value['scoring']['status'] != 'completed' and value['task_result']['score'] is not None:
            errors.append('Unscored projection invented score: ' + example['example'])
    pi = json.loads((source / 'references/pi-0.87.1.examples.json').read_text())
    model = pi['baseline_models_json']['providers']['local-lab']['models'][0]
    for trace in pi['event_examples']:
        with tempfile.TemporaryDirectory(prefix='pi-offline-trace-') as temporary:
            path = Path(temporary) / 'events.jsonl'
            path.write_text(''.join(json.dumps(event) + '\n' for event in trace['records']))
            result = pi_lab.analyze(path, model['id'], [], 0, release=pi['version'])
            if not result.get('protocol_valid'): errors.append('Invalid synthetic Pi lifecycle example')

    definitions = []
    with tempfile.TemporaryDirectory(prefix='pi-offline-definition-') as temporary:
        endpoint = Path(temporary) / 'endpoint.json'
        endpoint.write_text(json.dumps({'base_url': 'http://fixture.invalid/v1', 'model': 'synthetic-not-contacted',
            'api_key_env': 'FIXTURE_KEY', 'context_window': 32768, 'max_tokens': 4096}))
        for name in ('application-baseline', 'integration-baseline'):
            spec = importlib.util.spec_from_file_location(name, source / 'examples' / name / 'configure.py')
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            rendered = module.definitions('sha256:' + 'a' * 64) if name == 'application-baseline' else {'integration.json': module.definition('sha256:' + 'a' * 64)}
            for filename, value in rendered.items():
                path = Path(temporary) / filename; path.write_text(json.dumps(value))
                experiments.validate(path, pi_lab, endpoint_path=endpoint)
                definitions.append({'path': filename, 'planned_cells': len(value['cases']) * len(value['variants']) * value['repetitions']})

    from inference_catalog import Catalog
    with tempfile.TemporaryDirectory(prefix='pi-indexed-examples-') as temporary:
        catalog=Catalog(pi_lab.normalize_endpoint,Path(temporary)/'catalog',Path(temporary)/'store')
        for name in ('builder-local','reviewer-local'):
            configuration=json.loads((source/'assets/inference-profile.example.json').read_text())
            configuration['credential']={'source':'none'}
            catalog.register(name,configuration);catalog.confirm(name,'fixture')
        spec=importlib.util.spec_from_file_location('indexed_example',source/'examples/indexed-inference/configure.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for release in ('0.87.1','1.2.0'):
            for name,value in module.definitions('sha256:'+'a'*64,release).items():
                definition=Path(temporary)/(release+'-'+name);definition.write_text(json.dumps(value))
                normalized=experiments.validate(definition,pi_lab,catalog=catalog)
                definitions.append({'path':'indexed-'+release+'-'+name,'planned_cells':len(normalized['cases'])*len(normalized['variants'])*normalized['repetitions']})

    syntax = {'python': [], 'json': [], 'javascript': []}
    for path in sorted(source.rglob('*')):
        if '__pycache__' in path.parts or not path.is_file(): continue
        relative = path.relative_to(source).as_posix()
        if path.suffix == '.py':
            ast.parse(path.read_text(), filename=str(path), feature_version=(3, 10))
            syntax['python'].append(relative)
        elif path.suffix == '.json':
            json.loads(path.read_text()); syntax['json'].append(relative)
        elif path.suffix == '.mjs':
            row = subprocess_check(['node', '--check', str(path)], source)
            syntax['javascript'].append(row)
            if row['exit_code'] != 0: errors.append('JavaScript syntax failed: ' + relative)
    return {'status': 'fail' if errors else 'pass', 'errors': errors,
            'parsed_examples': commands, 'local_links': links, 'cli_help': helpers,
            'plans': plans, 'profiles': profiles, 'rendered_definitions': definitions,
            'outcome_examples': len(outcome_examples), 'pi_lifecycle_examples': len(pi['event_examples']),
            'syntax': syntax, 'python_grammar': '3.10',
            'scope': 'Offline schemas/parser/help/syntax/local links; synthetic metadata/traces only; no Docker/model/endpoint contact.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=REPO / 'skill')
    args = parser.parse_args()
    try:
        value = collect(args.source)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)})); return 2
    print(json.dumps(value, indent=2))
    return 0 if value['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
