"""Exact reviewed native JSON tool declarations; no TypeBox/runtime discovery.

Schemas were emitted from primary pinned Pi sources with their lock-pinned
TypeBox1.3.27 constructor in isolated research, then frozen here; each release's
upstream source and TypeBox pins live in the release_contracts registry. Missing JSON
keywords remain missing: builtin objects allow extra fields by JSON Schema
semantics, and all-optional ls omits required. Native preparation/coercion does
not grant permission to change raw arguments. Source review is not native
qualification; parent admission must freeze execution code/loadout separately.
"""
import copy
import hashlib
import json
import math

import release_contracts

BUILTINS = ('read', 'write', 'edit', 'bash', 'grep', 'find', 'ls')
INACTIVE_BUILTINS = frozenset((*BUILTINS, 'powershell'))

_TOOLS = {'read': {'name': 'read',
          'description': 'Read the contents of a file. Supports text files and images (jpg, png, gif, webp, '
                         'bmp). Images are sent as attachments. For text files, output is truncated to 2000 '
                         'lines or 50KB (whichever is hit first). Use offset/limit for large files. When you '
                         'need the full file, continue with offset until complete.',
          'parameters': {'type': 'object',
                         'required': ['path'],
                         'properties': {'path': {'type': 'string',
                                                 'description': 'Path to the file to read (relative or '
                                                                'absolute)'},
                                        'offset': {'type': 'number',
                                                   'description': 'Line number to start reading from '
                                                                  '(1-indexed)'},
                                        'limit': {'type': 'number',
                                                  'description': 'Maximum number of lines to read'}}}},
 'write': {'name': 'write',
           'description': "Write content to a file. Creates the file if it doesn't exist, overwrites if it "
                          'does. Automatically creates parent directories.',
           'parameters': {'type': 'object',
                          'required': ['path', 'content'],
                          'properties': {'path': {'type': 'string',
                                                  'description': 'Path to the file to write (relative or '
                                                                 'absolute)'},
                                         'content': {'type': 'string',
                                                     'description': 'Content to write to the file'}}}},
 'edit': {'name': 'edit',
          'description': 'Edit a single file using exact text replacement. Every edits[].oldText must match '
                         'a unique, non-overlapping region of the original file. If two changes affect the '
                         'same block or nearby lines, merge them into one edit instead of emitting '
                         'overlapping edits. Do not include large unchanged regions just to connect distant '
                         'changes.',
          'parameters': {'type': 'object',
                         'required': ['path', 'edits'],
                         'properties': {'path': {'type': 'string',
                                                 'description': 'Path to the file to edit (relative or '
                                                                'absolute)'},
                                        'edits': {'type': 'array',
                                                  'items': {'type': 'object',
                                                            'required': ['oldText', 'newText'],
                                                            'properties': {'oldText': {'type': 'string',
                                                                                       'description': 'Exact '
                                                                                                      'text '
                                                                                                      'for '
                                                                                                      'one '
                                                                                                      'targeted '
                                                                                                      'replacement. '
                                                                                                      'It '
                                                                                                      'must '
                                                                                                      'be '
                                                                                                      'unique '
                                                                                                      'in '
                                                                                                      'the '
                                                                                                      'original '
                                                                                                      'file '
                                                                                                      'and '
                                                                                                      'must '
                                                                                                      'not '
                                                                                                      'overlap '
                                                                                                      'with '
                                                                                                      'any '
                                                                                                      'other '
                                                                                                      'edits[].oldText '
                                                                                                      'in '
                                                                                                      'the '
                                                                                                      'same '
                                                                                                      'call.'},
                                                                           'newText': {'type': 'string',
                                                                                       'description': 'Replacement '
                                                                                                      'text '
                                                                                                      'for '
                                                                                                      'this '
                                                                                                      'targeted '
                                                                                                      'edit.'}}},
                                                  'description': 'One or more targeted replacements. Each '
                                                                 'edit is matched against the original file, '
                                                                 'not incrementally. Do not include '
                                                                 'overlapping or nested edits. If two '
                                                                 'changes touch the same block or nearby '
                                                                 'lines, merge them into one edit '
                                                                 'instead.'}}}},
 'bash': {'name': 'bash',
          'description': 'Execute a bash command in the current working directory. Returns stdout and '
                         'stderr. Output is truncated to last 2000 lines or 50KB (whichever is hit first). '
                         'If truncated, full output is saved to a temp file. Optionally provide a timeout in '
                         'seconds.',
          'parameters': {'type': 'object',
                         'required': ['command'],
                         'properties': {'command': {'type': 'string',
                                                    'description': 'Shell command to execute'},
                                        'timeout': {'type': 'number',
                                                    'description': 'Timeout in seconds (optional, no default '
                                                                   'timeout)'}}}},
 'grep': {'name': 'grep',
          'description': 'Search file contents for a pattern. Returns matching lines with file paths and '
                         'line numbers. Respects .gitignore. Output is truncated to 100 matches or 50KB '
                         '(whichever is hit first). Long lines are truncated to 500 chars.',
          'parameters': {'type': 'object',
                         'required': ['pattern'],
                         'properties': {'pattern': {'type': 'string',
                                                    'description': 'Search pattern (regex or literal '
                                                                   'string)'},
                                        'path': {'type': 'string',
                                                 'description': 'Directory or file to search (default: '
                                                                'current directory)'},
                                        'glob': {'type': 'string',
                                                 'description': "Filter files by glob pattern, e.g. '*.ts' "
                                                                "or '**/*.spec.ts'"},
                                        'ignoreCase': {'type': 'boolean',
                                                       'description': 'Case-insensitive search (default: '
                                                                      'false)'},
                                        'literal': {'type': 'boolean',
                                                    'description': 'Treat pattern as literal string instead '
                                                                   'of regex (default: false)'},
                                        'context': {'type': 'number',
                                                    'description': 'Number of lines to show before and after '
                                                                   'each match (default: 0)'},
                                        'limit': {'type': 'number',
                                                  'description': 'Maximum number of matches to return '
                                                                 '(default: 100)'}}}},
 'find': {'name': 'find',
          'description': 'Search for files by glob pattern. Returns matching file paths relative to the '
                         'search directory. Respects .gitignore. Output is truncated to 1000 results or 50KB '
                         '(whichever is hit first).',
          'parameters': {'type': 'object',
                         'required': ['pattern'],
                         'properties': {'pattern': {'type': 'string',
                                                    'description': 'Glob pattern to match files, e.g. '
                                                                   "'*.ts', '**/*.json', or "
                                                                   "'src/**/*.spec.ts'"},
                                        'path': {'type': 'string',
                                                 'description': 'Directory to search in (default: current '
                                                                'directory)'},
                                        'limit': {'type': 'number',
                                                  'description': 'Maximum number of results (default: '
                                                                 '1000)'}}}},
 'ls': {'name': 'ls',
        'description': "List directory contents. Returns entries sorted alphabetically, with '/' suffix for "
                       'directories. Includes dotfiles. Output is truncated to 500 entries or 50KB '
                       '(whichever is hit first).',
        'parameters': {'type': 'object',
                       'properties': {'path': {'type': 'string',
                                               'description': 'Directory to list (default: current '
                                                              'directory)'},
                                      'limit': {'type': 'number',
                                                'description': 'Maximum number of entries to return '
                                                               '(default: 500)'}}}},
 'fixture_lookup': {'name': 'fixture_lookup',
                    'description': 'Look up one exact key in the declared read-only fixture table. Returns '
                                   'key, found, and value.',
                    'parameters': {'type': 'object',
                                   'required': ['key'],
                                   'properties': {'key': {'type': 'string',
                                                          'minLength': 1,
                                                          'maxLength': 64,
                                                          'pattern': '^[a-z0-9-]+$'}},
                                   'additionalProperties': False}},
 'budget_status': {'name': 'budget_status',
                   'description': 'Return post-charge trusted remaining budgets.',
                   'parameters': {'type': 'object',
                                  'properties': {},
                                  'required': [],
                                  'additionalProperties': False}}}

_LOCAL_SCHEMA_SOURCES = {'fixture_lookup': {'asset': 'assets/profiles/fixture-lookup/fixture-lookup.mjs',
                    'sha256': '5cd2057772db58a5ac7f6b0ee38eef550226c858e36172d0a84f367350e34cdb'},
 'budget_status': {'asset': 'runtime/tool-budget.mjs',
                   'declaration_sha256': '8a1260df5fc4eb0a270f06cbfbbe1e9cd80a2e49187ab47e842cbac05969c911'}}


class NativeToolError(ValueError):
    def __init__(self, reason='runtime_mismatch'):
        self.reason = reason
        super().__init__(reason)


def canonical(value):
    nodes = [0]
    def check(item, depth=0):
        nodes[0] += 1
        if depth > 32 or nodes[0] > 10000:
            raise NativeToolError()
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise NativeToolError()
            for child in item.values(): check(child, depth + 1)
        elif type(item) is list:
            for child in item: check(child, depth + 1)
        elif type(item) is float:
            if not math.isfinite(item): raise NativeToolError()
        elif type(item) not in (str, int, bool, type(None)):
            raise NativeToolError()
    try:
        check(value)
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(raw) > 256 * 1024: raise NativeToolError()
        return raw
    except (UnicodeError, TypeError, ValueError, RecursionError, OverflowError):
        raise NativeToolError() from None


def _release(release):
    try:
        selected = release_contracts.entry(release)
    except (TypeError, ValueError):
        raise NativeToolError() from None
    return {'upstream_commit': selected['upstream_commit'], 'source_pins': selected['native_tool_sources'],
            'typebox': selected['typebox']}


def _names(names):
    if (type(names) is not list or not 1 <= len(names) <= len(_TOOLS)
            or any(type(name) is not str or name not in _TOOLS for name in names)
            or len(set(names)) != len(names)):
        raise NativeToolError()
    return names


def contract(release):
    selected = _release(release)
    return {'schema': 1, 'document_type': 'reviewed_native_tool_contract',
            'id': 'native-tools-pi-' + release, 'revision': 1, 'pi_release': release,
            **copy.deepcopy(selected), 'tools': copy.deepcopy(_TOOLS),
            'prepare_arguments': {name: 'reviewed_pure' if name == 'edit' else 'none' for name in _TOOLS},
            'local_schema_sources': copy.deepcopy(_LOCAL_SCHEMA_SOURCES),
            'inactive_builtin_allowlist': sorted(INACTIVE_BUILTINS),
            'public_parameters_observable': True, 'public_preparation_observable': False,
            'runtime_schema_projection': 'JSON.parse(JSON.stringify(tool.parameters))',
            'raw_input_policy': 'strict-unchanged-before-effects', 'native_qualified': False}


def identity(release):
    value = contract(release)
    return {key: value[key] for key in ('id', 'revision')} | {
        'sha256': hashlib.sha256(canonical(value)).hexdigest()}


def tools(release, names):
    _release(release)
    return [copy.deepcopy(_TOOLS[name]) for name in _names(names)]


def parameters(release, name):
    return tools(release, [name])[0]['parameters']


def preparation(release, names):
    _release(release)
    return {name: 'reviewed_pure' if name == 'edit' else 'none' for name in _names(names)}


def validate_observed(release, names, observed, *, inactive_builtins=None):
    """Compare JSON-projected getAllTools data; deny unknown registrations.

    The separately declared inactive allowlist may contain reviewed builtin
    registration names, including powershell. Such names never become admissible
    selected tools. Custom inactive registrations are never allowed implicitly.
    """
    _release(release); selected = _names(names)
    inactive = [] if inactive_builtins is None else inactive_builtins
    if (type(inactive) is not list or any(type(name) is not str or name not in INACTIVE_BUILTINS for name in inactive)
            or len(set(inactive)) != len(inactive) or set(inactive) & set(selected)
            or type(observed) is not list or len(observed) > 16):
        raise NativeToolError()
    found = {}
    for item in observed:
        if (type(item) is not dict or type(item.get('name')) is not str
                or item['name'] in found or item['name'] not in set(selected) | set(inactive)):
            raise NativeToolError()
        found[item['name']] = item
    if set(selected) - set(found):
        raise NativeToolError()
    for name in selected:
        if 'parameters' not in found[name] or canonical(found[name]['parameters']) != canonical(_TOOLS[name]['parameters']):
            raise NativeToolError()
    return {name: copy.deepcopy(_TOOLS[name]['parameters']) for name in selected}


# Parent bootstrap uses these explicit names; retrieval never discovers tools.
selected_tools = tools
prepare_arguments = preparation
