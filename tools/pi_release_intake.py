#!/usr/bin/env python3
"""Prepare a review packet for adopting a new upstream Pi release.

Read-only maintainer intake. For one exact release it fetches public upstream
metadata and source bytes, hashes every upstream file that the reviewed
registry entry pins, and compares them with the newest reviewed release or
--base. It writes intake.json, review-packet.md and draft-contract.json to a
fresh directory; the draft is a registry entry for release_contracts.py whose
behavior fields are carried over from the base entry, unreviewed.

It never installs or executes upstream code and never edits the repository.
Source drift narrows the review; it does not admit or qualify a release. npm
provenance is compared as a statement only: its signature and transparency-log
entry are not verified.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skill' / 'runtime'))
import release_contracts  # noqa: E402

UPSTREAM = 'earendil-works/pi'
NPM_PACKAGE = '@earendil-works/pi-coding-agent'
GITHUB_API = 'https://api.github.com'
GITHUB_RAW = 'https://raw.githubusercontent.com'
GITHUB_WEB = 'https://github.com'
NPM_REGISTRY = 'https://registry.npmjs.org'
CLI_ARGS = 'packages/coding-agent/src/cli/args.ts'
LOCKFILE = 'package-lock.json'
TOOLS_DIR = 'packages/coding-agent/src/core/tools'
# coding-agent builds the built-in tool schemas with TypeBox; pi-ai and pi-agent-core
# validate tool arguments, with pi-schema since 1.5.0.
SCHEMA_BUILDER_PACKAGE = 'packages/coding-agent/package.json'
VALIDATOR_PACKAGES = ('packages/ai/package.json', 'packages/agent/package.json')
WATCHED_PACKAGES = (SCHEMA_BUILDER_PACKAGE, *VALIDATOR_PACKAGES)
PI_SCHEMA = '@earendil-works/pi-schema'
# Registry entry fields that pin upstream files, and the fields the intake derives
# from upstream. Every other entry field is carried over from the base, unreviewed.
PIN_FIELDS = ('native_tool_sources', 'application_runtime_sources')
DERIVED_FIELDS = frozenset({'upstream_commit', 'revision', 'fixture_profile', *release_contracts.PACKAGE_PIN_FIELDS,
                            *PIN_FIELDS})
SCAN_ROOTS = ('skill', 'tests', 'tools', 'README.md', 'CONTRIBUTING.md')
SCAN_SKIP = ('tools/release-hardening', 'tools/validation', 'skill/MANIFEST.sha256')
USER_AGENT = 'pi-agent-test-env-release-intake'
LOOPBACK = frozenset({'127.0.0.1', 'localhost', '::1'})
MAX_METADATA = 8 << 20
MAX_SOURCE = 16 << 20
MAX_TARBALL = 64 << 20
TIMEOUT = 30
SEVERITIES = ('blocking', 'contract', 'review')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
COMMIT = re.compile(r'[0-9a-f]{40}')
FLAG = re.compile(r'''["'`](--[a-z][a-z0-9-]*)''')
LINK = re.compile(r'\[([^\]]*)\]\([^)]*\)')
TOPICS = tuple((name, re.compile(pattern, re.IGNORECASE)) for name, pattern in (
    ('tools', r'`(?:read|write|edit|bash|grep|find|ls)`|\b(?:read|write|edit|bash|grep|find|ls) tool\b'
              r'|\btool[- ]calls?\b|\btool arguments?\b|\bvalidat|\bfd\b|\brg\b|ripgrep'),
    ('cli', r'`--[a-z][a-z0-9-]*'),
    ('modes', r'\bjson mode\b|\bprint mode\b|\bexit codes?\b|\boffline\b|\bstdout\b|\bstdin\b'),
    ('session', r'\bsessions?\b|\bsettle|\babort|\bresum|stopReason|\btruncat|\boutput limit\b|\bcut off\b'),
    ('models', r'models\.json|openai[- ]compatible|chat completions|openai-completions|max_tokens|maxTokens'
               r'|\bcontext window\b|\bthinking\b|\breasoning\b|\bsampling|cache warming|cacheWarming'),
    ('extensions', r'\bextensions?\b|\bmcp\b|codemode|tool_search|\bskills?\b|\bprompt templates?\b'),
    ('retry', r'\bretr(?:y|ies|ying)\b|\bcompaction\b'),
    ('packaging', r'\bdependenc(?:y|ies)\b|\bfresh installs?\b|\bnpm install\b|shrinkwrap|lockfile'),
))
# Keywords also match changes that print-mode JSON runs in a Linux container
# against a local endpoint never reach: hosted providers and sign-in, interactive
# UI and `/slash` commands, RPC mode, other host platforms, `pi update`, and the
# MCP, codemode, tool-search, skill and prompt-template features the worker
# disables. Such bullets are dropped unless they name a CLI flag or sit under a
# breaking-changes heading.
ALWAYS_KEPT = frozenset({'breaking', 'cli'})
NOISE = re.compile(r'\b(?:gemini|vertex|copilot|bedrock|azure|anthropic|claude|gpt|codex|kimi|grok|xai'
                   r'|minimax|openrouter|cloudflare|xiaomi|mimo|typesafe|opencode|log ?in|log ?out|sign-in'
                   r'|oauth|dialogs?|overlays?|editors?|keybindings?|tui|interactive mode|selectors?|themes?'
                   r'|highlight\w*|mermaid|terminals?|rpc|windows|macos|bun|nix|powershell|pi update|mcp'
                   r'|codemode|tool[ _]search|classifiers?|skills?|prompt templates?)\b|`/[a-z][a-z-]*[`\s]',
                   re.IGNORECASE)


class IntakeError(Exception):
    """A required upstream fact could not be fetched or parsed; nothing is written."""


def parse_version(text):
    match = VERSION.fullmatch(text) if isinstance(text, str) else None
    if not match:
        raise IntakeError(f'Not an exact X.Y.Z release: {text!r}')
    return tuple(int(part) for part in match.groups())


def _version(text):
    try:
        return parse_version(text)
    except IntakeError:
        return None


def _sha256(data):
    return None if data is None else hashlib.sha256(data).hexdigest()


def checked_url(url):
    """HTTPS only; plain HTTP is accepted for loopback test services."""
    parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    host = (parts.hostname or '').lower() if parts else ''
    if parts and host and (parts.scheme == 'https' or (parts.scheme == 'http' and host in LOOPBACK)):
        return url
    raise IntakeError(f'Refusing a URL that is not HTTPS: {url!r}')


def _origin(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme, (parts.hostname or '').lower(), parts.port


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Upstream:
    """Bounded, read-only HTTP access to the public upstream repository and registry."""

    def __init__(self, *, repository=UPSTREAM, package=NPM_PACKAGE, github_api=GITHUB_API,
                 github_raw=GITHUB_RAW, github_web=GITHUB_WEB, npm_registry=NPM_REGISTRY,
                 timeout=TIMEOUT, proxies=None):
        self.repository, self.package, self.timeout = repository, package, timeout
        self.github_api, self.github_raw, self.github_web, self.npm_registry = (
            checked_url(url).rstrip('/') for url in (github_api, github_raw, github_web, npm_registry))
        handlers = [_CheckedRedirects()]
        if proxies is not None:
            handlers.append(urllib.request.ProxyHandler(proxies))
        self._opener = urllib.request.build_opener(*handlers)
        self.requests = 0

    def fetch(self, url, limit, *, headers=None, missing_ok=False):
        request = urllib.request.Request(checked_url(url), headers={'User-Agent': USER_AGENT, **(headers or {})})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            limited = exc.code in (403, 429) and exc.headers.get('X-RateLimit-Remaining') == '0'
            exc.close()
            if exc.code == 404 and missing_ok:
                return None
            if limited:
                raise IntakeError(f'GitHub API rate limit reached; retry after it resets ({url})') from None
            raise IntakeError(f'HTTP {exc.code} for {url}') from None
        except (urllib.error.URLError, OSError) as exc:
            raise IntakeError(f'Could not fetch {url}: {exc}') from None
        finally:
            self.requests += 1
        if len(body) > limit:
            raise IntakeError(f'Response exceeds {limit} bytes: {url}')
        return body

    def json(self, url, *, headers=None, missing_ok=False):
        body = self.fetch(url, MAX_METADATA, headers=headers, missing_ok=missing_ok)
        if body is None:
            return None
        try:
            return json.loads(body)
        except ValueError:
            raise IntakeError(f'Invalid JSON from {url}') from None

    def api(self, path, *, missing_ok=False):
        return self.json(f'{self.github_api}/repos/{self.repository}/{path}', missing_ok=missing_ok,
                         headers={'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})

    def tag_commit(self, tag):
        """The commit a tag names, following an annotated tag object."""
        def target(document):
            return document.get('object') if isinstance(document, dict) else None

        node = target(self.api('git/ref/tags/' + urllib.parse.quote(tag, safe='')))
        for _ in range(4):
            if not isinstance(node, dict) or not isinstance(node.get('sha'), str):
                break
            if node.get('type') == 'commit' and COMMIT.fullmatch(node['sha']):
                return node['sha']
            if node.get('type') != 'tag' or not COMMIT.fullmatch(node['sha']):
                break
            node = target(self.api('git/tags/' + node['sha']))
        raise IntakeError(f'Tag {tag} does not resolve to a commit')

    def source(self, commit, path):
        """Exact upstream bytes at a commit, or None when the path is absent there."""
        return self.fetch(f'{self.github_raw}/{self.repository}/{commit}/{urllib.parse.quote(path)}',
                          MAX_SOURCE, missing_ok=True)

    def directory(self, commit, path):
        listing = self.api(f'contents/{urllib.parse.quote(path)}?ref={commit}', missing_ok=True)
        if listing is None:
            return None
        if not isinstance(listing, list):
            raise IntakeError(f'Unexpected directory listing for {path} at {commit}')
        return sorted(item['name'] for item in listing if isinstance(item, dict)
                      and item.get('type') == 'file' and isinstance(item.get('name'), str))

    def releases(self, oldest):
        """Published releases, newest first, until a page reaches version `oldest`."""
        found = []
        for page in range(1, 21):
            batch = self.api(f'releases?per_page=100&page={page}')
            if not isinstance(batch, list):
                raise IntakeError('Unexpected GitHub releases listing')
            found.extend(item for item in batch if isinstance(item, dict))
            tags = [item.get('tag_name') for item in batch if isinstance(item, dict)]
            versions = [_version(tag[1:]) for tag in tags if isinstance(tag, str) and tag.startswith('v')]
            if len(batch) < 100 or any(version is not None and version <= oldest for version in versions):
                return found
        raise IntakeError('GitHub releases listing did not reach the base release')

    def npm_manifest(self, version, package=None, *, missing_ok=False):
        name = package or self.package
        return self.json(f'{self.npm_registry}/{urllib.parse.quote(name, safe="@")}/{version}', missing_ok=missing_ok)

    def registry_url(self, url):
        """Registry metadata may only name further files on the configured registry."""
        if not isinstance(url, str) or _origin(checked_url(url)) != _origin(self.npm_registry):
            raise IntakeError(f'npm metadata names a URL outside {self.npm_registry}: {url!r}')
        return url


class Snapshot:
    """Upstream files at one exact commit, fetched once each."""

    def __init__(self, upstream, commit):
        self.upstream, self.commit, self._files = upstream, commit, {}

    def get(self, path):
        if path not in self._files:
            self._files[path] = self.upstream.source(self.commit, path)
        return self._files[path]

    def sha256(self, path):
        return _sha256(self.get(path))

    def json(self, path):
        data = self.get(path)
        if data is None:
            return None
        try:
            value = json.loads(data)
        except ValueError:
            raise IntakeError(f'Invalid JSON in upstream {path} at {self.commit}') from None
        if not isinstance(value, dict):
            raise IntakeError(f'Unexpected JSON in upstream {path} at {self.commit}')
        return value


def reviewed_baseline(release):
    """The reviewed registry entry for one release; the runtime contracts derive from it."""
    try:
        return {'release': release, 'entry': release_contracts.entry(release)}
    except ValueError:
        raise IntakeError(f'Pi {release} has no reviewed contract to compare against') from None


def draft_entry(release, base_entry, snapshot, typebox_unchanged, pi_schema_pin):
    """A registry entry for the target: upstream facts derived, the rest carried over unreviewed."""
    value = {}
    for field in release_contracts.ENTRY_FIELDS:
        if field == 'upstream_commit':
            value[field] = snapshot.commit
        elif field == 'revision':
            value[field] = 1
        elif field == 'fixture_profile':
            value[field] = f'profile.pi-{release}.json'
        elif field == 'typebox':
            value[field] = copy.deepcopy(base_entry['typebox']) if typebox_unchanged else None
        elif field == 'pi_schema':
            value[field] = copy.deepcopy(pi_schema_pin)
        elif field in PIN_FIELDS:
            value[field] = {path: snapshot.sha256(path) for path in base_entry[field]}
        else:
            value[field] = copy.deepcopy(base_entry[field])
    return value


def registry_check(release, value):
    """Whether the draft would load when appended to the reviewed entries, as written."""
    table = {name: release_contracts.entry(name) for name in release_contracts.RELEASES}
    if release in table:
        return {'loads': False, 'reason': f'Pi {release} already has a reviewed entry'}
    table[release] = value
    try:
        release_contracts.check_registry(table)
    except ValueError as exc:
        return {'loads': False, 'reason': str(exc)}
    return {'loads': True, 'reason': None}


def entry_source(release, value):
    """The entry as a Python item for _REVIEWED, laid out like the reviewed entries."""
    lines = [f'    {release!r}: {{']
    for field, item in value.items():
        if field in PIN_FIELDS:
            lines.append(f'        {field!r}: {{')
            lines += [f'            {path!r}:\n                {digest!r},' for path, digest in item.items()]
            lines.append('        },')
        elif field in release_contracts.PACKAGE_PIN_FIELDS and isinstance(item, dict):
            lines += [f"        {field!r}: {{'version': {item['version']!r},",
                      ' ' * (11 + len(repr(field))) + f"'integrity': {item['integrity']!r}}},"]
        else:
            lines.append(f'        {field!r}: {item!r},')
    return '\n'.join(lines + ['    },'])


def newest_reviewed():
    return max(release_contracts.RELEASES, key=parse_version)


def cli_flags(source):
    """Flag literals in the CLI parser source, such as `arg === "--no-mcp"`."""
    return None if source is None else sorted(set(FLAG.findall(source.decode('utf-8', 'replace'))))


def classify(text):
    topics = [name for name, pattern in TOPICS if pattern.search(text)]
    relevant = bool(topics) and (bool(ALWAYS_KEPT.intersection(topics)) or not NOISE.search(text))
    return topics, relevant


def release_bullets(body):
    """Top-level bullets of a release body, with their section and keyword topics."""
    bullets, section = [], ''
    for line in (body or '').splitlines():
        heading = re.match(r'#{2,4}\s+(.*\S)', line)
        if heading:
            section = heading.group(1)
        elif re.match(r'[-*] ', line):
            bullets.append({'section': section, 'text': line[2:].strip()})
        elif bullets and line[:1] in (' ', '\t') and line.strip():
            bullets[-1]['text'] += ' ' + line.strip()
    for bullet in bullets:
        topics, relevant = classify(bullet['text'])
        breaking = 'breaking' in bullet['section'].lower()
        bullet['topics'] = ['breaking'] * breaking + topics
        bullet['relevant'] = breaking or relevant
    return bullets


def release_notes(upstream, base, target):
    low, high = parse_version(base), parse_version(target)
    notes = []
    for item in upstream.releases(low):
        tag = item.get('tag_name')
        version = _version(tag[1:]) if isinstance(tag, str) and tag.startswith('v') else None
        if version is None or item.get('draft') or item.get('prerelease') or not low < version <= high:
            continue
        notes.append({'release': tag[1:], 'published_at': item.get('published_at'),
                      'url': item.get('html_url'), 'bullets': release_bullets(item.get('body'))})
    return sorted(notes, key=lambda note: parse_version(note['release']))


def dependency_drift(old, new, scope):
    """Declared dependency changes; lockstep bumps inside the upstream scope are only listed."""
    if old is None or new is None:
        return {'base_present': old is not None, 'target_present': new is not None}
    before, after = old.get('dependencies') or {}, new.get('dependencies') or {}
    changed = {name: [before[name], after[name]] for name in sorted(before.keys() & after.keys())
               if before[name] != after[name]}
    lockstep = sorted(name for name in changed if name.startswith(scope))
    return {'added': {name: after[name] for name in sorted(after.keys() - before.keys())},
            'removed': {name: before[name] for name in sorted(before.keys() - after.keys())},
            'changed': {name: value for name, value in changed.items() if name not in lockstep},
            'lockstep': lockstep,
            'engines': {'base': old.get('engines'), 'target': new.get('engines')}}


def typebox_status(pin, base, target):
    """Whether the reviewed TypeBox pin still describes the TypeBox that builds the tool schemas."""
    if not pin:
        return {'status': 'not_pinned'}

    def facts(snapshot):
        declared = ((snapshot.json(SCHEMA_BUILDER_PACKAGE) or {}).get('dependencies') or {}).get('typebox')
        entry = ((snapshot.json(LOCKFILE) or {}).get('packages') or {}).get('node_modules/typebox') or {}
        return {'declared': declared, 'lock': {'version': entry.get('version'), 'integrity': entry.get('integrity')}}

    pinned = {'version': pin.get('version'), 'integrity': pin.get('integrity')}
    old, new = facts(base), facts(target)
    status = ('undeclared' if new['declared'] is None else
              'unchanged' if new['declared'] == pinned['version'] and new['lock'] == pinned else 'changed')
    return {'pin': pinned, 'base': old, 'target': new, 'status': status,
            'base_reproduced': old['declared'] == pinned['version'] and old['lock'] == pinned}


def pi_schema_status(pin, base, target, upstream):
    """Whether Pi validates tool arguments with pi-schema, and the registry pin that describes it.

    pi-schema is an upstream workspace package, so the lockfile links it without an
    integrity; npm's metadata for the declared version supplies the integrity.
    """
    def facts(snapshot):
        declared = {path: ((snapshot.json(path) or {}).get('dependencies') or {}).get(PI_SCHEMA)
                    for path in VALIDATOR_PACKAGES}
        declared = {path: spec for path, spec in declared.items() if spec is not None}
        versions = sorted(set(declared.values()))
        return {'declared_by': declared, 'version': versions[0] if len(versions) == 1 else None,
                'consistent': len(versions) <= 1}

    def integrity(version):
        manifest = upstream.npm_manifest(version, PI_SCHEMA, missing_ok=True) if version else None
        return ((manifest or {}).get('dist') or {}).get('integrity')

    pinned = None if pin is None else {'version': pin.get('version'), 'integrity': pin.get('integrity')}
    old, new = facts(base), facts(target)
    found = integrity(new['version'])
    target_pin = {'version': new['version'], 'integrity': found} if new['version'] and found else None
    if not new['declared_by']:
        status = 'not_used' if pinned is None else 'removed'
    else:
        status = 'introduced' if pinned is None else 'unchanged' if target_pin == pinned else 'changed'
    reproduced = (not old['declared_by'] if pinned is None else
                  old['version'] == pinned['version'] and integrity(pinned['version']) == pinned['integrity'])
    return {'pin': pinned, 'base': old, 'target': new, 'target_pin': target_pin, 'status': status,
            'base_reproduced': reproduced}


def provenance(document):
    """Source facts from the SLSA provenance statement; its signature is not verified."""
    if not isinstance(document, dict) or not isinstance(document.get('attestations'), list):
        raise IntakeError('Unreadable npm attestations document')
    for item in document['attestations']:
        kind = item.get('predicateType') if isinstance(item, dict) else None
        if not isinstance(kind, str) or not kind.startswith('https://slsa.dev/provenance/'):
            continue
        try:
            statement = json.loads(base64.b64decode(item['bundle']['dsseEnvelope']['payload'], validate=True))
            definition = statement['predicate']['buildDefinition']
            workflow = (definition.get('externalParameters') or {}).get('workflow') or {}
            commits = sorted({dependency['digest']['gitCommit'] for dependency in
                              definition.get('resolvedDependencies') or []
                              if isinstance((dependency.get('digest') or {}).get('gitCommit'), str)})
            subjects = sorted({subject['digest']['sha512'] for subject in statement.get('subject') or []
                               if isinstance((subject.get('digest') or {}).get('sha512'), str)})
        except (KeyError, TypeError, ValueError, AttributeError):
            raise IntakeError('Unreadable npm provenance statement') from None
        return {'predicate_type': kind, 'commits': commits, 'subject_sha512': subjects,
                'repository': workflow.get('repository'), 'ref': workflow.get('ref'),
                'workflow': workflow.get('path'), 'signature': 'not verified'}
    return None


def npm_identity(upstream, version, commit, *, check_tarball):
    manifest = upstream.npm_manifest(version)
    if not isinstance(manifest, dict) or manifest.get('name') != upstream.package or manifest.get('version') != version:
        raise IntakeError(f'npm metadata does not describe {upstream.package}@{version}')
    dist = manifest.get('dist') if isinstance(manifest.get('dist'), dict) else {}
    found = {'package': upstream.package, 'version': version, 'tarball': dist.get('tarball'),
             'integrity': dist.get('integrity'), 'shasum': dist.get('shasum'),
             'git_head': manifest.get('gitHead'), 'has_shrinkwrap': manifest.get('_hasShrinkwrap'),
             'engines': manifest.get('engines'), 'dependencies': manifest.get('dependencies') or {},
             'tarball_check': 'skipped', 'tarball_sha256': None, 'tarball_bytes': None, 'provenance': None}
    findings = []
    if found['git_head'] is not None and found['git_head'] != commit:
        findings.append(('blocking', f'npm gitHead {found["git_head"]} differs from tag commit {commit}.'))
    sha512_hex = None
    if check_tarball:
        data = upstream.fetch(upstream.registry_url(found['tarball']), MAX_TARBALL)
        sha512 = hashlib.sha512(data)
        sha512_hex = sha512.hexdigest()
        declared = [part for part in str(found['integrity'] or '').split() if part.startswith('sha512-')]
        matches = (declared == ['sha512-' + base64.b64encode(sha512.digest()).decode()]
                   and found['shasum'] in (None, hashlib.sha1(data).hexdigest()))
        found.update(tarball_check='match' if matches else 'mismatch',
                     tarball_sha256=hashlib.sha256(data).hexdigest(), tarball_bytes=len(data))
        if not matches:
            findings.append(('blocking', 'The downloaded npm tarball does not match the registry integrity metadata.'))
    attestations = dist.get('attestations')
    if isinstance(attestations, dict) and attestations.get('url'):
        found['provenance'] = statement = provenance(upstream.json(upstream.registry_url(attestations['url'])))
        if statement is None:
            findings.append(('review', 'npm attestations hold no SLSA provenance statement.'))
        else:
            if statement['commits'] != [commit]:
                findings.append(('blocking', f'npm provenance names commits {statement["commits"]}, not tag commit {commit}.'))
            if sha512_hex and statement['subject_sha512'] != [sha512_hex]:
                findings.append(('blocking', 'npm provenance subject digest differs from the downloaded tarball.'))
    elif found['git_head'] is None:
        findings.append(('review', 'npm metadata has neither gitHead nor provenance; '
                                   'the source-to-package link is unverified.'))
    return found, findings


def repository_mentions(repository, release):
    """Files that name a release literally, outside history, evidence and generated output."""
    literal = re.compile(r'(?<![0-9.])' + re.escape(release) + r'(?!\.?[0-9])')
    found = {'code': [], 'docs': []}
    for root in SCAN_ROOTS:
        start = repository / root
        for path in sorted([start] if start.is_file() else start.rglob('*') if start.is_dir() else []):
            relative = path.relative_to(repository).as_posix()
            if (not path.is_file() or path.is_symlink() or '__pycache__' in path.parts
                    or relative.startswith(SCAN_SKIP) or path.stat().st_size > 2 << 20):
                continue
            try:
                lines = sum(1 for line in path.read_text(encoding='utf-8').splitlines() if literal.search(line))
            except UnicodeDecodeError:
                continue
            if lines:
                found['docs' if path.suffix == '.md' else 'code'].append({'path': relative, 'lines': lines})
    return found


def diff_url(upstream, base, target, path=None):
    url = f'{upstream.github_web}/{upstream.repository}/compare/{base}...{target}'
    return url if path is None else url + '#diff-' + hashlib.sha256(path.encode()).hexdigest()


def intake(upstream, target, baseline, *, check_tarball=True, repository=None):
    """Compare one exact upstream release with a reviewed baseline; returns (report, draft)."""
    base = baseline['release']
    if parse_version(target) <= parse_version(base):
        raise IntakeError(f'Pi {target} is not newer than the reviewed base {base}')
    findings = []

    def note(severity, text):
        findings.append({'severity': severity, 'text': text})

    base_entry = baseline['entry']
    pinned = {field: base_entry[field] for field in PIN_FIELDS}
    base_commit = base_entry['upstream_commit']
    base_tag_commit = upstream.tag_commit('v' + base)
    if base_tag_commit != base_commit:
        note('blocking', f'Tag v{base} now resolves to {base_tag_commit}, not the reviewed commit {base_commit}.')
    target_commit = upstream.tag_commit('v' + target)
    before, after = Snapshot(upstream, base_commit), Snapshot(upstream, target_commit)

    paths = sorted({path for pins in pinned.values() for path in pins})
    unreproduced = [f'{group}: {path}' for group, pins in pinned.items()
                    for path, digest in sorted(pins.items()) if before.sha256(path) != digest]
    if unreproduced:
        note('blocking', f'{len(unreproduced)} reviewed pins do not reproduce at {base_commit}: '
                         + '; '.join(unreproduced))
    files = []
    for path in paths:
        old, new = before.sha256(path), after.sha256(path)
        status = 'missing' if new is None else 'unchanged' if new == old else 'changed'
        files.append({'path': path, 'pinned_by': sorted(group for group, pins in pinned.items() if path in pins),
                      'status': status, 'base_sha256': old, 'target_sha256': new,
                      'diff': None if status == 'unchanged' else diff_url(upstream, base_commit, target_commit, path),
                      'file': None if new is None else f'{upstream.github_web}/{upstream.repository}/blob/{target_commit}/{path}'})
    changed = [item['path'] for item in files if item['status'] == 'changed']
    missing = [item['path'] for item in files if item['status'] == 'missing']
    if missing:
        note('contract', f'{len(missing)} pinned files no longer exist at v{target}: ' + ', '.join(missing))
    note('review', f'{len(changed)} of {len(files)} pinned upstream files changed since Pi {base}.'
         + (' Read each diff before carrying any contract field over.' if changed else ''))

    reviewed_target = None
    if target in release_contracts.RELEASES:
        recorded = reviewed_baseline(target)['entry']
        mismatched = [f'{group}: {path}' for group in PIN_FIELDS
                      for path, digest in sorted(recorded[group].items()) if after.sha256(path) != digest]
        reviewed_target = {'recorded_commit': recorded['upstream_commit'], 'pins_mismatched': mismatched,
                           'pins_reproduced': sum(len(recorded[group]) for group in PIN_FIELDS) - len(mismatched)}
        if recorded['upstream_commit'] != target_commit:
            note('blocking', f'Tag v{target} resolves to {target_commit}, not its reviewed commit '
                             f'{recorded["upstream_commit"]}.')
        if mismatched:
            note('blocking', f'{len(mismatched)} reviewed Pi {target} pins do not reproduce: ' + '; '.join(mismatched))

    old_flags, new_flags = cli_flags(before.get(CLI_ARGS)), cli_flags(after.get(CLI_ARGS))
    required = sorted({*release_contracts.COMMON_FLAGS, *base_entry['extra_cli_flags']})
    flags = {'added': sorted(set(new_flags or ()) - set(old_flags or ())),
             'removed': sorted(set(old_flags or ()) - set(new_flags or ())),
             'missing_required': [flag for flag in required if flag not in (new_flags or ())]}
    if flags['missing_required']:
        note('contract', 'The CLI parser no longer names required flags: ' + ', '.join(flags['missing_required']))
    if flags['added']:
        note('review', 'The CLI parser names new flags: ' + ', '.join(flags['added'])
             + '. Decide whether any must be required or kept out of the worker argv.')

    old_tools, new_tools = upstream.directory(base_commit, TOOLS_DIR), upstream.directory(target_commit, TOOLS_DIR)
    tools = {'added': sorted(set(new_tools or ()) - set(old_tools or ())),
             'removed': sorted(set(old_tools or ()) - set(new_tools or ()))}
    if tools['added'] or tools['removed']:
        note('review', f'Files in {TOOLS_DIR} changed: added {", ".join(tools["added"]) or "none"}; removed '
                       f'{", ".join(tools["removed"]) or "none"}. Check whether a built-in tool was added or retired.')

    scope = upstream.package.split('/')[0] + '/'
    dependencies = {path: dependency_drift(before.json(path), after.json(path), scope) for path in WATCHED_PACKAGES}
    for path, drift in dependencies.items():
        engines = drift.get('engines') or {}
        if engines.get('base') != engines.get('target'):
            note('review', f'{path} changes its engines from {engines.get("base")} to {engines.get("target")}; '
                           'check the image Node version.')
        if drift.get('added') or drift.get('removed'):
            note('review', f'{path} dependencies: added {_packages(drift["added"])}; '
                           f'removed {_packages(drift["removed"])}.')

    typebox = typebox_status(base_entry['typebox'], before, after)
    if typebox['status'] != 'not_pinned':
        if not typebox['base_reproduced']:
            note('blocking', f'The reviewed TypeBox pin does not match Pi {base}\'s coding-agent dependency and lockfile.')
        if typebox['status'] == 'undeclared':
            note('contract', f'packages/coding-agent no longer declares typebox at v{target}, so the TypeBox '
                             f'{typebox["pin"]["version"]} pin no longer describes how the built-in tool schemas are '
                             'built. Re-derive the reviewed tool declarations and replace the pin.')
        elif typebox['status'] == 'changed':
            note('contract', f'The TypeBox that builds the tool schemas changed to {typebox["target"]["declared"]} '
                             f'(lock {typebox["target"]["lock"]["version"]}); re-derive the reviewed tool declarations '
                             'and update the pin.')

    schema = pi_schema_status(base_entry['pi_schema'], before, after, upstream)
    if not schema['base_reproduced']:
        note('blocking', f'The reviewed pi-schema pin does not match Pi {base}\'s validator dependencies and npm.')
    if not schema['target']['consistent']:
        note('blocking', f'packages/ai and packages/agent declare different pi-schema versions at v{target}.')
    elif schema['target']['version'] and schema['target_pin'] is None:
        note('blocking', f'npm has no integrity for {PI_SCHEMA}@{schema["target"]["version"]}.')
    if schema['status'] == 'introduced':
        note('contract', f'Pi validates tool arguments with pi-schema {schema["target"]["version"]} at v{target}. The '
                         'draft pins it; review its coercion rules against the runner\'s raw-argument policy.')
    elif schema['status'] == 'changed':
        note('review', f'pi-schema changes from {schema["pin"]["version"]} to {schema["target"]["version"]}; review '
                       'packages/schema for coercion and validation changes.')
    elif schema['status'] == 'removed':
        note('contract', f'Neither packages/ai nor packages/agent declares pi-schema at v{target}; re-derive the '
                         'tool-argument validator and replace the pin.')

    npm, npm_findings = npm_identity(upstream, target, target_commit, check_tarball=check_tarball)
    for severity, text in npm_findings:
        note(severity, text)
    notes = release_notes(upstream, base, target)
    if not any(item['release'] == target for item in notes):
        note('review', f'No published GitHub release notes were found for v{target}.')

    generated = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    report = {
        'schema': 1, 'document_type': 'pi_release_intake', 'generated_at': generated,
        'scope': 'Read-only upstream source and metadata drift. Not admission, review or qualification.',
        'upstream': upstream.repository,
        'target': {'release': target, 'tag': 'v' + target, 'commit': target_commit},
        'base': {'release': base, 'tag': 'v' + base, 'recorded_commit': base_commit, 'tag_commit': base_tag_commit,
                 'pins_reproduced': sum(map(len, pinned.values())) - len(unreproduced),
                 'pins_unreproduced': unreproduced},
        'reviewed_target': reviewed_target,
        'compare_url': diff_url(upstream, base_commit, target_commit),
        'pinned_files': files, 'cli_flags': flags, 'tools_directory': tools,
        'dependencies': dependencies, 'typebox': typebox, 'pi_schema': schema, 'npm': npm, 'release_notes': notes,
        'repository_mentions': repository_mentions(repository, base) if repository else None,
        'findings': sorted(findings, key=lambda item: SEVERITIES.index(item['severity'])),
        'requests': upstream.requests,
    }
    entry = draft_entry(target, base_entry, after, typebox['status'] == 'unchanged', schema['target_pin'])
    check = registry_check(target, entry)
    report['draft_entry'] = {'unreviewed_fields': [field for field in entry if field not in DERIVED_FIELDS],
                             'check': check, 'source': entry_source(target, entry)}
    draft = {
        'schema': 2, 'document_type': 'pi_release_intake_draft', 'status': 'unreviewed-draft',
        'release': target, 'derived_from': base,
        'upstream': {'repository': upstream.repository, 'tag': 'v' + target, 'commit': target_commit},
        'npm': {key: npm[key] for key in ('package', 'version', 'integrity', 'shasum', 'tarball_sha256', 'has_shrinkwrap')}
               | {'provenance_commits': (npm['provenance'] or {}).get('commits')},
        'registry_entry': entry,
        'unreviewed_fields': report['draft_entry']['unreviewed_fields'],
        'registry_check': check,
        'registry_entry_source': report['draft_entry']['source'],
        'open_items': [item['text'] for item in report['findings'] if item['severity'] != 'review'],
    }
    return report, draft


def _plain(text):
    return LINK.sub(r'\1', text)


def _packages(mapping):
    return ', '.join(f'{name} {" → ".join(spec) if isinstance(spec, list) else spec}'
                     for name, spec in mapping.items()) or 'none'


def render_packet(report):
    target, base, npm = report['target'], report['base'], report['npm']
    lines = [f'# Pi {target["release"]} intake against reviewed Pi {base["release"]}', '',
             f'Generated {report["generated_at"]} by `tools/pi_release_intake.py`. It narrows the review to '
             f'what the reviewed contracts depend on; it does not admit or qualify Pi {target["release"]}.', '',
             '## Findings', '']
    lines += [f'- **{item["severity"]}**: {item["text"]}' for item in report['findings']]
    provenance_state = ('absent' if not npm['provenance'] else
                        'commit matches tag' if npm['provenance']['commits'] == [target['commit']] else
                        'commit differs from tag')
    lines += ['', '## Identity', '', '| | Reviewed base | Target |', '|---|---|---|',
              f'| Tag | `{base["tag"]}` | `{target["tag"]}` |',
              f'| Commit | `{base["recorded_commit"]}` | `{target["commit"]}` |',
              f'| Pins reproduced at base | {base["pins_reproduced"]} | |',
              f'| npm integrity | | `{npm["integrity"]}` (tarball {npm["tarball_check"]}) |',
              f'| Tarball SHA-256 | | `{npm["tarball_sha256"] or "not downloaded"}` |',
              f'| npm provenance | | {provenance_state}; signature not verified |',
              f'| npm shrinkwrap | | {npm["has_shrinkwrap"]} |', '',
              f'Compare: {report["compare_url"]}', '']
    files = report['pinned_files']
    touched = [item for item in files if item['status'] != 'unchanged']
    lines += [f'## Pinned upstream files ({len(touched)} of {len(files)} changed)', '']
    if touched:
        lines += ['| File | Pinned by | Status | Links |', '|---|---|---|---|']
        for item in touched:
            links = f'[diff]({item["diff"]})' + (f' · [file]({item["file"]})' if item['file'] else '')
            lines.append(f'| `{item["path"]}` | {", ".join(item["pinned_by"])} | {item["status"]} | {links} |')
        lines += ['', 'Local review in a Pi clone:', '', '```bash',
                  f'git diff {base["recorded_commit"]} {target["commit"]} -- '
                  + ' '.join(item['path'] for item in touched), '```', '']
    unchanged = [item['path'] for item in files if item['status'] == 'unchanged']
    if unchanged:
        lines += ['Unchanged: ' + ', '.join(f'`{path}`' for path in unchanged), '']
    flags, tools, typebox, schema = report['cli_flags'], report['tools_directory'], report['typebox'], report['pi_schema']
    validator = schema['target']['version']
    lines += ['## Interfaces', '',
              f'- CLI flags added: {", ".join(flags["added"]) or "none"}; removed: {", ".join(flags["removed"]) or "none"}; '
              f'required flags missing: {", ".join(flags["missing_required"]) or "none"}.',
              f'- `{TOOLS_DIR}` files added: {", ".join(tools["added"]) or "none"}; '
              f'removed: {", ".join(tools["removed"]) or "none"}.',
              f'- TypeBox schema builder pin: {typebox["status"]}.',
              f'- pi-schema validator pin: {schema["status"]}' + (f' (target {validator})' if validator else '') + '.']
    for path, drift in report['dependencies'].items():
        if 'added' in drift:
            lines.append(f'- `{path}`: added {_packages(drift["added"])}; removed {_packages(drift["removed"])}; '
                         f'changed {_packages(drift["changed"])}; {len(drift["lockstep"])} lockstep internal bumps.')
    lines += ['', '## Release notes, keyword-filtered', '',
              'Bullets that mention tools, CLI flags, sessions, models, extensions, retries or breaking changes, '
              'minus hosted-provider and interactive-UI noise. Read the full notes for anything else.', '']
    for item in report['release_notes']:
        relevant = [bullet for bullet in item['bullets'] if bullet['relevant']]
        lines.append(f'### {item["release"]} ({(item["published_at"] or "")[:10]}) — '
                     f'{len(relevant)} of {len(item["bullets"])} bullets · [full notes]({item["url"]})')
        lines += [''] + [f'- [{", ".join(bullet["topics"])}] {_plain(bullet["text"])}' for bullet in relevant] + ['']
    draft = report['draft_entry']
    check = ('As written it loads: `check_registry()` accepts it after the reviewed entries.' if draft['check']['loads']
             else f'As written it does not load: {draft["check"]["reason"]}.')
    lines += ['## Draft registry entry', '',
              f'Append this to `_REVIEWED` in `skill/runtime/release_contracts.py` once reviewed. The commit, source and '
              f'package pins and fixture profile come from v{target["release"]}. These fields are carried over from Pi {base["release"]} '
              f'unreviewed: {", ".join(f"`{field}`" for field in draft["unreviewed_fields"])}. {check}', '',
              '```python', draft['source'], '```', '']
    mentions = report['repository_mentions']
    if mentions:
        lines += [f'## Repository places that name Pi {base["release"]}', '',
                  'For reference. A new release changes only the checklist places below; check the documentation '
                  'here for text that should also name it.', '']
        for group in ('code', 'docs'):
            lines.append(f'- {group}: ' + (', '.join(f'`{entry["path"]}` ({entry["lines"]})'
                                                     for entry in mentions[group]) or 'none'))
        lines.append('')
    release = target['release']
    lines += ['## Review checklist', '',
              f'- [ ] Read every changed pinned file and record behavior changes in a `PI-{release}.md` reference.',
              '- [ ] Confirm or correct each carried-over field of the draft registry entry.',
              '- [ ] Resolve every blocking and contract finding above.',
              '- [ ] Append the reviewed entry to `_REVIEWED` in `skill/runtime/release_contracts.py`.',
              f'- [ ] Add {release}\'s tool declarations to `_RELEASE_TOOLS` in `skill/runtime/native_tool_contracts.py`, '
              'checked against a live `getAllTools()` dump of an image built for the release.',
              f'- [ ] Add `skill/assets/profiles/fixture-lookup/profile.pi-{release}.json` and add {release} to the '
              '`pi_release` check in `skill/runtime/tool-budget.mjs`.',
              f'- [ ] Append the output of `python3 tests/test_release_registry.py --freeze {release}` to '
              '`REVIEWED_IDENTITIES`.',
              '- [ ] Add the new release identity to `PARALLEL_RELEASE_CONTRACTS` in '
              '`tools/qualification/application_sdk_admission.py`.',
              '- [ ] Update the documentation and `skill/MANIFEST.sha256`, then build exact images and run a native '
              f'campaign with `--release {release}` before any stable claim.', '']
    return '\n'.join(lines)


def _fresh_output(path):
    requested = Path(path).expanduser()
    if requested.exists() or requested.is_symlink():
        raise IntakeError(f'Choose a fresh output directory: {requested} exists')
    resolved = requested.resolve()
    for protected in ('skill', 'tests', 'tools'):
        inside = REPO / protected
        if resolved == inside or inside in resolved.parents:
            raise IntakeError(f'Choose an output directory outside {inside}')
    return resolved


def parser():
    result = argparse.ArgumentParser(
        description='Prepare a review packet for an upstream Pi release. Read-only: it installs, '
                    'executes, admits and qualifies nothing.')
    result.add_argument('--release', required=True, help='exact upstream release to review, for example 1.5.0')
    result.add_argument('--base', help='reviewed release to compare with (default: the newest reviewed release)')
    result.add_argument('--output-dir', required=True,
                        help='fresh directory for intake.json, review-packet.md and draft-contract.json')
    result.add_argument('--skip-tarball', action='store_true',
                        help='do not download the npm tarball; its integrity and SHA-256 stay unchecked')
    return result


def main(argv=None, upstream=None):
    arguments = parser().parse_args(argv)
    try:
        target = arguments.release.removeprefix('v')
        parse_version(target)
        baseline = reviewed_baseline(arguments.base or newest_reviewed())
        output = _fresh_output(arguments.output_dir)
        report, draft = intake(upstream or Upstream(), target, baseline,
                               check_tarball=not arguments.skip_tarball, repository=REPO)
    except IntakeError as exc:
        print(f'pi_release_intake: {exc}', file=sys.stderr)
        return 1
    try:
        output.mkdir(parents=True)
        (output / 'intake.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        (output / 'draft-contract.json').write_text(json.dumps(draft, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        (output / 'review-packet.md').write_text(render_packet(report), encoding='utf-8')
    except OSError as exc:
        print(f'pi_release_intake: could not write {output}: {exc}', file=sys.stderr)
        return 1
    counts = {severity: sum(item['severity'] == severity for item in report['findings']) for severity in SEVERITIES}
    changed = sum(item['status'] != 'unchanged' for item in report['pinned_files'])
    print(f'Pi {target} against reviewed {baseline["release"]}: {changed} of {len(report["pinned_files"])} '
          f'pinned files changed; {counts["blocking"]} blocking, {counts["contract"]} contract findings.')
    print(f'Review packet: {output / "review-packet.md"}')
    return 3 if counts['blocking'] else 0


if __name__ == '__main__':
    sys.exit(main())
