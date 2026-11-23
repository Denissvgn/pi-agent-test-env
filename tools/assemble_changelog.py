#!/usr/bin/env python3
"""Assemble changelog fragments from `changes/` into a new top entry of skill/CHANGELOG.md.

Each pending change adds one Markdown fragment, `changes/<short-name>.md`. Its first
line is `kind: <kind>` where kind is one of added, changed, fixed, removed, security
or upgrade-note; the rest of the file is the text as it should read in the changelog.
`changes/README.md` is documentation and is never assembled, and dotfiles in
`changes/` are ignored.

`--version X.Y.Z` inserts a new `## X.Y.Z` entry above the existing entries, groups
the fragments by kind (upgrade notes go under "Upgrading from <previous version>")
and then deletes the fragments. Existing entries are never reflowed: the new entry is
inserted as bytes ahead of the current top entry, in the file's own newline style.
The changelog write and the deletions happen together; if one fails, everything is
restored and the fragments are still there to retry with. `--check` validates the
fragments and writes nothing.
"""
import argparse
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from release_files import FileTransaction, read_exact  # noqa: E402  (sibling module beside this script)

REPO = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r'\d+\.\d+\.\d+')
KIND_RE = re.compile(r'kind: (added|changed|fixed|removed|security|upgrade-note)')
KIND_ORDER = ('added', 'changed', 'fixed', 'removed', 'security')
TITLES = {'added': 'Added', 'changed': 'Changed', 'fixed': 'Fixed', 'removed': 'Removed', 'security': 'Security'}
TOP_ENTRY_RE = re.compile(r'^## (.+)$', re.MULTILINE)


def read_text(path: Path) -> str:
    """Text exactly as stored: no newline translation, so existing bytes round-trip."""
    return read_exact(path)[0].decode('utf-8')


def parse_fragment(path: Path) -> tuple[str, str]:
    """Return (kind, body) for one fragment, or raise ValueError naming the file."""
    lines = [line.rstrip('\r') for line in read_text(path).split('\n')]
    match = KIND_RE.fullmatch(lines[0].rstrip())
    if match is None:
        raise ValueError(f'{path.name}: the first line must be "kind: " followed by added, changed, fixed, '
                         'removed, security or upgrade-note')
    body = '\n'.join(lines[1:]).strip()
    if not body:
        raise ValueError(f'{path.name}: the text after the kind line is empty')
    return match.group(1), body


def pending_fragments(root: Path) -> list[tuple[Path, str, str]]:
    """Return (path, kind, body) for every fragment, sorted by file name."""
    directory = root / 'changes'
    if not directory.is_dir():
        return []
    result = []
    for path in sorted(directory.iterdir()):
        if path.name == 'README.md' or path.name.startswith('.'):
            continue
        if not path.name.endswith('.md'):
            raise ValueError(f'{path.name}: only Markdown fragments (*.md) may be in changes/')
        kind, body = parse_fragment(path)
        result.append((path, kind, body))
    return result


def previous_version(changelog: str) -> str | None:
    """Version named by the current top entry, or None when there is no entry."""
    match = TOP_ENTRY_RE.search(changelog)
    if match is None:
        return None
    version = re.match(r'(\d+\.\d+\.\d+)\b', match.group(1))
    if version is None:
        raise ValueError(f'CHANGELOG top entry {match.group(1)!r} does not begin with a version')
    return version.group(1)


def bullet(body: str) -> str:
    lines = body.split('\n')
    return '\n'.join([f'- {lines[0]}'] + [f'  {line}' if line else '' for line in lines[1:]])


def render(version: str, previous: str | None, fragments: list[tuple[str, str]]) -> str:
    """Return the new entry with '\\n' line endings; the caller converts them to the file's style."""
    blocks = [f'## {version}']
    upgrades = [body for kind, body in fragments if kind == 'upgrade-note']
    if upgrades:
        blocks.append(f'### Upgrading from {previous}\n\n' + '\n'.join(bullet(body) for body in upgrades))
    for kind in KIND_ORDER:
        bodies = [body for item, body in fragments if item == kind]
        if bodies:
            blocks.append(f'### {TITLES[kind]}\n\n' + '\n'.join(bullet(body) for body in bodies))
    return '\n\n'.join(blocks) + '\n\n'


def assemble(root: Path, version: str) -> list[Path]:
    if not VERSION_RE.fullmatch(version):
        raise ValueError('version must have the form X.Y.Z')
    changelog_path = root / 'skill/CHANGELOG.md'
    changelog = read_text(changelog_path)
    if re.search(rf'^## {re.escape(version)}(?!\d)', changelog, re.MULTILINE):
        raise ValueError(f'CHANGELOG already has an entry for {version}')
    fragments = pending_fragments(root)
    if not fragments:
        raise ValueError('no fragments in changes/; nothing to assemble')
    previous = previous_version(changelog)
    if any(kind == 'upgrade-note' for _path, kind, _body in fragments) and previous is None:
        raise ValueError('upgrade-note fragments need an existing entry to name the previous version')
    newline = '\r\n' if '\r\n' in changelog else '\n'
    entry = render(version, previous, [(kind, body) for _path, kind, body in fragments]).replace('\n', newline)
    top = TOP_ENTRY_RE.search(changelog)
    if top is not None:
        updated = changelog[:top.start()] + entry + changelog[top.start():]
    else:
        updated = changelog + newline + entry
    removed = []
    with FileTransaction() as transaction:
        transaction.write(changelog_path, updated.encode('utf-8'))
        for path, _kind, _body in fragments:
            transaction.delete(path)
            removed.append(path)
    return removed


def check(root: Path) -> int:
    fragments = pending_fragments(root)
    changelog = read_text(root / 'skill/CHANGELOG.md')
    if any(kind == 'upgrade-note' for _path, kind, _body in fragments) and previous_version(changelog) is None:
        raise ValueError('upgrade-note fragments need an existing entry to name the previous version')
    print(f'{len(fragments)} changelog fragment(s) valid')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--version', help='version of the new top entry, X.Y.Z')
    group.add_argument('--check', action='store_true', help='validate the fragments; write nothing')
    parser.add_argument('--root', type=Path, default=REPO, help='repository root (default: this repository)')
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.check:
            return check(root)
        removed = assemble(root, args.version)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f'error: {exc}')
        return 1
    print(f'assembled {args.version}; removed {len(removed)} fragment(s)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
