#!/usr/bin/env python3
"""Keep the package version in every file that states it as live metadata.

`skill/skill.json` is the source of truth. `--check` reads every listed place and
exits 1 when any of them differs from it, naming the file and line. `X.Y.Z` rewrites
the version in skill.json and in every listed place, after confirming that the
places currently agree. Each place is a pattern that must match exactly once.
The rewrite is all-or-nothing: if any file cannot be written, every file already
rewritten is restored to its original bytes and mode.

Dated evidence (campaign results, historical archive names and feature notes such
as "added in 4.11.0") is not a place and is never rewritten.
"""
import argparse
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from release_files import FileTransaction, read_exact  # noqa: E402  (sibling module beside this script)

REPO = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r'\d+\.\d+\.\d+')
EOL = r'\r?$'  # a line may end in CRLF as well as LF

# (file relative to the root, pattern whose only group captures the version)
PLACES = (
    ('skill/skill.json', rf'^  "version": "(\d+\.\d+\.\d+)",{EOL}'),
    ('README.md', r'version-(\d+\.\d+\.\d+)-blue'),
    ('README.md', r'^Version (\d+\.\d+\.\d+) is a stable release'),
    ('skill/README.md', rf'^# Pi Agent Test Environment (\d+\.\d+\.\d+){EOL}'),
    ('skill/README.md', r'^Version (\d+\.\d+\.\d+) is stable for'),
    ('skill/SKILL.md', r'^Package version: (\d+\.\d+\.\d+)\. '),
    ('skill/SKILL.md', r'^Version (\d+\.\d+\.\d+) is stable for'),
    ('skill/references/HARNESSES.md', r'^Version comes from `skill\.json`\. The package version is (\d+\.\d+\.\d+)\.'),
    ('skill/references/HARNESSES.md', r'^\| `pi-agent-test-env-(\d+\.\d+\.\d+)\.zip`'),
    ('skill/references/OWNER-CLEANUP-COMPATIBILITY.md', r'^The owner-proof additions from package 4\.8\.0 remain experimental in (\d+\.\d+\.\d+)\.'),
    ('skill/QUALIFICATION.md', r'^Version (\d+\.\d+\.\d+) is a stable release\.'),
    ('skill/QUALIFICATION.md', rf'^\| Scope \| Status for (\d+\.\d+\.\d+) \|{EOL}'),
)


def read_text(path: Path) -> str:
    """Text exactly as stored: no newline translation, so CRLF stays CRLF."""
    return read_exact(path)[0].decode('utf-8')


def locate(root: Path):
    """Return (relative path, text, match, line number) for every place, plus problems."""
    found, problems = [], []
    for relative, pattern in PLACES:
        path = root / relative
        if not path.is_file():
            problems.append(f'{relative}: file is missing')
            continue
        text = read_text(path)
        matches = list(re.finditer(pattern, text, re.MULTILINE))
        if len(matches) != 1:
            problems.append(f'{relative}: pattern {pattern!r} matched {len(matches)} times, expected 1')
            continue
        match = matches[0]
        line = text.count('\n', 0, match.start(1)) + 1
        found.append((relative, text, match, line))
    return found, problems


def source_version(root: Path) -> str:
    text = read_text(root / 'skill/skill.json')
    match = re.search(PLACES[0][1], text, re.MULTILINE)
    if match is None:
        raise ValueError('skill/skill.json has no top-level version line')
    return match.group(1)


def mismatches(root: Path, expected: str) -> list[str]:
    found, problems = locate(root)
    report = list(problems)
    for relative, text, match, line in found:
        if match.group(1) != expected:
            report.append(f'{relative}:{line}: states {match.group(1)}, expected {expected}')
    return report


def check(root: Path) -> int:
    expected = source_version(root)
    report = mismatches(root, expected)
    if report:
        for item in report:
            print(item)
        print(f'version check failed: skill/skill.json is {expected}')
        return 1
    print(f'version check passed: {len(PLACES)} places state {expected}')
    return 0


def bump(root: Path, version: str) -> int:
    """Rewrite every place to version. Raises OSError, with the files restored, if a write fails."""
    current = source_version(root)
    report = mismatches(root, current)
    if report:
        for item in report:
            print(item)
        print('refusing to bump: the places do not agree; fix them first')
        return 1
    if current == version:
        print(f'refusing to bump: the package is already {version}')
        return 1
    rewrites: dict[str, list[tuple[int, int]]] = {}
    texts: dict[str, str] = {}
    found, _ = locate(root)
    for relative, text, match, _line in found:
        texts[relative] = text
        rewrites.setdefault(relative, []).append(match.span(1))
    new_texts = {}
    for relative, spans in rewrites.items():
        text = texts[relative]
        for start, end in sorted(spans, reverse=True):
            text = text[:start] + version + text[end:]
        new_texts[relative] = text
    with FileTransaction() as transaction:
        for relative, text in new_texts.items():
            transaction.write(root / relative, text.encode('utf-8'))
    print(f'bumped {current} -> {version} in {len(PLACES)} places')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('version', nargs='?', help='new version X.Y.Z')
    group.add_argument('--check', action='store_true', help='verify every place; write nothing')
    parser.add_argument('--root', type=Path, default=REPO, help='repository root (default: this repository)')
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.check:
            return check(root)
        if not VERSION_RE.fullmatch(args.version):
            parser.error('version must have the form X.Y.Z')
        return bump(root, args.version)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f'error: {exc}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
