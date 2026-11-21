#!/usr/bin/env python3
"""Check local Markdown links in files tracked by Git."""
import html
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FENCE = re.compile(r'^\s*(`{3,}|~{3,})')
LINK = re.compile(r'!?\[[^\]\n]*\]\(\s*(?:<([^>]+)>|((?:\\.|[^\s()\\]|\([^()]*\))+))(?:\s+[^)]*)?\)')
REFERENCE = re.compile(r'^\s{0,3}\[([^]]+)\]:\s*(?:<([^>]+)>|(\S+))', re.M)


def visible(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append('')
        elif fence is None:
            lines.append(line)
        else:
            lines.append('')
    return '\n'.join(lines)


def anchors(text):
    text = visible(text)
    result, counts = set(), {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = re.match(r'^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$', line)
        heading = match.group(1) if match else None
        if heading is None and i + 1 < len(lines) and re.match(r'^ {0,3}(?:=+|-+)\s*$', lines[i + 1]):
            heading = line.strip() or None
        if heading is not None:
            heading = re.sub(r'!?(?:\[([^]]+)\])\([^)]+\)', r'\1', heading)
            heading = html.unescape(re.sub(r'<[^>]*>|[`*_~]', '', heading)).lower()
            slug = ''.join(c for c in heading if c in '-_ ' or unicodedata.category(c)[0] in 'LNM')
            slug = slug.replace(' ', '-')
            count = counts.get(slug, 0)
            candidate = slug if not count else f'{slug}-{count}'
            while candidate in result:
                count += 1
                candidate = f'{slug}-{count}'
            counts[slug] = count + 1
            result.add(candidate)
    result.update(re.findall(r'<(?:a|[^\s>]+)\s+[^>]*(?:id|name)=["\']([^"\']+)', text, re.I))
    return result


def check(root, files):
    errors = []
    cache = {}
    for path in files:
        text = visible(path.read_text(encoding='utf-8'))
        text = re.sub(r'`+[^`\n]*`+', '', text)
        targets = [a or b for a, b in LINK.findall(text)]
        targets += [a or b for _, a, b in REFERENCE.findall(text)]
        for target in targets:
            target = html.unescape(re.sub(r'\\([!"#$%&\'()*+,./:;<=>?@\[\]\\^_`{|}~-])', r'\1', target))
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith('/'):
                continue
            relative = unquote(parsed.path)
            destination = (path.parent / relative).resolve() if relative else path.resolve()
            if not destination.exists():
                errors.append(f'{path.relative_to(root)}: {target}: missing target')
            elif parsed.fragment and destination.is_file() and destination.suffix.lower() == '.md':
                if destination not in cache:
                    cache[destination] = anchors(destination.read_text(encoding='utf-8'))
                if unquote(parsed.fragment) not in cache[destination]:
                    errors.append(f'{path.relative_to(root)}: {target}: missing anchor')
    return errors


def main():
    files = subprocess.check_output(['git', 'ls-files', '-z', '--', '*.md'], cwd=ROOT).decode().split('\0')
    errors = check(ROOT, [ROOT / name for name in files if name])
    print('\n'.join(errors) if errors else 'Relative Markdown links pass')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
