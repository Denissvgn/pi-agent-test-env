#!/usr/bin/env python3
"""Check local Markdown links in files tracked by Git."""
import html
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FENCE = re.compile(r'^\s*(`{3,}|~{3,})')
LIST_ITEM = re.compile(r'^ {0,3}(?:[-+*]|[0-9]{1,9}[.)]) +(?=\S)')
BLOCK_END = re.compile(
    r'^ {0,3}(?:#{1,6}(?:\s|$)|(?:=+|-+)\s*$|(?:(?:\*\s*){3,}|(?:_\s*){3,}|(?:-\s*){3,})$)'
)
CODE_SPAN = r'(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)'
COMMENT_TOKEN = re.compile(r'\\.|' + CODE_SPAN + r'|(?P<comment><!--)')
UNDERSCORE_MARKUP = re.compile(
    CODE_SPAN + r'|\\(?P<literal>_)|(?<!\w)(?P<delimiter>_+)(?=[^\s_])'
    r'(?P<emphasis>.+?)(?<![\s_])(?P=delimiter)(?!\w)'
)
LINK = re.compile(r'!?\[[^\]\n]*\]\(\s*(?:<([^>]+)>|((?:\\.|[^\s()\\]|\([^()]*\))+))(?:\s+[^)]*)?\)')
REFERENCE = re.compile(r'^\s{0,3}\[([^]]+)\]:\s*(?:<([^>]+)>|(\S+))', re.M)


def strip_comments(line, in_comment):
    parts = []
    while True:
        if in_comment:
            _, end, line = line.partition('-->')
            if not end:
                return ''.join(parts), True
        comment = next((token for token in COMMENT_TOKEN.finditer(line) if token['comment']), None)
        if comment is None:
            return ''.join(parts) + line, False
        parts.append(line[:comment.start()])
        line = line[comment.end():]
        in_comment = True


def visible(text):
    lines = []
    fence = None
    in_comment = paragraph = False
    list_indents = []
    for line in text.splitlines():
        match = FENCE.match(line)
        if fence is not None:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence):
                fence = None
            lines.append('')
            continue
        if not in_comment:
            expanded = line.expandtabs(4)
            if expanded.strip():
                indent = len(expanded) - len(expanded.lstrip(' '))
                while list_indents and indent < list_indents[-1]:
                    list_indents.pop()
            offset = list_indents[-1] if list_indents else 0
            content = expanded[offset:]
            # Indented code cannot interrupt a paragraph. List item indentation
            # is part of the container and does not count toward code indentation.
            if not paragraph and content.startswith('    '):
                lines.append('')
                continue
            item = LIST_ITEM.match(content)
            if item and not BLOCK_END.match(content):
                list_indents.append(offset + item.end())
        if not in_comment and match:
            fence = match[1]
            paragraph = False
            lines.append('')
            continue
        line, in_comment = strip_comments(line, in_comment)
        lines.append(line)
        paragraph = bool(line.strip()) and not BLOCK_END.match(line)
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
            heading = re.sub(r'<[^>]*>', '', heading)
            heading = UNDERSCORE_MARKUP.sub(lambda match: match['literal'] or match['emphasis'] or match[0], heading)
            heading = html.unescape(re.sub(r'[`*~]', '', heading)).lower()
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


def check(root, tracked_files):
    files = {path.relative_to(root).as_posix(): path for path in tracked_files}
    directories = {parent.as_posix() for name in files for parent in PurePosixPath(name).parents}
    errors = []
    cache = {}
    for name, path in files.items():
        if not name.endswith('.md'):
            continue
        text = visible(path.read_text(encoding='utf-8'))
        text = re.sub(r'`+[^`\n]*`+', '', text)
        targets = [a or b for a, b in LINK.findall(text)]
        targets += [a or b for _, a, b in REFERENCE.findall(text)]
        for target in targets:
            target = html.unescape(re.sub(r'\\([!"#$%&\'()*+,./:;<=>?@\[\]\\^_`{|}~-])', r'\1', target))
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            relative = unquote(parsed.path)
            if relative.startswith('/'):
                destination_name = posixpath.normpath(relative.lstrip('/'))
            elif relative:
                destination_name = posixpath.normpath(posixpath.join(posixpath.dirname(name), relative))
            else:
                destination_name = name
            destination = root / destination_name
            tracked = destination_name in files or destination_name in directories
            if not tracked or not destination.exists():
                errors.append(f'{name}: {target}: missing target')
                continue
            if parsed.fragment and destination.suffix.lower() == '.md' and destination.is_file():
                if destination_name not in cache:
                    cache[destination_name] = anchors(destination.read_text(encoding='utf-8'))
                if unquote(parsed.fragment) not in cache[destination_name]:
                    errors.append(f'{name}: {target}: missing anchor')
    return errors


def main():
    files = os.fsdecode(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT)).split('\0')
    errors = check(ROOT, [ROOT / name for name in files if name])
    print('\n'.join(errors) if errors else 'Relative Markdown links pass')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
