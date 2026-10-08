#!/usr/bin/env python3
"""Validate a version tag and extract its committed changelog entry."""
import argparse
from datetime import date
from pathlib import Path
import re

VERSION = re.compile(r'v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)\Z')


def release_notes(tag, changelog):
    match = VERSION.fullmatch(tag)
    if not match:
        raise ValueError('release tags must use vMAJOR.MINOR.PATCH (optionally with SemVer prerelease/build identifiers)')
    pre = match['pre']
    if pre and any(p.isdigit() and len(p) > 1 and p.startswith('0') for p in pre.split('.')):
        raise ValueError('numeric prerelease identifiers cannot have leading zeroes')
    version = match['version']
    entries = list(re.finditer(r'^## \[([^\]]+)\](?: - (\S+))?\s*$', changelog, re.MULTILINE))
    matches = [i for i, entry in enumerate(entries) if entry[1] == version]
    if len(matches) != 1:
        raise ValueError(f'CHANGELOG.md must contain exactly one ## [{version}] - YYYY-MM-DD entry')
    i = matches[0]
    entry = entries[i]
    if not entry[2]:
        raise ValueError('release entries need a release date')
    date.fromisoformat(entry[2])
    end = entries[i + 1].start() if i + 1 < len(entries) else len(changelog)
    notes = changelog[entry.end():end].strip()
    if not notes:
        raise ValueError('release notes must not be empty')
    return version, bool(pre), notes + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('--changelog', type=Path, default=Path('CHANGELOG.md'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    try:
        version, prerelease, notes = release_notes(args.tag, args.changelog.read_text())
    except (ValueError, OSError) as error:
        parser.error(str(error))
    args.output.write_text(notes)
    if args.github_output:
        with args.github_output.open('a') as output:
            output.write(f'tag={args.tag}\nversion={version}\nprerelease={str(prerelease).lower()}\n')


if __name__ == '__main__':
    main()
