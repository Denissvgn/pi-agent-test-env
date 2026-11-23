kind: added
Release tooling: `tools/assemble_changelog.py` builds a new top changelog entry from the fragments in `changes/`, `tools/bump_version.py` sets the package version in every place that states it, and `skill/scripts/export_skill.py --manifest-only` regenerates `skill/MANIFEST.sha256` without writing archives.
