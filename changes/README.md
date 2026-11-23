# Changelog fragments

A change that should appear in the changelog adds one fragment file here, named
`<short-name>.md` (lowercase words joined by hyphens is the convention). Pull requests
do not edit `skill/CHANGELOG.md`, and they do not touch `skill/MANIFEST.sha256`.

A fragment has two parts:

1. The first line is `kind:` followed by one of these words: `added`, `changed`,
   `fixed`, `removed`, `security` or `upgrade-note`.
2. The rest of the file is the text as it should read in the changelog: one or
   more sentences or a short list. Ordinary Markdown in the text is kept as written.

```markdown
kind: fixed
`bump_version.py --check` now names the file that disagrees with `skill/skill.json`.
```

`upgrade-note` fragments are listed under "Upgrading from <previous version>", so
write them as instructions for a user who is moving from the previous release.

This README is documentation and is never assembled.

When a release is prepared, `tools/assemble_changelog.py --version X.Y.Z` inserts
a new top entry above the existing ones, groups the fragments by kind and deletes
them. `tools/assemble_changelog.py --check` validates the fragments without writing
anything. See [CONTRIBUTING.md](../CONTRIBUTING.md#changelog-fragments-and-version-bumps).
