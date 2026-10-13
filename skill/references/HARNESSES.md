# Parent harness installation and discovery

The package name and entry file are `pi-agent-test-env/SKILL.md`. Install the entire
`skill/` directory from this repository, including scripts, runtime, assets,
examples, docker and references. Repository root is not the skill root.

## Documented discovery locations

Primary documentation reviewed 2026-10-07. These are documented recipes, not
claims that the installed harness discovered this revision. Actual version-scoped
qualification is described separately below.

| Parent | Workspace skill root | Personal skill root | Explicit selection |
|---|---|---|---|
| Codex CLI / IDE | `.agents/skills/pi-agent-test-env` | `~/.agents/skills/pi-agent-test-env` | `/skills` or `$pi-agent-test-env` |
| Claude Code | `.claude/skills/pi-agent-test-env` | `~/.claude/skills/pi-agent-test-env` | `/pi-agent-test-env` |
| Antigravity 2.0 / IDE | `.agents/skills/pi-agent-test-env` | `~/.gemini/config/skills/pi-agent-test-env` | `/pi-agent-test-env`; IDE Customizations |
| Antigravity CLI | `.agents/skills/pi-agent-test-env` | `~/.gemini/antigravity-cli/skills/pi-agent-test-env` | `/skills` or `/pi-agent-test-env` |

Sources: [OpenAI local skills](https://learn.chatgpt.com/docs/build-skills),
[Claude Code skills](https://code.claude.com/docs/en/skills),
[Google Antigravity skills](https://antigravity.google/docs/skills).
Codex follows skill symlinks. Claude also documents symlink support. Antigravity
link discovery remains subject to actual version qualification; a complete copy
is an alternative. Restart a harness if its skill list has not refreshed.

## Safe project installation from source

Use the exporter from the repository, selecting a disposable or intended project:

```bash
python3 skill/scripts/export_skill.py --output-dir /tmp/pi-agent-packages \
  --install codex --target-dir /path/to/project
```

Choose an output directory outside the canonical skill package. The package root
and its descendants, including relative, symlink and filesystem case aliases,
reject with exit 2 before manifest writes, directory/ZIP creation or installation.
The default package-parent directory and explicit parent/sibling outputs remain
supported. Existing generated files are preserved when a destination rejects.

Replace `codex` with `claude` or `antigravity`. `all` reports each target; Codex and
Antigravity share the same workspace skill root. The project must already exist.
The installer links the repository's **skill/** directory, so keep that checkout
available. It reports `created`, `already-correct`, `conflict` or `failed`, and
exits nonzero for any conflict/failure. Existing real directories, files, unrelated
links, broken links and commands survive. Linked parent directories are refused.
Claude's optional legacy command is created only after its skill succeeds.

There is no automatic replacement/update option. Review the old destination,
move it to a backup yourself only with authorization, then repeat installation.
A correct link points to live checkout content; it does not freeze a version.
No command here changes global configuration automatically.

## Archive installation

```bash
python3 skill/scripts/export_skill.py --output-dir /tmp/pi-agent-packages
```

Version comes from `skill.json`. The package version is 4.3.0. Emitted artifacts:

| Archive | Extraction layout | Extract into |
|---|---|---|
| `pi-agent-test-env-4.3.0.zip` | `pi-agent-test-env/SKILL.md` | Chosen skills parent |
| `pi-agent-test-env.zip` | Same universal layout | Chosen skills parent |
| `pi-agent-test-env-antigravity.zip` | Same universal layout | Workspace `.agents/skills` or chosen Antigravity personal skills parent |
| `pi-agent-test-env-claude.zip` | `.claude/skills/pi-agent-test-env/SKILL.md` plus optional `.claude/commands/pi-agent-test-env.md` | Project root |
| `pi-agent-test-env-codex.zip` | `.agents/skills/pi-agent-test-env/SKILL.md` | Project root |

Extract into a **new empty disposable directory** first, verify checksums there,
and inspect the destination for conflicts before moving the complete skill.
`unzip -n` into a populated destination can leave mixed versions; it is not an
update protocol. Example Codex staging:

```bash
STAGING=$(mktemp -d)
unzip /tmp/pi-agent-packages/pi-agent-test-env-codex.zip -d "$STAGING"
(cd "$STAGING/.agents/skills/pi-agent-test-env" && shasum -a 256 -c MANIFEST.sha256)
```

For an existing project, use the preserving installer above instead of overwriting
its configuration. All archives retain runtime/resources; copying SKILL.md alone
cannot execute this workflow. `skill.json`, `CODEX.md` and `CLAUDE.md` are package
reference metadata/guides, not independent skill discovery manifests. Do not copy
these files over a user's project instruction files.

## Legacy compatibility and evidence limits

Old `.codex/skills` installs are not the current Codex recipe. Antigravity documents
`.agent/skills` compatibility and IDE `~/.gemini/antigravity/skills` compatibility;
these legacy layouts are not emitted. Claude `.claude/commands` is the older
command format; the actual skill takes precedence if both share the same name.
Gemini CLI is a different parent and is not qualified by Antigravity evidence.
Successful extraction and direct Python execution do not prove harness discovery.
Unavailable versions remain unqualified; do not install software just to fill a
support table.

## Observed compatibility

| Parent | Actual observation | Scope |
|---|---|---|
| Codex CLI 0.144.6 | Enabled repo catalog entry and selected file content observed for the 4.0.1 entry | Workspace symlink; no automatic relevance selection or parent model turn |
| Antigravity CLI 1.2.9 and 1.3.1 | Workspace catalog and selected content observed for earlier 3.0.0/4.0.0 entries | 4.0.1 catalog/content was unqualified: the authorized UI could not access the interactive CLI; no new discovery qualification is claimed for 4.2.0 |
| Claude Code | Documented installation/archive layout | CLI discovery unqualified; Claude desktop is a separate product |
| Antigravity app / IDE | Documented layout | Native GUI discovery unqualified |

Direct installed-relative Python help, clean/repeated installation and refused
conflicts are separate from catalog/content observation. Version/help output does
not prove discovery. No package installer changes global skills or runs a parent
model turn. The entry retains standard name/description frontmatter; structural
validation of each named extracted root is part of publishing verification.

Historical observations keep their exact entry hashes, versions and dates.
Repackaging or a changed description/body does not qualify new discovery behavior.
See [QUALIFICATION.md](../QUALIFICATION.md) for the supported execution scope.
