# Claude Code guide: pi-agent-test-env

Read [SKILL.md](SKILL.md) for the environment gate and implemented workflow.
Resolve `SKILL_DIR` to this complete installed package, not the application project.
Use [HARNESSES.md](references/HARNESSES.md) for documented discovery paths and
qualification limits. This guide is a reference, not a discovery manifest or a
replacement for the user's project instructions.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" --help
```

Select an explicitly qualified image before model work. Preserve existing global
skills and project configuration; the exporter reports conflicts without replacing
contents. Harness discovery must identify the active path/content, not just show
that a directory exists.
