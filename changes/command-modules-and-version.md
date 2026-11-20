kind: added

New `pi_lab.py` commands can now be added as separate modules: each module
listed in `COMMAND_MODULES` in `scripts/command_modules.py` defines
`register(subparsers)`, and a command that sets a `handler` is dispatched without
editing the parser or `main()`. A listed module that cannot be imported stops the
program at start with its name. `pi_lab.py --version` prints
`pi-agent-test-env <version>` from `skill.json`. Existing commands and their help
text are unchanged.
