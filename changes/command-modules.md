kind: added

New subcommands can now be added as separate modules listed in `COMMAND_MODULES` (`skill/scripts/command_modules.py`), each exposing `register(subparsers)`, without editing the parser or the dispatch in `pi_lab.py`. A listed module that cannot be imported stops the program at start and names the module. `pi_lab.py --version` prints the skill version from `skill.json`.
