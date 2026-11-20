"""Command modules that add subcommands to pi_lab.py.

Each name in COMMAND_MODULES is an importable module that defines
register(subparsers). It adds its subparser or subparsers and calls
set_defaults(handler=function) on each, where function(args) returns the exit
code. pi_lab.py registers the modules after its built-in commands, in the order
listed here. Keep one name per line, in alphabetical order, so that two changes
that each add a line do not conflict.
"""

COMMAND_MODULES = (
)
