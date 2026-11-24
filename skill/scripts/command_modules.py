"""Modules that register additional pi_lab.py subcommands.

Each name below is a module in this directory that exposes
``register(subparsers)``. It adds its subparsers and calls
``set_defaults(handler=function)``; ``handler(args)`` returns the exit code.
Keep one name per line, in alphabetical order.
"""
COMMAND_MODULES: tuple[str, ...] = (
    'init_plan',
    'registry_compaction',
)
