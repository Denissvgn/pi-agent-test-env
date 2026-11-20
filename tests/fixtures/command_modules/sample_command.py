"""Sample command module for tests/test_command_modules.py; registered only inside that test."""


def register(subparsers):
    sample = subparsers.add_parser('sample-echo', help='Print the given text and exit with the given code')
    sample.add_argument('--text', default='')
    sample.add_argument('--code', type=int, default=0)
    sample.set_defaults(handler=handle)


def handle(args):
    print(f'sample:{args.text}')
    return args.code
