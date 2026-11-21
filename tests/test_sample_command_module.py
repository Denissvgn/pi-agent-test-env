"""Sample command module; registered only inside test_command_registration."""


def register(subparsers):
    parser = subparsers.add_parser('sample-greet', help='Sample command registered only by tests')
    parser.add_argument('--name', default='world')
    parser.add_argument('--exit-code', type=int, default=0)
    parser.set_defaults(handler=handle)


def handle(args):
    print(f'hello {args.name}')
    return args.exit_code
