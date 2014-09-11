import sys, os, argparse
from .util import *

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='cmd')




p_console = subparsers.add_parser('console')

def do_console():
    os.execlp('ipython', 'ipython', 'console', '--existing', str(RUNDIR / 'ipython.json'))

p_set = subparsers.add_parser('set')
p_set.add_argument('-e', dest='type', default='auto', action='store_const', const='eval',
        help='treat VALUE as a Python expression')
p_set.add_argument('-s', dest='type', action='store_const', const='str',
        help='treat VALUE as a string')
p_set.add_argument('name', metavar='NAME', help='The variable/attribute to assign to. E.g. ``ns.ifaces.wlan0.up``.')
p_set.add_argument('value', metavar='VALUE', help='The value to assign. True/False/None, numbers,'
        ' lists, dicts and anything in parentheses are parsed as Python expressions (with `eval`).'
        ' Anything else is treated as a verbatim string. See the `-e` and `-s` options.')

def do_set(name, value, type):
    pass

def main():
    args = parser.parse_args()
    kw = dict(vars(args))
    if not args.cmd:
        parser.print_usage(file=sys.stderr)
        return 1
    del kw['cmd']
    func = globals()['do_' + args.cmd]
    func(**kw)



if __name__ == '__main__':
    sys.exit(main())


