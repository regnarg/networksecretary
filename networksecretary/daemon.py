#!/usr/bin/python

import sys, os, argparse
import asyncio
import rulebook
from .util import *

class Daemon:
    def __init__(self):
        self.rulebooks = {}

    # arg_parser = argparse.ArgumentParser()
    # arg_parser.add_argument('-c', nargs=1, dest='config_path', help="Specify alternative configuration directory.")
    # arg_parser.add_argument('-C', action='store_false', dest='want_builtin', default=True,
    #                         help="Do not load builtin rules.")
    # def parse_cmdline(self, argv):
    #     args = self.arg_parser.parse_args(argv)

    def _load_rules(self, dirs):
        for dir in dirs:
            for file in Path(dir).glob('*.rbk'):
                self._load_rbk(file)

    def _load_rbk(self, file):
        file = Path(file).resolve()
        self.rulebooks[file] = rulebook.load(file)

    def main(self):
        for dir in [RULES_LIB, RULES_BUILTIN, RULES_USER]:
            self._load_rules(dir)


