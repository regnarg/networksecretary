#!/usr/bin/python

import sys, os, argparse
import asyncio
import rulebook
from .util import *
from .libnetconf import NetworkState
import rulebook.runtime

import logging
logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)

try:
    from IPython.kernel.zmq.kernelapp import IPKernelApp
    import zmq
except ImportError:
    logger.warn("IPython and/or pyzmq not available. Interactive console will not work.")
    HAVE_IPYTHON = False
else:
    HAVE_IPYTHON = True

if HAVE_IPYTHON:
    class IPythonEmbed:
        def __init__(self, ns):
            self.ns = ns
            self.app = IPKernelApp(transport='ipc')
            NOP = lambda *a,**kw: None
            # Don't exit upon parent process exit
            self.app.init_poller = NOP
            # Don't redirect stdio
            self.app.init_io = NOP
            self.app.init_blackhole = NOP
            # Don't catch SIGINT
            self.app.init_signal = NOP
            self.app.init_connection_file = NOP
            self.app.log_connection_info = NOP

            self.app.connection_file = str(RUNDIR / 'ipython.json')

        def start(self):
            # Make sure only root can access the sockets and the connection file
            with umask_ctx(0o077):
                try: os.unlink(self.app.connection_file)
                except FileNotFoundError: pass
                self.app.initialize()

            self.app.kernel.user_module = sys.modules[__name__]
            self.app.kernel.user_ns = self.ns
            self.app.shell.set_completer_frame()

            self.app.kernel.start()

            for stream in self.app.kernel.shell_streams:
                fd = stream.socket.getsockopt(zmq.FD)
                def callback(stream):
                    stream.flush(zmq.POLLIN, 1)
                    stream.flush(zmq.POLLOUT)
                asyncio.get_event_loop().add_reader(fd, callback, stream)



class Daemon:
    def __init__(self):
        self.rulebooks = {}
        if HAVE_IPYTHON:
            self.ipython = IPythonEmbed({'daemon': self})

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
        logger.info("Loading rulebook %s", file)
        self.rulebooks[file] = rulebook.load(file, self.ctx)[0]
        self.rulebooks[file].set_active(True)

    def main(self):
        if HAVE_IPYTHON:
            self.ipython.start()
            logger.info("IPython ready. Connect with: `` ipython console --existing %s ``",
                    self.ipython.app.connection_file)
        logger.info("Loading network state")
        self.loop = asyncio.get_event_loop()
        self.ns = NetworkState()
        self.ctx = rulebook.runtime.Context()
        self.ctx.ns.ns = self.ns # Make the NetworkState available under the name 'ns'
                                 # in the namespace of the rulebooks (a bit unfortunate
                                 # clash of acronyms, TODO better naming).
        self.ctx.ns.logger = logging.getLogger('ns_rbk')
        start_task = asyncio.Task(self.ns.start())
        self.loop.run_until_complete(start_task)

        logger.info("Loading configuration")
        self._load_rules([RULES_LIB, RULES_BUILTIN, RULES_USER])

        logger.info("Entering mainloop")
        self.loop.run_forever()

def main():
    daemon = Daemon()
    daemon.main()

if __name__ == '__main__':
    main()
