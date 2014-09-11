#!/usr/bin/python

import sys, os, argparse
import asyncio
import traceback
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
    # That wasn't so hard, right? Why do the IPython developers keep on recommending
    # regular polling as the way of integrating an IPython kernel with a mainloop then?



class Daemon:
    def __init__(self):
        self.rulebooks = {}
        self.loop = asyncio.get_event_loop()
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

    def _exception_handler(self, loop, context):
        exc = context.get('exception')
        if isinstance(exc, asyncio.InvalidStateError):
            # XXX Sometimes an exception like this appers as a result of a cancelled coroutine:
            #     Traceback (most recent call last):
            #       File "/usr/lib/python3.4/asyncio/events.py", line 39, in _run
            #         self._callback(*self._args)
            #       File "/usr/lib/python3.4/asyncio/subprocess.py", line 44, in connection_made
            #         self.waiter.set_result(None)
            #       File "/usr/lib/python3.4/asyncio/futures.py", line 298, in set_result
            #         raise InvalidStateError('{}: {!r}'.format(self._state, self))
            #     asyncio.futures.InvalidStateError: CANCELLED: Future<CANCELLED>
            # Maybe I'm doing something wrong, but it looks as a bug in `asyncio`.
            return
        if isinstance(exc, asyncio.CancelledError):
            return
        traceback.print_exception(type(exc), exc, exc.__traceback__)
        traceback.print_stack()
        sys.exit(1)

    @asyncio.coroutine
    def initialize(self):
        # Make all exceptions fatal for easier debugging
        self.loop.set_exception_handler(self._exception_handler)
        tasks = []
        if HAVE_IPYTHON:
            self.ipython.start()
            logger.info("IPython ready. Connect with: ``nsctl console`` or ``ipython console --existing %s``",
                    self.ipython.app.connection_file)
        logger.info("Loading network state")
        self.ns = NetworkState()
        self.ipython.ns['ns'] = self.ns
        self.ctx = rulebook.runtime.Context()
        self.ctx.ns.ns = self.ns # Make the NetworkState available under the name 'ns'
                                 # in the namespace of the rulebooks (a bit unfortunate
                                 # clash of acronyms, TODO better naming).
        self.ctx.ns.logger = logging.getLogger('ns_rbk')
        yield from self.ns.start()

        logger.info("Loading configuration")
        self._load_rules([RULES_BUILTIN, RULES_USER])

        ctl_path = str(RUNDIR / 'ctl.sock')
        try: os.unlink(ctl_path)
        except FileNotFoundError: pass
        yield from asyncio.start_unix_server(self._unix_conn, ctl_path)

    def _unix_conn(self, reader, writer):
        logger.info('New unix connection')
        @asyncio.coroutine
        def conn_coro():
            while True:
                line = yield from reader.readline()
                if not line: break
                line = line.decode('utf-8').strip()
                logger.info('Got ctl command: %s', line)
        run_task(conn_coro())

    def main(self):
        self.loop.run_until_complete(self.initialize())
        logger.info("Entering mainloop")
        self.loop.run_forever()

def main():
    daemon = Daemon()
    daemon.main()

if __name__ == '__main__':
    main()
