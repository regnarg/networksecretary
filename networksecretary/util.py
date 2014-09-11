import sys, os
from pathlib import Path
from contextlib import contextmanager
import types
import asyncio

@contextmanager
def umask_ctx(val):
    """A context manager for temporarily changing umask. Usage::

        with umask_ctx(0o077):
            ...
    """
    old = os.umask(val)
    try:
        yield
    finally:
        os.umask(old)

def _get_paths():
    global RULES_LIB, RULES_BUILTIN, RULES_USER, RUNDIR, LIBDIR
    prefix = Path(sys.prefix)
    my_path = Path(__file__).resolve()
    if prefix in my_path.parents:
        # System-wide installation
        LIBDIR = prefix / 'lib' / 'networksecretary'
    else:
        # Ran from source
        LIBDIR = my_path.parents[1]
    RULES_BUILTIN = LIBDIR / 'rules'
    RULES_USER = Path('/etc/networksecretary/rules')
    RUNDIR = Path('/run/networksecretary')
    if RUNDIR.exists():
        os.chown(str(RUNDIR), 0, 0)
        RUNDIR.chmod(0o700)
    else:
        RUNDIR.mkdir(0o700)

def run_task(coro):
    """Run a coroutine and exit upon any exception.
    (otherwise exceptions are silently ignored by asyncio)"""
    task = asyncio.Task(coro)
    def cb(future):
        exc = future.exception()
        if exc is not None:
            sys.excepthook(type(exc), exc, exc.__traceback__)
            sys.exit(1)
    task.add_done_callback(cb)
    return task

_get_paths()
