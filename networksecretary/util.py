import sys, os
from pathlib import Path
from contextlib import contextmanager

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
    global RULES_LIB, RULES_BUILTIN, RULES_USER, RUNDIR
    prefix = Path(sys.prefix)
    my_path = Path(__file__).resolve()
    if prefix in my_path.parents:
        # System-wide installation
        libdir = prefix / 'lib' / 'networksecretary'
        RULES_LIB = libdir / 'rulelib'
        RULES_BUILTIN = libdir / 'rules'
    else:
        # Ran from source
        repo_root = my_path.parents[1]
        RULES_LIB = repo_root / 'rulelib'
        RULES_BUILTIN = repo_root / 'rules'
    RULES_USER = Path('/etc/networksecretary/rules')
    RUNDIR = Path('/run/networksecretary')
    if RUNDIR.exists():
        os.chown(str(RUNDIR), 0, 0)
        RUNDIR.chmod(0o700)
    else:
        RUNDIR.mkdir(0o700)

_get_paths()
