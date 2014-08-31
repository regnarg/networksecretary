from pathlib import Path

def _get_paths():
    global RULES_LIB, RULES_BUILTIN, RULES_USER
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

_get_paths()
