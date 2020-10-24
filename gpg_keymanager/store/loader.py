"""
GNU password store directory loader
"""

from pathlib import Path

from systematic_cli.process import run_command
from systematic_files.tree import Tree

DEFAULT_PASSWORD_STORE_PATH = '~/.password-store'

EXCLUDED_PATTERNS = [
    '.git',
    '.gitattributes',
    '.DS_Store',
]


class PasswordStore(Tree):
    """
    GNU password store data directory
    """

    # pylint: disable=redefined-builtin
    # pylint: disable=arguments-differ
    # pylint: disable=unused-argument
    def __new__(cls, path=DEFAULT_PASSWORD_STORE_PATH, create_missing=False, sorted=True, mode=None, excluded=list):
        """
        Create a password store object
        """
        path = Path(path).expanduser()
        if create_missing and not path.exists():
            run_command('pass', 'init', str(path))
        return super().__new__(cls, path, excluded=excluded)

    # pylint: disable=redefined-builtin
    def __init__(self, path=DEFAULT_PASSWORD_STORE_PATH, create_missing=False, sorted=True, mode=None, excluded=list):
        self.excluded = list(excluded) if isinstance(excluded, (tuple, list)) else []
        super().__init__(path, create_missing, sorted, mode, self.excluded)

    def __configure_excluded__(self, excluded):
        """
        Configure excluded files for password store
        """
        return super().__configure_excluded__(EXCLUDED_PATTERNS)
