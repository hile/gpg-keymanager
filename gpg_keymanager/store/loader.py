"""
GNU password store directory loader
"""

import os

from pathlib import Path

from systematic_cli.process import run_command
from systematic_files.tree import Tree, TreeItem

from ..exceptions import PasswordStoreError
from ..keys.utils import validate_key_ids

from .keys import PasswordStoreKeys, PASSWORD_STORE_KEY_LIST_FILENAME

DEFAULT_PASSWORD_STORE_PATH = '~/.password-store'

ENV_VAR = 'PASSWORD_STORE_DIR'

EXCLUDED_PATTERNS = [
    '.git',
    '.gitattributes',
    '.DS_Store',
]
PASSWORD_STORE_CONFIG_FILES = (
    PASSWORD_STORE_KEY_LIST_FILENAME,
)
PASSWORD_STORE_SECRET_EXTENSIONS = (
    '.gpg',
)


class PasswordStoreFile(TreeItem):
    """
    Password store file
    """
    # pylint: disable=redefined-builtin
    # pylint: disable=unused-argument
    def __init__(self, path, password_store, create_missing=False, sorted=True, mode=None, excluded=None):  # noqa
        TreeItem.__init__(self)
        self.password_store = password_store

    @property
    def relative_path(self):
        """
        Return file path in password store as string
        """
        return str(self.relative_to(self.password_store))


class PasswordStore(Tree):
    """
    GNU password store data directory
    """
    __file_loader_class__ = PasswordStoreFile

    # pylint: disable=redefined-builtin
    # pylint: disable=arguments-differ
    # pylint: disable=unused-argument
    def __new__(cls, path=DEFAULT_PASSWORD_STORE_PATH, password_store=None,
                create_missing=False, sorted=True, mode=None, excluded=list):
        """
        Create a password store object
        """
        path = Path(path).expanduser()
        return super().__new__(cls, path, excluded=excluded)

    # pylint: disable=redefined-builtin
    def __init__(self, path=DEFAULT_PASSWORD_STORE_PATH, password_store=None, sorted=True, mode=None, excluded=list):
        self.excluded = list(excluded) if isinstance(excluded, (tuple, list)) else []
        super().__init__(path, False, sorted, mode, self.excluded)
        self.password_store = password_store if password_store is not None else self

    def __configure_excluded__(self, excluded):
        """
        Configure excluded files for password store
        """
        return super().__configure_excluded__(EXCLUDED_PATTERNS)

    def __load_tree__(self, item):
        """
        Load sub directory linked to password store
        """
        # pylint: disable=not-callable
        return self.__directory_loader__(
            item,
            password_store=self.password_store,
            sorted=self.sorted,
            excluded=self.excluded
        )

    def __load_file__(self, item):
        """
        Load file item to password store
        """
        # pylint: disable=not-callable
        return self.__file_loader__(item, password_store=self.password_store)

    @property
    def environment(self):
        """
        Expand environment variables with PASSWORD_STORE_DIR
        """
        env = os.environ.copy()
        env[ENV_VAR] = str(self)
        return env

    @property
    def parents(self):
        """
        Override parents method to limit to directories in password store
        """
        parents = []
        real_parents = list(super().parents)
        while True:
            parent = real_parents.pop(0)
            try:
                parent.relative_to(self.password_store)
            except ValueError:
                break
            parents.append(parent)
        return parents

    @property
    def relative_path(self):
        """
        Return file path in password store
        """
        if self.password_store is not None and self.password_store != self:
            return str(self.relative_to(self.password_store))
        return None

    @property
    def gpg_key_ids(self):
        """
        Get gpg key IDs applying to this directory
        """
        paths = [self] + self.parents
        for parent in paths:
            filename = parent.joinpath(PASSWORD_STORE_KEY_LIST_FILENAME)
            if filename.is_file():
                return PasswordStoreKeys(filename)
        raise PasswordStoreError(f'Error detecting .gpg-id file for {self}')

    def is_excluded(self, item):
        """
        Only process files with expected filename extensions, exclude any directories
        """
        if item.name in PASSWORD_STORE_CONFIG_FILES:
            return False
        if item.is_file() and item.suffix not in PASSWORD_STORE_SECRET_EXTENSIONS:
            return True
        return super().is_excluded(item)

    def create(self, gpg_key_ids=None):
        """
        Setup password store with 'pass init' and specified list of pgp keys

        Raise error if no PGP keys are provided
        """
        if not gpg_key_ids:
            raise PasswordStoreError('No PGP keys provided to initialize password store')

        validate_key_ids(gpg_key_ids)

        cmd = ['pass', 'init'] + list(gpg_key_ids)
        run_command(*cmd, env=self.environment)
