"""
Public key archive filesystem directory loader
"""

import pathlib

from pathlib_tree.tree import Tree, TreeItem

from .constants import PUBLIC_KEY_FILE_EXTENSIONS
from .parser import PublicKeyDataParser


class PublicKeyFile(TreeItem, PublicKeyDataParser):
    """
    Parser for public key export file from PGP key filesystem archive

    Overrides loading of keys with default gpg --list-keys flag to --show-keys
    """

    # pylint: disable=redefined-builtin
    # pylint: disable=unused-argument
    def __init__(self, path, keys=list, create_missing=False, sorted=True, mode=None, excluded=None):  # noqa
        TreeItem.__init__(self)
        PublicKeyDataParser.__init__(self, str(self), keys=keys)

    def __get_gpg_command_args__(self):
        """
        GPG command arguments
        """
        return ['--show-keys'] + [str(self)]


class PublicKeyDirectory(Tree):
    """
    Public key filesystem directory parser
    """
    __file_loader_class__ = PublicKeyFile

    # pylint: disable=redefined-builtin
    # pylint: disable=arguments-differ
    # pylint: disable=unused-argument
    def __new__(cls, path, store=None, create_missing=False, sorted=True, mode=None, excluded=list):
        """
        Create a public key directory object
        """
        path = pathlib.Path(path).expanduser()
        if create_missing and not path.exists():
            path.mkdir(parents=True)
        return super().__new__(cls, path, excluded=excluded)

    # pylint: disable=redefined-builtin
    def __init__(self, path, store=None, create_missing=False, sorted=True, mode=None, excluded=list):
        self.store = store
        self.excluded = list(excluded) if isinstance(excluded, (tuple, list)) else []
        super().__init__(path, create_missing, sorted, mode, self.excluded)

    @property
    def keys(self):
        """
        Load and return all detected public keys
        """
        keys = []
        for keyfile in self:
            keys.extend(list(keyfile))
        return keys

    def is_excluded(self, item):
        """
        Only process files with expected filename extensions, exclude any directories
        """
        if item.is_file() and item.suffix not in PUBLIC_KEY_FILE_EXTENSIONS:
            return True
        return super().is_excluded(item)

    def filter_keys(self, email=None, key_id=None):
        """
        Filter keys matching specified attributes
        """
        matches = []
        for keyfile in self:
            matches.extend(keyfile.filter_keys(email=email, key_id=key_id))
        return matches
