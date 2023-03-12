#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Public key archive filesystem directory loader
"""
import pathlib
from typing import Any, List, Optional, TYPE_CHECKING

from pathlib_tree.tree import Tree, TreeItem

from .constants import PUBLIC_KEY_FILE_EXTENSIONS
from .loader import PublicKeyDataParser

if TYPE_CHECKING:
    from ..store import PasswordStore
    from .public_key import PublicKey


class PublicKeyFile(TreeItem, PublicKeyDataParser):
    """
    Parser for public key export file from PGP key filesystem archive

    Overrides loading of keys with default gpg --list-keys flag to --show-keys
    """
    path: pathlib.Path
    create_missing: bool
    sorted: bool
    mode: Optional[str]

    # pylint: disable=redefined-builtin
    # pylint: disable=unused-argument
    def __init__(self,
                 path: pathlib.Path,
                 keys: List[Any] = list,
                 create_missing: bool = False,
                 sorted: bool = True,
                 mode: Optional[str] = None,
                 excluded: Optional[List[str]] = None) -> None:  # noqa
        TreeItem.__init__(self)
        PublicKeyDataParser.__init__(self, str(self), keys=keys)

    def __get_gpg_command_args__(self) -> List[str]:
        """
        GPG command arguments
        """
        return ['--show-keys'] + [str(self)]


class PublicKeyDirectory(Tree):
    """
    Public key filesystem directory parser
    """
    store: 'PasswordStore'
    __file_loader_class__ = PublicKeyFile

    # pylint: disable=redefined-builtin
    # pylint: disable=arguments-differ
    # pylint: disable=unused-argument
    def __new__(cls,
                path: pathlib.Path,
                store: 'PasswordStore' = None,
                create_missing: bool = False,
                sorted: bool = True,
                mode: Optional[str] = None,
                excluded: Optional[List[str]] = None) -> None:
        """
        Create a public key directory object
        """
        path = pathlib.Path(path).expanduser()
        if create_missing and not path.exists():
            path.mkdir(parents=True)
        return super().__new__(cls, path, excluded=excluded)

    # pylint: disable=redefined-builtin
    def __init__(self,
                 path: pathlib.Path,
                 store: 'PasswordStore' = None,
                 create_missing: bool = False,
                 sorted: bool = True,
                 mode: Optional[str] = None,
                 excluded: Optional[List[str]] = None) -> None:
        self.store = store
        self.excluded = list(excluded) if isinstance(excluded, (tuple, list)) else []
        super().__init__(path, create_missing, sorted, mode, self.excluded)

    @property
    def keys(self) -> List['PublicKey']:
        """
        Load and return all detected public keys
        """
        keys = []
        for keyfile in self:
            keys.extend(list(keyfile))
        return keys

    def is_excluded(self, item) -> bool:
        """
        Only process files with expected filename extensions, exclude any directories
        """
        if item.is_file() and item.suffix not in PUBLIC_KEY_FILE_EXTENSIONS:
            return True
        return super().is_excluded(item)

    def filter_keys(self,
                    email: Optional[str] = None,
                    key_id: Optional[str] = None) -> List[PublicKeyFile]:
        """
        Filter keys matching specified attributes
        """
        matches = []
        for keyfile in self:
            matches.extend(keyfile.filter_keys(email=email, key_id=key_id))
        return matches
