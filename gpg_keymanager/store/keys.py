#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Password store encryption keys handling
"""
from pathlib import Path

from gpg_keymanager.exceptions import PasswordStoreError, PGPKeyError
from gpg_keymanager.keys.base import GPGItemCollection
from gpg_keymanager.keys.utils import validate_key_ids


class PasswordStoreKeys(GPGItemCollection):
    """
    Handle password store encryption key files
    """
    path: Path

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path

    def __repr__(self) -> str:
        return str(self.path)

    def load(self) -> None:
        """
        Load password store .gpg-id key list file

        Allows file to contain comments with # both beginning of line and after key ID
        """
        self.clear()

        if not self.path.is_file():
            raise PasswordStoreError(f'No such file: {self.path}')

        keys = []
        with self.path.open('r') as filedescriptor:
            for line in filedescriptor.readlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                key = line.split()[0]
                try:
                    validate_key_ids(key)
                except PGPKeyError as error:
                    raise PasswordStoreError(f'{self.path} invalid key {key}') from error
                keys.append(key)
            self.__loaded__ = True

        if not keys:
            raise PasswordStoreError(f'{self.path} contains no keys')
        self.extend(keys)

    def append(self, value: str) -> None:
        """
        Add key to .gpg-id key list
        """
        try:
            validate_key_ids(value)
            super().append(value)
        except PGPKeyError as error:
            raise PasswordStoreError(f'Invalid key {value}: {error}') from error

    def get(self, value: str) -> str:
        """
        Get key
        """
        for key in self:
            if key == value:
                return key
        return None
