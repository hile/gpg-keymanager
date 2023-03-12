#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Utilities to manage GPG owner trust database
"""
import re
import sys

from pathlib import Path
from subprocess import run, CalledProcessError
from typing import List, Union, TYPE_CHECKING

from sys_toolkit.subprocess import run_command_lineoutput

from ..exceptions import PGPKeyError
from .base import GPGItemCollection, FingerprintObject
from .constants import TRUSTDB_TRUST_LABELS, KeyTrustDB

if TYPE_CHECKING:
    from .loader import UserPublicKeys

USER_TRUSTDB = Path('~/.gnupg/trustdb.gpg').expanduser()

RE_OWNERTRUST = re.compile(
    r'^(?P<fingerprint>[A-Z0-9]+):(?P<trust>\d+):$'
)


class TrustDBItem(FingerprintObject):
    """
    Fingerprint in trust database
    """
    fingerprint: str
    trust: KeyTrustDB

    def __init__(self, fingerprint: str, trust: Union[int, str]):
        self.fingerprint = fingerprint
        self.trust = KeyTrustDB(int(trust))

    def __repr__(self) -> str:
        return f'{self.fingerprint}:{TRUSTDB_TRUST_LABELS[self.trust]}:'

    @property
    def value(self) -> str:
        """
        Return value in original format for exporting back to trust db
        """
        return f'{self.fingerprint}:{self.trust.value}:'


class OwnerTrustDB(GPGItemCollection):
    """
    GPG owner trust database
    """
    keyring: 'UserPublicKeys'

    def __init__(self, keyring: 'UserPublicKeys') -> None:
        super().__init__()
        self.keyring = keyring

    @property
    def stale_trust(self) -> List[TrustDBItem]:
        """
        Return trust database items for which the key has been removed from user keys
        """
        fingerprints = [key.fingerprint for key in self.keyring]
        return [
            item
            for item in self
            if item.fingerprint not in fingerprints
        ]

    def remove_stale_entries(self) -> None:
        """
        Remove any stale trustdb items

        Creates a backup copy of existing trust database and re-imports any non-stale items
        """
        valid = []
        stale = self.stale_trust
        if not stale:
            return

        for trust in self:
            if trust in stale:
                print(f'Remove stale trust {trust}')
            else:
                valid.append(trust)

        if not USER_TRUSTDB.exists():
            raise PGPKeyError(f'No trust gpg database detected {USER_TRUSTDB}')

        backup = USER_TRUSTDB.with_suffix('.gpg.old')
        USER_TRUSTDB.rename(backup)
        data = '\n'.join(item.value for item in valid)
        try:
            run(
                ('gpg', '--import-ownertrust'),
                input=bytes(f'{data}\n', 'utf-8'),
                stdout=sys.stdout,
                stderr=sys.stderr,
                check=True
            )
            self.load()
        except CalledProcessError as error:
            backup.rename(USER_TRUSTDB)
            raise PGPKeyError('Error cleaning up user gpg owner trust database') from error

    def load(self) -> None:
        """
        Load keys in owner trust database
        """
        self.clear()

        command = ('gpg', '--export-ownertrust')
        try:
            stdout, _stderr = run_command_lineoutput(*command)
            self.__loaded__ = True
        except Exception as error:
            raise PGPKeyError(f'Error loading gpg owner trust database: {error}') from error

        for line in stdout:
            if line.startswith('#'):
                continue

            match = RE_OWNERTRUST.match(line)
            if match:
                item = TrustDBItem(**match.groupdict())
                self.append(item)
            else:
                raise PGPKeyError(f'Unexpected owner trust output line: {line}')

    def get(self, value: str) -> TrustDBItem:
        """
        Get trust database item by key ID or fingerprint
        """
        for trust in self:
            if trust.fingerprint == value:
                return trust
        try:
            key = self.keyring.get(value)
            for trust in self:
                if trust.fingerprint == key.fingerprint:
                    return trust
        except PGPKeyError:
            pass
        raise PGPKeyError(f'Trust DB item not found: {value}')
