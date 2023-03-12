#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Loading of PGP public key details for password store management
"""
import fnmatch
import re

from datetime import datetime, timezone
from subprocess import run, PIPE, CalledProcessError
from typing import Any, Dict, List, Optional, Tuple

from ..exceptions import PGPKeyError
from .base import FingerprintObject
from .constants import (
    FIELD_CREATION_DATE,
    FIELD_EXPIRATION_DATE,
    FIELD_KEY_CAPABILITIES,
    FIELD_KEY_ID,
    FIELD_KEY_LENGTH,
    FIELD_RECORD_TYPE,
    FIELD_USER_ID,
    FIELD_KEY_VALIDITY,
    KEY_CAPABILITIES,
    KEY_VALIDITY_FLAGS,
    REQUIRED_CAPABILITIES,
    TRUSTDB_TRUST_LABELS,
    KeyCapability,
    KeyValidityStatus,
    KeyRecordType,
    KeyTrustDB,
)

# Parse public key user ID required fields
RE_USER_ID = re.compile(r'^(?P<fullname>.*) <(?P<email>[^<]+)>$')


# pylint: disable=too-few-public-methods
class GpgOutputLine:
    """
    Parsed key fields line from key data output linked to a key
    """
    __data__: Dict[Any, Any]

    def __init__(self, *args, **kwargs):
        self.__data__ = dict(*args, **kwargs)

    def __get_timestamp_as_date__(self, field: Optional[Any]) -> Optional[datetime]:
        """
        Get field timestamp value as date or None if not defined
        """
        value = self.__data__.get(field, None)
        if not value:
            return None
        return datetime.fromtimestamp(int(value)).astimezone(timezone.utc)


class KeyData(GpgOutputLine):
    """
    GPG output line for key (public key, sub key) data
    """
    @property
    def key_id(self) -> str:
        """
        Return key ID
        """
        return f"""0x{self.__data__[FIELD_KEY_ID]}"""

    @property
    def key_length(self) -> int:
        """
        Return key length
        """
        return int(self.__data__[FIELD_KEY_LENGTH])

    @property
    def key_capabilities(self) -> Tuple[str]:
        """
        Return key capabilities
        """
        capabilities = self.__data__.get(FIELD_KEY_CAPABILITIES, [])
        return tuple(set(
            KEY_CAPABILITIES[capability.lower()]
            for capability in capabilities
        ))

    @property
    def key_validity(self) -> str:
        """
        Return key validity
        """
        try:
            return KEY_VALIDITY_FLAGS[self.__data__[FIELD_KEY_VALIDITY].lower()]
        except KeyError:
            return KeyValidityStatus.INVALID

    @property
    def creation_date(self) -> datetime:
        """
        Return key creation date
        """
        return self.__get_timestamp_as_date__(FIELD_CREATION_DATE)

    @property
    def expiration_date(self) -> datetime:
        """
        Return key creation date
        """
        return self.__get_timestamp_as_date__(FIELD_EXPIRATION_DATE)


class GpgOutputLineChild(GpgOutputLine):
    """
    Parsed key fields linked to parent key
    """
    key: 'PublicKey'

    def __init__(self, key: 'PublicKey', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key


class Fingerprint(GpgOutputLineChild, FingerprintObject):
    """
    Fingerprint for public key file
    """
    fingerprint: str

    def __init__(self, key: 'PublicKey', *args, **kwargs):
        super().__init__(key, *args, **kwargs)
        self.fingerprint = self.__data__[FIELD_USER_ID]


class UserID(GpgOutputLineChild):
    """
    User ID record for public key
    """
    user_id: str
    email: str
    fullname: str

    def __init__(self, key: 'PublicKey', *args, **kwargs):
        super().__init__(key, *args, **kwargs)
        match = RE_USER_ID.match(self.__data__[FIELD_USER_ID])
        if not match:
            raise PGPKeyError(f'Unexpected user ID {self.__data__[FIELD_USER_ID]}')
        self.user_id = self.__data__[FIELD_USER_ID]
        for attr, value in match.groupdict().items():
            setattr(self, attr, value)

    def __repr__(self) -> str:
        return self.__data__[FIELD_USER_ID]

    def __eq__(self, other: Any) -> bool:
        return str(self) == str(other)

    def __ne__(self, other: Any) -> bool:
        return str(self) != str(other)

    def __lt__(self, other: Any) -> bool:
        return str(self) < str(other)

    def __gt__(self, other: Any) -> bool:
        return str(self) > str(other)

    def __le__(self, other: Any) -> bool:
        return str(self) <= str(other)

    def __ge__(self, other: Any) -> bool:
        return str(self) >= str(other)

    @property
    def creation_date(self) -> Optional[datetime]:
        """
        Return key user ID creation date
        """
        return self.__get_timestamp_as_date__(FIELD_CREATION_DATE)


class SubKey(KeyData, GpgOutputLineChild):
    """
    Sub key of a public key
    """
    def __repr__(self):
        return self.key_id if self.key_id else ''


class PublicKey(KeyData, GpgOutputLine):
    """
    Public key parsed from gpg output
    """
    def __init__(self, *args, **kwargs) -> None:
        self.keyring = kwargs.pop('keyring', None)
        super().__init__(*args, **kwargs)
        self.fingerprint = None
        self.user_ids = []
        self.sub_keys = []

    def __repr__(self) -> str:
        return self.key_id if FIELD_USER_ID in self.__data__ else 'uninitialized'

    def __eq__(self, other: Any) -> bool:
        return str(self) == str(other)

    def __ne__(self, other: Any) -> bool:
        return str(self) != str(other)

    def __lt__(self, other: Any) -> bool:
        return str(self) < str(other)

    def __gt__(self, other: Any) -> bool:
        return str(self) > str(other)

    def __le__(self, other: Any) -> bool:
        return str(self) <= str(other)

    def __ge__(self, other: Any) -> bool:
        return str(self) >= str(other)

    def __load_child_record__(self, **data) -> None:
        """
        Load a child record from parsed data
        """
        record_type = data[FIELD_RECORD_TYPE]
        if record_type == KeyRecordType.FINGERPRINT.value:
            key = self.sub_keys[-1] if self.sub_keys else self
            key.fingerprint = Fingerprint(key, **data)
            return key.fingerprint
        if record_type == KeyRecordType.SUB_KEY.value:
            subkey = SubKey(self, **data)
            self.sub_keys.append(subkey)
            return subkey
        if record_type == KeyRecordType.USER_ID.value:
            user_id = UserID(self, **data)
            self.user_ids.append(user_id)
            return user_id
        if record_type == KeyRecordType.USER_ATTRIBUTE.value:
            # User attributes are ignored for now
            return None
        raise PGPKeyError(f'{self} Unexpected public key child record type {record_type}')

    @property
    def primary_user_id(self) -> str:
        """
        Return first user ID as primary user ID for key
        """
        try:
            return self.user_ids[0]
        except IndexError as error:
            raise PGPKeyError(f'No user ID detected {self}') from error

    @property
    def emails(self) -> List[str]:
        """
        Return email addresses in key identities
        """
        return list(set(user_id.email for user_id in self.user_ids))

    def validate(self, capabilities=REQUIRED_CAPABILITIES) -> None:
        """
        Validate key attributes for password store encryption usage

        Checks if:
        - key can be used for encryption
        """
        for capability in capabilities:
            if isinstance(capability, str):
                capability = KeyCapability(capability)
            if capability not in self.key_capabilities:
                raise PGPKeyError(f'Key does not have capability {capability}')

    def match_key_id(self, value: str) -> bool:
        """
        Match PGP key ID to specified value by short or long key ID, with or without 0x prefix
        """
        if value[:2] == '0x':
            value = value[2:]
        if len(value) == 8 and self.key_id[-8:] == value:
            return True
        if self.key_id == f'0x{value}':
            return True
        return False

    def match_email_pattern(self, pattern: str) -> bool:
        """
        Match key user ID emails to specified pattern, returning True if any ID matches pattern
        """
        for email in self.emails:
            if email == pattern or fnmatch.fnmatch(email, f'*{pattern}*'):
                return True
        return False

    def delete_from_keyring(self) -> None:
        """
        Delete key from user keyring
        """
        command = ('gpg', '--batch', '--yes', '--delete-keys', self.key_id)
        try:
            run(command, check=True)
        except CalledProcessError as error:
            raise PGPKeyError(f'Error deleting key from user keyring {self}: {error}') from error

        if self.keyring is not None:
            self.keyring.__remove_key__(self.key_id)

    def update_trust(self, value: str) -> None:
        """
        Update owner trust value. Value can be either integer or string from TRUSTDB_TRUST_LABELS
        """
        for trust, label in TRUSTDB_TRUST_LABELS.items():
            if value == label:
                value = trust.value
        try:
            trust = KeyTrustDB(int(value))
        except ValueError as error:
            raise PGPKeyError(f'Invalid trust value {value}: {error}') from error
        label = TRUSTDB_TRUST_LABELS[trust]
        print(f'set owner trust key {self} trust {label}')
        response = run(
            ('gpg', '--import-ownertrust'),
            input=bytes(f'{self.fingerprint}:{value}:\n', 'utf-8'),
            stdout=PIPE,
            stderr=PIPE,
            check=False
        )
        if response.returncode != 0:
            raise PGPKeyError(f'Error updating key owner trust: {response.stderr}')
        self.keyring.load()
