"""
Loading of PGP public key details for password store management
"""

import fnmatch
import re

from datetime import datetime, timezone
from subprocess import run, PIPE, CalledProcessError

from ..exceptions import PGPKeyError
from .base import FingerprintObject
from .constants import (
    ACCEPTED_VALIDITY_STATES,
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
    KEY_VALIDITY_STATUS_INVALID,
    RECORD_TYPE_FINGERPRINT,
    RECORD_TYPE_SUB_KEY,
    RECORD_TYPE_USER_ATTRIBUTE,
    RECORD_TYPE_USER_ID,
    REQUIRED_CAPABILITIES,
    TRUSTDB_TRUST_LABELS,
)

# Parse public key user ID required fields
RE_USER_ID = re.compile(r'^(?P<fullname>.*) <(?P<email>[^<]+)>$')


# pylint: disable=too-few-public-methods
class GpgOutputLine:
    """
    Parsed key fields line from key data output linked to a key
    """
    def __init__(self, *args, **kwargs):
        self.__data__ = dict(*args, **kwargs)

    def __get_timestamp_as_date__(self, field):
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
    def key_id(self):
        """
        Return key ID
        """
        return f"""0x{self.__data__[FIELD_KEY_ID]}"""

    @property
    def key_length(self):
        """
        Return key length
        """
        return int(self.__data__[FIELD_KEY_LENGTH])

    @property
    def key_capabilities(self):
        """
        Return key capabilities
        """
        return set(
            KEY_CAPABILITIES[capability.lower()]
            for capability in self.__data__[FIELD_KEY_CAPABILITIES]
        )

    @property
    def key_validity(self):
        """
        Return key validity
        """
        try:
            return KEY_VALIDITY_FLAGS[self.__data__[FIELD_KEY_VALIDITY].lower()]
        except KeyError:
            return KEY_VALIDITY_STATUS_INVALID

    @property
    def creation_date(self):
        """
        Return key creation date
        """
        return self.__get_timestamp_as_date__(FIELD_CREATION_DATE)

    @property
    def expiration_date(self):
        """
        Return key creation date
        """
        return self.__get_timestamp_as_date__(FIELD_EXPIRATION_DATE)


class GpgOutputLineChild(GpgOutputLine):
    """
    Parsed key fields linked to parent key
    """
    def __init__(self, key, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key


class Fingerprint(GpgOutputLineChild, FingerprintObject):
    """
    Fingerprint for public key file
    """
    def __init__(self, key, *args, **kwargs):
        super().__init__(key, *args, **kwargs)
        self.fingerprint = self.__data__[FIELD_USER_ID]


class UserID(GpgOutputLineChild):
    """
    User ID record for public key
    """
    def __init__(self, key, *args, **kwargs):
        super().__init__(key, *args, **kwargs)
        match = RE_USER_ID.match(self.__data__[FIELD_USER_ID])
        if not match:
            raise PGPKeyError(f'Unexpected user ID {self.__data__[FIELD_USER_ID]}')
        self.user_id = self.__data__[FIELD_USER_ID]
        for attr, value in match.groupdict().items():
            setattr(self, attr, value)

    def __repr__(self):
        return self.__data__[FIELD_USER_ID]

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other):
        return str(self) != str(other)

    def __lt__(self, other):
        return str(self) < str(other)

    def __gt__(self, other):
        return str(self) > str(other)

    def __le__(self, other):
        return str(self) <= str(other)

    def __ge__(self, other):
        return str(self) >= str(other)

    @property
    def creation_date(self):
        """
        Return key user ID creation date
        """
        return self.__get_timestamp_as_date__(FIELD_CREATION_DATE)


class SubKey(KeyData, GpgOutputLineChild):
    """
    Sub key of a public key
    """
    def __init__(self, key, *args, **kwargs):
        super().__init__(key, *args, **kwargs)
        self.fingerprint = None

    def __repr__(self):
        return self.key_id


class PublicKey(KeyData, GpgOutputLine):
    """
    Public key parsed from gpg output
    """
    def __init__(self, *args, **kwargs):
        self.keyring = kwargs.pop('keyring', None)
        super().__init__(*args, **kwargs)
        self.fingerprint = None
        self.user_ids = []
        self.sub_keys = []

    def __repr__(self):
        return self.key_id if FIELD_USER_ID in self.__data__ else 'uninitialized'

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other):
        return str(self) != str(other)

    def __lt__(self, other):
        return str(self) < str(other)

    def __gt__(self, other):
        return str(self) > str(other)

    def __le__(self, other):
        return str(self) <= str(other)

    def __ge__(self, other):
        return str(self) >= str(other)

    def __load_child_record__(self, **data):
        """
        Load a child record from parsed data
        """
        record_type = data[FIELD_RECORD_TYPE]
        if record_type == RECORD_TYPE_FINGERPRINT:
            key = self.sub_keys[-1] if self.sub_keys else self
            key.fingerprint = Fingerprint(key, **data)
            return key.fingerprint
        if record_type == RECORD_TYPE_SUB_KEY:
            subkey = SubKey(self, **data)
            self.sub_keys.append(subkey)
            return subkey
        if record_type == RECORD_TYPE_USER_ID:
            user_id = UserID(self, **data)
            self.user_ids.append(user_id)
            return user_id
        if record_type == RECORD_TYPE_USER_ATTRIBUTE:
            # User attributes are ignored for now
            return None
        raise PGPKeyError(f'{self} Unexpected public key child record type {record_type}')

    @property
    def primary_user_id(self):
        """
        Return first user ID as primary user ID for key
        """
        try:
            return self.user_ids[0]
        except IndexError as error:
            raise PGPKeyError(f'No user ID detected {self}') from error

    @property
    def emails(self):
        """
        Return email addresses in key identities
        """
        return set(user_id.email for user_id in self.user_ids)

    def validate(self, capabilities=REQUIRED_CAPABILITIES, validity_states=ACCEPTED_VALIDITY_STATES):
        """
        Validate key attributes for password store encryption usage

        Checks if:
        - key validity is one of accepted key validity states
        - key can be used for encryption
        """
        if self.key_validity not in validity_states:
            raise PGPKeyError(
                f'Key validity status is "{self.key_validity}" '
                f"""must be one of {','.join(validity_states)}"""
            )
        for capability in capabilities:
            if capability not in self.key_capabilities:
                raise PGPKeyError(f'Key does not have capability {capability}')

    def match_key_id(self, value):
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

    def match_email_pattern(self, pattern):
        """
        Match key user ID emails to specified pattern, returning True if any ID matches pattern
        """
        for email in self.emails:
            if email == pattern or fnmatch.fnmatch(email, f'*{pattern}*'):
                return True
        return False

    def delete_from_keyring(self):
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

    def update_trust(self, value):
        """
        Update owner trust value. Value can be either integer or string from TRUSTDB_TRUST_LABELS
        """
        for code, label in TRUSTDB_TRUST_LABELS.items():
            if value == label:
                value = code
        try:
            value = int(value)
            if value not in TRUSTDB_TRUST_LABELS:
                raise ValueError
        except ValueError as error:
            raise PGPKeyError(f'Invalid trust value {value}: {error}') from error
        label = TRUSTDB_TRUST_LABELS[value]
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
