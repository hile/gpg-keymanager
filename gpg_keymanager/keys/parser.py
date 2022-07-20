"""
Parser for GPG command line output for public key data
"""

from operator import attrgetter

from sys_toolkit.subprocess import run_command_lineoutput

from ..exceptions import PGPKeyError

from .base import GPGItemCollection
from .constants import (
    KEY_FIELDS,
    KEY_VALIDITY_STATUS_EXPIRED,
    KEY_VALIDITY_STATUS_REVOKED,
    FIELD_RECORD_TYPE,
    RECORD_TYPE_PUBLIC_KEY
)
from .public_key import PublicKey
from .trustdb import OwnerTrustDB


class PublicKeyDataParser(GPGItemCollection):
    """
    Parser for public key data from gpg command output
    """
    def __init__(self, *gpg_args, **kwargs):
        super().__init__()
        self.__gpg_args__ = gpg_args

        keys = kwargs.pop('keys', None)
        if isinstance(keys, (list, tuple)):
            self.__items__ = list(keys)
            self.__loaded__ = True

    def __get_gpg_command_args__(self):
        """
        GPG command arguments

        By default call with --list-args and key IDs
        """
        return ['--list-keys'] + list(self.__gpg_args__)

    @property
    def expired_keys(self):
        """
        Return expired keys
        """
        return [key for key in self if key.key_validity == KEY_VALIDITY_STATUS_EXPIRED]

    @property
    def revoked_keys(self):
        """
        Return revoked keys
        """
        return [key for key in self if key.key_validity == KEY_VALIDITY_STATUS_REVOKED]

    def load(self):
        """
        Load public key details with gpg CLI command
        """
        self.clear()

        command = ['gpg', '--with-colons', '--keyid-format=long'] + self.__get_gpg_command_args__()
        try:
            stdout, _stderr = run_command_lineoutput(*command)
            self.__loaded__ = True
        except Exception as error:
            raise PGPKeyError(error) from error

        public_key = None
        for line in stdout:
            try:
                fields = line.split(':')
                data = dict(
                    (KEY_FIELDS[index], field if field else None)
                    for index, field in enumerate(fields)
                )
                record_type = data[FIELD_RECORD_TYPE]
                if record_type == RECORD_TYPE_PUBLIC_KEY:
                    public_key = PublicKey(keyring=self, **data)
                    self.append(public_key)
                elif public_key is not None:
                    public_key.__load_child_record__(**data)
            except PGPKeyError as error:
                raise PGPKeyError(f'Error parsing GPG output line {line}: {error}') from error

        self.__items__.sort(key=attrgetter('primary_user_id'))

    def filter_keys(self, email=None, fingerprint=None, key_id=None):
        """
        Filter keys matching specified attributes

        Email address can be a fnmatch pattern.
        Key ID is matched by both short and long ID, with and without 0x prefix
        """
        def match_key(key, email, fingerprint, key_id):
            """
            Return True if key matches all specified filter conditions
            """
            if key_id is not None and not key.match_key_id(key_id):
                return False
            if email is not None and not key.match_email_pattern(email):
                return False
            if fingerprint is not None and not key.fingerprint == fingerprint:
                return False
            return True

        matches = []
        for key in self:
            if match_key(key, email, fingerprint, key_id):
                matches.append(key)
        return self.__class__(*self.__gpg_args__, keys=matches)

    def get(self, value):
        """
        Return key for specified key ID or fingerprint
        """
        if not self.is_loaded:
            self.load()
        for key in self.__items__:
            if key.match_key_id(value) or key.fingerprint == value:
                return key
        raise PGPKeyError(f'Key not found: {value}')


class UserPublicKeys(PublicKeyDataParser):
    """
    List of keys in user keyring

    Just like PublicKeyDataParser but extended with some arguments
    """
    def __init__(self, *gpg_args, **kwargs):
        super().__init__(*gpg_args, **kwargs)
        self.trustdb = OwnerTrustDB(self)

    def cleanup_owner_trust_database(self):
        """
        Cleanup owner trust database of keys not found in keyring

        This method fails if this is a filtered keyring
        """
        if self.__gpg_args__:
            raise PGPKeyError(
                'Owner trust cleanup only available for unfiltered user public keys object'
            )
        self.trustdb.load()
        self.trustdb.remove_stale_entries()
