
"""
Unit tests for gpg_keymanager.keys.public_key module
"""

from datetime import datetime, timezone

import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys.constants import (
    FIELD_RECORD_TYPE,
    FIELD_USER_ID,
    RECORD_TYPE_USER_ATTRIBUTE
)
from gpg_keymanager.keys.public_key import Fingerprint, PublicKey
from gpg_keymanager.keys.parser import UserPublicKeys

KEY_FINGERPRINT = 'EA1DAF5C552EEC9BBCEE08D8E8EF3D54894DBC28'
OTHER_FINGERPRINT = '9EC90B9B66D8C96449DCAAACDE134CA92809EF31'
KEY_ID = '0xE8EF3D54894DBC28'
OTHER_KEY_ID = '0xFAFAEF3D54894DBC28'
SHORT_ID = '894DBC28'
USER_ID = 'Ilkka Tuohela (Codento Work Key) <hile@codento.com>'
OTHER_USER_ID = 'Teemu Test <testi@example.com'
EXPECTED_KEY_CAPABILITIES_COUNT = 2


def test_public_key_init():
    """
    Test initializing a PublicKey object with no data and no associated password store
    """
    key = PublicKey()
    assert key.keyring is None
    assert key.fingerprint is None
    assert key.user_ids == []
    assert key.sub_keys == []
    assert isinstance(key.__repr__(), str)
    assert key.__repr__() == 'uninitialized'

    assert key.creation_date is None

    with pytest.raises(PGPKeyError):
        # pylint: disable=pointless-statement
        key.primary_user_id

    assert key.__load_child_record__(**{FIELD_RECORD_TYPE: RECORD_TYPE_USER_ATTRIBUTE}) is None
    with pytest.raises(PGPKeyError):
        key.__load_child_record__(**{FIELD_RECORD_TYPE: 'test'})


# pylint: disable=unused-argument
def test_public_key_properties(mock_gpg_key_list):
    """
    Test properties of loaded public key
    """
    keys = UserPublicKeys()
    keys.load()
    key = next(keys)
    assert key.key_id == KEY_ID
    assert isinstance(key.key_length, int)

    assert len(key.key_capabilities) == EXPECTED_KEY_CAPABILITIES_COUNT
    for value in key.key_capabilities:
        assert isinstance(value, str)

    assert key == KEY_ID
    assert key != OTHER_KEY_ID
    assert key < OTHER_KEY_ID
    assert key <= OTHER_KEY_ID
    assert OTHER_KEY_ID > key
    assert OTHER_KEY_ID >= key

    assert key.primary_user_id == USER_ID
    assert key.primary_user_id != OTHER_USER_ID
    assert key.primary_user_id < OTHER_USER_ID
    assert key.primary_user_id <= OTHER_USER_ID
    assert OTHER_USER_ID > key.primary_user_id
    assert OTHER_USER_ID >= key.primary_user_id

    assert key.match_key_id(KEY_ID) is True
    assert key.match_key_id(SHORT_ID) is True
    assert key.match_key_id(OTHER_KEY_ID) is False

    for attr in ('creation_date', 'expiration_date'):
        value = getattr(key, attr)
        assert isinstance(value, datetime)
        assert value.tzinfo == timezone.utc

    subkey = key.sub_keys[0]
    assert isinstance(subkey.__repr__(), str)

    created = key.primary_user_id.creation_date
    assert isinstance(created, datetime)
    assert created.tzinfo == timezone.utc

    assert isinstance(key.fingerprint.__repr__(), str)
    assert key.fingerprint == KEY_FINGERPRINT
    assert key.fingerprint != OTHER_FINGERPRINT
    assert key.fingerprint > OTHER_FINGERPRINT
    assert key.fingerprint >= OTHER_FINGERPRINT
    assert OTHER_FINGERPRINT < key.fingerprint
    assert OTHER_FINGERPRINT <= key.fingerprint

    other_fingerprint = Fingerprint(key, **{FIELD_USER_ID: OTHER_FINGERPRINT})
    assert key.fingerprint == key.fingerprint
    assert key.fingerprint != other_fingerprint
    assert key.fingerprint > other_fingerprint
    assert key.fingerprint >= other_fingerprint
    assert other_fingerprint < key.fingerprint
    assert other_fingerprint <= key.fingerprint


def test_public_key_validiation(mock_gpg_key_list):
    """
    Test public key validate() methid
    """
    keys = UserPublicKeys()
    keys.load()

    # First key has expired
    key = keys[0]
    with pytest.raises(PGPKeyError):
        key.validate()

    # Last key is valid
    key = keys[-1]
    key.validate()
