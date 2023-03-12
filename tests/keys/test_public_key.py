#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Unit tests for gpg_keymanager.keys.public_key module
"""
from datetime import datetime, timezone

import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys.constants import (
    FIELD_KEY_VALIDITY,
    FIELD_KEY_CAPABILITIES,
    KEY_FIELDS,
    FIELD_RECORD_TYPE,
    FIELD_USER_ID,
    KeyCapability,
    KeyValidityStatus,
    KeyRecordType,
)
from gpg_keymanager.keys.public_key import Fingerprint, PublicKey
from gpg_keymanager.keys.loader import UserPublicKeys

from ..base import MockCallArguments, mock_called_process_error

KEY_FINGERPRINT = 'EA1DAF5C552EEC9BBCEE08D8E8EF3D54894DBC28'
OTHER_FINGERPRINT = '9EC90B9B66D8C96449DCAAACDE134CA92809EF31'
KEY_ID = '0xE8EF3D54894DBC28'
OTHER_KEY_ID = '0xFAFAEF3D54894DBC28'
SHORT_ID = '894DBC28'
USER_ID = 'Ilkka Tuohela (Codento Work Key) <hile@codento.com>'
OTHER_USER_ID = 'Teemu Test <testi@example.com'
EXPECTED_KEY_CAPABILITIES_COUNT = 2

INVALID_USER_ID = 'uid:e::::123::223::invalid@example.com::::::::::0:'


def test_public_key_init() -> None:
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
    assert key.key_validity == KeyValidityStatus.INVALID

    with pytest.raises(PGPKeyError):
        # pylint: disable=pointless-statement
        key.primary_user_id

    assert key.__load_child_record__(**{FIELD_RECORD_TYPE: KeyRecordType.USER_ATTRIBUTE.value}) is None
    with pytest.raises(PGPKeyError):
        key.__load_child_record__(**{FIELD_RECORD_TYPE: 'test'})

    key.__data__[FIELD_KEY_VALIDITY] = 'n'
    with pytest.raises(PGPKeyError):
        key.validate()

    key.__data__[FIELD_KEY_VALIDITY] = 'f'
    key.__data__[FIELD_KEY_CAPABILITIES] = ['a', 'c']
    with pytest.raises(PGPKeyError):
        key.validate()

    key.__data__[FIELD_KEY_CAPABILITIES] = ['a', 'c', 'e']
    key.validate()


def test_public_key_init_user_id() -> None:
    """
    Assert loading unexpected user ID string to key
    """
    key = PublicKey()
    fields = INVALID_USER_ID.split(':')
    record = dict(
        (KEY_FIELDS[index], field if field else None)
        for index, field in enumerate(fields)
    )
    with pytest.raises(PGPKeyError):
        key.__load_child_record__(**record)


# pylint: disable=unused-argument
def test_public_key_properties(mock_gpg_key_list) -> None:
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
        assert isinstance(value, KeyCapability)

    assert key == KEY_ID
    assert key != OTHER_KEY_ID
    assert key < OTHER_KEY_ID
    assert key <= OTHER_KEY_ID
    assert not key > OTHER_KEY_ID
    assert not key >= OTHER_KEY_ID

    assert key.primary_user_id == USER_ID
    assert key.primary_user_id != OTHER_USER_ID
    assert key.primary_user_id < OTHER_USER_ID
    assert key.primary_user_id <= OTHER_USER_ID
    assert not key.primary_user_id > OTHER_USER_ID
    assert not key.primary_user_id >= OTHER_USER_ID

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

    assert isinstance(key.fingerprint, Fingerprint)
    assert isinstance(key.fingerprint.__repr__(), str)
    assert key.fingerprint == KEY_FINGERPRINT
    assert key.fingerprint != OTHER_FINGERPRINT
    assert key.fingerprint > OTHER_FINGERPRINT
    assert key.fingerprint >= OTHER_FINGERPRINT
    assert not key.fingerprint < OTHER_FINGERPRINT
    assert not key.fingerprint <= OTHER_FINGERPRINT

    other_fingerprint = Fingerprint(key, **{FIELD_USER_ID: OTHER_FINGERPRINT})
    assert key.fingerprint == key.fingerprint
    assert key.fingerprint != other_fingerprint
    assert key.fingerprint > other_fingerprint
    assert key.fingerprint >= other_fingerprint
    assert other_fingerprint < key.fingerprint
    assert other_fingerprint <= key.fingerprint


def test_public_key_validiation(mock_gpg_key_list) -> None:
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


# pylint: disable=unused-argument
def test_public_key_delete_from_keyring(mock_gpg_key_list, monkeypatch) -> None:
    """
    Test command to delete key from keyring
    """
    mock_run = MockCallArguments()
    monkeypatch.setattr('gpg_keymanager.keys.public_key.run', mock_run)
    keys = UserPublicKeys()
    keys.load()

    key = keys[0]
    key.delete_from_keyring()
    assert mock_run.call_count == 1

    key = keys[0]
    key.keyring = None
    key.delete_from_keyring()
    assert mock_run.call_count == 2


# pylint: disable=unused-argument
def test_public_key_delete_from_keyring_exception(mock_gpg_key_list, monkeypatch) -> None:
    """
    Test command to delete key from keyring
    """
    keys = UserPublicKeys()
    keys.load()

    monkeypatch.setattr('gpg_keymanager.keys.public_key.run', mock_called_process_error)

    key = keys[0]
    with pytest.raises(PGPKeyError):
        key.delete_from_keyring()


# pylint: disable=unused-argument
def test_public_key_update_trust(mock_gpg_key_list, monkeypatch) -> None:
    """
    Test command to update key trust value
    """
    mock_run = MockCallArguments()
    monkeypatch.setattr('gpg_keymanager.keys.public_key.run', mock_run)
    keys = UserPublicKeys()
    keys.load()

    key = keys[0]
    key.update_trust('full')
    assert mock_run.call_count == 1

    with pytest.raises(PGPKeyError):
        key.update_trust(0)


# pylint: disable=unused-argument
def test_public_key_update_trust_error(mock_gpg_key_list, monkeypatch) -> None:
    """
    Test command to update key trust value with error from CLI
    """
    mock_run = MockCallArguments(returncode=1, stderr='Error running command')
    monkeypatch.setattr('gpg_keymanager.keys.public_key.run', mock_run)
    keys = UserPublicKeys()
    keys.load()

    key = keys[0]
    with pytest.raises(PGPKeyError):
        key.update_trust('ultimate')
