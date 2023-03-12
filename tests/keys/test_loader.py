#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Unit tests for gpg_keymanager.keys.directory module
"""
import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys import UserPublicKeys
from gpg_keymanager.keys.loader import PublicKeyDataParser

from ..base import mock_called_process_error, mock_pgp_key_error

TOTAL_KEY_COUNT = 5
EXPIRED_KEY_COUNT = 2
REVOKED_KEYS_COUNT = 1

TEST_EMAIL = 'hile@iki.fi'
TEST_KEY_ID = '0x3119E470AD3CCDEC'
TEST_FINGERPRINT = '87DF5EA2B85E025D159888ACC660ACF1DA570475'


# pylint: disable=too-few-public-methods
class MockCalledMethod:
    """
    Test class to check a method was called
    """
    def __init__(self):
        self.call_count = 0
        self.args = None
        self.kwargs = None

    def __call__(self, *args, **kwargs):
        self.call_count += 1
        self.args = args
        self.kwargs = kwargs


def test_parser_init():
    """
    Test initializing a PublicKeyDataParser object
    """
    parser = PublicKeyDataParser()
    assert len(parser.__items__) == 0
    assert parser.is_loaded is False


# pylint: disable=unused-argument
def test_user_keys_load(mock_gpg_key_list):
    """
    Test loading user gpg key list with mocked test data
    """
    keys = UserPublicKeys()
    keys.load()
    assert len(keys) == TOTAL_KEY_COUNT
    assert len(keys.expired_keys) == EXPIRED_KEY_COUNT
    assert len(keys.revoked_keys) == REVOKED_KEYS_COUNT

    assert len(keys.filter_keys(email=TEST_EMAIL)) == 4
    assert len(keys.filter_keys(key_id=TEST_KEY_ID)) == 1
    assert len(keys.filter_keys(fingerprint=TEST_FINGERPRINT)) == 1

    keys.clear()
    assert keys.get(TEST_KEY_ID) is not None
    assert keys.get(TEST_FINGERPRINT) is not None
    with pytest.raises(PGPKeyError):
        keys.get(TEST_EMAIL)


# pylint: disable=unused-argument
def test_user_keys_load_error(monkeypatch, mock_gpg_key_list):
    """
    Test error parsing keys when loading user keys
    """
    monkeypatch.setattr(
        'gpg_keymanager.keys.public_key.PublicKey.__load_child_record__',
        mock_pgp_key_error
    )
    keys = UserPublicKeys()
    with pytest.raises(PGPKeyError):
        keys.load()


# pylint: disable=unused-argument
def test_user_keys_load_fail(monkeypatch, mock_gpg_key_list):
    """
    Test failure loading user keys
    """
    monkeypatch.setattr(
        'gpg_keymanager.keys.loader.run_command_lineoutput',
        mock_called_process_error
    )
    keys = UserPublicKeys()
    with pytest.raises(PGPKeyError):
        keys.load()


# pylint: disable=unused-argument
def test_user_keys_trustdb_cleanup(monkeypatch, mock_gpg_key_list):
    """
    Test calling cleanup of user trus database from user keys
    """
    keys = UserPublicKeys()

    mock_method = MockCalledMethod()
    monkeypatch.setattr(
        'gpg_keymanager.keys.trustdb.OwnerTrustDB.remove_stale_entries',
        mock_method
    )
    keys.cleanup_owner_trust_database()
    assert mock_method.call_count == 1

    with pytest.raises(PGPKeyError):
        keys.__gpg_args__ = [TEST_KEY_ID]
        keys.cleanup_owner_trust_database()
