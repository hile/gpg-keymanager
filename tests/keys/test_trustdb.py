#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Unit tests for gpg_keymanager.keys.trustdb module
"""
from pathlib import Path

import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys.parser import UserPublicKeys
from gpg_keymanager.keys.trustdb import TrustDBItem

from ..base import mock_called_process_error, mock_return_false
from ..conftest import (
    MOCK_TRUSTDB_EXISTS_METHOD,
    MOCK_TRUSTDB_RUN_METHOD,
    MOCK_KEY_DATA,
)

MOCK_TRUSTDB_STALE_PROPERTY = 'gpg_keymanager.keys.trustdb.OwnerTrustDB.stale_trust'

EXPECTED_RECORD_COUNT = 4
EXPECTED_STALE_COUNT = 3
KEY_ID = '0xCB3B6A73C71838F3'
MISSING_KEY_ID = 'DE134CA92809EF31'
TRUST_FINGERPRINT = '4AEA7B607FD11C25882D7C8BCB3B6A73C71838F3'
OTHER_FINGERPRINT = 'D91CBC43256EF761A182FF2D5A7EC13A9F145EBF'


# pylint: disable=unused-argument
def mock_wrong_input_data(*args, **kwargs):
    """
    Mock loading trust database with incorrect test data (key details)
    """
    with open(MOCK_KEY_DATA, encoding='utf-8') as filedescriptor:
        return filedescriptor.readlines(), []


# pylint: disable=unused-argument
def test_trustdb_properties(mock_gpg_key_list):
    """
    Test public key trust database properties
    """
    keys = UserPublicKeys()
    keys.load()
    trustdb = keys.trustdb

    assert trustdb.keyring == keys
    assert len(trustdb) == EXPECTED_RECORD_COUNT

    trust = next(trustdb)

    assert len(trustdb.stale_trust) == EXPECTED_STALE_COUNT

    assert trustdb.get(TRUST_FINGERPRINT) == trust

    assert isinstance(trust.__repr__(), str)
    assert str(trust) == f'{TRUST_FINGERPRINT}:unknown:'
    assert trust.value == f'{TRUST_FINGERPRINT}:2:'

    assert trust == TRUST_FINGERPRINT
    assert trust != OTHER_FINGERPRINT
    assert trust < OTHER_FINGERPRINT
    assert trust <= OTHER_FINGERPRINT
    assert not trust > OTHER_FINGERPRINT
    assert not trust >= OTHER_FINGERPRINT

    other = TrustDBItem(OTHER_FINGERPRINT, 6)
    # pylint: disable=comparison-with-itself
    assert trust == trust
    assert trust != other
    assert trust < other
    assert trust <= other
    assert not trust > other
    assert not trust >= other


def test_trusbdb_load_invalid_data(mock_gpg_key_list, monkeypatch):
    """
    Test failure loading trust database with invalid data
    """
    monkeypatch.setattr(
        'gpg_keymanager.keys.trustdb.run_command_lineoutput',
        mock_wrong_input_data
    )
    keys = UserPublicKeys()
    with pytest.raises(PGPKeyError):
        keys.trustdb.load()
    assert len(keys.trustdb) == 0


def test_trusbdb_load_fail(monkeypatch):
    """
    Test failure loading trust database
    """
    monkeypatch.setattr(
        'gpg_keymanager.keys.trustdb.run_command_lineoutput',
        mock_called_process_error
    )
    keys = UserPublicKeys()
    with pytest.raises(PGPKeyError):
        keys.trustdb.load()


def test_trustdb_lookup(mock_gpg_key_list):
    """
    Test public key trust database get() method
    """
    keys = UserPublicKeys()
    keys.load()

    assert isinstance(keys.trustdb.get(TRUST_FINGERPRINT), TrustDBItem)
    assert keys.trustdb.get(TRUST_FINGERPRINT) == TRUST_FINGERPRINT
    assert keys.trustdb.get(KEY_ID) == TRUST_FINGERPRINT

    for value in ('invalid item', MISSING_KEY_ID):
        with pytest.raises(PGPKeyError):
            keys.trustdb.get(value)


# pylint: disable=unused-argument
def test_trustdb_remove_stale_entries(mock_gpg_key_list, mock_gpg_trustdb_cleanup):
    """
    Test public key trust database stale entry removal function
    """
    keys = UserPublicKeys()
    keys.load()
    trustdb = keys.trustdb

    mock_exists_method = mock_gpg_trustdb_cleanup['exists']
    mock_rename_method = mock_gpg_trustdb_cleanup['rename']
    mock_run_method = mock_gpg_trustdb_cleanup['run']

    trustdb.remove_stale_entries()

    # Check for existing trust database
    print(mock_exists_method.args, mock_exists_method.kwargs)
    assert mock_exists_method.call_count == 1
    assert mock_exists_method.args == ()
    assert mock_exists_method.kwargs == {}

    # Rename existing trust database call
    print(mock_rename_method.args, mock_rename_method.kwargs)
    assert mock_rename_method.call_count == 1
    assert len(mock_rename_method.args) == 1
    assert isinstance(mock_rename_method.args[0], Path)
    assert mock_rename_method.kwargs == {}

    # Check command arguments for trust database import
    assert mock_run_method.call_count == 1
    assert len(mock_run_method.args) == 1
    assert mock_run_method.args[0] == ('gpg', '--import-ownertrust')
    assert 'input' in mock_run_method.kwargs
    # One left key remaining with trust to import
    expected_import = b'4AEA7B607FD11C25882D7C8BCB3B6A73C71838F3:2:\n'
    assert mock_run_method.kwargs['input'] == expected_import


# pylint: disable=unused-argument
def test_trustdb_remove_stale_entries_no_action(monkeypatch,
                                                mock_gpg_key_list,
                                                mock_gpg_trustdb_cleanup):
    """
    Test public key trust database stale entry removal function with no
    stale keys to remove. Command returns immediately when there are no
    stale items, without calling any of removal methods.
    """
    keys = UserPublicKeys()
    keys.load()
    trustdb = keys.trustdb

    monkeypatch.setattr(MOCK_TRUSTDB_STALE_PROPERTY, [])
    trustdb.remove_stale_entries()

    for method in mock_gpg_trustdb_cleanup.values():
        assert method.call_count == 0


# pylint: disable=unused-argument
def test_trustdb_remove_stale_entries_missing_trustdb(monkeypatch,
                                                      mock_gpg_key_list,
                                                      mock_gpg_trustdb_cleanup):
    """
    Test calling key trust database stale entry removal when no trust database
    exists for user
    """
    keys = UserPublicKeys()
    keys.load()
    trustdb = keys.trustdb

    monkeypatch.setattr(MOCK_TRUSTDB_EXISTS_METHOD, mock_return_false)
    with pytest.raises(PGPKeyError):
        trustdb.remove_stale_entries()


# pylint: disable=unused-argument
def test_trustdb_remove_stale_entries_error(monkeypatch,
                                            mock_gpg_key_list,
                                            mock_gpg_trustdb_cleanup):
    """
    Test calling key trust database stale entry removal with runtime error for gpg command

    This command will NOT fail with error, but
    """
    keys = UserPublicKeys()
    keys.load()
    trustdb = keys.trustdb

    mock_rename_method = mock_gpg_trustdb_cleanup['rename']

    # Override mocked run method with error
    monkeypatch.setattr(MOCK_TRUSTDB_RUN_METHOD, mock_called_process_error)

    with pytest.raises(PGPKeyError):
        trustdb.remove_stale_entries()

    # First rename is for backup creation, second for restore
    assert mock_rename_method.call_count == 2
