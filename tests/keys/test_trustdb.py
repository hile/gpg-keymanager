"""
Unit tests for gpg_keymanager.keys.trustdb module
"""

import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys.parser import UserPublicKeys
from gpg_keymanager.keys.trustdb import TrustDBItem

from ..base import mock_called_process_error

EXPECTED_RECORD_COUNT = 4
EXPECTED_STALE_COUNT = 3
KEY_ID = '0xCB3B6A73C71838F3'
MISSING_KEY_ID = 'DE134CA92809EF31'
TRUST_FINGERPRINT = '4AEA7B607FD11C25882D7C8BCB3B6A73C71838F3'
OTHER_FINGERPRINT = 'D91CBC43256EF761A182FF2D5A7EC13A9F145EBF'


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
    assert OTHER_FINGERPRINT > trust
    assert OTHER_FINGERPRINT >= trust

    other = TrustDBItem(OTHER_FINGERPRINT, 6)
    # pylint: disable=comparison-with-itself
    assert trust == trust
    assert trust != other
    assert trust < other
    assert trust <= other
    assert other > trust
    assert other >= trust


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
