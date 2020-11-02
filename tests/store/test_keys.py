"""
Test gpg_keymanager.store.keys module
"""

from pathlib import Path

import pytest

from gpg_keymanager.exceptions import PasswordStoreError
from gpg_keymanager.store.keys import PasswordStoreKeys, PASSWORD_STORE_KEY_LIST_FILENAME

INVALID_TEST_FILE = Path(__file__).parent.parent.joinpath(
    'data/password-store/invalid-ids.txt'
)
VALID_TEST_FILE = Path(__file__).parent.parent.joinpath(
    'data/password-store/valid-ids.txt'
)
EXPECTED_KEYS_COUNT = 2
VALID_LONG_KEY_ID = '123456781234ABCD'
VALID_SHORT_KEY_ID = '12345678'
INVALID_KEY_ID = '1234abcd'


def test_store_keys_load_valid():
    """
    Test loading valid password store keys file
    """
    keys = PasswordStoreKeys(VALID_TEST_FILE)
    assert isinstance(keys.__repr__(), str)
    assert keys.path.is_file()
    assert len(keys) == EXPECTED_KEYS_COUNT

    keys.append(VALID_LONG_KEY_ID)
    keys.append(VALID_SHORT_KEY_ID)
    assert len(keys) == EXPECTED_KEYS_COUNT + 2

    with pytest.raises(PasswordStoreError):
        keys.append(INVALID_KEY_ID)

    assert keys.get(VALID_LONG_KEY_ID) == VALID_LONG_KEY_ID
    assert keys.get(INVALID_KEY_ID) is None


def test_store_keys_load_no_file(tmpdir):
    """
    Test loading non-existing password store keys file
    """
    filename = Path(tmpdir).joinpath(PASSWORD_STORE_KEY_LIST_FILENAME)
    keys = PasswordStoreKeys(filename)
    assert not keys.path.is_file()
    with pytest.raises(PasswordStoreError):
        keys.load()


def test_store_keys_load_empty_file(tmpdir):
    """
    Test loading empty password store keys file
    """
    filename = Path(tmpdir).joinpath(PASSWORD_STORE_KEY_LIST_FILENAME)
    with filename.open('w') as filedescriptor:
        filedescriptor.write('# This test file is empty\n')

    with pytest.raises(PasswordStoreError):
        PasswordStoreKeys(filename).load()


def test_store_keys_load_invalid():
    """
    Test loading invalid password store keys file
    """
    keys = PasswordStoreKeys(INVALID_TEST_FILE)
    assert keys.path.is_file()
    with pytest.raises(PasswordStoreError):
        keys.load()
