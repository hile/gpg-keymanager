"""
Unit tests for gpg_keymanager.store.loader module
"""

from pathlib import Path

import pytest

from gpg_keymanager.exceptions import PasswordStoreError
from gpg_keymanager.store.constants import ENV_VAR
from gpg_keymanager.store.loader import PasswordStore

from .test_keys import EXPECTED_KEYS_COUNT

MOCK_RUN_COMMAND = 'gpg_keymanager.store.loader.run_command'

TEST_DIRECTORY = Path(__file__).parent.parent.joinpath(
    'data/password-store/valid-store'
)
TEST_CREATE_KEYS = (
    'AABBCCDDEEDDFFAA',
    '123456781234ABCD',
)


class MockCreateStore:
    """
    Mock running 'pass init <keyids>' command
    """
    def __init__(self, store):
        self.store = store
        self.call_count = 0
        self.args = None
        self.kwargs = None

    def __call__(self, *args, **kwargs):
        """
        Mock calling pass init command
        """
        self.call_count += 1
        self.args = args
        self.kwargs = kwargs
        self.create()

    def create(self):
        """
        Create mocked password store
        """
        if not self.store.is_dir():
            self.store.mkdir()


def test_store_loader_init():
    """
    Test initializing a password store loader object
    """
    store = PasswordStore(TEST_DIRECTORY)
    assert store.is_dir()
    env = store.environment
    assert ENV_VAR in env

    # Root has no parents
    assert len(store.parents) == 0
    # Store is encrypted for 2 keys
    assert len(store.gpg_key_ids) == EXPECTED_KEYS_COUNT

    assert store.relative_path is None
    matches = store.filter('test.gpg')
    assert isinstance(matches, list)
    item = matches[0]
    assert item.relative_path == 'test.gpg'

    # Matches dir and dir/other.gpg
    matches = store.filter('dir')
    assert len(matches) == 2

    subdir = matches[0]
    assert len(subdir.parents) == 1
    assert len(subdir.gpg_key_ids) == EXPECTED_KEYS_COUNT
    assert isinstance(subdir.relative_path, str)

    item = matches[-1]
    assert isinstance(item.relative_path, str)


def test_store_loader_create_mock(tmpdir, monkeypatch):
    """
    Test initializing a password store loader object with mocked create command
    """
    path = Path(tmpdir).joinpath('password-store')
    store = PasswordStore(path)
    with pytest.raises(PasswordStoreError):
        store.create()
    assert not store.is_dir()

    with pytest.raises(PasswordStoreError):
        # pylint: disable=pointless-statement
        store.gpg_key_ids

    mock_create_store = MockCreateStore(store)
    monkeypatch.setattr(MOCK_RUN_COMMAND, mock_create_store)

    store.create(gpg_key_ids=TEST_CREATE_KEYS)
    assert store.is_dir()

    assert mock_create_store.call_count == 1

    # Check env contains password store path
    env = mock_create_store.kwargs.get('env', None)
    assert env is not None
    password_store_dir = env.get(ENV_VAR, None)
    assert password_store_dir == str(store)

    # Check command arguments
    expected_args = ['pass', 'init'] + list(TEST_CREATE_KEYS)
    assert list(mock_create_store.args) == expected_args


def test_store_loader_create(tmpdir):
    """
    Test initializing a password store with real 'pass' command

    Creates new password store to tmpdir and makes sure .gpg-id file for new store
    contains specified keys
    """
    path = Path(tmpdir).joinpath('password-store')
    store = PasswordStore(path)
    store.create(gpg_key_ids=TEST_CREATE_KEYS)
    assert list(store.gpg_key_ids) == list(TEST_CREATE_KEYS)
