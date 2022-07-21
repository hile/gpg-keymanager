"""
Unit tests for gpg_keymanager.store.loader module
"""

from pathlib import Path

import pytest

from gpg_keymanager.exceptions import PasswordStoreError
from gpg_keymanager.store.constants import ENV_VAR
from gpg_keymanager.store.loader import PasswordStore
from gpg_keymanager.store.secret import Secret

from ..conftest import MOCK_VALID_STORE_PATH
from .test_keys import EXPECTED_KEYS_COUNT
from .test_secret import validate_secret_properties

MOCK_RUN_COMMAND = 'gpg_keymanager.store.loader.run_command'

VALID_STORE_PATH = Path('dir/other')
UNEXPECTED_STORE_PATH = Path('foo/bar')
EXPECTED_PATH_CHILD_COUNT = 1
EXPECTED_SECRET_CHILD_COUNT = 2
EXPECTED_RECURSIVE_SECRET_CHILD_COUNT = EXPECTED_SECRET_CHILD_COUNT + 1

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


# pylint: disable=unused-argument
def test_store_loader_init(mock_valid_store):
    """
    Test initializing a password store loader object
    """
    store = PasswordStore()
    assert store.is_dir()
    assert store == MOCK_VALID_STORE_PATH
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


def test_store_children(mock_valid_store):
    """
    Test listing the children objects for a valid store
    """
    store = PasswordStore()
    children = store.children
    path_children = []
    secret_children = []
    for item in children:
        if isinstance(item, PasswordStore):
            path_children.append(item)
        elif isinstance(item, Secret):
            secret_children.append(item)
        else:
            raise ValueError(f'Unexpected child item type: {type(item)}')
    assert len(path_children) == EXPECTED_PATH_CHILD_COUNT
    assert len(secret_children) == EXPECTED_SECRET_CHILD_COUNT


def test_store_secrets_non_recursive(mock_valid_store):
    """
    Test 'secrets' method of password store with 'recursive' as True

    This returns only the 2 secrets in root folder
    """
    store = PasswordStore()
    secrets = store.secrets(recursive=False)
    assert len(secrets) == EXPECTED_SECRET_CHILD_COUNT
    for secret in secrets:
        validate_secret_properties(store, secret)


def test_store_secrets_recursive(mock_valid_store):
    """
    Test 'secrets' method of password store with 'recursive' as True

    This returns 2 secrets in root folder and the subdirectory secret
    """
    store = PasswordStore()
    secrets = store.secrets(recursive=True)
    assert len(secrets) == EXPECTED_RECURSIVE_SECRET_CHILD_COUNT
    for secret in secrets:
        validate_secret_properties(store, secret)


def test_store_get_parent_invalid(mock_valid_store):
    """
    Test fetching parent for unexpected item
    """
    store = PasswordStore()
    assert store.get_parent(UNEXPECTED_STORE_PATH) is None


def test_store_get_invalid_path(mock_valid_store):
    """
    Test fetching invalid path from store
    """
    store = PasswordStore()
    assert store.get(UNEXPECTED_STORE_PATH) is None


def test_store_get_valid_items(mock_valid_store):
    """
    Test fetching valid paths from store
    """
    store = PasswordStore()

    secret = store.get(VALID_STORE_PATH)
    assert isinstance(secret, Secret)

    parent = secret.parent
    assert isinstance(store.get(parent.relative_path), PasswordStore)
