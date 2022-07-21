"""
Unit tests for gpg_keymanager.store.secret module
"""

from pathlib import Path

from gpg_keymanager.store.keys import PasswordStoreKeys
from gpg_keymanager.store.loader import PasswordStore
from gpg_keymanager.store.secret import Secret

EXPECTED_SECRETS_COUNT = 3

SECRET_A_PATH = Path('Services/A')
SECRET_B_PATH = Path('Systems/A')


def mock_store_secrets(store):
    """
    Return mocked store secrets a and b for given password store
    """
    parent_a = PasswordStore(store.joinpath(SECRET_A_PATH.parent), password_store=store)
    parent_b = PasswordStore(store.joinpath(SECRET_B_PATH.parent), password_store=store)
    a = Secret(store, parent_a, str(SECRET_A_PATH))
    b = Secret(store, parent_b, str(SECRET_B_PATH))
    return a, b


def validate_secret_properties(store, secret):
    """
    Validate properties of a Secret object
    """
    assert isinstance(secret, Secret)
    assert isinstance(secret.gpg_key_ids, PasswordStoreKeys)
    assert isinstance(secret.__repr__(), str)
    assert secret.store == store
    assert secret.relative_path == secret.path.relative_to(store)


# pylint: disable=unused-argument
def test_secret_valid_store_properties(mock_valid_store):
    """
    Test loading secrets from valid password store
    """
    store = PasswordStore()
    secrets = store.secrets(recursive=True)
    assert len(secrets) == EXPECTED_SECRETS_COUNT
    for secret in secrets:
        validate_secret_properties(store, secret)


# pylint: disable=unused-argument
def test_secret_mock_attributes(mock_valid_store):
    """
    Test attributes of mocked secrets
    """
    store = PasswordStore()
    a, b = mock_store_secrets(store)
    validate_secret_properties(store, a)
    validate_secret_properties(store, b)


# pylint: disable=unused-argument
def test_secret_compare_by_secret(mock_valid_store):
    """
    Test comparing secrets with known paths
    """
    a, b = mock_store_secrets(PasswordStore())

    assert a == a  # pylint: disable=comparison-with-itself
    assert a != b

    assert a < b
    assert b > a

    assert a <= a  # pylint: disable=comparison-with-itself
    assert a <= b
    assert a >= a  # pylint: disable=comparison-with-itself
    assert b >= a


# pylint: disable=unused-argument
def test_secret_compare_by_string(mock_valid_store):
    """
    Test comparing secrets with known paths
    """
    a, b = mock_store_secrets(PasswordStore())

    assert a == str(a)
    assert a != str(b)

    assert a < str(b)
    assert b > str(a)

    assert a <= str(a)
    assert a <= str(b)
    assert a >= str(a)
    assert b >= str(a)
