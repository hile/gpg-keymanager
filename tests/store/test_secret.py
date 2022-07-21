"""
Unit tests for gpg_keymanager.store.secret module
"""

from gpg_keymanager.store.keys import PasswordStoreKeys
from gpg_keymanager.store.loader import PasswordStore
from gpg_keymanager.store.secret import Secret

EXPECTED_SECRETS_COUNT = 3


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
