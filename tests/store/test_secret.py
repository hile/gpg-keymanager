"""
Unit tests for gpg_keymanager.store.secret module
"""

from pathlib import Path
from subprocess import CalledProcessError

import pytest

from sys_toolkit.tests.mock import MockCalledMethod, MockException

from gpg_keymanager.exceptions import PasswordStoreError
from gpg_keymanager.store.keys import PasswordStoreKeys
from gpg_keymanager.store.loader import PasswordStore
from gpg_keymanager.store.secret import Secret

from ..conftest import (
    MOCK_SECRET_PASSWORD,
    MOCK_SECRET_BINARY_CONTENTS,
    MOCK_SECRET_STRING_CONTENTS
)

EXPECTED_SECRETS_COUNT = 3

SECRET_A_PATH = Path('Services/A')
SECRET_B_PATH = Path('Systems/A')


# pylint: disable=too-few-public-methods
class MockStdoutCommand(MockCalledMethod):
    """
    Mock a called method with stdout and stderr attributes
    """
    def __init__(self, stdout='', stderr='', return_value=None):
        super().__init__(return_value)
        self.stdout = bytes(stdout, encoding='utf-8') if isinstance(stdout, str) else stdout
        self.stderr = bytes(stderr, encoding='utf-8') if isinstance(stderr, str) else stderr

    def __call__(self, *args, **kwargs):
        """
        Run command, returning self.stdout and self.stderr as bytes
        """
        super().__call__(*args, **kwargs)
        return self


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


def test_secret_load_gpg_data_arguments(monkeypatch):
    """
    Test arguments of the __get_gpg_file_contents__ call to gpg command

    This command checks exact run() arguments for gpg command
    """
    mock_run = MockStdoutCommand()
    monkeypatch.setattr('gpg_keymanager.store.secret.run', mock_run)
    store = PasswordStore()
    secret, _other = mock_store_secrets(store)
    contents = secret.__get_gpg_file_contents__()
    assert contents == mock_run.stdout
    assert mock_run.call_count == 1
    args = mock_run.args[0]
    assert args == (('gpg', '-o-', '-d', str(secret.path)),)


def test_secret_load_gpg_data_error(monkeypatch):
    """
    Test exception running command in __get_gpg_file_contents__
    """
    mock_run_error = MockException(CalledProcessError, cmd=('gpg', '-o-'), returncode=1)
    monkeypatch.setattr('gpg_keymanager.store.secret.run', mock_run_error)
    store = PasswordStore()
    secret, _other = mock_store_secrets(store)
    with pytest.raises(PasswordStoreError):
        secret.__get_gpg_file_contents__()


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


def test_secret_read_password(mock_secret_string_data):
    """
    Mock reading secret password (first line in text format secret)
    """
    a, b = mock_store_secrets(PasswordStore())

    assert a.password == MOCK_SECRET_PASSWORD
    assert b.password == MOCK_SECRET_PASSWORD


def test_secret_read_password_empty_file(mock_secret_empty_data):
    """
    Mock reading secret password (first line in text format secret) from empty file
    """
    a, b = mock_store_secrets(PasswordStore())
    with pytest.raises(PasswordStoreError):
        a.password  # pylint: disable=pointless-statement
    with pytest.raises(PasswordStoreError):
        b.password  # pylint: disable=pointless-statement


def test_secret_read_password_binary_error(mock_secret_binary_data):
    """
    Mock reading secret password with binary data, causing exception
    """
    a, b = mock_store_secrets(PasswordStore())
    with pytest.raises(PasswordStoreError):
        a.password  # pylint: disable=pointless-statement
    with pytest.raises(PasswordStoreError):
        b.password  # pylint: disable=pointless-statement


def test_secret_read_data_binary(mock_secret_binary_data):
    """
    Mock reading secret binary  contents as data
    """
    a, b = mock_store_secrets(PasswordStore())

    assert a.data == bytes(MOCK_SECRET_BINARY_CONTENTS)
    assert a.data == b.data


def test_secret_read_data_string(mock_secret_string_data):
    """
    Mock reading secret string contents as data
    """
    a, b = mock_store_secrets(PasswordStore())

    assert a.data == bytes(MOCK_SECRET_STRING_CONTENTS, encoding='utf-8')
    assert a.data == b.data


def test_secret_read_text_ok(mock_secret_string_data):
    """
    Mock reading secret contents as text
    """
    a, b = mock_store_secrets(PasswordStore())

    assert a.text == MOCK_SECRET_STRING_CONTENTS
    assert a.text == b.text


def test_secret_read_text_binary_error(mock_secret_binary_data):
    """
    Mock reading secret contents as text with binary data, causing exception
    """
    a, b = mock_store_secrets(PasswordStore())
    with pytest.raises(PasswordStoreError):
        a.text  # pylint: disable=pointless-statement
    with pytest.raises(PasswordStoreError):
        b.text  # pylint: disable=pointless-statement
