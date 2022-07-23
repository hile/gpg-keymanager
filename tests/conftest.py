"""
Python pytest unit tests configuration for gpg_keymanager
"""

import shutil

from pathlib import Path

import pytest

from sys_toolkit.tests.mock import MockCalledMethod
from sys_toolkit.subprocess import run_command_lineoutput
from sys_toolkit.path import Executables

from gpg_keymanager.store.loader import PasswordStore

from .base import MockCallArguments

MOCK_DATA = Path(__file__).parent.joinpath('mock')

MOCK_BIN_DIRECTORY = MOCK_DATA.joinpath('bin')
MOCK_KEYS_DIRECTORY = MOCK_DATA.joinpath('pgp-keys')
MOCK_STORE_DIRECTORY = MOCK_DATA.joinpath('password-store')

MOCK_KEY_DATA = MOCK_KEYS_DIRECTORY.joinpath('keys.txt')
MOCK_OWNERTRUST_DATA = MOCK_KEYS_DIRECTORY.joinpath('ownertrust.txt')

MOCK_VALID_STORE_PATH = MOCK_STORE_DIRECTORY.joinpath('valid-store')

MOCK_TRUSTDB_EXISTS_METHOD = 'gpg_keymanager.keys.trustdb.Path.exists'
MOCK_TRUSTDB_RENAME_METHOD = 'gpg_keymanager.keys.trustdb.Path.rename'
MOCK_TRUSTDB_RUN_METHOD = 'gpg_keymanager.keys.trustdb.run'

EXPECTED_PUBLIC_KEY_COUNT = 5

# Mock binary contents for data parser. This is first bytes of /bin/sh on macOS
MOCK_SECRET_BINARY_CONTENTS = b'\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07\x00\x00\x00\x03\x00\x00'

# Test password in generated sectet text entry
MOCK_SECRET_PASSWORD = 'verysecretpassword'
# Multiline mock contents of a secret
MOCK_SECRET_STRING_CONTENTS = f"""{MOCK_SECRET_PASSWORD}

This file contains mocked condifential data for GPG output file tests.
""".strip()


def load_key_testdata(*args, **kwargs):
    """
    Load test key data
    """
    if args[:3] == ('gpg', '--with-colons', '--keyid-format=long'):
        with open(MOCK_KEY_DATA, encoding='utf-8') as filedescriptor:
            return filedescriptor.readlines(), []
    return run_command_lineoutput(*args, **kwargs)


def load_trust_data_testdata(*args, **kwargs):
    """
    Load test trust database data
    """
    if args[:2] == ('gpg', '--export-ownertrust'):
        with open(MOCK_OWNERTRUST_DATA, encoding='utf-8') as filedescriptor:
            return filedescriptor.readlines(), []
    return run_command_lineoutput(*args, **kwargs)


@pytest.fixture
def mock_editor_path(monkeypatch):
    """
    Mock environment PATH to contain only test mock script directory
    """
    monkeypatch.setenv('PATH', str(MOCK_BIN_DIRECTORY))
    Executables.__commands__ = None


@pytest.fixture
def mock_editor_invalid_path(monkeypatch, tmpdir):
    """
    Mock environment PATH to contain only directory in tmpdir
    """
    monkeypatch.setenv('PATH', str(Path(tmpdir.strpath, 'bin')))
    Executables.__commands__ = None


@pytest.fixture
def mock_gpg_key_list(monkeypatch):
    """
    Mock reading of gpg key list for keys.PublicKeyDataParser
    """
    monkeypatch.setattr(
        'gpg_keymanager.keys.parser.run_command_lineoutput',
        load_key_testdata
    )
    monkeypatch.setattr(
        'gpg_keymanager.keys.trustdb.run_command_lineoutput',
        load_trust_data_testdata
    )


@pytest.fixture
def mock_gpg_trustdb_cleanup(monkeypatch):
    """
    Mock arguments for gpg trustdb cleanup functions
    """
    mock_exists_method = MockCallArguments()
    mock_rename_method = MockCallArguments()
    mock_run_method = MockCallArguments()
    monkeypatch.setattr(MOCK_TRUSTDB_EXISTS_METHOD, mock_exists_method)
    monkeypatch.setattr(MOCK_TRUSTDB_RENAME_METHOD, mock_rename_method)
    monkeypatch.setattr(MOCK_TRUSTDB_RUN_METHOD, mock_run_method)

    return {
        'exists': mock_exists_method,
        'rename': mock_rename_method,
        'run': mock_run_method
    }


@pytest.fixture
def mock_empty_store(tmpdir):
    """
    Mock creating an empty store
    """
    store_path = Path(tmpdir.strpath, 'test-mock-store')
    store_path.mkdir()
    store_path.joinpath('.gpg-id').write_text('12345667', encoding='utf-8')
    store = PasswordStore(store_path)
    yield store
    if store_path.is_dir():
        shutil.rmtree(store_path)


@pytest.fixture
def mock_valid_store(monkeypatch):
    """
    Mock configuring a valid password store
    """
    monkeypatch.setenv('PASSWORD_STORE_DIR', str(MOCK_VALID_STORE_PATH))


@pytest.fixture
def mock_secret_empty_data(monkeypatch):
    """
    Mock reading GPG secret file string contents with empty file
    """
    mock_method = MockCalledMethod(return_value=bytes('', encoding='utf-8'))
    monkeypatch.setattr('gpg_keymanager.store.secret.Secret.__get_gpg_file_contents__', mock_method)


@pytest.fixture
def mock_secret_string_data(monkeypatch):
    """
    Mock reading GPG secret file string contents from Secret object
    """
    mock_method = MockCalledMethod(return_value=bytes(MOCK_SECRET_STRING_CONTENTS, encoding='utf-8'))
    monkeypatch.setattr('gpg_keymanager.store.secret.Secret.__get_gpg_file_contents__', mock_method)


@pytest.fixture
def mock_secret_binary_data(monkeypatch):
    """
    Mock reading GPG secret file binary contents from Secret object
    """
    mock_method = MockCalledMethod(return_value=MOCK_SECRET_BINARY_CONTENTS)
    monkeypatch.setattr('gpg_keymanager.store.secret.Secret.__get_gpg_file_contents__', mock_method)
