"""
Python pytest unit tests configuration for gpg_keymanager
"""

from pathlib import Path

import pytest

from sys_toolkit.subprocess import run_command_lineoutput

from .base import MockCallArguments

MOCK_DATA = Path(__file__).parent.joinpath('mock')

MOCK_KEYS_DIRECTORY = MOCK_DATA.joinpath('pgp-keys')
MOCK_STORE_DIRECTORY = MOCK_DATA.joinpath('password-store')

MOCK_KEY_DATA = MOCK_KEYS_DIRECTORY.joinpath('keys.txt')
MOCK_OWNERTRUST_DATA = MOCK_KEYS_DIRECTORY.joinpath('ownertrust.txt')

MOCK_VALID_STORE_PATH = MOCK_STORE_DIRECTORY.joinpath('valid-store')

MOCK_TRUSTDB_EXISTS_METHOD = 'gpg_keymanager.keys.trustdb.Path.exists'
MOCK_TRUSTDB_RENAME_METHOD = 'gpg_keymanager.keys.trustdb.Path.rename'
MOCK_TRUSTDB_RUN_METHOD = 'gpg_keymanager.keys.trustdb.run'

EXPECTED_PUBLIC_KEY_COUNT = 5


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
def mock_valid_store(monkeypatch):
    """
    Mock configuring a valid password store
    """
    monkeypatch.setenv('PASSWORD_STORE_DIR', str(MOCK_VALID_STORE_PATH))
