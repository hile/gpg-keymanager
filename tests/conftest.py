"""
Python pytest unit tests configuration for gpg_keymanager
"""

from pathlib import Path

import pytest

from cli_toolkit.process import run_command_lineoutput

from .base import MockCallArguments

TEST_KEY_DATA = Path(__file__).parent.joinpath('data/pgp-keys/keys.txt')
TEST_OWNERTRUST_DATA = Path(__file__).parent.joinpath('data/pgp-keys/ownertrust.txt')

MOCK_TRUSTDB_EXISTS_METHOD = 'gpg_keymanager.keys.trustdb.Path.exists'
MOCK_TRUSTDB_RENAME_METHOD = 'gpg_keymanager.keys.trustdb.Path.rename'
MOCK_TRUSTDB_RUN_METHOD = 'gpg_keymanager.keys.trustdb.run'


def load_key_testdata(*args, **kwargs):
    """
    Load test key data
    """
    if args[:3] == ('gpg', '--with-colons', '--keyid-format=long'):
        with open(TEST_KEY_DATA, encoding='utf-8') as filedescriptor:
            return filedescriptor.readlines(), []
    return run_command_lineoutput(*args, **kwargs)


def load_trust_data_testdata(*args, **kwargs):
    """
    Load test trust database data
    """
    if args[:2] == ('gpg', '--export-ownertrust'):
        with open(TEST_OWNERTRUST_DATA, encoding='utf-8') as filedescriptor:
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
