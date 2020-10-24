"""
Python pytest unit tests configuration for gpg_keymanager
"""

from pathlib import Path

import pytest

from systematic_cli.process import run_command_lineoutput

TEST_KEY_DATA = Path(__file__).parent.joinpath('data/pgp-keys/keys.txt')
TEST_OWNERTRUST_DATA = Path(__file__).parent.joinpath('data/pgp-keys/ownertrust.txt')


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
