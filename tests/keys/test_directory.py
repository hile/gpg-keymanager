"""
Unit tests for gpg_keymanager.keys.directory module
"""

from pathlib import Path

from gpg_keymanager.keys.directory import PublicKeyDirectory

from .test_public_key import KEY_ID

TEST_DIRECTORY = Path(__file__).parent.parent.joinpath('data/pgp-keys')

EXPECTED_KEY_COUNT = 1


def test_keys_directory_init(tmpdir):
    """
    Test initializing PublicKeyDirectory object for non-existing path
    """
    path = Path(tmpdir).joinpath('password-store')
    directory = PublicKeyDirectory(path)
    assert not directory.is_dir()

    directory = PublicKeyDirectory(path, create_missing=True)
    assert directory.is_dir()
    assert len(directory.keys) == 0
    assert len(directory.filter_keys(key_id=KEY_ID)) == 0


def test_keys_directory_load():
    """
    Test loading test data directory as key directory
    """
    directory = PublicKeyDirectory(TEST_DIRECTORY)
    assert directory.is_dir()
    assert len(directory.keys) == EXPECTED_KEY_COUNT
    assert len(directory.filter_keys(key_id=KEY_ID)) == 1
