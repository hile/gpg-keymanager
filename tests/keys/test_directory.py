"""
Unit tests for gpg_keymanager.keys.directory module
"""

from pathlib import Path

from gpg_keymanager.keys.directory import PublicKeyDirectory

TEST_DIRECTORY = Path(__file__).parent.parent.joinpath('data/pgp-keys')


def test_directory_init():
    """
    Test initializing PublicKeyDirectory object
    """
    directory = PublicKeyDirectory(TEST_DIRECTORY)
    assert directory.is_dir()
