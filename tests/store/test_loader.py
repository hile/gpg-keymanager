"""
Unit tests for gpg_keymanager.store.loader module
"""

from pathlib import Path

from gpg_keymanager.store.loader import PasswordStore

TEST_DIRECTORY = Path(__file__).parent.parent.joinpath('data/pgp-keys')


def test_store_loader_init():
    """
    Test initializing a password store loader object
    """
    loader = PasswordStore(TEST_DIRECTORY)
    assert loader.is_dir()


def test_store_loader_create(tmpdir):
    """
    Test initializing a password store loader object
    """
    path = Path(tmpdir).joinpath('password-store')
    loader = PasswordStore(path, create_missing=True)
    assert loader.is_dir()
