"""
Unit tests for gpg_keymanager.platform.base module
"""

import pytest

from gpg_keymanager.platform.base import Clipboard, SecureTemporaryDirectory

TEST_DATA = 'test string'
MOCK_VOLUME = '/dev/mock-dev'


class ImcompleteImplementation(SecureTemporaryDirectory):
    """
    Test incomplete implementation of SecureTemporaryDirectory
    """
    def __init__(self, suffix=None, prefix=None, dir=None):  # pylint: disable=redefined-builtin
        super().__init__(suffix, prefix, dir)  # pylint: disable=redefined-builtin
        self.volume = None

    def attach_storage_volume(self):
        """
        Call parent method that triggers the exception by default
        """
        print(f'attach mock device {self.volume}')

    def create_storage_volume(self):
        """
        Implement mocked method to set
        """
        self.volume = MOCK_VOLUME
        print('created volume')

    def detach_storage_volume(self):
        """
        Implement mocked method to detach and delete storage volume
        """
        self.volume = None


def test_base_clipboard_properties():
    """
    Test properties of the base class for Clipboards
    """
    obj = Clipboard()
    with pytest.raises(NotImplementedError):
        obj.copy(TEST_DATA)
    with pytest.raises(NotImplementedError):
        obj.paste()


def test_base_secure_temporary_directory_properties():
    """
    Test properties of the base class for secure temporary directories
    """
    obj = SecureTemporaryDirectory()
    assert obj.path is None

    with pytest.raises(NotImplementedError):
        obj.create_storage_volume()
    with pytest.raises(NotImplementedError):
        obj.attach_storage_volume()
    with pytest.raises(NotImplementedError):
        obj.detach_storage_volume()


def test_base_temporary_directory_incomplete_properties():
    """
    Test properties of incomplete child class for secure temporary directory to catch cases
    where the functions quit early due to NotImplementedError
    """
    assert ImcompleteImplementation().volume is None

    with ImcompleteImplementation() as obj:
        assert obj.volume == MOCK_VOLUME

    directory = None
    with ImcompleteImplementation() as obj:
        directory = obj.path
        assert directory is not None
        assert directory.is_dir()
        # Run this explicitly to trigger call from __exit__ and to handle the 'if' case there
        obj.delete_storage_directory()

    assert not directory.is_dir()
