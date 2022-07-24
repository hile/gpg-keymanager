"""
Base classes for platform specific tasks
"""

import shutil

from pathlib import Path
from tempfile import mkdtemp

DEFAULT_TMPDIR_DIRECTORY = None
DEFAULT_TMPDIR_SUFFIX = None
DEFAULT_TMPDIR_PREFIX = 'pass.'


class Clipboard:
    """
    Base class implementation of clipboard copy and paste functions
    """
    def copy(self, data):
        """
        Copy data to clipboard
        """
        raise NotImplementedError('Clipboard copy() must be implemented in child class')

    def paste(self):
        """
        Get data from clipboard
        """
        raise NotImplementedError('Clipboard paste() must be implemented in child class')


class SecureTemporaryDirectory:
    """
    Class to wrap a temporary directory to secure temporary storage
    """
    def __init__(self, suffix=None, prefix=None, dir=None):  # pylint: disable=redefined-builtin
        self.__tmpdir__ = mkdtemp(suffix, prefix, dir)  # pylint: disable=redefined-builtin
        self.path = Path(self.__tmpdir__)

    def create_secure_storage(self):
        """
        Create secure volume storage space and mount it to the temporary directory
        """
        self.create_storage_volume()
        self.attach_storage_volume()

    def destroy_secure_storage(self):
        """
        Create secure volume storage space and mount it to the temporary directory
        """
        self.detach_storage_volume()
        self.delete_storage_directory()

    def delete_storage_directory(self):
        """
        Method to destroy the created secure storage space directory in self.path

        This method is platform specific and by default raises NotImplementedError
        """
        if self.path is not None and self.path.is_dir():
            shutil.rmtree(self.path)
        self.__tmpdir__ = None
        self.path = None

    def create_storage_volume(self):
        """
        Method to create a secure storage space

        This method is platform specific and by default raises NotImplementedError
        """
        raise NotImplementedError('create_storage_volume() must be implemented in child class')

    def attach_storage_volume(self):
        """
        Method to attach created secure storage space to self.path

        This method is platform specific and by default raises NotImplementedError
        """
        raise NotImplementedError('attach_storage_volume() must be implemented in child class')

    def detach_storage_volume(self):
        """
        Method to detach created secure storage space from self.path

        This method is platform specific and by default raises NotImplementedError
        """
        raise NotImplementedError('detach_storage_volume() must be implemented in child class')
