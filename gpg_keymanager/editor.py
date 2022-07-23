"""
Launch text editor for text files
"""
import os

from pathlib import Path
from subprocess import run, CalledProcessError

from sys_toolkit.path import Executables

from .exceptions import KeyManagerError

DEFAULT_EDITOR = 'vi'


# pylint: disable=too-few-public-methods
class Editor:
    """
    Wrapper to detect editor binary for editing text files
    """
    def __init__(self, path=None):
        self.path = Path(path) if path else self.__detect_editor__()

    @staticmethod
    def __detect_editor__():
        """
        Detect editor path
        """
        executables = Executables()
        editor = os.environ.get('EDITOR', None)
        if editor and editor in executables:
            return executables.get(editor)
        if DEFAULT_EDITOR in executables:
            return executables.get(DEFAULT_EDITOR)
        raise KeyManagerError('Suitable text editor not found')

    def edit(self, path):
        """
        Edit specified text file with editor
        """
        try:
            run((str(self.path), str(path)), check=True)
        except CalledProcessError as error:
            raise KeyManagerError(f'Error editing file {self.path}: {error}') from error
