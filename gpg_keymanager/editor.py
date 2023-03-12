#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Launch text editor for text files
"""
import os

from pathlib import Path
from subprocess import run, CalledProcessError
from typing import Union

from sys_toolkit.path import Executables

from .exceptions import KeyManagerError

DEFAULT_EDITOR = 'vi'


# pylint: disable=too-few-public-methods
class Editor:
    """
    Wrapper to detect editor binary for editing text files
    """
    path: Path

    def __init__(self, path: Union[str, Path] = None):
        self.path = Path(path) if path else self.__detect_editor__()

    @staticmethod
    def __detect_editor__() -> Path:
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

    def edit(self, path: Union[str, Path]) -> None:
        """
        Edit specified text file with editor
        """
        try:
            run((str(self.path), str(path)), check=True)
        except CalledProcessError as error:
            raise KeyManagerError(f'Error editing file {self.path}: {error}') from error
