"""
Unit tests for gpg_keymanager.editor module
"""

import os

from subprocess import CalledProcessError

import pytest

from sys_toolkit.tests.mock import MockCalledMethod, MockException

from gpg_keymanager.exceptions import KeyManagerError
from gpg_keymanager.editor import Editor, DEFAULT_EDITOR

from .conftest import MOCK_BIN_DIRECTORY

EDITOR_EXPLICIT = 'vim'
EDITOR_NOT_FOUND = 'nvim'
MOCK_TEST_FILE = '/tmp/test.txt'


# pylint: disable=unused-argument
def test_editor_executable_default_editor(monkeypatch, mock_editor_path):
    """
    Test editor with default editor executable
    """
    if 'EDITOR' in os.environ:
        monkeypatch.delenv('EDITOR')
    editor = Editor()
    assert editor.path == MOCK_BIN_DIRECTORY.joinpath(DEFAULT_EDITOR)


# pylint: disable=unused-argument
def test_editor_executable_name_from_env(monkeypatch, mock_editor_path):
    """
    Test editor with executable path from environment variables
    """
    monkeypatch.setenv('EDITOR', EDITOR_EXPLICIT)
    editor = Editor()
    assert editor.path == MOCK_BIN_DIRECTORY.joinpath(EDITOR_EXPLICIT)


# pylint: disable=unused-argument
def test_editor_executable_not_found(monkeypatch, mock_editor_invalid_path):
    """
    Test editor with executable path from environment variables
    """
    monkeypatch.setenv('EDITOR', EDITOR_NOT_FOUND)
    with pytest.raises(KeyManagerError):
        Editor()


# pylint: disable=unused-argument
def test_editor_edit_text_ok(monkeypatch, mock_editor_path):
    """
    Test editor with executable path from environment variables
    """
    mock_run = MockCalledMethod()
    monkeypatch.setattr('gpg_keymanager.editor.run', mock_run)
    Editor().edit(MOCK_TEST_FILE)
    assert mock_run.call_count == 1
    args = mock_run.args[0]
    expected = ((str(MOCK_BIN_DIRECTORY.joinpath(DEFAULT_EDITOR)), str(MOCK_TEST_FILE)),)
    assert args == expected


# pylint: disable=unused-argument
def test_editor_edit_text_error(monkeypatch, mock_editor_path):
    """
    Test editor with executable path from environment variables and error running command
    """
    expected = ((str(MOCK_BIN_DIRECTORY.joinpath(DEFAULT_EDITOR)), str(MOCK_TEST_FILE)),)
    mock_run_error = MockException(CalledProcessError, cmd=expected, returncode=1)
    monkeypatch.setattr('gpg_keymanager.editor.run', mock_run_error)
    with pytest.raises(KeyManagerError):
        Editor().edit(MOCK_TEST_FILE)
