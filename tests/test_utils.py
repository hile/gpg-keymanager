"""
Unit tests for gpg_keymanager.tests module
"""

from sys_toolkit.tests.mock import (
    MockCalledMethod,
    MockReturnFalse,
    MockReturnTrue,
)

from gpg_keymanager.utils import reset_tty


def test_utils_reset_tty_not_tty(monkeypatch):
    """
    Test reset_tty method when stdout is not a tty
    """
    mock_run = MockCalledMethod()
    monkeypatch.setattr('gpg_keymanager.utils.run', mock_run)
    monkeypatch.setattr('sys.stdout.isatty', MockReturnFalse())
    reset_tty()
    assert mock_run.call_count == 0


def test_utils_reset_tty_reset_fail(monkeypatch):
    """
    Test reset_tty method when stdout is a tty and reset fails
    """
    mock_run_error = MockCalledMethod(return_value=127)
    monkeypatch.setattr('gpg_keymanager.utils.run', mock_run_error)
    monkeypatch.setattr('sys.stdout.isatty', MockReturnTrue())
    reset_tty()
    assert mock_run_error.call_count == 1


def test_utils_reset_tty_reset_success(monkeypatch):
    """
    Test reset_tty method when stdout is a tty and reset is successful
    """
    mock_run = MockCalledMethod()
    monkeypatch.setattr('gpg_keymanager.utils.run', mock_run)
    monkeypatch.setattr('sys.stdout.isatty', MockReturnTrue())
    reset_tty()
    assert mock_run.call_count == 1
