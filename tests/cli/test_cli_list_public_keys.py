"""
Unit tests for 'gpg-keymanager list-public-keys' command
"""

import re
import sys

import pytest

from gpg_keymanager.bin.gpg_keymanager import main

from ..conftest import EXPECTED_PUBLIC_KEY_COUNT

RE_KEY_OUTPUT = re.compile(r'^0x[0-9A-Z]+ .+$')


# pylint: disable=unused-argument
def test_gpg_manager_list_public_keys_help(mock_gpg_key_list, monkeypatch):
    """
    Test running 'gpg-keymanager --help'
    """
    argv = [
        'gpg-keymanager',
        'list-public-keys',
        '--help'
    ]
    monkeypatch.setattr(sys, 'argv', argv)
    with pytest.raises(SystemExit) as exit_status:
        main()
    assert exit_status.value.code == 0


# pylint: disable=unused-argument
def test_gpg_manager_list_public_keys__no_args(mock_gpg_key_list, capsys, monkeypatch):
    """
    Test running 'gpg-keymanager' without arguments
    """
    argv = [
        'gpg-keymanager',
        'list-public-keys',
    ]
    monkeypatch.setattr(sys, 'argv', argv)
    with pytest.raises(SystemExit) as exit_status:
        main()
    assert exit_status.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    assert len(lines) == EXPECTED_PUBLIC_KEY_COUNT
    for line in lines:
        match = RE_KEY_OUTPUT.match(line)
        assert match is not None
