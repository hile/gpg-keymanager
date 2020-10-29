"""
Unit tests for 'gpg-keymanager list-public-keys' command
"""

import re
import sys

import pytest

from gpg_keymanager.bin.gpg_keymanager import main

RE_KEY_OUTPUT = re.compile(r'^0x[0-9A-Z]+ .+$')


def test_gpg_manager_list_public_keys_help(monkeypatch):
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


def test_gpg_manager_list_public_keys__no_args(capsys, monkeypatch):
    """
    Test running 'gpg-keymanager' without arguments
    """
    argv = [
        'gpg-keymanager',
        'list-public-keys',
    ]
    monkeypatch.setattr(sys, 'argv', argv)
    main()
    captured = capsys.readouterr()
    assert captured.err == ''
    lines = captured.out.splitlines()
    assert len(lines) > 0
    for line in lines:
        print(line)
        match = RE_KEY_OUTPUT.match(line)
        assert match is not None
