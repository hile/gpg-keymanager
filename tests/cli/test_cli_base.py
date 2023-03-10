#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Unit tests for gpg-keymanager CLI base class
"""
import sys

import pytest

from gpg_keymanager.bin.gpg_keymanager import main


def test_gpg_manager_help(monkeypatch):
    """
    Test running 'gpg-keymanager --help'
    """
    monkeypatch.setattr(sys, 'argv', ['gpg-keymanager', '--help'])
    with pytest.raises(SystemExit) as exit_status:
        main()
    assert exit_status.value.code == 0


def test_gpg_manager_no_args(monkeypatch):
    """
    Test running 'gpg-keymanager' without arguments
    """
    monkeypatch.setattr(sys, 'argv', ['gpg-keymanager'])
    with pytest.raises(SystemExit) as exit_status:
        main()
    assert exit_status.value.code == 1
