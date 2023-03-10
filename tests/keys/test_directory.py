#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Unit tests for gpg_keymanager.keys.directory module
"""
from pathlib import Path

from gpg_keymanager.keys.directory import PublicKeyDirectory

from ..conftest import MOCK_KEYS_DIRECTORY
from .test_public_key import KEY_ID

EXPECTED_KEY_COUNT = 1


def test_keys_directory_init(tmpdir):
    """
    Test initializing PublicKeyDirectory object for non-existing path
    """
    path = Path(tmpdir).joinpath('password-store')
    directory = PublicKeyDirectory(path)
    assert not directory.is_dir()

    directory = PublicKeyDirectory(path, create_missing=True)
    assert directory.is_dir()
    assert len(directory.keys) == 0
    assert len(directory.filter_keys(key_id=KEY_ID)) == 0


def test_keys_directory_load():
    """
    Test loading test data directory as key directory
    """
    directory = PublicKeyDirectory(MOCK_KEYS_DIRECTORY)
    assert directory.is_dir()
    assert len(directory.keys) == EXPECTED_KEY_COUNT
    filtered = directory.filter_keys(key_id=KEY_ID)
    assert len(filtered) == 1
    assert KEY_ID in filtered
