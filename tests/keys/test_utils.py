"""
Unit tests for gpg_keymanager.keys.utils module
"""

import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys.utils import validate_key_ids

VALID_IDS = (
    '0x1234567812345678',
    '1234567812345678',
    '12345678',
)
INVALID_IDS = (
    '0x12345678aaaaaaaa',
    12345678,
    ''
)


def test_validate_key_ids_valid_values():
    """
    Test valid values for GPG IDs
    """
    for value in VALID_IDS:
        validate_key_ids(value)


def test_validate_key_ids_valid_lists():
    """
    Test valid values for GPG IDs from lists and tuples
    """
    validate_key_ids(VALID_IDS)
    validate_key_ids(tuple(VALID_IDS))


def test_validate_key_ids_valid_errors():
    """
    Test errors in validating key IDs
    """
    for value in INVALID_IDS:
        with pytest.raises(PGPKeyError):
            validate_key_ids(value)

    valid_invalid = VALID_IDS + INVALID_IDS
    with pytest.raises(PGPKeyError):
        validate_key_ids(valid_invalid)
