#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Utilities for PGP public keys
"""
import re

from typing import List, Tuple, Union

from ..exceptions import PGPKeyError

RE_KEY_ID_FORMATS = (
    re.compile(r'^0x[0-9A-Z]{16}$'),
    re.compile(r'^[0-9A-Z]{16}$'),
    re.compile(r'[0-9A-Z]{8}$'),
)


def validate_key_ids(value: Union[str, List[str], Tuple[str]]):
    """
    Validate PGP key ID value string
    """
    def match_pattern(value: str):
        """
        Match key ID to valid patterns
        """
        if not isinstance(value, str):
            return False
        for pattern in RE_KEY_ID_FORMATS:
            if pattern.match(value):
                return True
        return False

    if isinstance(value, (list, tuple)):
        invalid_keys = []
        for key in value:
            if not match_pattern(key):
                invalid_keys.append(key)
        if invalid_keys:
            raise PGPKeyError(
                f"""Invalid PGP key IDs: {' '.join(str(item) for item in invalid_keys)}"""
            )
    elif isinstance(value, str):
        if not match_pattern(value):
            raise PGPKeyError(f'Invalid PGP key ID {value}')
    else:
        raise PGPKeyError(f'Unexpected type: {type(value)}')
