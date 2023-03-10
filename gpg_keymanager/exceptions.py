#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Exceptions raised by gpg-keymanager python package
"""


class PGPKeyError(Exception):
    """
    Exceptions raised by PGP key processing
    """


class PasswordStoreError(Exception):
    """
    Execptions raised by password store handling utilities
    """


class KeyManagerError(Exception):
    """
    Execptions raised by password store handling utilities
    """
