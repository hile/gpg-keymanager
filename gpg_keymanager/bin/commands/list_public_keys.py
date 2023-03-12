#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
CLI subcommand to list PGP keys
"""
from argparse import Namespace

from ...keys.public_key import PublicKey
from .base import GpgKeymanagerCommand


class ListPublicKeys(GpgKeymanagerCommand):
    """
    Command 'gpg-keymanager list-public-keys'
    """
    name = 'list-public-keys'

    @staticmethod
    def format_key_details(key: PublicKey) -> str:
        """
        Format key details for output
        """
        expires = f'{key.expiration_date.date()}' if key.expiration_date is not None else ''
        return f'{key.key_id} {key.key_validity:8} {expires:10} {key.primary_user_id}'

    def run(self, args: Namespace) -> None:
        """
        List PGP public keys
        """
        for key in self.user_keyring:
            self.message(self.format_key_details(key))
