#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Common base command for gpg-keymanager CLI subcommands
"""
from cli_toolkit.command import Command

from gpg_keymanager.keys.loader import UserPublicKeys


class GpgKeymanagerCommand(Command):
    """
    Common base class for gpg-keymanager subcommands
    """

    @property
    def user_keyring(self) -> UserPublicKeys:
        """
        Return user PGP keyring
        """
        return UserPublicKeys()
