"""
Common base command for gpg-keymanager CLI subcommands
"""

from cli_toolkit.command import Command

from gpg_keymanager.keys.parser import UserPublicKeys


class GpgKeymanagerCommand(Command):
    """
    Common base class for gpg-keymanager subcommands
    """

    @property
    def user_keyring(self):
        """
        Return user PGP keyring
        """
        return UserPublicKeys()
