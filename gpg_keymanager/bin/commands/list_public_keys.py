"""
CLI subcommand to list PGP keys
"""

from .base import GpgKeymanagerCommand


class ListPublicKeys(GpgKeymanagerCommand):
    """
    Command 'gpg-keymanager list-public-keys'
    """
    name = 'list-public-keys'

    def run(self, args):
        """
        List PGP public keys
        """
