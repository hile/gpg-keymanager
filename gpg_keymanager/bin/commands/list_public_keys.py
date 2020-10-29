"""
CLI subcommand to list PGP keys
"""

from .base import GpgKeymanagerCommand


class ListPublicKeys(GpgKeymanagerCommand):
    """
    Command 'gpg-keymanager list-public-keys'
    """
    name = 'list-public-keys'

    @staticmethod
    def format_key_details(key):
        """
        Format key details for output
        """
        expires = f'{key.expiration_date.date()}' if key.expiration_date is not None else ''
        return f'{key.key_id} {key.key_validity:8} {expires:10} {key.primary_user_id}'

    def run(self, args):
        """
        List PGP public keys
        """
        for key in self.user_keyring:
            self.message(self.format_key_details(key))
