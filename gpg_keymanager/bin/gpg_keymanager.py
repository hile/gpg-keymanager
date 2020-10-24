"""
CLI command gpg-keymanager
"""

from systematic_cli.script import Script

from .commands.list_public_keys import ListPublicKeys


class GpgKeymanager(Script):
    """
    Main class for CLI command gpg-keymanager
    """
    subcommands = (
        ListPublicKeys,
    )


def main():
    """
    Run gpg-keymanager CLI
    """
    GpgKeymanager().run()
