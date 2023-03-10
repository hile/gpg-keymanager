#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
CLI command gpg-keymanager
"""
from cli_toolkit.script import Script

from .commands.list_public_keys import ListPublicKeys


class GpgKeymanager(Script):
    """
    Main class for CLI command gpg-keymanager
    """
    subcommands = (
        ListPublicKeys,
    )


def main() -> None:
    """
    Run gpg-keymanager CLI
    """
    GpgKeymanager().run()
