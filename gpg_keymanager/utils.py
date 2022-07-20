"""
Utility methods for gpg_keymanager module
"""

import sys

from subprocess import run, PIPE


def reset_tty():
    """
    Try resetting TTY after errors with GPG commands
    """
    if not sys.stdout.isatty():
        return
    run(('stty', 'sane'), stdout=PIPE, stderr=PIPE, check=False)
