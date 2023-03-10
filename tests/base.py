#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Common methods for unit tests
"""
from subprocess import CalledProcessError

from gpg_keymanager.exceptions import PGPKeyError


# pylint: disable=too-few-public-methods
class MockCallArguments:
    """
    Test class to validate command call arguments
    """
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.call_count = 0
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.args = None
        self.kwargs = None

    def __call__(self, *args, **kwargs):
        """
        Call mocked method, setting parameters to variables
        """
        self.call_count += 1
        self.args = args
        self.kwargs = kwargs
        return self


# pylint: disable=no-value-for-parameter,unused-argument
def mock_return_false(*args, **kwargs):
    """
    Mock returning false for function
    """
    return False


# pylint: disable=no-value-for-parameter
def mock_called_process_error(*args, **kwargs):
    """
    Mock raising CalledProcessError running shell command
    """
    raise CalledProcessError(cmd=args[0], returncode=1)


# pylint: disable=no-value-for-parameter
def mock_pgp_key_error(*args, **kwargs):
    """
    Mock raising PGPKeyError running shell command
    """
    raise PGPKeyError(f'Error parsing record: {args}')
