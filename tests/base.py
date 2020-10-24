"""
Common methods for unit tests
"""

from subprocess import CalledProcessError


# pylint: disable=no-value-for-parameter
def mock_called_process_error(cmd, *args, **kwargs):
    """
    Mock raising CalledProcessError running shell command
    """
    raise CalledProcessError('Error running command')
