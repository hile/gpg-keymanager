
from cli_toolkit.tests.packaging import validate_version_string
from gpg_keymanager import __version__


def test_version_string():
    """
    Test format of module version string
    """
    validate_version_string(__version__)
