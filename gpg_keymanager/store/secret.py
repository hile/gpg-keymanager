"""
Password store secret item
"""

from itertools import chain
from pathlib import Path
from subprocess import run, PIPE
from tempfile import mkstemp

from ..exceptions import PasswordStoreError
from ..utils import reset_tty

from .constants import PASSWORD_ENTRY_ENCODING


class Secret:
    """
    Encrypted secret in password store
    """
    def __init__(self, directory, path):
        self.__contents__ = None
        self.directory = directory
        try:
            Path(path).relative_to(self.directory)
        except ValueError:
            path = self.directory.joinpath(path)
        self.path = path

    def __repr__(self):
        return f"""{self.relative_path.with_suffix('')}"""

    def __eq__(self, other):
        if isinstance(other, Secret):
            return self.path == other.path
        return self.path == other

    def __ne__(self, other):
        if isinstance(other, Secret):
            return self.path != other.path
        return self.path != other

    def __lt__(self, other):
        if isinstance(other, Secret):
            return self.path < other.path
        return self.path < other

    def __gt__(self, other):
        if isinstance(other, Secret):
            return self.path > other.path
        return self.path > other

    def __le__(self, other):
        if isinstance(other, Secret):
            return self.path <= other.path
        return self.path <= other

    def __ge__(self, other):
        if isinstance(other, Secret):
            return self.path >= other.path
        return self.path >= other

    @property
    def gpg_key_ids(self):
        """
        Return list of key IDs used for encrypting item
        """
        return self.directory.gpg_key_ids

    @property
    def relative_path(self):
        """
        Return secret relative path in password store
        """
        return self.path.relative_to(self.directory.password_store)

    @property
    def data(self):
        """
        Return raw data from password store

        Loads encrypted data as side effect if not available, returns bytes
        """
        if self.__contents__ is None:
            self.load()
        return self.__contents__

    @property
    def text(self):
        """
        Load secret contents as utf-8 text
        """
        if self.__contents__ is None:
            self.load()
        try:
            return str(self.__contents__, 'utf-8').rstrip('\n')
        except Exception as error:
            raise PasswordStoreError(f'Error parsing {self} as string') from error

    @property
    def lines(self):
        """
        Return raw data from password store as utf-8 strings

        Loads encrypted data as side effect if not available
        """
        return self.text.splitlines()

    @property
    def password(self):
        """
        Return password from first line of secret data loaded as string

        This uses the pass password-store convention of storing multi-line data with password
        on first line and other details on following lines
        """
        try:
            return self.lines[0]
        except Exception as error:
            raise PasswordStoreError(f'Error looking up password from {self}') from error

    def load(self):
        """
        Load secret contents to self.__contents__ as bytes
        """
        cmd = ('gpg', '-o-', '-d', str(self.path))
        try:
            self.__contents__ = None
            res = run(cmd, stdout=PIPE, stderr=PIPE, check=True)
        except Exception:
            reset_tty()

        self.__contents__ = res.stdout

    def save(self, data):
        """
        Save password entry, encrypting it with correct PGP keys

        Data can be either bytes or string
        """
        if isinstance(data, str):
            data = bytes(f'{data.rstrip()}\n', PASSWORD_ENTRY_ENCODING)

        if self.path.is_dir():
            raise PasswordStoreError(f'Error saving {self.path}: is a directory')

        if not self.path.parent.is_dir():
            self.path.parent.mkdir(parents=True)

        backup = self.path.with_suffix(f'{self.path.suffix}.tmp')
        if self.path.is_file():
            self.path.rename(backup)

        tmp_fd, filename = mkstemp(prefix='pass-', suffix='.tmp')
        filename = Path(filename)
        try:
            with open(tmp_fd, 'wb') as filedescriptor:
                filedescriptor.write(data)
            recipient_list = list(chain(*[['-r', key_id] for key_id in self.gpg_key_ids]))
            cmd = [
                'gpg',
                '-e',
                '-o', str(self.path)
            ] + recipient_list + [str(filename)]
            res = run(cmd, stdout=PIPE, stderr=PIPE, check=True)
            if res.returncode != 0:
                raise PasswordStoreError(f'Error saving {self}: {res.stderr}')
        finally:
            self.__contents__ = None
            if backup.is_file():
                backup.unlink()
            if filename.is_fifo():
                print('remove', filename)
                filename.unlink()
            reset_tty()

    def save_from_file(self, path):
        """
        Encrypt file to secret
        """
        with open(path, 'rb') as filedescriptor:
            data = filedescriptor.read()
        self.save(data)
