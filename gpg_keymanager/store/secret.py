"""
Password store secret item
"""

import shutil

from itertools import chain
from operator import eq, ge, gt, le, lt, ne
from pathlib import Path
from subprocess import run, PIPE, CalledProcessError
from tempfile import mkstemp, NamedTemporaryFile

from ..editor import Editor
from ..exceptions import PasswordStoreError, KeyManagerError

from .constants import PASSWORD_ENTRY_ENCODING


class Secret:
    """
    Encrypted secret in password store
    """
    def __init__(self, store, parent, path):
        self.__contents__ = None
        self.store = store
        self.parent = parent

        # Make path in store relative to store root
        try:
            Path(path).relative_to(self.store)
        except ValueError:
            path = self.store.joinpath(path)
        self.path = path

    def __repr__(self):
        return str(self.relative_path.with_suffix(''))

    def __compare__(self, operator, other):
        """
        Rick comparison with specified operator
        """
        if isinstance(other, Secret):
            return operator(self.path, other.path)
        return operator(str(self), str(other))

    def __eq__(self, other):
        return self.__compare__(eq, other)

    def __ne__(self, other):
        return self.__compare__(ne, other)

    def __lt__(self, other):
        return self.__compare__(lt, other)

    def __gt__(self, other):
        return self.__compare__(gt, other)

    def __le__(self, other):
        return self.__compare__(le, other)

    def __ge__(self, other):
        return self.__compare__(ge, other)

    @property
    def gpg_key_ids(self):
        """
        Return list of key IDs used for encrypting item
        """
        return self.parent.gpg_key_ids

    @property
    def relative_path(self):
        """
        Return secret relative path in password store
        """
        return self.path.relative_to(self.parent.password_store)

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
        except ValueError as error:
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
        if not self.lines:
            raise PasswordStoreError('No text lines in secret data')
        return self.lines[0]

    def __get_gpg_file_contents__(self):
        """
        Return contents of specified PGP file with PGP CLI command
        """
        try:
            cmd = ('gpg', '-o-', '-d', str(self.path))
            res = run(cmd, stdout=PIPE, stderr=PIPE, check=True)
            return res.stdout
        except CalledProcessError as error:
            raise PasswordStoreError(f'Error loading secret {self.path}: {error}') from error

    def load(self):
        """
        Load secret contents to self.__contents__ as bytes
        """
        self.__contents__ = self.__get_gpg_file_contents__()

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
            shutil.copyfile(self.path, backup)
            self.path.unlink()

        tmp_fd, filename = mkstemp(prefix='pass-', suffix='.tmp')
        filename = Path(filename)
        try:
            with open(tmp_fd, 'wb') as filedescriptor:
                filedescriptor.write(data)
            recipient_list = list(chain(*[['-r', key_id] for key_id in self.gpg_key_ids]))
            cmd = ['gpg', '-e', '-o', str(self.path)] + recipient_list + [str(filename)]
            res = run(cmd, stdout=PIPE, stderr=PIPE, check=True)
            if res.returncode != 0:
                raise PasswordStoreError(f'Error saving {self}: {res.stderr}')
            self.__contents__ = data
        finally:
            self.__contents__ = None
            if backup.is_file():
                backup.unlink()

    def save_from_file(self, path):
        """
        Encrypt file to secret
        """
        with open(path, 'rb') as filedescriptor:
            data = filedescriptor.read()
        self.save(data)

    def edit(self):
        """
        Edit encrypted secret file with editor
        """
        editor = Editor()
        data = self.__get_gpg_file_contents__()
        with NamedTemporaryFile(prefix='pass.') as tmpfile:
            tmpfile.write(data)
            tmpfile.flush()
            try:
                editor.edit(tmpfile.name)
            except KeyManagerError as error:
                raise PasswordStoreError(f'Error editing secret {self.path}: {error}') from error
            self.save_from_file(tmpfile.name)
