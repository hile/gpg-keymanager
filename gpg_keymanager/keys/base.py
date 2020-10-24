"""
Common base classes for GPG key processing
"""

from collections.abc import MutableSequence

from ..exceptions import PGPKeyError


class GPGItemCollection(MutableSequence):
    """
    List of gpg data items
    """
    def __init__(self, **kwargs):
        self.__items__ = kwargs.get('keys', [])
        self.__gpg_args__ = []
        self.__loaded__ = self.__items__ != []
        self.__iter_items__ = None

    def __iter__(self):
        if not self.is_loaded:
            self.load()
        return self

    def __next__(self):
        if self.__iter_items__ is None:
            if not self.is_loaded:
                self.load()
            self.__iter_items__ = iter(self.__items__)
        try:
            return next(self.__iter_items__)
        except StopIteration:
            self.__iter_items__ = None
            raise StopIteration

    def __delitem__(self, index):
        """
        Remove key from collection
        """
        del self.__items__[index]

    def __getitem__(self, item):
        """
        Get key from collection
        """
        if not self.is_loaded:
            self.load()
        if isinstance(item, int):
            try:
                return self.__items__[item]
            except IndexError as error:
                raise PGPKeyError(error)
        return self.get(item)

    def __len__(self):
        """
        Return number of keys
        """
        if not self.is_loaded:
            self.load()
        return len(self.__items__)

    def __setitem__(self, index, key):
        """
        Set key to collection
        """
        self.__items__[index] = key

    def __remove_key__(self, key_id):
        """
        Remove key by ID from loaded identities

        This does NOT remove key from keyring or filesystem
        """
        for index, key in enumerate(self.__items__):
            if key.match_key_id(key_id):
                del self.__items__[index]

    @property
    def is_loaded(self):
        """
        Property to check if PGP key password store is loaded
        """
        return self.__loaded__

    def clear(self):
        """
        Clear key collection and set loaded status to False
        """
        self.__items__ = []
        self.__iter_items__ = None
        self.__loaded__ = False

    # pylint: disable=arguments-differ
    def count(self, item):
        """
        Count number of keys
        """
        return self.__items__.count(item)

    def insert(self, index, value):
        """
        Insert key to collection
        """
        self.__items__.insert(index, value)

    def load(self):
        """
        Load keys to collection

        Must be implemented in child class
        """
        raise NotImplementedError

    def get(self, value):
        """
        Get item from collection

        Must be implemented in child class
        """
        raise NotImplementedError
