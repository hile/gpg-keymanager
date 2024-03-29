#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Common base classes for GPG key processing
"""
from collections.abc import MutableSequence
from typing import Any, Iterator, List, Optional, Union

from ..exceptions import PGPKeyError


class GPGItemCollection(MutableSequence):
    """
    List of gpg data items
    """
    __gpg_args__: List[str]
    __loaded__: bool
    __iter_items__: List[Any]

    def __init__(self, **kwargs):
        self.__items__ = kwargs.get('keys', [])
        self.__gpg_args__ = []
        self.__loaded__ = self.__items__ != []
        self.__iter_items__ = None

    def __iter__(self) -> Iterator['GPGItemCollection']:
        if not self.is_loaded:
            self.load()
        return self

    def __next__(self) -> Any:
        if self.__iter_items__ is None:
            if not self.is_loaded:
                self.load()
            self.__iter_items__ = iter(self.__items__)
        try:
            return next(self.__iter_items__)
        except StopIteration as error:
            self.__iter_items__ = None
            raise StopIteration from error

    def __delitem__(self, index) -> None:
        """
        Remove key from collection
        """
        del self.__items__[index]

    def __getitem__(self, item: Union[int, str]) -> Any:
        """
        Get key from collection
        """
        if not self.is_loaded:
            self.load()
        if isinstance(item, int):
            try:
                return self.__items__[item]
            except IndexError as error:
                raise PGPKeyError(error) from error
        return self.get(item)

    def __len__(self) -> int:
        """
        Return number of keys
        """
        if not self.is_loaded:
            self.load()
        return len(self.__items__)

    def __setitem__(self, index: int, key: Any) -> None:
        """
        Set key to collection
        """
        self.__items__[index] = key

    def __remove_key__(self, key_id: int) -> None:
        """
        Remove key by ID from loaded identities

        This does NOT remove key from keyring or filesystem
        """
        for index, key in enumerate(self.__items__):
            if key.match_key_id(key_id):
                del self.__items__[index]

    @property
    def is_loaded(self) -> bool:
        """
        Property to check if PGP key password store is loaded
        """
        return self.__loaded__

    def clear(self) -> None:
        """
        Clear key collection and set loaded status to False
        """
        self.__items__ = []
        self.__iter_items__ = None
        self.__loaded__ = False

    # pylint: disable=arguments-differ
    def count(self, value) -> int:
        """
        Count number of keys
        """
        return self.__items__.count(value)

    def insert(self, index: int, value: Any) -> None:
        """
        Insert key to collection
        """
        self.__items__.insert(index, value)

    def load(self) -> None:
        """
        Load keys to collection

        Must be implemented in child class
        """
        raise NotImplementedError

    def get(self, value: Any) -> Any:
        """
        Get item from collection

        Must be implemented in child class
        """
        raise NotImplementedError


class FingerprintObject:
    """
    Generic key object with 'fingerprint' attribute used for sorting
    """
    fingerprint: Optional[str] = None

    def __repr__(self):
        return self.fingerprint if self.fingerprint else str(self.__class__)

    def __eq__(self, other: Union[str, 'FingerprintObject']) -> bool:
        if isinstance(other, str):
            return self.fingerprint == other
        return self.fingerprint == other.fingerprint

    def __ne__(self, other: Union[str, 'FingerprintObject']) -> bool:
        if isinstance(other, str):
            return self.fingerprint != other
        return self.fingerprint != other.fingerprint

    def __lt__(self, other: Union[str, 'FingerprintObject']) -> bool:
        print('__lt__', type(self), type(other))
        if isinstance(other, str):
            return self.fingerprint < other
        return self.fingerprint < other.fingerprint

    def __gt__(self, other: Union[str, 'FingerprintObject']) -> bool:
        if isinstance(other, str):
            return self.fingerprint > other
        return self.fingerprint > other.fingerprint

    def __le__(self, other: Union[str, 'FingerprintObject']) -> bool:
        if isinstance(other, str):
            return self.fingerprint <= other
        return self.fingerprint <= other.fingerprint

    def __ge__(self, other: Union[str, 'FingerprintObject']) -> bool:
        if isinstance(other, str):
            return self.fingerprint >= other
        return self.fingerprint >= other.fingerprint
