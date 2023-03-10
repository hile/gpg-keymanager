#
# Copyright (C) 2020-2023 by Ilkka Tuohela <hile@iki.fi>
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Unit tests for gpg_keymanager.keys.base module
"""
import pytest

from gpg_keymanager.exceptions import PGPKeyError
from gpg_keymanager.keys.base import GPGItemCollection

TEST_KEY = 'test item'
OTHER_KEY = 'other item'


class MockKey:
    """
    Mocked key item with match_key_id() method
    """
    def __init__(self, key_id):
        self.key_id = key_id

    def __repr__(self):
        return self.key_id

    def __eq__(self, other):
        return self.key_id == other

    def __ne__(self, other):
        return self.key_id != other

    def match_key_id(self, value):
        """
        Mock match_key_id() lookup for keys
        """
        return self.key_id == value


class LoadableCollection(GPGItemCollection):
    """
    Test base collection with load() and get() implemented
    """
    def load(self):
        """
        Dummy load method
        """
        self.__items__ = [MockKey(TEST_KEY), MockKey(OTHER_KEY)]

    def get(self, value):
        """
        Dummy get method
        """
        for item in self.__items__:
            if item == value or item.match_key_id(value):
                return item
        raise PGPKeyError(f'Error looking up {value}')


def test_gpg_item_collection_load_get():
    """
    Test load and get methods on dummy child class of GPGItemCollection
    """
    obj = LoadableCollection()
    assert obj.is_loaded is False
    assert list(obj) == [TEST_KEY, OTHER_KEY]
    assert obj[TEST_KEY] == TEST_KEY

    obj.__remove_key__(OTHER_KEY)
    assert obj.__items__ == [TEST_KEY]


def test_gpg_item_collection_properties():
    """
    Test properties of GPGItemCollection base class
    """
    obj = GPGItemCollection()
    assert obj.__items__ == []
    assert obj.__gpg_args__ == []
    assert obj.__iter_items__ is None

    # Would trigger load() which is not implemented
    with pytest.raises(NotImplementedError):
        list(obj)

    assert obj.__loaded__ is False
    assert obj.is_loaded is False
    assert obj.count(TEST_KEY) == 0

    obj.__items__.append(TEST_KEY)
    obj.__items__.extend([OTHER_KEY])
    obj.__loaded__ = True
    obj.__iter_items__ = iter([TEST_KEY, OTHER_KEY])
    assert obj.is_loaded is True

    assert obj[0] == TEST_KEY
    assert obj[1] == OTHER_KEY
    assert list(obj) == [TEST_KEY, OTHER_KEY]

    with pytest.raises(PGPKeyError):
        # pylint: disable=pointless-statement
        obj[2]

    assert next(obj) == TEST_KEY
    assert next(obj) == OTHER_KEY
    with pytest.raises(StopIteration):
        next(obj)

    obj[0] = OTHER_KEY
    del obj[1]
    assert len(obj) == 1
    assert obj[0] == OTHER_KEY

    obj.insert(0, TEST_KEY)
    assert list(obj) == [TEST_KEY, OTHER_KEY]

    obj.clear()
    assert obj.__items__ == []
    assert obj.__loaded__ is False
    assert obj.is_loaded is False


def test_gpg_item_collection_errors():
    """
    Test properties of GPGItemCollection base class
    """
    obj = GPGItemCollection()

    with pytest.raises(NotImplementedError):
        # pylint: disable=pointless-statement
        obj[TEST_KEY]

    with pytest.raises(NotImplementedError):
        obj.load()

    with pytest.raises(NotImplementedError):
        obj.get(TEST_KEY)

    with pytest.raises(NotImplementedError):
        len(obj)
