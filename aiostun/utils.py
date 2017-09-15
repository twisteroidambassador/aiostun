import stringprep
import unicodedata
import itertools
import time

from contextlib import contextmanager
from collections.abc import MutableMapping


def saslprep(instr):
    """Apply the SASLPrep StringPrep profile to `instr`.
    
    Raises ValueError if the output string would include illegal characters.
    
    References:
    https://tools.ietf.org/html/rfc4013.html
    https://tools.ietf.org/html/rfc3454
    """
    # ========== mapping ==========
    mapped = ''.join(' ' if stringprep.in_table_c12(c) else c
                     for c in instr
                     if not stringprep.in_table_b1(c))
    # ========== normalization ==========
    normed = unicodedata.normalize('NFKC', mapped)
    if not normed:  # return empty string early
        return normed
    # ========== prohibited output ==========
    if any(fn(c) for fn, c in itertools.product(
            (stringprep.in_table_c12,
             stringprep.in_table_c21,
             stringprep.in_table_c22,
             stringprep.in_table_c3,
             stringprep.in_table_c4,
             stringprep.in_table_c5,
             stringprep.in_table_c6,
             stringprep.in_table_c7,
             stringprep.in_table_c8,
             stringprep.in_table_c9),
            normed)):
        raise ValueError('Prohibited character in normalized string {!r}'
                         .format(normed))
    # ========== bidirectional characters ==========
    if any(stringprep.in_table_d1(c) for c in normed):
        if any(stringprep.in_table_d2(c) for c in normed):
            raise ValueError('Both RandALCat and LCat characters in normalized '
                             'string {!r}'.format(normed))
        if not (stringprep.in_table_d1(normed[0])
                and stringprep.in_table_d1(normed[-1])):
            raise ValueError('First and last characters not both RandALCat in '
                             'normalized string {!r}'.format(normed))

    return normed


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def bit_mask(length, shift=0):
    return (2 ** length - 1) << shift


def get_enum(enum_type, value):
    """Return enum_type(value), or value if enum_type does not contain value."""
    try:
        return enum_type(value)
    except ValueError:
        return value


class HoldExpiringMapping(MutableMapping):
    """A MutableMapping that supports timeouts on items, and a "hold" feature.

    This object is NOT THREAD SAFE!!! It is asyncio-safe, however.

    The add() method adds or replaces an item with an optional timeout. (
    Items added or replaced with [] access do not have timeouts.) Before any
    individual access to an item, its timeout is checked, and the item is
    removed if timeout has expired. Before potentially adding an item,
    timeouts of all items are checked.

    The hold() method is a context manager and is intended to be used with the
    "with" statement. The item is added when entering the context, and removed
    when exiting.

    Since modifying keys while iterating over a dict is bad business, and items
    may expire while iterating, all methods of iterating over this object makes
    a list instead of an iterator. This includes __iter__(), .keys(), .items(),
    .values().

    Equality tests between this object and something else only compares keys
    and values, not expiry times.
    """
    def __init__(self):
        self._data = dict()

    def _check_key_expiry(self, key):
        if (key in self._data
                and self._data[key][1] is not None
                and time.monotonic() >= self._data[key][1]):
            del self._data[key]

    def _check_all_keys_expiry(self):
        keys = list(self._data.keys())
        for key in keys:
            self._check_key_expiry(key)

    def __setitem__(self, key, value):
        self._check_all_keys_expiry()
        self._data[key] = (value, None)

    def __getitem__(self, key):
        self._check_key_expiry(key)
        return self._data[key][0]

    def __delitem__(self, key):
        self._check_key_expiry(key)
        del self._data[key]

    def __len__(self):
        self._check_all_keys_expiry()
        return len(self._data)

    def __iter__(self):
        self._check_all_keys_expiry()
        return list(self._data)

    def keys(self):
        self._check_all_keys_expiry()
        return list(self._data.keys())

    def items(self):
        self._check_all_keys_expiry()
        return list((k, self._data[k][0]) for k in self._data)

    def values(self):
        self._check_all_keys_expiry()
        return list(self._data[k][0] for k in self._data)

    def add(self, key, value, timeout=None):
        """Add or update self[key] to value, with optional timeout.

        If timeout is not None, then after timeout seconds self[key] will be
        deleted on access.
        """
        if timeout is not None:
            expire = time.monotonic() + timeout
        else:
            expire = None
        self._data[key] = (value, expire)
        self._check_all_keys_expiry()

    @contextmanager
    def hold(self, key, value):
        """Add key:value on entry, remove it on exit of context.

        If key is already in the dict, raises KeyError.
        Note: if key is removed while inside context, there will be an exception
        on exit.
        """
        if key in self:
            raise KeyError('key {!r} already in dict'.format(key))
        self[key] = value
        try:
            yield
        finally:
            del self[key]
