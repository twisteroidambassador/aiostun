import pytest
import asyncio
import time

from . import utils


def test_saslprep():
    before = 'The\u00ADM\u00AAtr\u2168'
    after = 'TheMatrIX'
    assert utils.saslprep(before) == after


def test_bit_mask():
    assert utils.bit_mask(3, 0) == 0b111
    assert utils.bit_mask(5, 3) == 0b11111000
    assert utils.bit_mask(2, 14) == 0xC000


def test_hold_expiring_mapping():
    m = utils.HoldExpiringMapping()
    m[1] = '1'
    m[2] = '2'
    assert m[1] == '1'
    assert m.get(1) == '1'
    assert 1 in m
    assert 2 in m
    assert m[2] == '2'
    assert 3 not in m
    with pytest.raises(KeyError):
        m[3]
    assert m.get(3) is None
    del m[2]
    assert 2 not in m

    with m.hold(4, '4'):
        assert m[4] == '4'
        assert m[1] == '1'
    assert 4 not in m
    with pytest.raises(KeyError):
        with m.hold(1, 'one'):
            pass

    m.add(5, '5')
    assert m[5] == '5'
    m.add(6, '6', 0.1)
    m.add(7, '7', 0.2)
    assert m[6] == '6'
    assert m[7] == '7'
    time.sleep(0.12)
    assert 6 not in m
    assert m[7] == '7'
    del m[7]
    assert 7 not in m
    time.sleep(0.1)
    m.add(8, '8', 0)
    assert 8 not in m

