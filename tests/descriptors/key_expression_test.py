# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `KeyExpression`'s derivation at an index.

Issue btclib-org/btclib-wallet#383.

A `pub_key` that is a `bytes` subclass is sized by the bytes it holds,
whatever its `__len__` says. Issue btclib-org/bip32-descriptors#355.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS
from typing_extensions import override

from bip32_descriptors.bip32 import xpub_from_xprv
from bip32_descriptors.bip32.bip32 import rootxprv_from_seed
from bip32_descriptors.descriptors import KeyExpression, parse

TPRV = rootxprv_from_seed("0f" * 16, NETWORKS["testnet"].bip32_prv)
XPUB = xpub_from_xprv(TPRV)
_REFUSED = "invalid derivation index"


def _key(expression: str) -> tuple[KeyExpression, dict[str, str]]:
    """Return the key of `pkh(expression)` and the `prv_keys` of its parse."""
    prv_keys: dict[str, str] = {}
    descriptor = parse(f"pkh({expression})", "testnet", prv_keys)
    return descriptor.key_expressions[0], prv_keys


@pytest.mark.parametrize(
    "expression, index",
    [
        (f"{TPRV}/0/*", 0x80000000),
        (f"{TPRV}/*", 0x80000000),
        (f"{TPRV}/*h", -0x80000000 + 5),
        (f"{TPRV}/*", -1),
        (f"{TPRV}/*", 2**32),
    ],
)
def test_sec_refuses_an_index_out_of_range(expression: str, index: int) -> None:
    """`sec` refuses what `Descriptor.address` refuses, with its message."""
    key, prv_keys = _key(expression)
    with pytest.raises(BTClibValueError, match=_REFUSED):
        key.sec(index, "testnet", prv_keys)
    with pytest.raises(BTClibValueError, match=_REFUSED):
        parse(f"pkh({expression})", "testnet").address(index)


def test_sec_refuses_an_index_out_of_range_on_a_fixed_key() -> None:
    """A key with no wildcard refuses it too."""
    key, _ = _key("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
    assert not key.is_ranged
    with pytest.raises(BTClibValueError, match=_REFUSED):
        key.sec(0x80000000)


def test_sec_answers_at_the_ends_of_the_range() -> None:
    """The first and the last index of the range derive."""
    key, prv_keys = _key(f"{TPRV}/0/*")
    assert len(key.sec(0, "testnet", prv_keys)) == 33
    assert len(key.sec(0x7FFFFFFF, "testnet", prv_keys)) == 33


@pytest.mark.parametrize("index", [-1, 0x80000000])
def test_a_musig_refuses_an_index_out_of_range(index: int) -> None:
    """`sec`, `participant_keys` and `aggregate` refuse it, ranged or not."""
    first, _ = _key(f"{TPRV}/*")
    second, _ = _key(f"{TPRV}/1/*")
    fixed, _ = _key(f"{XPUB}")
    stepped, _ = _key(f"{XPUB}/1")
    cases = (
        ((first, second), None, True),
        ((fixed,), 0, True),
        ((fixed, stepped), None, False),
    )
    for participants, wildcard, ranged in cases:
        musig = KeyExpression(participants=participants, wildcard=wildcard)
        assert musig.is_ranged is ranged
        for call in (musig.sec, musig.participant_keys, musig.aggregate):
            with pytest.raises(BTClibValueError, match=_REFUSED):
                call(index, "testnet")


@pytest.mark.parametrize("index", ["1", None, b"\x01", 1.0, True, False, object()])
@pytest.mark.parametrize("ranged", [False, True])
def test_public_index_methods_refuse_a_non_integer(index: Any, *, ranged: bool) -> None:
    """Refuse non-integer indexes before deriving or comparing bounds."""
    expression = f"{XPUB}/*" if ranged else _key(XPUB)[0].sec(network="testnet").hex()
    descriptor = parse(f"tr({expression})", "testnet")
    calls = [
        getattr(descriptor, name)
        for name in (
            "script_pub_keys",
            "script_pub_key",
            "redeem_script",
            "address",
            "addresses",
            "provider",
            "expand",
            "expansion",
            "taproot_merkle_root",
            "taproot_leaf_scripts",
            "taproot_tree",
        )
    ]
    calls.extend(
        [
            lambda index: descriptor.satisfy({}, index),
            descriptor.key_expressions[0].sec,
        ]
    )
    for call in calls:
        with pytest.raises(BTClibTypeError, match="^invalid derivation index type:"):
            call(index)


def test_public_index_methods_accept_integer_subclasses() -> None:
    """Integer subclasses derive the same keys and scripts as plain ints."""

    class Index(IntEnum):
        ZERO = 0
        ONE = 1

    class Integer(int):
        pass

    for expression in (XPUB, f"{XPUB}/*"):
        descriptor = parse(f"pkh({expression})", "testnet")
        key = descriptor.key_expressions[0]
        indexes = [Index.ZERO, Integer(0)]
        if descriptor.is_ranged:
            indexes.extend([Index.ONE, Integer(1)])
        for index in indexes:
            assert descriptor.address(index) == descriptor.address(int(index))
            assert key.sec(index, "testnet") == key.sec(int(index), "testnet")


class _Says(bytes):
    """Bytes whose length says `n`, whatever they hold."""

    n = 0

    @override
    def __len__(self) -> int:
        return self.n


def _says(octets: bytes, n: int) -> bytes:
    """Return `octets` as bytes whose length says `n`."""
    says = _Says(octets)
    says.n = n
    return says


_SEC = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
_SEC65 = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


@pytest.mark.parametrize("length", [65, 1])
@pytest.mark.parametrize("sec", [_SEC, _SEC65], ids=["compressed", "uncompressed"])
def test_a_pub_key_is_sized_by_its_bytes(sec: bytes, length: int) -> None:
    """Built, and compressed or not, as its plain bytes are.

    Its length saying more or less than it holds changes nothing. Issue
    btclib-org/bip32-descriptors#355.
    """
    assert len(_says(sec, length)) == length
    key = KeyExpression(pub_key=_says(sec, length))
    plain = KeyExpression(pub_key=sec)
    assert key == plain
    assert key.is_compressed is plain.is_compressed
    assert str(key) == str(plain)


def test_a_pub_key_of_the_wrong_size_is_refused_whatever_its_length_says() -> None:
    """Refused for the size it holds, not for the one it claims.

    Issue btclib-org/bip32-descriptors#355.
    """
    with pytest.raises(BTClibValueError, match="length in bytes: 32$"):
        KeyExpression(pub_key=_says(_SEC[1:], 33))
