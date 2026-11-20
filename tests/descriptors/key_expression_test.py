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
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS

from bip32_descriptors.bip32 import xpub_from_xprv
from bip32_descriptors.bip32.bip32 import rootxprv_from_seed
from bip32_descriptors.descriptors import KeyExpression, parse, private_string
from bip32_descriptors.descriptors.descriptors import (
    MiniscriptDescriptor,
    PkhDescriptor,
    TrDescriptor,
    WpkhDescriptor,
    WshDescriptor,
)
from bip32_descriptors.descriptors.miniscript import P2WSH, Miniscript
from tests import says_length

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


_SEC = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
_SEC65 = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
# lengths a key says: below both SEC sizes, between them and above both
_LENGTHS = [1, 34, 66]
_KEYS = pytest.mark.parametrize(
    "sec", [_SEC, _SEC65], ids=["compressed", "uncompressed"]
)


@pytest.mark.parametrize("length", _LENGTHS)
@_KEYS
def test_a_pub_key_is_sized_by_its_bytes(sec: bytes, length: int) -> None:
    """Built, and compressed or not, as its plain bytes are.

    Its length saying more or less than it holds changes nothing. Issue
    btclib-org/bip32-descriptors#355.
    """
    assert len(says_length(sec, length)) == length
    key = KeyExpression(pub_key=says_length(sec, length))
    plain = KeyExpression(pub_key=sec)
    assert key == plain
    assert key.is_compressed is plain.is_compressed
    assert str(key) == str(plain)


def test_a_pub_key_of_the_wrong_size_is_refused_whatever_its_length_says() -> None:
    """Refused for the size it holds, not for the one it claims.

    Issue btclib-org/bip32-descriptors#355.
    """
    with pytest.raises(BTClibValueError, match="length in bytes: 32$"):
        KeyExpression(pub_key=says_length(_SEC[1:], 33))


def _pk(key: KeyExpression) -> Miniscript:
    """Return ``pk(key)`` in a p2wsh: ``c:pk_k(key)``."""
    return Miniscript("c:", P2WSH, (Miniscript("pk_k", P2WSH, keys=(key,)),))


def _timelocked(node: Miniscript) -> Miniscript:
    """Return ``and_v(v:node,older(1))``, which `parse` reads as a miniscript.

    A bare ``pk()`` it reads as the descriptor function instead.
    """
    older = Miniscript("older", P2WSH, threshold=1)
    return Miniscript("and_v", P2WSH, (Miniscript("v:", P2WSH, (node,)), older))


@pytest.mark.parametrize("length", _LENGTHS)
def test_a_miniscript_pushes_the_bytes_a_pub_key_holds(length: int) -> None:
    """The script, and a ``wsh()`` holding it, are those of its plain bytes.

    `serialize` sizes a push by `len()`, so the key goes in as the bytes
    it holds. Issue btclib-org/bip32-descriptors#355.
    """
    node = _pk(KeyExpression(pub_key=says_length(_SEC, length)))
    plain = _pk(KeyExpression(pub_key=_SEC))
    assert plain.script() == bytes.fromhex(f"21{_SEC.hex()}ac")
    assert node.script() == plain.script()
    wsh = WshDescriptor(MiniscriptDescriptor(_timelocked(node)))
    plain_wsh = WshDescriptor(MiniscriptDescriptor(_timelocked(plain)))
    assert wsh.script_pub_key().script == plain_wsh.script_pub_key().script
    assert wsh.address() == plain_wsh.address()


@pytest.mark.parametrize("length", _LENGTHS)
@_KEYS
def test_a_script_sig_pushes_the_bytes_a_pub_key_holds(sec: bytes, length: int) -> None:
    """A ``pkh()`` script_sig pushes the bytes the key holds, sized by them.

    Issue btclib-org/bip32-descriptors#355.
    """
    signature = b"\x01" * 71
    descriptor = PkhDescriptor(KeyExpression(pub_key=says_length(sec, length)))
    script_sig, _ = descriptor.satisfy({sec: signature})
    assert script_sig == bytes([71]) + signature + bytes([len(sec)]) + sec


@pytest.mark.parametrize("length", _LENGTHS)
def test_a_wif_is_found_under_the_x_only_hex_of_the_bytes_a_key_holds(
    length: int,
) -> None:
    """`private_string` looks the key up as its plain bytes.

    A key of 33 bytes is looked for under its x-only hex too, whatever its
    length says. Issue btclib-org/bip32-descriptors#355.
    """
    wif = b58.wif_from_prv_key(1)
    descriptor = WpkhDescriptor(KeyExpression(pub_key=says_length(_SEC, length)))
    wifs = {_SEC[1:].hex(): wif}
    assert private_string(descriptor, None, None, wifs) == f"wpkh({wif})"


@pytest.mark.parametrize("length", _LENGTHS)
def test_a_tr_of_an_x_only_pub_key_is_that_of_its_bytes(length: int) -> None:
    """Built, and its output, as the ``tr()`` of its plain bytes.

    Issue btclib-org/bip32-descriptors#355.
    """
    key = KeyExpression(pub_key=says_length(_SEC, length), x_only=True)
    descriptor = TrDescriptor(key)
    plain = TrDescriptor(KeyExpression(pub_key=_SEC, x_only=True))
    assert descriptor.script_pub_key().script == plain.script_pub_key().script
    assert descriptor.address() == plain.address()
