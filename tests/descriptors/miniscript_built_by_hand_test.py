# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a `Miniscript` built by hand is refused for, and what it names.

A context the library does not define, a fragment it does not know, and
a subexpression whose context is not the node's. The first two are any
value a caller passes, so the refusal names none of it. Issues
btclib-org/bip32-descriptors#120, btclib-org/bip32-descriptors#130 and
btclib-org/bip32-descriptors#133.

Subexpressions given as no tuple, naming the type alone. Issue
btclib-org/bip32-descriptors#287.

Data sized by the bytes it holds, whatever a subclass's `__len__` says.
Issue btclib-org/bip32-descriptors#355.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import sha256
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors import parse
from bip32_descriptors.descriptors.descriptors import (
    MiniscriptDescriptor,
    WshDescriptor,
)
from bip32_descriptors.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    SpendContext,
    SpendingPath,
)
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript
from tests import says_length
from tests.secret_free import assert_secret_free

_C = PrvKeyData(3).pub.sec.hex()
_WIF = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
_RANDOM_HEX = "7e3d796f1b20eb42c57e4f6a0c6ecaf1879529ae1ad154cebf0ed79035de2901"


@pytest.mark.parametrize("context", [P2WSH, TAPSCRIPT])
def test_a_node_built_by_hand_in_one_context_is_built(context: str) -> None:
    """The control: the node `parse` reads, built field by field."""
    older = Miniscript("older", context, threshold=1)
    verify = Miniscript("v:", context, (Miniscript("1", context),))
    node = Miniscript("and_v", context, (verify, older))
    assert node == parse_miniscript("and_v(v:1,older(1))", context)


@pytest.mark.parametrize("unknown", [_WIF, _RANDOM_HEX])
def test_an_unknown_fragment_is_refused_without_its_text(unknown: str) -> None:
    """Text in the wrong field, a WIF among them, is not echoed."""
    node = parse_miniscript("1", TAPSCRIPT)
    with pytest.raises(BTClibValueError, match="^unknown miniscript fragment$") as e:
        replace(node, fragment=unknown)
    assert_secret_free(e.value, [unknown])


@pytest.mark.parametrize("context", [_WIF, _RANDOM_HEX])
def test_an_unknown_context_is_refused_without_its_text(context: str) -> None:
    """Unrefused, every rule would read it as the p2wsh context.

    Issues btclib-org/bip32-descriptors#120 and
    btclib-org/bip32-descriptors#133.
    """
    node = parse_miniscript("1", TAPSCRIPT)
    err_msg = r"^unknown spend context; it must be one of \['P2WSH', 'tapscript'\]$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        replace(node, context=context)
    assert_secret_free(e.value, [context])
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        parse_miniscript("1", context)
    assert_secret_free(e.value, [context])


@pytest.mark.parametrize("context", [_WIF, _RANDOM_HEX])
def test_parse_refuses_unknown_context_without_its_text(context: str) -> None:
    """An unknown context given to parse() is refused without echoing secrets."""
    err_msg = r"^unknown spend context; it must be one of \['P2WSH', 'tapscript'\]$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        parse_miniscript("1", context)
    assert_secret_free(e.value, [context])


# a fixed random value in each shape other than text, and the spelling of
# it a refusal could print
@pytest.mark.parametrize(
    "context,spelling",
    [
        (770907403214864877517, "770907403214864877517"),
        (bytes.fromhex(_RANDOM_HEX), bytes.fromhex(_RANDOM_HEX)),
    ],
)
def test_a_context_of_another_type_is_refused(
    context: Any, spelling: str | bytes
) -> None:
    """A context is text, and the refusal names its type alone."""
    node = parse_miniscript("1", TAPSCRIPT)
    err_msg = f"^invalid context type: {type(context).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg) as e:
        replace(node, context=context)
    assert_secret_free(e.value, [spelling])


# subexpressions of types other than a tuple, and the spelling of each a
# refusal could print; unrefused, the list of a node builds
@pytest.mark.parametrize(
    "fragment,subs,spelling",
    [
        ("and_v", 770907403214864877517, "770907403214864877517"),
        ("and_v", None, _RANDOM_HEX),
        ("and_v", _RANDOM_HEX, _RANDOM_HEX),
        ("and_v", bytes.fromhex(_RANDOM_HEX), bytes.fromhex(_RANDOM_HEX)),
        ("v:", [parse_miniscript("older(1)")], _RANDOM_HEX),
        ("and_v", [_RANDOM_HEX], _RANDOM_HEX),
    ],
    ids=["int", "None", "str", "bytes", "list", "list of text"],
)
def test_subexpressions_of_another_type_are_refused(
    fragment: str, subs: Any, spelling: str | bytes
) -> None:
    """They are a tuple, and the refusal names the type alone.

    After the fragment's type and value, a ``thresh()`` included, and
    before the keys. Issue btclib-org/bip32-descriptors#287.
    """
    err_msg = f"^invalid subs type: {type(subs).__name__}$"
    no_keys: tuple[Any, ...] = ()
    for keys in (no_keys, ("abc",)):
        with pytest.raises(BTClibTypeError, match=err_msg) as e:
            Miniscript(fragment, P2WSH, subs, keys)
        assert_secret_free(e.value, [spelling])
    with pytest.raises(BTClibTypeError, match=err_msg):
        Miniscript("thresh", P2WSH, subs, threshold=1)
    with pytest.raises(BTClibTypeError, match="^invalid fragment type: int$"):
        Miniscript(5, P2WSH, subs)  # type: ignore[arg-type]
    with pytest.raises(
        BTClibValueError, match="^unknown miniscript fragment$"
    ) as unknown:
        Miniscript(_RANDOM_HEX, P2WSH, subs)
    assert_secret_free(unknown.value, [_RANDOM_HEX])


def test_a_p2wsh_node_of_a_tapscript_subexpression_is_refused() -> None:
    """Its key would be written x-only into a p2wsh script.

    Built, ``wsh()`` of it would write a script whose text `parse` reads
    with the 33-byte key, so the descriptor would not round-trip.
    """
    tapscript = parse_miniscript(f"and_v(v:pk({_C}),older(1))", TAPSCRIPT)
    older = Miniscript("older", P2WSH, threshold=1)
    err_msg = "^a subexpression of and_v is not in P2WSH$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        Miniscript("and_v", P2WSH, (tapscript.subs[0], older))
    assert_secret_free(e.value, [_C, _C[2:]])
    p2wsh = parse_miniscript(f"and_v(v:pk({_C}),older(1))", P2WSH)
    descriptor = WshDescriptor(MiniscriptDescriptor(p2wsh))
    assert parse(str(descriptor)) == descriptor


def test_a_subexpression_of_another_context_is_refused_in_any_position() -> None:
    """A ``thresh()`` is checked past its first subexpression."""
    one = Miniscript("1", TAPSCRIPT)
    Miniscript("thresh", TAPSCRIPT, (one, one, one), threshold=1)
    err_msg = "^a subexpression of thresh is not in tapscript$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        Miniscript("thresh", TAPSCRIPT, (one, one, Miniscript("1")), threshold=1)
    assert_secret_free(e.value, [P2WSH])


@pytest.mark.parametrize("length", [33, 31])
def test_data_is_sized_by_its_bytes(length: int) -> None:
    """Built as its plain bytes are, and refused for the size it holds.

    Issue btclib-org/bip32-descriptors#355.
    """
    digest = bytes.fromhex(_RANDOM_HEX)
    assert len(says_length(digest, length)) == length
    node = Miniscript("sha256", P2WSH, data=says_length(digest, length))
    assert node == Miniscript("sha256", P2WSH, data=digest)
    with pytest.raises(BTClibValueError, match="takes 32 bytes of data, 31 given$"):
        Miniscript("sha256", P2WSH, data=says_length(digest[1:], 32))


def _with_data(node: Miniscript, data: bytes) -> Miniscript:
    """Return `node` built again, with `data` in place of the data it holds."""
    if node.data:
        return replace(node, data=data)
    return replace(node, subs=tuple(_with_data(sub, data) for sub in node.subs))


# a 20-byte hash for ``rawpkh()``, the data of its ``raw_pk_h``
_HASH160_HEX = "9a1c78a507689f6f54b847ad1cef1e614ee23f1e"


@pytest.mark.parametrize("length", [1, 33])
@pytest.mark.parametrize(
    "text,data",
    [
        (f"and_v(v:pk({_C}),sha256({_RANDOM_HEX}))", _RANDOM_HEX),
        (f"and_v(v:rawpkh({_HASH160_HEX}),pkh({_C}))", _HASH160_HEX),
    ],
    ids=["sha256", "rawpkh"],
)
def test_data_is_pushed_as_the_bytes_it_holds(
    text: str, data: str, length: int
) -> None:
    """The script, and the ``wsh()`` of it, are those of its plain bytes.

    `serialize` sizes a push by `len()`, so the data goes in as the bytes
    it holds. Issue btclib-org/bip32-descriptors#355.
    """
    plain = parse_miniscript(text, P2WSH)
    node = _with_data(plain, says_length(bytes.fromhex(data), length))
    assert bytes.fromhex(data) in plain.script()
    assert node.script() == plain.script()
    wsh = WshDescriptor(MiniscriptDescriptor(node))
    plain_wsh = WshDescriptor(MiniscriptDescriptor(plain))
    assert wsh.script_pub_key().script == plain_wsh.script_pub_key().script
    assert wsh.address() == plain_wsh.address()


@pytest.mark.parametrize("length", [1, 33])
def test_a_hash_lock_is_spent_as_the_bytes_it_holds(length: int) -> None:
    """Its spending paths and its satisfaction are those of its plain bytes.

    A path holds the digest as the bytes the node holds. Issue
    btclib-org/bip32-descriptors#355.
    """
    preimage = bytes(32)
    digest = sha256(preimage)
    plain = parse_miniscript(f"and_v(v:pk({_C}),sha256({digest.hex()}))", P2WSH)
    node = _with_data(plain, says_length(digest, length))
    paths = node.spending_paths
    assert paths == plain.spending_paths
    held = [data for path in paths for _, data in path.hashes]
    assert held == [digest]
    assert type(held[0]) is bytes
    signature = "30" * 71 + "01"
    spend = SpendContext(sha256_preimages={digest: preimage})
    witness = plain.satisfy({_C: signature}, spend)
    assert witness == [preimage, bytes.fromhex(signature)]
    assert node.satisfy({_C: signature}, spend) == witness


@pytest.mark.parametrize("length", [31, 33])
def test_a_spending_path_sizes_a_digest_by_its_bytes(length: int) -> None:
    """Built for a digest of 32 bytes, refused for one of 31, whatever it says.

    Issue btclib-org/bip32-descriptors#355.
    """
    digest = bytes(32)
    path = SpendingPath(hashes=(("sha256", says_length(digest, length)),))
    assert path == SpendingPath(hashes=(("sha256", digest),))
    with pytest.raises(BTClibValueError, match="takes 32 bytes of data$"):
        SpendingPath(hashes=(("sha256", says_length(digest[1:], 32)),))
