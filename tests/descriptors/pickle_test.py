# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `pickle.loads` refuses in a descriptor and in what it holds.

The cases of what CONTRIBUTING.md's *The public surface* says of an
object `pickle.loads` restores, each refusal quoting none of the field.
A key that is no point is taken in a `KeyExpression` and a `Miniscript`
node, as `miniscript.from_script` builds one, and refused in a
descriptor. A valid pickle restores the object it was written from, at
every protocol. Issue btclib-org/bip32-descriptors#363.
"""

from __future__ import annotations

import copy
import pickle
import re
from collections.abc import Callable
from dataclasses import dataclass, fields
from typing import Any

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData
from ecc.exceptions import EccValueError
from typing_extensions import override

from bip32_descriptors.bip32 import BIP32KeyOrigin, rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import miniscript, parse
from bip32_descriptors.descriptors.descriptors import (
    Descriptor,
    MultiA,
    RawLeaf,
    RawNode,
)
from bip32_descriptors.descriptors.key_expression import KeyExpression
from bip32_descriptors.descriptors.miniscript import Miniscript
from tests.secret_free import assert_secret_free

_K = PrvKeyData(1).pub.sec.hex()
_X = _K[2:]
_XPRV = rootxprv_from_seed("00" * 32)
_XPUB = xpub_from_xprv(_XPRV)
_XPUB2 = xpub_from_xprv(rootxprv_from_seed("01" * 32))
_RANDOM_HEX = "7e3d796f1b20eb42c57e4f6a0c6ecaf1879529ae1ad154cebf0ed79035de2901"
# a 0x02 key whose x is on no point of the curve
_NO_POINT = "02" + "00" * 32
_PROTOCOLS = range(pickle.HIGHEST_PROTOCOL + 1)

# a descriptor of every fragment, and of every leaf and key a tr() takes
_TEXTS = [
    f"pk({_K})",
    f"pkh([deadbeef/1h/2]{_XPUB}/0/*)",
    f"wpkh({_XPRV}/1h/*)",
    f"sh(wpkh({_K}))",
    f"sh(multi(1,{_K},{_XPUB}/0/*))",
    f"wsh(sortedmulti(1,{_K},{_XPUB}/0/*))",
    f"wsh(and_v(v:pk({_XPUB}/0/*),or_d(pk({_K}),sha256({'11' * 32}))))",
    f"wsh(thresh(1,pk({_K}),s:pk({_XPUB}/0/*)))",
    f"combo({_K})",
    "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)",
    "raw(51)",
    f"rawpkh({'00' * 20})",
    f"tr({_X})",
    f"tr({_XPUB}/0/*,{{pk({_XPUB2}/0/*),multi_a(1,{_XPUB}/1/*,{_XPUB2}/1/*)}})",
    f"tr({_X},{{and_v(v:pk({_XPUB}/0/*),older(1)),{{rawleaf(51,c0),raw(52)}}}})",
    f"tr({_X},rawnode({'22' * 32}))",
    f"tr(musig({_XPUB},{_XPUB2})/0/*)",
    f"rawtr({_XPUB}/0/*)",
    f"unused({_XPUB}/0)",
]


def _tr(text: str) -> Any:
    return parse(f"tr({text})")


def _wsh(text: str) -> Any:
    return parse(f"wsh({text})")


# the classes whose objects `pickle.loads` checks as it restores them
_RESTORED = (
    BIP32KeyOrigin,
    Descriptor,
    KeyExpression,
    Miniscript,
    MultiA,
    RawLeaf,
    RawNode,
)


def _objects(descriptor: Any) -> list[Any]:
    """Return the descriptor, then what it holds that pickle restores too."""
    found = [descriptor]
    for obj in found:
        for value in vars(obj).values():
            items = [value]
            while items:
                item = items.pop()
                if isinstance(item, tuple):
                    items += item
                elif isinstance(item, _RESTORED):
                    found.append(item)
    return found


@pytest.mark.parametrize("text", _TEXTS)
def test_a_pickle_restores_what_it_was_written_from(text: str) -> None:
    """At every protocol, the descriptor and each object it holds.

    The same class and fields, the same text and the same scripts, a key
    behind a hardened step derived with the `prv_keys` `parse` filed.
    """
    prv_keys: dict[str, str] = {}
    descriptor = parse(text, prv_keys=prv_keys)
    scripts = descriptor.script_pub_keys(prv_keys=prv_keys)
    for protocol in _PROTOCOLS:
        restored = pickle.loads(pickle.dumps(descriptor, protocol))  # noqa: S301
        assert type(restored) is type(descriptor)
        assert restored == descriptor
        assert str(restored) == str(descriptor)
        assert restored.script_pub_keys(prv_keys=prv_keys) == scripts
        for obj in _objects(descriptor):
            again = pickle.loads(pickle.dumps(obj, protocol))  # noqa: S301
            assert type(again) is type(obj)
            assert again == obj
            assert vars(again) == vars(obj)


def test_a_key_that_is_no_point_is_restored_in_a_node() -> None:
    """As `miniscript.from_script` builds it, and refused in a ``tr()``.

    With the refusal of the ``tr()``'s build.
    """
    node = miniscript.from_script(bytes.fromhex(f"21{_NO_POINT}ac"))
    for protocol in _PROTOCOLS:
        restored = pickle.loads(pickle.dumps(node, protocol))  # noqa: S301
        assert restored == node
        assert restored.script() == node.script()
    descriptor = _tr(_X)
    object.__setattr__(descriptor.internal_key, "pub_key", bytes.fromhex(_NO_POINT))
    with pytest.raises(EccValueError, match="^key 0: not a public key$"):
        pickle.loads(pickle.dumps(descriptor))  # noqa: S301


# a descriptor, the object in it given one forged field, that field, its
# forged value, and the refusal of the build
_FORGED: list[
    tuple[str, Callable[[], Any], Callable[[Any], Any], str, Any, Any, str]
] = [
    (
        "tr-internal-key-text",
        lambda: _tr(_X),
        lambda d: d,
        "internal_key",
        "garbage",
        BTClibTypeError,
        "invalid internal key type: str",
    ),
    (
        "tr-internal-key-none",
        lambda: _tr(_X),
        lambda d: d,
        "internal_key",
        None,
        BTClibTypeError,
        "invalid internal key type: NoneType",
    ),
    (
        "tr-internal-key-int",
        lambda: _tr(_X),
        lambda d: d,
        "internal_key",
        5,
        BTClibTypeError,
        "invalid internal key type: int",
    ),
    (
        "network",
        lambda: parse(f"wpkh({_K})"),
        lambda d: d,
        "network",
        5,
        BTClibTypeError,
        "invalid network type: int",
    ),
    (
        "key-pub-key-int",
        lambda: _tr(_X),
        lambda d: d.internal_key,
        "pub_key",
        int(_RANDOM_HEX, 16),
        BTClibTypeError,
        "invalid pub_key type: int",
    ),
    (
        "key-xkey",
        lambda: _tr(_XPUB),
        lambda d: d.internal_key,
        "xkey",
        _RANDOM_HEX,
        BTClibValueError,
        "invalid xkey: no extended public key and no placeholder",
    ),
    (
        "key-origin",
        lambda: _tr(f"[deadbeef/1]{_XPUB}"),
        lambda d: d.internal_key,
        "origin",
        _RANDOM_HEX,
        BTClibTypeError,
        "invalid origin type: str",
    ),
    (
        "origin-fingerprint",
        lambda: _tr(f"[deadbeef/1]{_XPUB}"),
        lambda d: d.internal_key.origin,
        "master_fingerprint",
        _RANDOM_HEX,
        BTClibTypeError,
        "invalid master_fingerprint type: str",
    ),
    (
        "origin-fingerprint-size",
        lambda: _tr(f"[deadbeef/1]{_XPUB}"),
        lambda d: d.internal_key.origin,
        "master_fingerprint",
        bytes.fromhex(_RANDOM_HEX),
        BTClibValueError,
        "invalid master fingerprint length: 32",
    ),
    (
        "participant",
        lambda: _tr(f"musig({_XPUB},{_XPUB2})"),
        lambda d: d.internal_key,
        "participants",
        (_RANDOM_HEX, _RANDOM_HEX),
        BTClibTypeError,
        "invalid participant type: str",
    ),
    (
        "node-subs",
        lambda: _wsh(f"and_v(v:pk({_K}),older(1))"),
        lambda d: d.inner.node.subs[0],
        "subs",
        (_RANDOM_HEX,),
        BTClibTypeError,
        "invalid subexpression type: str",
    ),
    (
        "node-data",
        lambda: _wsh(f"and_v(v:pk({_K}),sha256({'11' * 32}))"),
        lambda d: d.inner.node.subs[1],
        "data",
        bytes.fromhex(_RANDOM_HEX)[:31],
        BTClibValueError,
        "sha256 takes 32 bytes of data, 31 given",
    ),
    (
        "node-fragment",
        lambda: _wsh(f"and_v(v:pk({_K}),older(1))"),
        lambda d: d.inner.node.subs[1],
        "fragment",
        _RANDOM_HEX,
        BTClibValueError,
        "unknown miniscript fragment",
    ),
    (
        "multi-a-threshold",
        lambda: _tr(f"{_X},multi_a(1,{_XPUB},{_XPUB2})"),
        lambda d: d.tree,
        "threshold",
        _RANDOM_HEX,
        BTClibTypeError,
        "invalid threshold type: str",
    ),
    (
        "raw-leaf-script",
        lambda: _tr(f"{_X},rawleaf(51,c0)"),
        lambda d: d.tree,
        "script",
        _RANDOM_HEX,
        BTClibTypeError,
        "invalid leaf script type: str",
    ),
    (
        "raw-node-digest",
        lambda: _tr(f"{_X},rawnode({'22' * 32})"),
        lambda d: d.tree,
        "digest",
        b"\x00" + bytes.fromhex(_RANDOM_HEX),
        BTClibValueError,
        "256 bits digest expected",
    ),
]


@pytest.mark.parametrize(
    "build,target,name,value,error,refusal",
    [case[1:] for case in _FORGED],
    ids=[case[0] for case in _FORGED],
)
def test_a_pickle_holding_a_forged_field_is_refused(
    build: Callable[[], Any],
    target: Callable[[Any], Any],
    name: str,
    value: Any,
    error: type[Exception],
    refusal: str,
) -> None:
    """At every protocol, with the build's refusal, quoting no forged value.

    The field is forged where the pickle is written, which `pickle.loads`
    reads as any other. The control is the pickle of the same descriptor
    unforged, which restores it.
    """
    descriptor = build()
    assert pickle.loads(pickle.dumps(descriptor)) == descriptor  # noqa: S301
    object.__setattr__(target(descriptor), name, value)
    secrets: list[str | bytes] = [_RANDOM_HEX, bytes.fromhex(_RANDOM_HEX)]
    for protocol in _PROTOCOLS:
        forged = pickle.dumps(descriptor, protocol)
        with pytest.raises(error, match=f"^{re.escape(refusal)}$") as e:
            pickle.loads(forged)  # noqa: S301
        assert_secret_free(e.value, secrets)


class _Pickled:
    """Pickled as an object of `cls` restored from `state`, whatever it is."""

    def __init__(self, cls: type, state: object) -> None:
        self.cls = cls
        self.state = state

    @override
    def __reduce__(self) -> tuple[Any, ...]:
        return object.__new__, (self.cls,), self.state


# an object of each class `pickle.loads` checks, a descriptor among them
_VALID = [
    _tr(_X),
    _tr(_X).internal_key,
    _wsh(f"and_v(v:pk({_K}),older(1))").inner.node,
    MultiA(1, (_tr(_X).internal_key,)),
    RawLeaf(b"\x51"),
    RawNode(bytes(32)),
]


@pytest.mark.parametrize("valid", _VALID, ids=lambda valid: type(valid).__name__)
def test_a_pickle_state_of_another_shape_is_refused(valid: Any) -> None:
    """One that is no dictionary, and one without a field or with another.

    The control is the object's own state, which restores it.
    """
    state = dict(vars(valid))
    restored = pickle.loads(pickle.dumps(_Pickled(type(valid), state)))  # noqa: S301
    assert restored == valid
    with pytest.raises(BTClibTypeError, match="^invalid pickle state type: list$"):
        pickle.loads(pickle.dumps(_Pickled(type(valid), list(state))))  # noqa: S301
    first = next(iter(state))
    other_shapes = (
        {name: value for name, value in state.items() if name != first},
        {**state, _RANDOM_HEX: 1},
    )
    err_msg = f"^invalid pickle state: not the fields of {type(valid).__name__}$"
    for other in other_shapes:
        with pytest.raises(BTClibValueError, match=err_msg) as e:
            pickle.loads(pickle.dumps(_Pickled(type(valid), other)))  # noqa: S301
        assert_secret_free(e.value, [_RANDOM_HEX])


def test_a_pickle_of_a_node_holding_itself_is_refused() -> None:
    """Which a reader would walk without end.

    A node and a key holding themselves, and a ``tr()`` holding itself as
    its tree, at every protocol. A node holding one that holds it is
    refused when the inner one is restored, the outer one not restored
    yet.
    """
    node = _wsh(f"and_v(v:pk({_K}),older(1))").inner.node.subs[0]
    object.__setattr__(node, "subs", (node,))
    key = _tr(f"musig({_XPUB},{_XPUB2})").internal_key
    object.__setattr__(key, "participants", (key, key))
    descriptor = _tr(f"{_X},rawleaf(51,c0)")
    object.__setattr__(descriptor, "tree", (descriptor.tree, descriptor))
    outer = _wsh(f"and_v(v:pk({_K}),older(1))").inner.node
    object.__setattr__(outer.subs[0], "subs", (outer,))
    for forged, refusal in (
        (node, "an object holding itself"),
        (key, "an object holding itself"),
        (descriptor, "an object holding itself"),
        (outer, "an object not restored yet"),
    ):
        for protocol in _PROTOCOLS:
            with pytest.raises(
                BTClibValueError, match=f"^invalid pickle state: {refusal}$"
            ):
                pickle.loads(pickle.dumps(forged, protocol))  # noqa: S301


class _Rebuilt:
    """Pickled as a copy of `valid`, then given `state` holding the copy.

    `field` holds the copy itself, through the tuple `around` returns.
    """

    def __init__(
        self, valid: object, field: str, around: Callable[[object], tuple[Any, ...]]
    ) -> None:
        self.valid = valid
        self.field = field
        self.around = around

    @override
    def __reduce__(self) -> tuple[Any, ...]:
        state = {**vars(self.valid), self.field: self.around(self)}
        return copy.copy, (self.valid,), state


class _Built:
    """Pickled as an object `cls` builds from `args`."""

    def __init__(self, cls: type, args: tuple[Any, ...]) -> None:
        self.cls = cls
        self.args = args

    @override
    def __reduce__(self) -> tuple[Any, ...]:
        return self.cls, self.args


def test_a_second_state_for_an_object_restored_already_is_refused() -> None:
    """A node a copy restored, then given a state holding the node.

    At every protocol: the copy holds its fields when the second state
    is set. The control is the copy given its own state.
    """
    valid = _wsh(f"and_v(v:pk({_K}),older(1))").inner.node
    for protocol in _PROTOCOLS:
        unchanged = _Rebuilt(valid, "subs", lambda _: valid.subs)
        with pytest.raises(
            BTClibValueError, match="^invalid pickle state: an object restored already$"
        ):
            pickle.loads(pickle.dumps(unchanged, protocol))  # noqa: S301
        itself = _Rebuilt(valid, "subs", lambda me: (me, valid.subs[1]))
        with pytest.raises(
            BTClibValueError, match="^invalid pickle state: an object restored already$"
        ):
            pickle.loads(pickle.dumps(itself, protocol))  # noqa: S301


def test_a_key_reaching_itself_through_a_key_its_build_built_is_refused() -> None:
    """A ``musig()`` whose participant holds the ``musig()``.

    The participant is built by `KeyExpression` from the ``musig()`` not
    restored yet, which the build takes, before the ``musig()`` is given
    its state, at every protocol. It is refused before the build of the
    ``musig()``, which refuses a ``musig()`` participant too. The control
    is the participant built from a key restored.
    """
    musig = _tr(f"musig({_XPUB},{_XPUB2})").internal_key
    names = [item.name for item in fields(KeyExpression) if item.init]

    def built_from(key: object) -> _Built:
        args = {**vars(musig), "participants": (key, musig.participants[1])}
        return _Built(KeyExpression, tuple(args[name] for name in names))

    restored = pickle.loads(pickle.dumps(built_from(musig.participants[0])))  # noqa: S301
    assert restored == musig
    forged = _Pickled(KeyExpression, {})
    forged.state = {
        **vars(musig),
        "participants": (built_from(forged), musig.participants[1]),
    }
    for protocol in _PROTOCOLS:
        with pytest.raises(
            BTClibValueError, match="^invalid pickle state: an object holding itself$"
        ):
            pickle.loads(pickle.dumps(forged, protocol))  # noqa: S301


def test_a_field_the_build_computes_is_computed_again() -> None:
    """Whatever the pickle holds for it, at every protocol.

    A node's fields `__init__` does not take, each forged, as -1 where it
    holds an integer and as None otherwise, and all of them at once.
    """
    valid = _wsh(f"and_v(v:pk({_K}),older(1))").inner.node
    computed = [item.name for item in fields(Miniscript) if not item.init]
    assert computed
    for names in [[name] for name in computed] + [computed]:
        node = copy.copy(valid)
        for name in names:
            wrong = -1 if isinstance(getattr(node, name), int) else None
            object.__setattr__(node, name, wrong)
        for protocol in _PROTOCOLS:
            restored = pickle.loads(pickle.dumps(node, protocol))  # noqa: S301
            assert vars(restored) == vars(valid)


def test_a_copy_is_checked_as_a_pickle_is() -> None:
    """`copy.copy` restores through `__setstate__` too.

    The control is a copy of the unforged ``tr()``.
    """
    descriptor = _tr(_X)
    assert copy.copy(descriptor) == descriptor
    object.__setattr__(descriptor, "internal_key", _RANDOM_HEX)
    with pytest.raises(BTClibTypeError, match="^invalid internal key type: str$"):
        copy.copy(descriptor)


@dataclass(frozen=True, slots=True)
class _Slotted:
    """A dataclass whose field is a slot, which no `__dict__` holds."""

    value: int = 0


class _Plain:
    """A class that gives each class derived from it a `__dict__`."""


@dataclass(frozen=True, slots=True)
class _SlottedBesideDict(_Plain):
    """A dataclass whose field is a slot, beside the `__dict__` of `_Plain`."""

    value: int = 0


@pytest.mark.parametrize("cls", [_Slotted, _SlottedBesideDict])
def test_a_pickle_holding_an_object_of_slots_is_refused_by_the_build(
    cls: type,
) -> None:
    """Which the check of what is restored reads in its slots.

    A ``musig()`` participant that is no `KeyExpression`, with or
    without a `__dict__`, with the build's refusal, at every protocol.
    One whose slot is unset is refused as an object not restored yet.
    """
    key = _tr(f"musig({_XPUB},{_XPUB2})").internal_key
    state = {**vars(key), "participants": (_Pickled(cls, None),)}
    with pytest.raises(
        BTClibValueError, match="^invalid pickle state: an object not restored yet$"
    ):
        pickle.loads(pickle.dumps(_Pickled(KeyExpression, state)))  # noqa: S301
    object.__setattr__(key, "participants", (cls(), cls()))
    for protocol in _PROTOCOLS:
        forged = pickle.dumps(key, protocol)
        with pytest.raises(
            BTClibTypeError, match=f"^invalid participant type: {cls.__name__}$"
        ):
            pickle.loads(forged)  # noqa: S301


@pytest.mark.parametrize(
    "valid",
    [*_VALID, BIP32KeyOrigin("deadbeef", "m/1h/2")],
    ids=lambda valid: type(valid).__name__,
)
def test_a_pickle_with_no_state_never_calls_setstate(
    valid: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At every protocol: an object of no field set is restored as it was.

    The default pickling writes no state for it. The control is the
    pickle of `valid`, whose state reaches `__setstate__`, which here
    only records it.
    """
    calls: list[object] = []

    def recorded(_: object, state: object) -> None:
        calls.append(state)

    monkeypatch.setattr(type(valid), "__setstate__", recorded)
    empty = object.__new__(type(valid))
    for protocol in _PROTOCOLS:
        restored = pickle.loads(pickle.dumps(empty, protocol))  # noqa: S301
        assert type(restored) is type(valid)
        assert not vars(restored)
        assert not calls
        pickle.loads(pickle.dumps(valid, protocol))  # noqa: S301
        assert calls
        calls.clear()


def test_a_pickle_holding_one_tuple_through_many_is_read_at_once() -> None:
    """Each tuple once, though the paths through them double at each level.

    A path of a key holding such a tuple, refused by the build.
    """
    nested: tuple[Any, ...] = (0,)
    for _ in range(64):
        nested = (nested, nested)
    key = _tr(_XPUB).internal_key
    object.__setattr__(key, "der_path", nested)
    with pytest.raises(BTClibTypeError, match="^invalid derivation index type: tuple$"):
        pickle.loads(pickle.dumps(key))  # noqa: S301
