# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How a refusal shows the value it refuses, and that it shows no secret.

Section 7 of the btclib-org standard, *A refusal carries no secret*. The
helpers of `bip32_descriptors._refusal` first, then a refusal of each
kind a key in the wrong place can reach, fed one, with the secret-free
assertion over the exception and every one it chains (issue
btclib-org/bip32-descriptors#390).
"""

from __future__ import annotations

import hmac
import pickle
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import replace
from hashlib import shake_256
from io import BytesIO

import pytest
from base58_bech32.exceptions import Base58Bech32ValueError
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS
from btclib.script.script_pub_key import ScriptPubKey
from ecc.curves import CURVES
from ecc.exceptions import EccValueError
from typing_extensions import override

import bip32_descriptors
from bip32_descriptors._refusal import (
    _LONG_TYPE_NAMES,
    _label,
    _message_text,
    _position,
    _quoted,
    _relayed,
    _size,
    _type_name,
)
from bip32_descriptors.bip32 import (
    BIP32KeyData,
    BIP32KeyOrigin,
    assert_valid_hd_key_paths,
    derive,
    derive_from_account,
    derive_from_account_range,
    indexes_from_der_path,
    int_from_index_str,
    point_from_xkey,
    prv_keyinfo_from_xprv,
    rootxprv_from_seed,
    str_from_der_path,
    str_from_index_int,
    xpub_from_xprv,
)
from bip32_descriptors.bip32 import bip32 as bip32_module
from bip32_descriptors.descriptors import (
    KeyExpression,
    MiniscriptDescriptor,
    MultiA,
    MultiDescriptor,
    PkDescriptor,
    Provider,
    PrvKeys,
    Quorum,
    RawDescriptor,
    ShDescriptor,
    SpendingPath,
    TrDescriptor,
    WshDescriptor,
    at_index,
    infer_descriptor,
    parse,
    strip_checksum,
    wallet_policy,
    wallet_policy_descriptor,
)
from bip32_descriptors.descriptors import key_expression as ke
from bip32_descriptors.descriptors.compiler import compile_policy
from bip32_descriptors.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    _multi_fault,
    from_script,
)
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript
from tests.secret_free import assert_secret_free

KEY = shake_256(b"bip32-descriptors issue 390").digest(32)
SCALAR = int.from_bytes(KEY)
HEX = KEY.hex()
XPRV = rootxprv_from_seed(KEY)
XPUB = xpub_from_xprv(XPRV)
ACCOUNT = xpub_from_xprv(derive(XPRV, "m/44h/0h/0h"))
ROOT = BIP32KeyData.b58decode(XPRV)
# each spelling of the key a refusal could print, the decimal included
SPELLINGS: list[str | bytes] = [KEY, HEX, str(SCALAR), f"{SCALAR:x}", XPRV]


class _EqualToAll(int):
    """An int equal to every value, so that it is in any range."""

    @override
    def __eq__(self, _other: object) -> bool:
        return True

    __hash__ = int.__hash__


def test_an_int_equal_to_all_is_in_any_range() -> None:
    """By its own comparison, which is why `_exact_int` reads int's."""
    assert _EqualToAll(SCALAR) in range(-(10**16), 10**16)


class _NoLength:
    """A value whose `__len__` raises, which a description survives."""

    def __len__(self) -> int:
        raise RuntimeError(HEX)


@pytest.mark.parametrize(
    "value, shown",
    [
        (0, "0"),
        (3, "3"),
        (-1, "-1"),
        (10**16 - 1, "9999999999999999"),
        (10**16, "an int of 54 bits"),
        (-(10**16), "a negative int of 54 bits"),
        (True, "a bool"),
        ("3", "a str of length 1"),
        (SCALAR, f"an int of {SCALAR.bit_length()} bits"),
        (_EqualToAll(SCALAR), f"an int of {SCALAR.bit_length()} bits"),
    ],
    ids=[
        "zero",
        "index",
        "negative",
        "16 digits",
        "17 digits",
        "17 negative digits",
        "bool",
        "str",
        "scalar",
        "int equal to all",
    ],
)
def test_a_position_is_written_in_decimal_up_to_16_digits(
    value: object, shown: str
) -> None:
    """An index or a count is printed, and a key handed in its place is not."""
    assert _position(value) == shown
    assert_secret_free(BTClibValueError(_position(value)), SPELLINGS)


@pytest.mark.parametrize(
    "value, shown",
    [
        ("mainnet", "'mainnet'"),
        ("m" * 16, f"'{'m' * 16}'"),
        ("m" * 17, "a value of 17 characters"),
        (True, "True"),
        (False, "False"),
        (3, "an int of 2 bits"),
        (-1, "a negative int of 1 bits"),
        (SCALAR, f"an int of {SCALAR.bit_length()} bits"),
        (KEY, "a bytes of length 32"),
        (HEX, "a value of 64 characters"),
    ],
    ids=[
        "name",
        "16 characters",
        "17 characters",
        "true",
        "false",
        "int",
        "negative",
        "scalar",
        "bytes",
        "hex",
    ],
)
def test_a_refused_int_is_described_and_a_name_quoted(
    value: object, shown: str
) -> None:
    """Section 7 lets a refusal quote a short name, and no int it refuses."""
    assert _quoted(value) == shown
    assert_secret_free(BTClibValueError(_quoted(value)), SPELLINGS)


@pytest.mark.parametrize(
    "value, shown",
    [
        ("mainnet", "mainnet"),
        ("other", "'other'"),
        (HEX, "a value of 64 characters"),
        (KEY, "a bytes of length 32"),
        (SCALAR, f"an int of {SCALAR.bit_length()} bits"),
    ],
    ids=["label", "short", "hex", "bytes", "scalar"],
)
def test_a_label_is_written_only_where_the_package_holds_it(
    value: object, shown: str
) -> None:
    """Any other value is shown as `_quoted` shows it."""
    labels = ("mainnet", "testnet")
    assert _label(value, labels) == shown
    assert_secret_free(BTClibValueError(_label(value, labels)), SPELLINGS)


def test_a_label_written_is_the_package_s_own() -> None:
    """The element of the labels is returned, not the value handed over."""
    labels = ("mainnet",)
    value = b"mainnet".decode()
    assert _label(value, labels) is labels[0]


@pytest.mark.parametrize(
    "value, shown",
    [
        (SCALAR, f"an int of {SCALAR.bit_length()} bits"),
        (-SCALAR, f"a negative int of {SCALAR.bit_length()} bits"),
        (True, "a bool"),
        (HEX, "a str of length 64"),
        (KEY, "a bytes of length 32"),
        (object(), "an object"),
        (_NoLength(), "a _NoLength"),
        (1.5, "a float"),
    ],
    ids=["int", "negative", "bool", "str", "bytes", "object", "no length", "float"],
)
def test_a_value_is_described_by_its_type_and_length(value: object, shown: str) -> None:
    """Never by its digits or characters, and never raising."""
    assert _message_text(value) == shown
    assert_secret_free(BTClibValueError(_message_text(value)), SPELLINGS)


# the digits of the key, in numbers of 16 digits
_GROUPED = ", ".join(
    str(SCALAR)[start : start + 16] for start in range(0, len(str(SCALAR)), 16)
)
_KNOWN = (
    ("invalid key", "invalid key"),
    ("key {}: invalid index", "invalid index"),
    ("lengths [{,}] differ", "lengths differ"),
    ("a {brace} at {}", "a brace"),
)


@pytest.mark.parametrize(
    "caught, relayed",
    [
        ("invalid key", "invalid key"),
        ("key 3: invalid index", "invalid index"),
        ("key 007: invalid index", "invalid index"),
        (f"key {SCALAR}: invalid index", "invalid index"),
        ("key -1: invalid index", "a default"),
        ("key \N{ARABIC-INDIC DIGIT THREE}: invalid index", "a default"),
        ("key : invalid index", "a default"),
        (f"invalid key {HEX}", "a default"),
        ("key 3: invalid index and more", "a default"),
        (HEX, "a default"),
        ("lengths [2] differ", "lengths differ"),
        (f"lengths [{_GROUPED}] differ", "lengths differ"),
        ("lengths [2,3] differ", "a default"),
        ("lengths [] differ", "a default"),
        ("lengths [2, ] differ", "a default"),
        ("a {brace} at 3", "a brace"),
        ("a 7brace} at 3", "a default"),
    ],
    ids=[
        "fixed",
        "number",
        "leading zeros",
        "scalar",
        "sign",
        "not ascii",
        "no digit",
        "text after a fixed text",
        "text after a template",
        "hex",
        "list of one",
        "key in numbers of 16 digits",
        "list without spaces",
        "empty list",
        "list ending in a comma",
        "brace that is text",
        "brace as a number",
    ],
)
def test_a_caught_text_only_chooses_among_the_package_s_texts(
    caught: str, relayed: str
) -> None:
    """Nothing of the caught text is written: no number, no character.

    Each `{}` of a known text matches a number of ASCII digits, and each
    `{,}` such numbers joined by ", "; any other brace is text.
    """
    assert _relayed(BTClibValueError(caught), _KNOWN, "a default") == relayed
    assert_secret_free(BTClibValueError(relayed), SPELLINGS)


class _HostileError(BTClibValueError):
    """A refusal whose text is a str subclass, or which raises for it."""

    def __init__(self, text: str | None) -> None:
        super().__init__()
        self.text = text

    @override
    def __str__(self) -> str:
        if self.text is None:
            raise RuntimeError(HEX)
        return _Text(self.text)


class _Text(str):
    """A str whose comparison and length answer what a caller chooses."""

    __slots__ = ()

    @override
    def __eq__(self, _other: object) -> bool:
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize(
    "error, relayed",
    [
        (_HostileError("invalid key"), "invalid key"),
        (_HostileError(HEX), "a default"),
        (_HostileError(None), "a default"),
    ],
    ids=["str subclass", "str subclass equal to all", "text raising"],
)
def test_a_caught_text_is_read_as_an_exact_str(
    error: BTClibValueError, relayed: str
) -> None:
    """A text that claims to equal any other, or raises, chooses no text.

    An exact copy of it is what is compared; a refusal raising for its
    text is relayed as `default`.
    """
    assert _relayed(error, _KNOWN, "a default") == relayed


def test_a_label_is_chosen_by_an_exact_copy_of_the_value() -> None:
    """A value that claims to equal any label is no label, and is quoted."""
    assert _label(_Text("x"), ("mainnet",)) == "'x'"


def test_a_text_relayed_is_the_package_s_own() -> None:
    """The text paired with the known one is returned, not the text caught."""
    known = (("invalid key", "invalid key"),)
    caught = BTClibValueError(b"invalid key".decode())
    assert _relayed(caught, known, "a default") is known[0][1]


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: getattr(bip32_descriptors, HEX),
            "^module 'bip32_descriptors' has no attribute a value of 64 characters$",
        ),
        (
            lambda: BIP32KeyData.b58decode(f"{XPRV[:-1]}é"),
            "^non-ascii character in base58 string at position 110$",
        ),
        (
            lambda: BIP32KeyData.b58decode(f"{XPRV[:-1]}0"),
            "^Base58 string contains invalid characters$",
        ),
        (lambda: xpub_from_xprv(XPUB), "^not a private key$"),
        (lambda: prv_keyinfo_from_xprv(XPUB), "^not a private key$"),
        (lambda: derive(XPRV, SCALAR), r"^invalid index: not in 0\.\.2\*\*32-1$"),
        (
            lambda: derive(XPRV, f"m/{SCALAR}"),
            "^invalid derivation index: more than 10 digits$",
        ),
        (
            lambda: int_from_index_str(f"1{HEX[:20]}"),
            "^invalid derivation index: not ASCII decimal digits$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, SCALAR, 0, branches_0_1_only=False),
            "^invalid private derivation at branch level$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, 0, SCALAR),
            "^invalid private derivation at address index level$",
        ),
        (
            lambda: str_from_index_int(1, HEX),
            "^invalid hardening symbol: a value of 64 characters$",
        ),
        (
            lambda: derive_from_account_range(
                ACCOUNT, SCALAR, range(1), branches_0_1_only=True
            ),
            "^invalid private derivation at branch level$",
        ),
        (
            lambda: replace(ROOT, depth=SCALAR),
            "^invalid depth: an int of 254 bits$",
        ),
        (
            lambda: replace(ROOT, depth=-SCALAR),
            "^invalid depth: a negative int of 254 bits$",
        ),
        (
            lambda: replace(ROOT, index=SCALAR),
            "^invalid index: an int of 254 bits$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, -SCALAR, 0),
            r"^invalid branch number: a negative int of 254 bits not in \(0, 1\)$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, HEX, 0),  # type: ignore[arg-type]
            "^non-integer branch: a str of length 64$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, 0, HEX),  # type: ignore[arg-type]
            "^non-integer address index: a str of length 64$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, 0, 0, max_index=HEX),  # type: ignore[arg-type]
            "^non-integer max_index: a str of length 64$",
        ),
        (
            lambda: derive_from_account(ACCOUNT, 0, 0, max_index=-SCALAR),
            (
                "^invalid branch number: an int of 0 bits is higher than"
                r" a negative int of 254 bits\.$"
            ),
        ),
        (
            lambda: derive_from_account_range(ACCOUNT, -SCALAR, range(2)),
            r"^invalid branch number: a negative int of 254 bits not in \(0, 1\)$",
        ),
        (
            lambda: derive_from_account_range(ACCOUNT, KEY, range(2)),  # type: ignore[arg-type]
            "^non-integer branch: a bytes of length 32$",
        ),
        (
            lambda: derive_from_account_range(ACCOUNT, 0, range(2), max_index=XPRV),  # type: ignore[arg-type]
            "^non-integer max_index: a str of length 111$",
        ),
    ],
    ids=[
        "attribute",
        "non-ascii xkey",
        "xkey character",
        "xpub for an xprv",
        "xpub read as an xprv",
        "derivation index",
        "derivation path",
        "index digits",
        "branch",
        "address index",
        "hardening symbol",
        "branch of a range",
        "depth",
        "negative depth",
        "index",
        "negative branch",
        "non-integer branch",
        "non-integer address index",
        "non-integer max_index",
        "max_index below the branch",
        "negative branch of a range",
        "non-integer branch of a range",
        "non-integer max_index of a range",
    ],
)
def test_a_bip32_refusal_fed_a_key_prints_none_of_it(
    call: Callable[[], object], err_msg: str
) -> None:
    """A key passed in the wrong place is not in the refusal."""
    errors = (AttributeError, BTClibTypeError, BTClibValueError)
    with pytest.raises(errors, match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


@pytest.mark.parametrize(
    "call, err_msg",
    [
        (
            lambda: parse(f"pkh({XPRV}é)"),
            "^invalid descriptor character at position 115$",
        ),
        (
            lambda: parse(f"pkh({XPUB})").script_pub_keys(SCALAR),
            "^invalid derivation index: an int of 254 bits$",
        ),
        (
            lambda: parse(f"pkh({XPUB}/*)").index_of(b"\x00", -SCALAR),
            "^negative last_index: a negative int of 254 bits$",
        ),
        (
            lambda: parse(f"sh(multi({SCALAR},{XPUB}))"),
            r"^invalid multi\(\) threshold: more than 10 digits$",
        ),
        (
            lambda: parse(f"tr({XPUB},multi_a({SCALAR},{XPUB}))"),
            r"^invalid multi_a\(\) threshold: more than 10 digits$",
        ),
        (
            lambda: parse(f"pkh({XPRV}/{HEX})"),
            "^key 0: invalid derivation index$",
        ),
        (
            lambda: parse(f"tr(musig({XPRV},{HEX}))"),
            (
                "^key 1: musig[(][)]: x-only public keys are allowed in a taproot"
                " key expression only$"
            ),
        ),
        (
            lambda: parse(f"{HEX}({XPRV})"),
            "^top-level expression is not a valid descriptor function$",
        ),
        (
            lambda: parse(f"tr({HEX})"),
            "^key 0: not a public key$",
        ),
        (
            lambda: PkDescriptor(
                parse(f"tr(musig({XPRV},{ACCOUNT}))").key_expressions[0]
            ),
            r"^key 0: musig\(\) is only allowed in tr\(\) and rawtr\(\)$",
        ),
        (
            lambda: wallet_policy_descriptor(
                "pkh(@0/**)", [KeyExpression(xkey=XPUB)], SCALAR
            ),
            "^invalid multipath index: an int of 254 bits$",
        ),
        (
            lambda: parse_miniscript(f"older({SCALAR})"),
            r"^invalid older\(\) number: more than 10 digits$",
        ),
        (
            lambda: parse_miniscript(f"thresh({SCALAR % 2**60},pk({XPUB}))"),
            r"^invalid thresh\(\) threshold: an int of 60 bits of 1$",
        ),
        (
            lambda: parse_miniscript(f"{HEX}({XPUB})"),
            "^unknown miniscript fragment$",
        ),
        (
            lambda: from_script(b"\x20" + KEY + b"\x87"),
            "^not a miniscript: op code an int of 8 bits closes no fragment$",
        ),
        (
            lambda: compile_policy(f"older({SCALAR})"),
            r"^invalid older\(\) number: more than 10 digits$",
        ),
        (
            lambda: compile_policy(f"{HEX}(1)"),
            "^invalid policy: unknown call$",
        ),
        (
            lambda: parse(f"pkh({XPUB}/*)").script_pub_key(SCALAR),
            "^invalid derivation index: an int of 254 bits$",
        ),
        (
            lambda: at_index(parse(f"pkh({XPUB}/*)"), SCALAR),
            "^invalid derivation index: an int of 254 bits$",
        ),
        (
            lambda: from_script(b"\x4c\x40" + KEY),
            "^not a script: a push runs past its end$",
        ),
        (
            lambda: from_script(b"\x76\xa9\x14" + KEY[:20] + b"\x88\xac"),
            "^no public key for a hash160 the script holds$",
        ),
        (
            lambda: parse(f"wsh(sha256({HEX}))"),
            "^a sub-expression is not sane: witnesses without signature exist$",
        ),
    ],
    ids=[
        "descriptor character",
        "script index",
        "last index",
        "multi threshold",
        "multi_a threshold",
        "key path",
        "musig participant",
        "function",
        "no point",
        "key relayed",
        "multipath index",
        "older",
        "thresh threshold",
        "fragment",
        "script",
        "policy older",
        "policy call",
        "script index of one",
        "script index of a descriptor",
        "push past the end",
        "hash160 with no key",
        "insane hash",
    ],
)
def test_a_descriptor_refusal_fed_a_key_prints_none_of_it(
    call: Callable[[], object], err_msg: str
) -> None:
    """A key passed in the wrong place is not in the refusal."""
    with pytest.raises((BTClibValueError, EccValueError), match=err_msg) as e:
        call()
    assert_secret_free(e.value, SPELLINGS)


# a key whose hex is also an x coordinate, as this digest's is and
# `KEY`'s is not: only such a key is read as an x-only key and reaches
# the type check
X_ONLY = shake_256(b"bip32-descriptors issue 390\x00").digest(32)


def test_a_key_read_as_an_x_only_key_is_not_in_the_type_refusal() -> None:
    """The fragment that is no script is named by its type alone."""
    err_msg = "^not a miniscript script: a 'K', not a B$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        parse_miniscript(f"pk_h({X_ONLY.hex()})", TAPSCRIPT)
    assert_secret_free(e.value, [X_ONLY, X_ONLY.hex()])


def test_a_base58_text_not_known_is_refused_with_none_of_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A codec text none of `_B58_REFUSALS` starts is not relayed.

    The codec raises no such text today: one is planted, holding the key,
    where a later release of the codec could write it.
    """

    def planted(_address: object) -> bytes:
        raise Base58Bech32ValueError(f"a text no release writes yet: {HEX}")

    monkeypatch.setattr(bip32_module, "b58decode_check", planted)
    bip32_module._cached_base58_decode.cache_clear()
    with pytest.raises(BTClibValueError, match="^invalid base58 string$") as e:
        BIP32KeyData.b58decode(XPRV)
    bip32_module._cached_base58_decode.cache_clear()
    assert_secret_free(e.value, SPELLINGS)


# the keys of the BIP390 test vectors, one with each prefix
_C1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
_C2 = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
_X1 = _C1[2:]
# the generator, uncompressed
_G = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
_NO_POINT = "02" + "00" * 31 + "07"
_DEEP = "/".join(["0"] * 256)


def _forged_musig(**fields: object) -> Callable[[], object]:
    """Return the build of a ``tr()`` whose ``musig()`` has `fields` forged.

    The key is a copy of one `parse` read, made by pickling, which checks
    it as `KeyExpression` does; `object.__setattr__` then sets its fields
    without that check, so they reach the one ``tr()`` makes, which
    refuses with the same texts.
    """

    def build() -> object:
        musig = parse(f"tr(musig({_C1},{_C2}))").key_expressions[0]
        key: KeyExpression = pickle.loads(pickle.dumps(musig))  # noqa: S301
        for name, value in fields.items():
            object.__setattr__(key, name, value)
        return TrDescriptor(key)

    return build


def _read(text: str) -> Callable[[], object]:
    """Return the `parse` of a descriptor."""
    return lambda: parse(text)


def _read_miniscript(text: str, context: str | None = None) -> Callable[[], object]:
    """Return the `parse` of a miniscript, in P2WSH unless told otherwise."""
    if context is None:
        return lambda: parse_miniscript(text)
    return lambda: parse_miniscript(text, context)


# each template a refusal is relayed by, with a call that reaches it and
# the text written: `parse` where it reaches the template, the build of
# a ``tr()`` holding a forged musig() where `parse` writes no such key
_TEMPLATES: list[tuple[str, Callable[[], object], str]] = [
    (
        "invalid derivation index",
        _read(f"pkh({XPUB}/x)"),
        "key 0: invalid derivation index",
    ),
    (
        "invalid index",
        _read(f"pkh([deadbeef/4294967296]{XPUB})"),
        "key 0: invalid index",
    ),
    (
        "depth greater than 255",
        _read(f"pkh({XPUB}/{_DEEP})"),
        "key 0: depth greater than 255",
    ),
    (
        ke._SEVERAL_ORIGIN_ENDS,
        _read(f"pkh([deadbeef]]{XPUB})"),
        f"key 0: {ke._SEVERAL_ORIGIN_ENDS}",
    ),
    (
        ke._MISSING_ORIGIN_END,
        _read(f"pkh([deadbeef{XPUB})"),
        f"key 0: {ke._MISSING_ORIGIN_END}",
    ),
    (
        ke._ORIGIN_WITHOUT_START,
        _read(f"pkh(deadbeef]{XPUB})"),
        f"key 0: {ke._ORIGIN_WITHOUT_START}",
    ),
    (
        ke._MULTIPLE_MULTIPATH,
        _read(f"pkh({XPUB}/<0;1>/<2;3>)"),
        f"key 0: {ke._MULTIPLE_MULTIPATH}",
    ),
    (
        ke._ONE_ITEM_STEP,
        _read(f"pkh({XPUB}/<0>)"),
        f"key 0: {ke._ONE_ITEM_STEP}",
    ),
    (
        ke._UNDERIVABLE,
        _read(f"pkh({_C1}/0)"),
        f"key 0: {ke._UNDERIVABLE}",
    ),
    (ke._NO_KEY, _read("pkh()"), f"key 0: {ke._NO_KEY}"),
    (
        ke._X_ONLY_REFUSED,
        _read(f"pkh({_X1})"),
        f"key 0: {ke._X_ONLY_REFUSED}",
    ),
    (
        ke._UNCOMPRESSED_REFUSED,
        _read(f"wpkh({_G})"),
        f"key 0: {ke._UNCOMPRESSED_REFUSED}",
    ),
    (
        ke._MUSIG_IN_ORIGIN,
        _read(f"tr([deadbeef/0]musig({_C1},{_C2}))"),
        f"key 0: {ke._MUSIG_IN_ORIGIN}",
    ),
    (
        ke._MUSIG_CLOSES,
        _read(f"tr(musig(musig({_C1},{_C2}),{_C1}))"),
        f"key 0: {ke._MUSIG_CLOSES}",
    ),
    (
        ke._RANGED_PARTICIPANT,
        _read(f"tr(musig({XPUB}/*,{ACCOUNT})/0)"),
        f"key 2: {ke._RANGED_PARTICIPANT}",
    ),
    (
        ke._HARDENED_MUSIG_STEP,
        _read(f"tr(musig({XPUB},{ACCOUNT})/0h)"),
        f"key 2: {ke._HARDENED_MUSIG_STEP}",
    ),
    (
        ke._HARDENED_MUSIG_WILDCARD,
        _read(f"tr(musig({XPUB},{ACCOUNT})/*h)"),
        f"key 2: {ke._HARDENED_MUSIG_WILDCARD}",
    ),
    (
        ke._UNEXTENDED_PARTICIPANT,
        _read(f"tr(musig({_C1},{XPUB})/0)"),
        f"key 2: {ke._UNEXTENDED_PARTICIPANT}",
    ),
    (
        ke._MUSIG_ONE_MULTIPATH,
        _read(f"tr(musig({XPUB}/<0;1>,{ACCOUNT})/<2;3>)"),
        f"key 2: {ke._MUSIG_ONE_MULTIPATH}",
    ),
    (
        "Key is invalid due to whitespace",
        _read(f"pkh({_C1} )"),
        "key 0: Key is invalid due to whitespace",
    ),
    (
        "key is not valid",
        _read(f"wsh(multi(1,{XPUB},{XPUB}<0;1>/*))"),
        "key 1: key is not valid",
    ),
    (
        "Key path value is not a valid uint32",
        _read(f"pkh({XPUB}/<0;1>h/*)"),
        "key 0: Key path value is not a valid uint32",
    ),
    (
        "Key path value specifies multipath in a section where multipath is not allowed",
        _read(f"pkh([deadbeef/<0;1>]{XPUB})"),
        (
            "key 0: Key path value specifies multipath in a section where"
            " multipath is not allowed"
        ),
    ),
    (
        "invalid key origin fingerprint: 8 hex digits expected",
        _read(f"pkh([012345678]{XPUB})"),
        "key 0: invalid key origin fingerprint: 8 hex digits expected",
    ),
    (
        "not a key expression",
        _read(f"pkh([deadbeef]pk({_C1}))"),
        "key 0: not a key expression",
    ),
    (
        "invalid key expression",
        _read(f"tr(musig({XPUB}{{,{ACCOUNT})/x)"),
        "key 0: musig(): invalid key expression",
    ),
    (
        "invalid public key prefix for 33 bytes",
        _read(f"pkh(07{_C2[2:]})"),
        "key 0: invalid public key prefix for 33 bytes",
    ),
    (
        "invalid public key prefix for 65 bytes",
        _read(f"pkh(06{_G[2:]})"),
        "key 0: invalid public key prefix for 65 bytes",
    ),
    (
        "invalid public key length: {} characters",
        _read("pkh(00)"),
        "key 0: invalid public key length",
    ),
    (
        "invalid public key length in bytes: {}",
        _forged_musig(pub_key=b"\x02" * 10),
        "key 0: invalid public key length in bytes",
    ),
    (
        "invalid x-only key: no pub_key",
        _forged_musig(x_only=True),
        "key 0: invalid x-only key: no pub_key",
    ),
    (
        "invalid x-only key prefix: 0x03",
        _forged_musig(pub_key=bytes.fromhex(_C2), x_only=True),
        "key 0: invalid x-only key prefix: 0x03",
    ),
    (
        "invalid hardening symbol: h or ' expected",
        _forged_musig(hardening="H"),
        "key 0: invalid hardening symbol: h or ' expected",
    ),
    (
        "invalid wildcard: None, 0 or 2**31 expected",
        _forged_musig(wildcard=5),
        "key 2: invalid wildcard: None, 0 or 2**31 expected",
    ),
    (
        "invalid index: not in 0..2**32-1",
        _forged_musig(der_path=(2**32,)),
        "key 2: invalid index: not in 0..2**32-1",
    ),
    (
        "invalid musig() hardening symbol: h expected",
        _forged_musig(hardening="'"),
        "key 0: invalid musig() hardening symbol: h expected",
    ),
    (
        "a musig() takes no xkey",
        _forged_musig(xkey=XPUB),
        "key 0: a musig() takes no xkey",
    ),
    (
        "a pub_key takes no xkey",
        _forged_musig(pub_key=bytes.fromhex(_C1), xkey=XPUB),
        "key 0: a pub_key takes no xkey",
    ),
    (
        "a pub_key takes no participants",
        _forged_musig(pub_key=bytes.fromhex(_C1)),
        "key 0: a pub_key takes no participants",
    ),
    (
        "not a public key",
        _read(f"tr(musig({_C1},{_NO_POINT}))"),
        "key 1: musig(): not a public key",
    ),
    (
        "unbalanced brackets",
        _read(f"tr(musig({_C2}}}{{))"),
        "key 1: unbalanced brackets",
    ),
    (
        "Duplicated key path value an int of {} bits in multipath specifier",
        _read(f"pkh({XPUB}/<1;1>)"),
        "key 0: Duplicated key path value in multipath specifier",
    ),
    (
        "multipath steps of different length: [{,}]",
        _read(f"tr(musig({XPUB}/<0;1>,{ACCOUNT}/<0;1;2>,{XPUB}/<1;2;3;4>))"),
        "key 3: multipath steps of different length",
    ),
    (
        "musig() is only allowed in tr() and rawtr()",
        _read(f"pkh(musig({_C1},{_C2}))"),
        "key 0: musig() is only allowed in tr() and rawtr()",
    ),
    (
        "musig() takes at least one key",
        _read("tr(musig())"),
        "key 0: musig() takes at least one key",
    ),
    (
        "not a musig() derivation path: '/' expected",
        _read(f"tr(musig({_C1},{_C2})0)"),
        "key 2: not a musig() derivation path: '/' expected",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg",
    [(call, err_msg) for _, call, err_msg in _TEMPLATES],
    ids=[template for template, _, _ in _TEMPLATES],
)
def test_each_relayed_template_is_written_where_it_is_met(
    call: Callable[[], object], err_msg: str
) -> None:
    """The text of the template, after the key's position where it has one.

    Dropping the template from its table writes the default instead,
    which no row here expects.
    """
    with pytest.raises(BTClibValueError, match=f"^{re.escape(err_msg)}$"):
        call()


def test_every_relayed_template_is_one_some_call_meets() -> None:
    """A template no row reaches is one no code raises, and is dropped."""
    templates = {template for template, _, _ in _TEMPLATES}
    assert templates == {template for template, _ in ke._KEY_FAULTS}
    assert templates >= {written for _, written in ke._PATH_FAULTS}


# a reading of each refusal of a multisig node, which `parse` writes
# again from the threshold and the keys it read, numbers included
_MULTISIG_FAULTS = [
    (
        "invalid multi() threshold: more than 10 digits",
        _read_miniscript(f"multi(12345678901,{_C2})"),
        "invalid multi() threshold: more than 10 digits",
    ),
    (
        "invalid multi_a() threshold: more than 10 digits",
        _read_miniscript(f"multi_a(12345678901,{_X1})", TAPSCRIPT),
        "invalid multi_a() threshold: more than 10 digits",
    ),
    (
        "invalid k in k-of-n multi: an int of {} bits",
        _read_miniscript(f"multi(2,{_C2})"),
        "invalid k in k-of-n multi: an int of 2 bits",
    ),
    (
        "invalid k in k-of-n multi_a: an int of {} bits",
        _read_miniscript(f"multi_a(2,{_X1})", TAPSCRIPT),
        "invalid k in k-of-n multi_a: an int of 2 bits",
    ),
    (
        "invalid number of keys in multi: an int of {} bits",
        _read_miniscript(f"multi(1,{','.join([_C2] * 21)})"),
        "invalid number of keys in multi: an int of 5 bits",
    ),
    (
        "invalid number of keys in multi_a: an int of {} bits",
        _read_miniscript(f"multi_a(1,{','.join([_X1] * 1000)})", TAPSCRIPT),
        "invalid number of keys in multi_a: an int of 10 bits",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg",
    [(call, err_msg) for _, call, err_msg in _MULTISIG_FAULTS],
    ids=[fault for fault, _, _ in _MULTISIG_FAULTS],
)
def test_a_multisig_refusal_is_written_from_what_parse_read(
    call: Callable[[], object], err_msg: str
) -> None:
    """With the threshold or the number of keys, as the node writes it."""
    with pytest.raises(BTClibValueError, match=f"^{re.escape(err_msg)}$"):
        call()


@pytest.mark.parametrize(
    "threshold, count, fault",
    [
        (1, 21, "invalid number of keys in multi: an int of 5 bits"),
        (2, 1, "invalid k in k-of-n multi: an int of 2 bits"),
        (1, 1, "invalid multi() threshold"),
    ],
    ids=["keys", "threshold", "neither"],
)
def test_a_multisig_fault_is_the_first_check_its_numbers_fail(
    threshold: int, count: int, fault: str
) -> None:
    """The number of keys, then the threshold, and else the threshold's text."""
    assert _multi_fault("multi", threshold, count) == fault


@pytest.mark.parametrize(
    "error, err_msg",
    [
        (BTClibValueError, "^key 0: invalid key expression$"),
        (EccValueError, "^key 0: not a public key$"),
    ],
    ids=["value error", "not a point"],
)
def test_a_key_read_refused_with_a_text_not_known_relays_none_of_it(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception], err_msg: str
) -> None:
    """A text none of `_FAULTS` is refused with the default, not relayed.

    The reading raises no such text today: one is planted, holding the
    key, where a later change to what a key reading calls could write it.
    """

    def planted(*_args: object, **_kwargs: object) -> KeyExpression:
        raise error(f"a text no reading writes yet: {HEX}")

    monkeypatch.setattr(ke, "_read_key_on_a_path", planted)
    with pytest.raises((BTClibValueError, EccValueError), match=err_msg) as e:
        parse(f"pkh({XPUB})")
    assert_secret_free(e.value, SPELLINGS)


# the digits of a secret, each of the four numbers of 16 digits a relay
# that copied numbers out of a caught text would write together
_SECRET_DIGITS = str(SCALAR)[:64]
_SECRET_NUMBERS = ", ".join(
    _SECRET_DIGITS[start : start + 16] for start in range(0, 64, 16)
)


class _LyingKey(KeyExpression):
    """A key whose compression raises a refusal in the package's form."""

    @property
    @override
    def is_compressed(self) -> bool:
        err_msg = f"multipath steps of different length: [{_SECRET_NUMBERS}]"
        raise BTClibValueError(err_msg)


def test_a_relay_writes_no_number_a_caller_s_object_raised() -> None:
    """The caught text chooses the package's own text, and no more of it.

    A key of a caller's class raises, from a property the check of
    ``tr()`` reads, a text in the form of `_assert_same_length`'s, its
    numbers the digits of a secret.
    """
    read = parse(f"tr({XPUB})").key_expressions[0]
    key: KeyExpression = pickle.loads(pickle.dumps(read))  # noqa: S301
    object.__setattr__(key, "__class__", _LyingKey)
    err_msg = "^key 0: multipath steps of different length$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        TrDescriptor(key)
    assert_secret_free(e.value, [_SECRET_DIGITS, *SPELLINGS])


class _NamedForKey(type):
    """A metaclass answering a key's hex for the name of its classes."""

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        return HEX


class _RaisingForName(type):
    """A metaclass raising, with a key's hex, for the name of its classes."""

    @property
    @override
    def __name__(cls) -> str:  # type: ignore[override]
        raise RuntimeError(HEX)


class _Text64(str):
    """A str that claims to be a short identifier, and formats as the key."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return 1

    @override
    def isidentifier(self) -> bool:
        return True

    @override
    def __format__(self, _spec: str) -> str:
        return HEX


def _named(name: str) -> object:
    """Return an instance of a class named `name`."""
    kind = type("_Plain", (), {})
    kind.__name__ = name
    return kind()


class _LongList(list[int]):
    """A list whose length is whatever a caller says it is."""

    @override
    def __len__(self) -> int:
        return SCALAR % 10**15


class _Sized:
    """An object of no built-in type, with a length of its own."""

    def __len__(self) -> int:
        return SCALAR % 10**15


@pytest.mark.parametrize(
    "value, shown",
    [
        (_NamedForKey("_Hidden", (), {})(), "a _Hidden"),
        (_RaisingForName("_Hidden", (), {})(), "a _Hidden"),
        (_named(HEX), "a value of a type whose name has 64 characters"),
        (_named(_Text64(HEX)), "a value of a type whose name has 64 characters"),
        (_named("a b"), "a value of a type whose name has 3 characters"),
        (_LongList([1, 2, 3]), "a _LongList of length 3"),
        (_Sized(), "a _Sized"),
    ],
    ids=[
        "metaclass naming the key",
        "metaclass raising",
        "class named the key",
        "class named by a str subclass",
        "class named with a space",
        "list subclass with a length of its own",
        "object with a length of its own",
    ],
)
def test_a_value_is_described_by_what_its_type_is_and_holds(
    value: object, shown: str
) -> None:
    """Through a public call: the name `type` holds, and a built-in length.

    Neither the metaclass nor the class is asked for the name, nor the
    value for its length, and the description raises nothing.
    """
    err_msg = f"^non-integer branch: {re.escape(shown)}$"
    with pytest.raises(BTClibTypeError, match=err_msg) as e:
        derive_from_account(ACCOUNT, value, 0)  # type: ignore[arg-type]
    assert_secret_free(e.value, [*SPELLINGS, str(SCALAR % 10**15)])


class _LyingSubs(tuple[Miniscript, ...]):
    """A tuple whose length answers what a caller chooses."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return 7


class _LyingData(bytes):
    """Bytes whose length answers what a caller chooses."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return 5


@pytest.mark.parametrize(
    "build, err_msg",
    [
        (
            lambda: Miniscript(
                "thresh", subs=_LyingSubs((Miniscript("1"),)), threshold=9
            ),
            "invalid thresh() threshold: an int of 4 bits of 1",
        ),
        (
            lambda: Miniscript("sha256", data=_LyingData(KEY[:31])),
            "sha256 takes 32 bytes of data, 31 given",
        ),
    ],
    ids=["subexpressions", "data"],
)
def test_a_node_s_count_is_measured_by_its_built_in_type(
    build: Callable[[], object], err_msg: str
) -> None:
    """The number written is the tuple's or the bytes', not the value's own."""
    with pytest.raises(BTClibValueError, match=f"^{re.escape(err_msg)}$") as e:
        build()
    assert_secret_free(e.value, SPELLINGS)


def test_a_length_its_type_cannot_measure_is_not_written() -> None:
    """A released memoryview is described by its type alone."""
    view = memoryview(KEY)
    view.release()
    assert _message_text(view) == "a memoryview"
    assert _size(view) == "a memoryview"
    assert _size(KEY) == "32"


class _ReprKey(str):
    """A str whose length and repr are whatever a caller says they are."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return 1

    @override
    def __repr__(self) -> str:
        return HEX


def test_a_quoted_name_is_an_exact_copy_of_the_value() -> None:
    """Through a public call: the length and repr of str, not the value's."""
    err_msg = "^invalid hardening symbol: 'x'$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        str_from_index_int(1, _ReprKey("x"))
    assert_secret_free(e.value, SPELLINGS)


_X05 = b"\x05" + KEY


@pytest.mark.parametrize(
    "build",
    [
        lambda: KeyExpression(pub_key=_X05),
        lambda: replace(parse(f"pk({_C1})").key_expressions[0], pub_key=_X05),
    ],
    ids=["construction", "replace"],
)
def test_a_public_key_refused_for_its_prefix_carries_none_of_it(
    build: Callable[[], object],
) -> None:
    """Its text, args, attributes, notes and chain hold no byte of the key."""
    with pytest.raises(
        BTClibValueError, match="^invalid public key prefix for 33 bytes$"
    ) as e:
        build()
    assert_secret_free(e.value, [_X05, _X05.hex(), *SPELLINGS])


class _PartedText(str):
    """A descriptor text whose `partition` answers what a caller chooses."""

    __slots__ = ()

    @override
    def partition(self, _sep: str) -> tuple[str, str, str]:
        return (HEX, "#", "#")


class _PartedObject:
    """An object of no str type, with a `partition` of its own."""

    def partition(self, _sep: str) -> tuple[str, str, str]:
        return (HEX, "#", "#")


@pytest.mark.parametrize(
    "descriptor, err_msg",
    [
        (_PartedText("pk(00)#a#b"), "at position 8"),
        (_PartedText("pk(00)"), None),
        (_PartedObject(), None),
    ],
    ids=["str subclass", "str subclass with one part", "not a str"],
)
def test_a_second_hash_is_counted_on_the_text_itself(
    descriptor: object, err_msg: str | None
) -> None:
    """Its position is counted on an exact copy, and only where there is one.

    What a caller's `partition` answers decides whether a second '#' is
    refused, as it did, and not where it is.
    """
    expected = "more than one '#' in the descriptor"
    expected += "" if err_msg is None else f" {err_msg}"
    with pytest.raises(BTClibValueError, match=f"^{re.escape(expected)}$") as e:
        strip_checksum(descriptor)  # type: ignore[arg-type]
    assert_secret_free(e.value, SPELLINGS)


def test_the_hostile_values_answer_what_they_claim() -> None:
    """The control: each method above answers what a helper would meet."""
    with pytest.raises(RuntimeError):
        len(_NoLength())
    assert _Text("x") == "y"
    with pytest.raises(RuntimeError):
        _ = _RaisingForName("_Hidden", (), {}).__name__
    assert _NamedForKey("_Hidden", (), {}).__name__ == HEX
    text = _Text64("x")
    assert (len(text), text.isidentifier(), f"{text}") == (1, True, HEX)
    assert len(_LongList([1])) == len(_Sized()) == SCALAR % 10**15
    assert (len(_ReprKey("xy")), repr(_ReprKey("xy"))) == (1, HEX)
    assert (len(_LyingSubs()), len(_LyingData())) == (7, 5)


class _IteratedText(str):
    """A str whose iteration answers characters a caller chooses.

    Its `strip` answers itself, so that it reaches the decoding as it is.
    """

    __slots__ = ()

    @override
    def __iter__(self) -> Iterator[str]:
        return iter("\N{LATIN SMALL LETTER E WITH ACUTE}" * 3)

    @override
    def strip(self, _chars: str | None = None) -> str:
        return self


def test_a_non_ascii_character_is_counted_in_the_text_itself() -> None:
    """Its position is counted on an exact copy, not as the value iterates."""
    xkey = _IteratedText(XPRV[:-1] + "\N{LATIN SMALL LETTER E WITH ACUTE}")
    assert next(iter(xkey)) != xkey[0]
    assert xkey.strip() is xkey
    err_msg = "^non-ascii character in base58 string at position 110$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        BIP32KeyData.b58decode(xkey)
    assert_secret_free(e.value, SPELLINGS)


ACCOUNT_XPRV = derive(XPRV, "m/44h/0h/0h")
# what a call below holds that a refusal could print
_HELD = [*SPELLINGS, ACCOUNT_XPRV]
_PUB = BIP32KeyData.b58decode(XPUB).key


def _forged_multi(**fields: object) -> MultiDescriptor:
    """Return a parsed ``multi()``, `fields` forged.

    `object.__setattr__` skips the checks `MultiDescriptor` makes when
    built, which ``sh()`` makes again.
    """
    parsed = parse(f"multi(1,{XPRV})")
    multi: MultiDescriptor = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    for name, value in fields.items():
        object.__setattr__(multi, name, value)
    return multi


def _paths_of_forged(text: str, **fields: object) -> object:
    """Return the spending paths of a miniscript whose second sub is forged."""
    parsed = parse_miniscript(text)
    node: Miniscript = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    for name, value in fields.items():
        object.__setattr__(node.subs[1], name, value)
    return node.spending_paths


_PRV_NODE = f"pk({XPRV})"


@pytest.mark.parametrize(
    "call, err_msg",
    [
        pytest.param(
            lambda: replace(ROOT, parent_fingerprint=KEY[:4]),
            "zero depth with non-zero parent fingerprint",
            id="parent fingerprint",
        ),
        pytest.param(
            lambda: replace(ROOT, index=SCALAR % 2**32),
            "zero depth with non-zero index: an int of 31 bits",
            id="index at zero depth",
        ),
        pytest.param(
            lambda: replace(ROOT, version=KEY[:4]),
            "unknown extended key version",
            id="version",
        ),
        pytest.param(
            lambda: point_from_xkey(XPRV, CURVES["secp256r1"]),
            "ec/xpub version mismatch",
            id="curve",
        ),
        pytest.param(
            lambda: derive(XPRV, "m/0h", NETWORKS["mainnet"].slip132_p2wpkh_p2sh_pub),
            "invalid version forced on the extended key",
            id="forced version",
        ),
        pytest.param(
            lambda: derive(ACCOUNT_XPRV, "m" + 253 * "/0"),
            "final depth greater than 255: an int of 9 bits",
            id="final depth",
        ),
        pytest.param(
            lambda: derive_from_account(ACCOUNT_XPRV, 0, 5, max_index=3),
            "invalid address index: an int of 3 bits is higher than 3.",
            id="address index above max_index",
        ),
        pytest.param(
            lambda: compile_policy(f"and(older({HEX}),pk({XPRV}))"),
            "invalid older() number: digits expected",
            id="policy number",
        ),
        pytest.param(
            lambda: compile_policy(f"and(older(0),pk({XPRV}))"),
            "invalid older() value: an int of 0 bits",
            id="policy lock time",
        ),
        pytest.param(
            lambda: compile_policy(f"sha256({HEX}00)"),
            "invalid sha256() digest: 32 bytes of hex",
            id="policy digest",
        ),
        pytest.param(
            lambda: compile_policy(f"or({HEX})"),
            "or() takes two arguments",
            id="policy arguments",
        ),
        pytest.param(
            lambda: compile_policy("thresh(1" + f",pk({XPRV})" * 101 + ")"),
            "thresh() takes 1 to 100 arguments",
            id="policy thresh arguments",
        ),
        pytest.param(
            lambda: compile_policy(f"thresh(2,pk({XPRV}))"),
            "invalid thresh() threshold: an int of 2 bits of 1",
            id="policy thresh threshold",
        ),
        pytest.param(
            lambda: MultiA(2, parse(f"tr({XPRV})").key_expressions),
            "invalid k in k-of-n multi_a: an int of 2 bits",
            id="multi_a built",
        ),
        pytest.param(
            lambda: parse(f"wpkh({XPRV}/0/*)").satisfy({}, 1),
            "no signature for public key",
            id="no signature",
        ),
        pytest.param(
            lambda: parse(f"wpkh({XPRV})").satisfy({}, 1),
            "not a ranged descriptor: no script at index an int of 1 bits",
            id="index of a fixed descriptor",
        ),
        pytest.param(
            _forged_musig(der_path=(SCALAR,)),
            "key 2: invalid index: not in 0..2**32-1",
            id="musig step",
        ),
        pytest.param(
            lambda: parse(f"wsh(pk(02{HEX}))"),
            "key 0: not a public key",
            id="no point",
        ),
        pytest.param(
            lambda: WshDescriptor(
                MiniscriptDescriptor(from_script(b"\x21\x02" + KEY + b"\xac"))
            ),
            "key 0: not a public key",
            id="no point read from a script",
        ),
        pytest.param(
            lambda: MultiDescriptor(2, parse(f"pk({XPRV})").key_expressions),
            "invalid k in k-of-n multi: an int of 2 bits",
            id="multi built",
        ),
        pytest.param(
            lambda: parse(f"wsh(multi(1,{XPRV}))").satisfy({}),
            "0 signatures of 1, missing for keys 0",
            id="missing signatures",
        ),
        pytest.param(
            lambda: ShDescriptor(_forged_multi(threshold=-SCALAR)),
            "invalid multi() threshold: digits expected",
            id="sh multi negative threshold",
        ),
        pytest.param(
            lambda: ShDescriptor(_forged_multi(keys=())),
            "multi() takes a threshold and at least one key",
            id="sh multi no keys",
        ),
        pytest.param(
            lambda: ShDescriptor(_forged_multi(threshold=2)),
            "invalid k in k-of-n multi: an int of 2 bits",
            id="sh multi threshold",
        ),
        pytest.param(
            lambda: parse(f"tr({XPRV},multi_a(1))"),
            "multi_a() takes a threshold and at least one key",
            id="multi_a no keys",
        ),
        pytest.param(
            lambda: parse(f"tr({XPUB},multi_a(2,{XPRV}))"),
            "invalid k in k-of-n multi_a: an int of 2 bits",
            id="multi_a threshold",
        ),
        pytest.param(
            lambda: parse(f"sh(multi(2,{XPRV}))"),
            "invalid k in k-of-n multi: an int of 2 bits",
            id="multi threshold",
        ),
        pytest.param(
            lambda: ShDescriptor(RawDescriptor(script=KEY * 20)),
            "raw() inside sh() is 640 bytes, over the 520-byte limit",
            id="raw too large",
        ),
        pytest.param(
            lambda: wallet_policy(parse(f"sh(raw(20{HEX}ac))")),
            "raw() in a wallet policy: BIP388 has no template for it",
            id="policy raw",
        ),
        pytest.param(
            lambda: wallet_policy(parse(f"wpkh({XPRV}/0/*)")),
            "explicit derivation step before the wildcard",
            id="policy step",
        ),
        pytest.param(
            lambda: wallet_policy(parse(f"wpkh({XPRV})")),
            "not an unhardened wildcard, no wallet-policy placeholder",
            id="policy wildcard",
        ),
        pytest.param(
            lambda: wallet_policy(parse(f"tr(musig({XPRV},{XPRV})/*)")),
            "musig() repeats a participant",
            id="policy participant",
        ),
        pytest.param(
            lambda: wallet_policy(parse(f"tr(musig({XPRV}/*,{XPUB}/*))")),
            "derivation before aggregation is not allowed in a wallet policy",
            id="policy aggregation",
        ),
        pytest.param(
            lambda: wallet_policy(
                parse(f"tr(musig({XPRV},{ACCOUNT})/*,pk(musig({XPRV},{ACCOUNT})/*))")
            ),
            "musig() placeholder used more than once",
            id="policy musig twice",
        ),
        pytest.param(
            lambda: wallet_policy(parse(f"sh(multi(1,{XPRV}/*,{XPRV}/*))")),
            "a key expression used more than once",
            id="policy key twice",
        ),
        pytest.param(
            lambda: wallet_policy(
                parse(f"wpkh({XPRV}/0/0/*)"), parse(f"wpkh({XPRV}/1/*)")
            ),
            "not a receive/change chain step before the wildcard",
            id="pair step",
        ),
        pytest.param(
            lambda: wallet_policy(
                parse(f"wpkh({XPRV}/0/*)"), parse(f"wpkh({XPRV}/0/*)")
            ),
            "receive and change use the same chain step: an int of 0 bits",
            id="pair same step",
        ),
        pytest.param(
            lambda: wallet_policy(
                parse(f"tr(musig({XPRV}/0/*,{ACCOUNT}/0/*))"),
                parse(f"tr(musig({XPRV}/1/*,{ACCOUNT}/1/*))"),
            ),
            "derivation before aggregation is not allowed in a wallet policy",
            id="pair aggregation",
        ),
        pytest.param(
            lambda: wallet_policy(
                parse(f"tr(musig({XPRV},{ACCOUNT})/0/*)"),
                parse(f"tr(musig({XPRV},{XPUB})/1/*)"),
            ),
            "receive and change disagree on a musig() participant",
            id="pair participant",
        ),
        pytest.param(
            lambda: wallet_policy(
                parse(f"wpkh({XPRV}/0/*)"), parse(f"wpkh({ACCOUNT}/1/*)")
            ),
            "receive and change disagree on a key",
            id="pair key",
        ),
        pytest.param(
            lambda: wallet_policy_descriptor(
                "wpkh(@0/**)", parse(f"pk({XPRV}/*)").key_expressions
            ),
            "not a bare key-information entry",
            id="key information",
        ),
        pytest.param(
            lambda: wallet_policy_descriptor(
                "wpkh(@1/**)", parse(f"pk({XPRV})").key_expressions
            ),
            "key placeholder out of range: '@1/**'",
            id="placeholder",
        ),
        pytest.param(
            lambda: parse(f"tr(musig({XPRV}/<0;1>,{XPUB}/<0;1;2>))"),
            "key 2: multipath steps of different length",
            id="multipath lengths",
        ),
        pytest.param(
            lambda: parse(f"wpkh({XPRV}/<0;1>/*)"),
            "multipath key expression: use multipath_descriptors first",
            id="multipath key",
        ),
        pytest.param(
            lambda: wallet_policy_descriptor(
                f"sh(multi(1,@0/**,{XPRV}/<0;1>/*))",
                parse(f"pk({XPUB})").key_expressions,
            ),
            "multipath key expression: use multipath_descriptors first",
            id="multipath key in a template",
        ),
        pytest.param(
            lambda: parse(f"wpkh({XPRV}/<0;0>/*)"),
            "key 0: Duplicated key path value in multipath specifier",
            id="multipath duplicate",
        ),
        pytest.param(
            lambda: parse(f"tr(musig({XPRV},{XPUB})/<0;1>/*)"),
            "multipath key expression: use multipath_descriptors first",
            id="multipath musig",
        ),
        pytest.param(
            lambda: parse(f"tr(musig({XPRV},{XPUB})/0h/*)"),
            "key 2: musig() cannot have hardened derivation steps",
            id="musig hardened step",
        ),
        pytest.param(
            lambda: parse(f"tr(musig({XPRV},{XPUB})/{HEX})"),
            "key 2: musig(): invalid derivation index",
            id="musig path",
        ),
        pytest.param(
            lambda: parse(f"tr(musig({XPRV}/<0;1>,{XPUB}/<0;1>))"),
            "musig(): multipath key expression: use multipath_descriptors first",
            id="multipath participants",
        ),
        pytest.param(
            lambda: _paths_of_forged(f"and_v(v:{_PRV_NODE},1)", script_size=7),
            "1 holds a type or bounds its build does not compute",
            id="forged bounds",
        ),
        pytest.param(
            lambda: Miniscript("and_v", subs=(parse_miniscript(_PRV_NODE),)),
            "and_v takes 2 subexpressions, 1 given",
            id="arity",
        ),
        pytest.param(
            lambda: Miniscript(
                "pk_k", keys=parse(_PRV_NODE).key_expressions, threshold=1
            ),
            "pk_k takes no number: an int of 1 bits",
            id="number",
        ),
        pytest.param(
            lambda: Miniscript(
                "and_b", subs=(parse_miniscript(_PRV_NODE), Miniscript("1"))
            ).script(),
            "invalid miniscript",
            id="invalid script",
        ),
        pytest.param(
            lambda: parse_miniscript(_PRV_NODE).satisfy({}),
            "no satisfaction with the signatures, preimages and lock times given",
            id="no satisfaction",
        ),
        pytest.param(
            lambda: parse_miniscript(f"or_b(ll:0,sc:pk_k({XPRV}))").satisfy(
                {_PUB: "30" * 71 + "01"}
            ),
            (
                "no non-malleable satisfaction: every witness that would satisfy"
                " it is one a third party could rewrite"
            ),
            id="malleable satisfaction",
        ),
        pytest.param(
            lambda: parse_miniscript(f"and_v(v:{_PRV_NODE}," * 200 + "1" + ")" * 200),
            "miniscript too large for P2WSH: at least 3605 bytes of script",
            id="too large",
        ),
        pytest.param(
            lambda: parse_miniscript(f"q:{_PRV_NODE}"),
            "unknown miniscript wrapper: 'q'",
            id="wrapper",
        ),
        pytest.param(
            lambda: parse_miniscript(f"multi(1,{XPRV},,()"),
            "unbalanced brackets",
            id="multi brackets",
        ),
        pytest.param(
            lambda: parse_miniscript(f"and_v(v:multi(1),{_PRV_NODE})"),
            "multi() takes a threshold and at least one key",
            id="multi no keys",
        ),
        pytest.param(
            lambda: parse_miniscript(f"and_v(v:multi(1,{XPRV},),pk({XPUB}))"),
            "empty key in multi()",
            id="multi empty key",
        ),
        pytest.param(
            lambda: parse_miniscript(f"and_v(v:{_PRV_NODE},sha256({HEX}zz))"),
            "invalid sha256() hash: hex expected",
            id="hash digits",
        ),
        pytest.param(
            lambda: parse_miniscript(f"and_v(v:{_PRV_NODE},sha256({HEX}00))"),
            "invalid size: 33 bytes instead of 32",
            id="hash size",
        ),
        pytest.param(
            lambda: from_script(b"\x01\x01\x20" + KEY + b"\xac"),
            "non-minimal push: an op code pushes the same number",
            id="push of a number",
        ),
        pytest.param(
            lambda: from_script(b"\x4c\x20" + KEY + b"\xac", TAPSCRIPT),
            "non-minimal push of 32 bytes: op code an int of 7 bits",
            id="push",
        ),
        pytest.param(
            lambda: from_script(b"\x21\x02" + KEY + b"\xac\x69\x51"),
            "non-minimal VERIFY after op code an int of 8 bits",
            id="verify",
        ),
        pytest.param(
            lambda: from_script(b"\x20" + KEY + b"\xac"),
            "not a P2WSH public key: 32 bytes",
            id="key size",
        ),
        pytest.param(
            lambda: from_script(
                parse(f"pkh({XPUB})").script_pub_key().script,
                P2WSH,
                {hash160(_PUB): b"\x02" + KEY},
            ),
            "the key answered for a hash160 hashes to another",
            id="key for a hash",
        ),
        pytest.param(
            lambda: from_script(b"\x21\x02" + KEY + b"\xac\x00\x87"),
            "invalid thresh() threshold: an int of 0 bits",
            id="thresh zero",
        ),
        pytest.param(
            lambda: from_script(b"\x21\x02" + KEY + b"\xac\x52\x87"),
            "invalid thresh() threshold: an int of 2 bits of 1",
            id="thresh above",
        ),
        pytest.param(
            lambda: from_script(b"\x21\x02" + KEY + b"\xac\x6b\x51\x68"),
            "not a miniscript: op code an int of 7 bits before an OP_ENDIF",
            id="before OP_ENDIF",
        ),
        pytest.param(
            lambda: from_script(b"\x21\x02" + KEY + b"\xac\x7c\x51\x67\x51\x68"),
            "not a miniscript: op code an int of 7 bits before OP_ELSE",
            id="before OP_ELSE",
        ),
        pytest.param(
            lambda: from_script(KEY * 113),
            "script too large for P2WSH: 3616 bytes",
            id="script too large",
        ),
        pytest.param(
            lambda: from_script(b"\x20" + KEY + b"\x6b\x51", TAPSCRIPT),
            "not a miniscript: the script holds more than one expression",
            id="more than one expression",
        ),
        pytest.param(
            lambda: parse(f"wsh(and_v(v:{_PRV_NODE},0))"),
            "the miniscript is not satisfiable",
            id="not satisfiable",
        ),
        pytest.param(
            lambda: parse(f"wsh(and_v(v:{_PRV_NODE},or_i(1,1)))"),
            "a sub-expression is not sane: malleable witnesses exist",
            id="malleable",
        ),
        pytest.param(
            lambda: parse(
                f"wsh(and_v(v:{_PRV_NODE},and_v(v:older(1),older(4194305))))"
            ),
            (
                "a sub-expression is not sane: it mixes timelocks expressed in"
                " blocks and in seconds"
            ),
            id="timelocks",
        ),
        pytest.param(
            lambda: parse("wsh(" + "and_v(v:older(1)," * 101 + _PRV_NODE + ")" * 102),
            (
                "a sub-expression is not sane: satisfying it may exceed the"
                " resource limits"
            ),
            id="resource limits",
        ),
        pytest.param(
            lambda: _paths_of_forged(
                f"and_v(v:{_PRV_NODE},sha256({HEX}))", data=KEY[:31]
            ),
            "sha256 takes 32 bytes of data, 31 given",
            id="hash data of a node",
        ),
        pytest.param(
            lambda: SpendingPath(hashes=(("sha256", KEY[:20]),)),
            "sha256 takes 32 bytes of data",
            id="hash data of a path",
        ),
        pytest.param(
            lambda: (
                Miniscript(
                    "and_v", subs=(parse_miniscript(_PRV_NODE),) * 2
                ).spending_paths
            ),
            "invalid miniscript",
            id="paths of an invalid miniscript",
        ),
    ],
)
def test_a_refusal_of_a_call_holding_a_key_prints_none_of_it(
    call: Callable[[], object], err_msg: str
) -> None:
    """Its text, args, attributes, notes and chain hold none of the key.

    The key is the value refused, or one the call holds beside it, in a
    descriptor text, an extended key, a script or a mapping.
    """
    errors = (BTClibTypeError, BTClibValueError, EccValueError)
    with pytest.raises(errors, match=f"^{re.escape(err_msg)}$") as e:
        call()
    assert_secret_free(e.value, _HELD)


@pytest.mark.parametrize(
    "xkey, err_msg",
    [
        (XPRV, "the child private key is zero"),
        (XPUB, "the child public key is the point at infinity"),
    ],
    ids=["private", "public"],
)
def test_an_invalid_child_refusal_prints_none_of_its_parent(
    xkey: str, err_msg: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On the hmac whose left half cancels the parent key out.

    The refusal names the index, which is the caller's to choose, and
    nothing of the key.
    """
    offset = CURVES["secp256k1"].n - int.from_bytes(ROOT.key[1:])
    digest = offset.to_bytes(32) + ROOT.chain_code

    class _Forced:
        def digest(self) -> bytes:
            return digest

    monkeypatch.setattr(hmac, "new", lambda *_args, **_kwargs: _Forced())
    expected = f"invalid child index 0: {err_msg};"
    expected += " BIP32 mandates deriving the next index instead"
    with pytest.raises(BTClibValueError, match=f"^{re.escape(expected)}$") as e:
        derive(xkey, "m/0")
    assert_secret_free(e.value, _HELD)


# a value of each shape a class can be named the key by: a metaclass
# answering the key's hex, one raising it, and a class named by it
_HOSTILE_TYPES = {
    "metaclass naming the key": (_NamedForKey("_Hidden", (), {})(), "_Hidden"),
    "metaclass raising": (_RaisingForName("_Hidden", (), {})(), "_Hidden"),
    "class named the key": (_named(HEX), "a type whose name has 64 characters"),
}
# a public call per refusal of the package that names a type, with its
# text, `{}` the name. A refusal btclib or Python writes names the class
# as the class names itself, and is not the package's
_TYPE_REFUSALS: dict[str, tuple[Callable[[object], object], str]] = {
    "path element": (
        lambda v: derive(XPRV, [v]),  # type: ignore[list-item]
        "invalid derivation index type: {}",
    ),
    "xkey": (lambda v: KeyExpression(xkey=v), "invalid xkey type: {}"),  # type: ignore[arg-type]
    "threshold": (
        lambda v: MultiDescriptor(v, parse(f"pk({XPUB})").key_expressions),  # type: ignore[arg-type]
        "invalid threshold type: {}",
    ),
    "fragment": (Miniscript, "invalid fragment type: {}"),  # type: ignore[dict-item]
    "musig hardening": (
        lambda v: _forged_musig(hardening=v)(),
        "invalid hardening type: {}",
    ),
    "musig wildcard": (
        lambda v: _forged_musig(wildcard=v)(),
        "invalid wildcard type: {}",
    ),
    "musig step": (
        lambda v: _forged_musig(der_path=(v,))(),
        "invalid derivation index type: {}",
    ),
    "last_index": (
        lambda v: parse(f"pkh({XPUB}/*)").index_of(b"\0", v),  # type: ignore[arg-type]
        "invalid last_index type: {}",
    ),
}


@pytest.mark.parametrize("hostile", _HOSTILE_TYPES.values(), ids=_HOSTILE_TYPES)
@pytest.mark.parametrize("call, text", _TYPE_REFUSALS.values(), ids=_TYPE_REFUSALS)
def test_a_type_refused_is_named_as_type_holds_it(
    call: Callable[[object], object], text: str, hostile: tuple[object, str]
) -> None:
    """Neither the metaclass nor the class is asked for the name.

    A name longer than a refusal may quote is described by its length.
    """
    value, name = hostile
    err_msg = f"^{re.escape(text.format(name))}$"
    with pytest.raises(BTClibTypeError, match=err_msg) as e:
        call(value)
    assert_secret_free(e.value, SPELLINGS)


def test_a_long_name_written_whole_is_one_of_the_package_s_classes() -> None:
    """Each class of the package with a name past 16 characters, no other.

    Its exceptions excepted, which no refusal names by type.
    """
    module_names = [
        f"bip32_descriptors.{name}"
        for name in (
            "bip32.bip32",
            "bip32.der_path",
            "bip32.key_origin",
            "descriptors.compiler",
            "descriptors.descriptors",
            "descriptors.key_expression",
            "descriptors.miniscript",
        )
    ]
    long_names = {
        kind.__name__
        for module_name in module_names
        for kind in vars(sys.modules[module_name]).values()
        if isinstance(kind, type)
        and kind.__module__ == module_name
        and not issubclass(kind, BaseException)
        and len(kind.__name__) > 16
    }
    assert long_names == set(_LONG_TYPE_NAMES)
    named = _named("MiniscriptDescriptor")
    assert _type_name(named) is _LONG_TYPE_NAMES[0]


# a length a caller's class answers, past any a refusal could measure
_LIE = SCALAR % 10**19


def _lying(base: type, length: int = _LIE) -> type:
    """Return a subclass of `base` whose length is `length`."""
    return type(f"_Lying{base.__name__}", (base,), {"__len__": lambda _self: length})


def _handing(octets: bytes) -> bytes:
    """Return bytes whose `__bytes__` answers `octets` with a length of `_LIE`.

    What btclib's `bytes_from_octets` returns for it, `bytes()` handing
    back the subclass `__bytes__` answers.
    """
    lying = _lying(bytes)(octets)
    handing = type("_Handing", (bytes,), {"__bytes__": lambda _self: lying})
    return handing(octets)  # type: ignore[no-any-return]


class _Itself(bytes):
    """Bytes of a length of `_LIE` that `bytes()` answers with themselves."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return _LIE

    @override
    def __bytes__(self) -> bytes:
        return self


class _LyingText(str):
    """A text whose length is `_LIE`, and which strips to itself."""

    __slots__ = ()

    @override
    def __len__(self) -> int:
        return _LIE

    @override
    def strip(self, chars: str | None = None) -> str:
        return self


class _LyingStream(BytesIO):
    """A stream that reads 10 bytes whose length is `_LIE`."""

    @override
    def read(self, size: int | None = -1, /) -> bytes:
        return _lying(bytes)(b"\0" * 10)  # type: ignore[no-any-return]


class _ManyScripts(RawDescriptor):
    """A descriptor whose scripts are its own twice, of length `_LIE`."""

    @override
    def script_pub_keys(
        self, index: int = 0, prv_keys: PrvKeys | None = None
    ) -> list[ScriptPubKey]:
        found = super().script_pub_keys(index, prv_keys)
        return _lying(list)(found * 2)  # type: ignore[no-any-return]


def _forged_origin(**fields: object) -> Callable[[], object]:
    """Return the check of a key origin whose fields are set by hand."""
    origin = BIP32KeyOrigin(b"\0" * 4, "m/0")
    for name, value in fields.items():
        object.__setattr__(origin, name, value)
    return origin.assert_valid


@pytest.mark.parametrize(
    "build, err_msg",
    [
        (
            lambda: Miniscript("and_v", subs=_lying(tuple)((Miniscript("1"),))),
            "and_v takes 2 subexpressions, 1 given",
        ),
        (
            lambda: KeyExpression(pub_key=_lying(bytes)(b"\x02" * 10)),
            "invalid public key length in bytes: 10",
        ),
        (
            lambda: MultiDescriptor(
                1, _lying(tuple)(parse(f"pk({XPUB})").key_expressions * 21)
            ),
            "multi() takes at most 20 keys, 21 given",
        ),
        (
            lambda: TrDescriptor(
                parse(f"tr({XPUB})").key_expressions[0], _lying(tuple)((1, 2, 3))
            ),
            "a script tree branch takes two subtrees, 3 given",
        ),
        (
            lambda: from_script(
                b"\x76\xa9\x14" + hash160(b"\x02" * 10) + b"\x88\xac",
                TAPSCRIPT,
                {hash160(b"\x02" * 10): _handing(b"\x02" * 10)},
            ),
            "not a tapscript public key: 10 bytes",
        ),
        (
            lambda: from_script(_handing(b"\x51"), P2WSH),
            "script too large for P2WSH: 1 bytes",
        ),
        (
            lambda: WshDescriptor(RawDescriptor(_handing(b"\x51" * 600))),
            "raw() inside wsh() is 600 bytes, over the 10000-byte limit",
        ),
        (
            lambda: rootxprv_from_seed(_handing(b"\x01" * 32)),
            "too many bits for seed: 256",
        ),
        (
            lambda: replace(ROOT, chain_code=_Itself(b"\0" * 10)),
            "invalid chain_code length: 10 bytes instead of 32",
        ),
        (
            lambda: KeyExpression(pub_key=_lying(bytes, 33)(b"\x05" * 10)),
            "invalid public key prefix for 10 bytes",
        ),
        (
            lambda: _ManyScripts(b"\x51").script_pub_key(),
            "2 scripts: use script_pub_keys instead",
        ),
        (
            lambda: MultiA(1, _lying(tuple)(parse(f"rawtr({XPUB})").key_expressions)),
            "invalid n in k-of-n multi_a: 1",
        ),
        (
            lambda: Quorum(1, _lying(tuple, 0)(parse(f"pk({XPUB})").key_expressions)),
            "invalid quorum: threshold not from 1 to 1",
        ),
        (
            _forged_origin(master_fingerprint=_lying(bytes)(b"\0" * 3)),
            "invalid master fingerprint length: 3",
        ),
        (
            _forged_origin(der_path=_lying(tuple, 256)((0,) * 3)),
            "invalid der_path size: 3",
        ),
        (
            lambda: assert_valid_hd_key_paths(
                {_lying(bytes)(b"\2" * 10): BIP32KeyOrigin(b"\0" * 4, "m/0")}
            ),
            "invalid public key length: 10",
        ),
        (
            lambda: indexes_from_der_path(_lying(bytes, 5)(b"\0" * 6)),
            "index are not a multiple of 4-bytes: 6",
        ),
        (
            lambda: str_from_der_path("m/0", _LyingText("abc")),
            "invalid master fingerprint length: 3 characters instead of 8 hex digits",
        ),
        (
            lambda: BIP32KeyData.parse(_LyingStream()),
            "invalid decoded length: 10 instead of 78",
        ),
        (
            lambda: infer_descriptor(
                b"\x51", Provider(trees={b"\0" * 32: _lying(tuple)((b"", b""))})
            ),
            "invalid taproot spend data: 2 items",
        ),
        (
            lambda: infer_descriptor(
                b"\x51",
                Provider(
                    trees={
                        b"\1" * 32: (b"\1" * 32, b"", {b"\xc0": _lying(tuple)((b"",))})
                    }
                ),
            ),
            "invalid leaf script: 1 items",
        ),
    ],
    ids=[
        "subexpressions",
        "public key",
        "keys",
        "script tree branch",
        "supplied tapscript key",
        "script",
        "raw() inside wsh()",
        "seed",
        "extended key field",
        "public key prefix",
        "scripts",
        "multi_a keys",
        "quorum keys",
        "origin fingerprint",
        "origin path",
        "hd key path",
        "path octets",
        "fingerprint text",
        "decoded key",
        "taproot spend data",
        "leaf script",
    ],
)
def test_a_count_a_refusal_writes_is_the_built_in_one(
    build: Callable[[], object], err_msg: str
) -> None:
    """Not the length a caller's class answers.

    The refusal may decide by that one: what is written is measured.
    """
    errors = (BTClibTypeError, BTClibValueError)
    with pytest.raises(errors, match=f"^{re.escape(err_msg)}$") as e:
        build()
    assert_secret_free(e.value, [*SPELLINGS, str(_LIE)])
