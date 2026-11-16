# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The sizes and bounds `miniscript.py` computes, on the inputs that pin them.

Issue btclib-org/bip32-descriptors#41. Each of its cases has another
answer where one operator of the script-size, witness-size, stack or
key-count computations is changed. The mutation profile
`.github/mutation/descriptors.toml` names the operators of those
computations that no input can tell apart.

BIP 379's limit vectors, at the end, put each resource limit at its
bound and one past it: issue btclib-org/bip32-descriptors#376.
"""

import hashlib
import re

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    from_script,
    parse,
)

K = [PrvKeyData(i).pub.sec.hex() for i in range(1, 6)]


def test_the_largest_tapscript_from_script_reads() -> None:
    """A tapscript is refused for its length one byte past 329482.

    At 329482 bytes it is read, and refused for what it holds.
    """
    with pytest.raises(BTClibValueError, match="closes no fragment"):
        from_script(b"\xff" * 329482, TAPSCRIPT)
    with pytest.raises(BTClibValueError, match="script too large"):
        from_script(b"\xff" * 329483, TAPSCRIPT)


def test_the_script_size_of_a_multi_a_with_one_key() -> None:
    """`script_size` is the length of the script `script` writes."""
    node = parse(f"multi_a(1,{K[0]})", TAPSCRIPT)
    assert node.script_size == len(node.script()) == 36


def test_the_witness_of_a_multisig() -> None:
    """A multi() dissatisfaction and a multi_a() satisfaction, in bytes.

    multi(2,...) is dissatisfied by three empty pushes, the dummy element
    and one per signature it asks for, before multi(3,...) is satisfied by
    its dummy
    and three 73-byte signature pushes. multi_a(1,...) of three keys is
    satisfied by one 66-byte signature push and two empty pushes.
    """
    node = parse(f"or_d(multi(2,{K[0]},{K[1]}),multi(3,{K[2]},{K[3]},{K[4]}))")
    assert node.max_witness_size == 3 + 1 + 3 * 73
    node = parse(f"multi_a(1,{K[0]},{K[1]},{K[2]})", TAPSCRIPT)
    assert node.max_witness_size == 66 + 2


def test_a_dissatisfied_thresh_costs_its_dissatisfactions() -> None:
    """The stack a thresh() dissatisfaction leaves is not its satisfaction's.

    The or_i() is dissatisfied by two elements and satisfied by up to
    three, so dissatisfying the thresh() and satisfying pk() needs three
    elements, as satisfying the thresh() does.
    """
    expression = f"thresh(1,or_i(pk({K[0]}),and_v(v:pk({K[1]}),pk({K[2]}))))"
    node = parse(f"or_d({expression},pk({K[3]}))")
    assert node.max_stack_items == 3
    assert node.max_exec_stack_items == 3


def test_the_stack_peaks_above_the_witness() -> None:
    """`max_exec_stack_items` counts what the script pushes on the witness.

    A multi_a() of three keys takes three witness elements, and its first
    key is pushed on top of them.
    """
    node = parse(f"multi_a(1,{K[0]},{K[1]},{K[2]})", TAPSCRIPT)
    assert node.max_stack_items == 3
    assert node.max_exec_stack_items == 4


def test_a_multi_a_takes_its_most_keys() -> None:
    """`multi_a()` holds as many keys as BIP387 allows, and no more."""
    x_only = K[0][2:]
    node = parse(f"multi_a(1,{','.join([x_only] * 999)})", TAPSCRIPT)
    assert len(node.keys) == 999
    with pytest.raises(BTClibValueError, match="invalid number of keys"):
        parse(f"multi_a(1,{','.join([x_only] * 1000)})", TAPSCRIPT)


def _and_v(firsts: list[str], last: str) -> str:
    """Return the and_v() chain of `firsts`, ending in `last`."""
    return "".join(f"and_v({first}," for first in firsts) + last + ")" * len(firsts)


def _keys(first: int, last: int) -> str:
    """Return the key placeholders from `first` to `last`."""
    return ",".join(f"K{i}" for i in range(first, last + 1))


def _older_tree(leaves: int) -> str:
    """Return the balanced and_v() tree of `leaves` vdv:older(1)."""
    if leaves == 1:
        return "vdv:older(1)"
    half = leaves // 2
    return f"and_v({_older_tree(half)},{_older_tree(leaves - half)})"


_AFTER = ["v:after(1)"]
_MULTI = [f"v:multi(1,{_keys(i, i + 19)})" for i in (1, 21, 41, 61)]
_SCRIPT_SIZE = _MULTI + [f"v:pk(K{i})" for i in range(101, 106)]
_LAST_MULTI = f"multi(1,{_keys(81, 100)})"

# BIP 379's limits.txt and limits_tap.txt, line by line, as
# bitcoin/bips#2240 adds them at its head
# 91fdd5d3aa9e9131c4109cf84891241d8dce7f3a. The BIP and its files are
# CC0-1.0, which asks for no notice. `K<n>` stands for the public key of
# the secret key n, as the BIP's Conventions say.
BIP379_LIMITS = {
    "limits.txt": [
        (_and_v(_AFTER * 100, "pk(K1)"), "ops", "within"),
        (_and_v(["v:pk(K2)", *_AFTER * 100], "pk(K1)"), "ops", "over"),
        (_and_v([_MULTI[0], "v:pk(K22)", *_AFTER * 89], "pk(K21)"), "ops", "within"),
        (_and_v([_MULTI[0], *_AFTER * 90], "pk(K21)"), "ops", "over"),
        (
            _and_v([*_SCRIPT_SIZE, "v:after(1000)"], _LAST_MULTI),
            "script_size",
            "within",
        ),
        (
            _and_v([*_SCRIPT_SIZE, "v:after(100000)"], _LAST_MULTI),
            "script_size",
            "over",
        ),
        (
            _and_v([f"v:pk(K{i})" for i in range(1, 100)], "pk(K100)"),
            "witness_elements",
            "within",
        ),
        (
            _and_v([f"v:pk(K{i})" for i in range(1, 101)], "pk(K101)"),
            "witness_elements",
            "over",
        ),
    ],
    "limits_tap.txt": [
        (_and_v([_older_tree(998)], "pk(K1)"), "stack", "within"),
        (_and_v([_older_tree(999)], "pk(K1)"), "stack", "over"),
    ],
}
# each file's blob at that head: the `sha` that
# `gh api 'repos/bitcoin/bips/contents/bip-0379/<file>?ref=<head>'` answers
BIP379_BLOBS = {
    "limits.txt": "acf0edae1ad15839dc64e0c8abc051022597d9ae",
    "limits_tap.txt": "76f1000f6c3989497175109a65930f70b91f4df6",
}
# the property each limit bounds, and its bound
BIP379_BOUNDS = {
    "ops": ("max_ops", 201),
    "script_size": ("script_size", 3600),
    "witness_elements": ("max_stack_items", 100),
    "stack": ("max_exec_stack_items", 1000),
}


@pytest.mark.parametrize("name", BIP379_LIMITS)
def test_the_bip379_limit_vectors_are_its_files(name: str) -> None:
    """The vectors above rebuild each file of BIP 379 byte for byte."""
    text = "".join(" ".join(vector) + "\n" for vector in BIP379_LIMITS[name])
    data = text.encode()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False)
    assert blob.hexdigest() == BIP379_BLOBS[name]


@pytest.mark.parametrize(
    "name, expression, limit, verdict",
    [
        pytest.param(name, *vector, id=f"{name}:{line}")
        for name, vectors in BIP379_LIMITS.items()
        for line, vector in enumerate(vectors, 1)
    ],
)
def test_a_bip379_limit_vector(
    name: str, expression: str, limit: str, verdict: str
) -> None:
    """A within vector is sane at its bound, and an over vector refused past it.

    What the limit bounds is the bound in a within vector and one more in
    an over vector. `parse` refuses a script larger than P2WSH allows, and
    BIP 379 lets the parser or the sanity checks refuse an over vector.
    """
    context = TAPSCRIPT if name == "limits_tap.txt" else P2WSH

    def key(match: re.Match[str]) -> str:
        sec = PrvKeyData(int(match[1])).pub.sec.hex()
        return sec[2:] if context == TAPSCRIPT else sec

    expression = re.sub(r"K(\d+)", key, expression)
    attribute, bound = BIP379_BOUNDS[limit]
    if (limit, verdict) == ("script_size", "over"):
        refusal = f"too large for P2WSH: at least {bound + 1} bytes"
        with pytest.raises(BTClibValueError, match=refusal):
            parse(expression, context)
        return
    node = parse(expression, context)
    assert getattr(node, attribute) == bound + (verdict == "over")
    assert node.is_sane() is (verdict == "within")
