# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`Miniscript.spending_paths` and `Descriptor.spending_paths`.

Issue btclib-org/bip32-descriptors#356. What a path says is checked
against the satisfier, which reads the same script another way: a set of
signatures, lock times and preimages satisfies a sane expression exactly
where it meets one of the expression's paths. `satisfy` puts placeholder
signatures on the stack and checks none of them.

Liana's own vectors are in `liana_test.py`.
"""

from __future__ import annotations

import itertools
import pickle
from collections.abc import Callable
from typing import Any

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.key import PrvKeyData
from typing_extensions import override

from bip32_descriptors.bip32 import rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import (
    KeyExpression,
    Quorum,
    SpendContext,
    SpendingPath,
    TrDescriptor,
    miniscript,
    parse,
)
from bip32_descriptors.descriptors.miniscript import P2WSH, TAPSCRIPT, Miniscript
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript

# keys by name, the SEC hex of the first few multiples of the generator
NAMES = "ABCDEFGHJ"
SEC = {name: PrvKeyData(i).pub.sec.hex() for i, name in enumerate(NAMES, 1)}
A, B, C, D, E, F, G, H, J = (SEC[name] for name in NAMES)
# what `str` writes for each key, in either context, back to its name
NAME = {spelling: name for name, sec in SEC.items() for spelling in (sec, sec[2:])}

PREIMAGES = [bytes([i]) * 32 for i in range(1, 5)]
HASHES: dict[str, Callable[[bytes], bytes]] = {
    "sha256": sha256,
    "hash256": hash256,
    "ripemd160": ripemd160,
    "hash160": hash160,
}
DIGEST = {name: function(PREIMAGES[0]).hex() for name, function in HASHES.items()}

XPUB = xpub_from_xprv(rootxprv_from_seed("00" * 32))
# BIP341's H, x-only, and an xpub of it as Liana writes one
NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
NUMS_XPUB = (
    "xpub661MyMwAqRbcFERisZuMzFcfg3Ur3dKB17kb8iEG89ZJYMHTWqKQGRdLjTXC6Byr8kjK"
    "o6JabFfRCm3ETM4woq7DxUXuUxxRFHfog4Peh41"
)


def shape(path: SpendingPath) -> tuple[Any, ...]:
    """Return a path, each key by its name and each digest by its fragment."""
    quorums = tuple(
        (quorum.threshold, "".join(NAME.get(str(key), str(key)) for key in quorum.keys))
        for quorum in path.quorums
    )
    hashes = tuple(fragment for fragment, _ in path.hashes)
    return quorums, path.older, path.after, hashes, path.leaf


def shapes(paths: tuple[SpendingPath, ...]) -> list[tuple[Any, ...]]:
    """Return `shape` of each path."""
    return [shape(path) for path in paths]


def test_the_issue_example() -> None:
    """A alone, now; and B alone, after 144 blocks."""
    descriptor = parse(f"wsh(or_d(pk({A}),and_v(v:pkh({B}),older(144))))")
    assert shapes(descriptor.spending_paths) == [
        (((1, "A"),), None, None, (), None),
        (((1, "B"),), 144, None, (), None),
    ]


# (expression, its paths), each read in P2WSH
SHAPES = [
    # keys that each spend alone and otherwise wait for the same are one
    # quorum of one, as Liana's primary path is
    (
        f"or_i(pk({A}),or_i(pk({B}),or_i(pk({C}),and_v(v:pk({D}),older(42)))))",
        [(((1, "ABC"),), None, None, ()), (((1, "D"),), 42, None, ())],
    ),
    # and two that sign together are not
    (
        f"or_i(and_v(v:pk({A}),pk({B})),or_i(pk({C}),and_v(v:pk({D}),older(42))))",
        [
            (((2, "AB"),), None, None, ()),
            (((1, "C"),), None, None, ()),
            (((1, "D"),), 42, None, ()),
        ],
    ),
    # the vault of btclib-wallet's custody tests: two quorums no single
    # threshold states, then a recovery quorum
    (
        f"andor(multi(2,{A},{B},{C}),multi(3,{D},{E},{F},{G}),and_v(v:multi(2,{H},{J}),older(5184)))",
        [(((2, "ABC"), (3, "DEFG")), None, None, ()), (((2, "HJ"),), 5184, None, ())],
    ),
    # every key a conjunction needs is one quorum, wherever it stands
    (
        f"and_v(v:pk({A}),and_v(v:multi(2,{B},{C},{D}),pk({E})))",
        [(((2, "AE"), (2, "BCD")), None, None, ())],
    ),
    # a thresh() of keys is one quorum, a thresh() of other branches a path
    # per choice of them, the keys making up the rest of the threshold
    (f"thresh(2,pk({A}),s:pk({B}),s:pk({C}))", [(((2, "ABC"),), None, None, ())]),
    (
        f"thresh(3,pk({A}),s:pk({B}),sln:older(10),sln:after(100))",
        [
            (((2, "AB"),), 10, None, ()),
            (((2, "AB"),), None, 100, ()),
            (((1, "AB"),), 10, 100, ()),
        ],
    ),
    (
        f"thresh(2,pk({A}),a:sha256({DIGEST['sha256']}),a:hash160({DIGEST['hash160']}))",
        [
            (((1, "A"),), None, None, ("sha256",)),
            (((1, "A"),), None, None, ("hash160",)),
            ((), None, None, ("sha256", "hash160")),
        ],
    ),
    # a thresh() of a multisig and a key is a quorum of all of them
    (
        f"thresh(2,multi(2,{A},{B}),a:pk({C}))",
        [(((3, "ABC"),), None, None, ())],
    ),
    # andor(X,Y,Z) is X and Y, or Z
    (
        f"andor(pk({A}),older(10000),pk({B}))",
        [(((1, "A"),), 10000, None, ()), (((1, "B"),), None, None, ())],
    ),
    # two lock times of a kind: the later one, BIP68 reading the low bits
    # of a relative one, which 65541 has set to 5
    (
        f"and_v(v:pk({A}),and_v(v:older(65541),older(10)))",
        [(((1, "A"),), 10, None, ())],
    ),
    (
        f"and_v(v:pk({A}),and_v(v:older(10),older(65541)))",
        [(((1, "A"),), 10, None, ())],
    ),
    # and two that BIP68 reads alike are one path, whichever comes first
    (
        "or_i(and_v(v:older(65541),older(5)),and_v(v:older(5),older(65541)))",
        [((), 65541, None, ())],
    ),
    (
        f"and_v(v:pk({A}),and_v(v:after(20),after(10)))",
        [(((1, "A"),), None, 20, ())],
    ),
    # a relative and an absolute lock are two locks of one path
    (
        f"and_v(v:pk({A}),and_v(v:after(500000001),older(4194305)))",
        [(((1, "A"),), 4194305, 500000001, ())],
    ),
    # a preimage the path reveals twice is one
    (
        f"and_v(v:pk({A}),and_v(v:sha256({DIGEST['sha256']}),sha256({DIGEST['sha256']})))",
        [(((1, "A"),), None, None, ("sha256",))],
    ),
    # a branch the other repeats is one path
    (f"or_i(pk({A}),pk({A}))", [(((1, "A"),), None, None, ())]),
    # a merge leaves the merged path's other quorums: the third path, which
    # could have joined the first before it took E, now cannot
    (
        f"or_i(and_v(v:or_i(pk({A}),pk({B})),or_i(pk({C}),pk({D}))),or_i(and_v(v:pk({E}),or_i(pk({C}),pk({D}))),and_v(v:or_i(pk({A}),pk({B})),pk({F}))))",
        [
            (((1, "ABE"), (1, "CD")), None, None, ()),
            (((1, "AB"), (1, "F")), None, None, ()),
        ],
    ),
    # a thresh() of a key and a multisig needing both is one quorum, its keys
    # in the order the expression names them
    (f"thresh(2,pk({A}),a:multi(2,{B},{C}))", [(((3, "ABC"),), None, None, ())]),
    # a merge that makes two paths share a rest merges them in turn
    (
        (
            f"or_i(or_i(and_v(v:or_i(pk({A}),pk({B})),or_i(pk({C}),pk({D}))),"
            f"and_v(v:or_i(pk({E}),pk({F})),or_i(pk({G}),pk({H})))),"
            f"or_i(and_v(v:or_i(pk({A}),pk({B})),or_i(pk({G}),pk({H}))),"
            f"and_v(v:or_i(pk({E}),pk({F})),or_i(pk({C}),pk({D})))))"
        ),
        [(((1, "ABEF"), (1, "CDGH")), None, None, ())],
    ),
    # a thresh() branch with no path is no key, and adds none
    (f"thresh(1,pk({A}),a:0)", [(((1, "A"),), None, None, ())]),
    # the sugar for or_i() with a 0, and for and_v() with a 1
    (f"and_v(v:pk({A}),l:pk({B}))", [(((2, "AB"),), None, None, ())]),
    (f"and_v(v:pk({A}),u:pk({B}))", [(((2, "AB"),), None, None, ())]),
    (f"or_d(pk({A}),tv:pk({B}))", [(((1, "AB"),), None, None, ())]),
]


@pytest.mark.parametrize("expression, expected", SHAPES)
def test_the_paths_of_an_expression(
    expression: str, expected: list[tuple[Any, ...]]
) -> None:
    """Each path's quorums, lock times and hashes, as the cases above say."""
    paths = parse_miniscript(expression).spending_paths
    assert [shape(path)[:4] for path in paths] == expected


def test_a_path_no_transaction_takes_is_not_listed() -> None:
    """A height and a time lock of one kind, in one path, are no path.

    Which `mixes_timelocks` says of the expression.
    """
    for expression in (
        f"or_d(pk({A}),and_v(v:pk({B}),and_v(v:older(10),older(4194305))))",
        f"or_d(pk({A}),and_v(v:pk({B}),and_v(v:after(10),after(500000001))))",
    ):
        node = parse_miniscript(expression)
        assert node.mixes_timelocks
        assert shapes(node.spending_paths) == [(((1, "A"),), None, None, (), None)]


def test_a_zero_has_no_path() -> None:
    """An expression no witness satisfies has none to list."""
    node = Miniscript("0")
    assert node.spending_paths == ()
    assert Miniscript("1").spending_paths == (SpendingPath(),)


# sane expressions, each small enough that every set of signatures, lock
# times and preimages can be tried
SANE = [
    *(expression for expression, _ in SHAPES[:6]),
    SHAPES[8][0],
    f"and_v(v:pk({A}),or_d(pk({B}),and_v(v:sha256({DIGEST['sha256']}),after(500))))",
    f"or_d(multi(1,{A},{B}),and_v(v:multi(2,{C},{D}),older(1000)))",
    f"and_v(v:thresh(2,pkh({A}),a:pkh({B}),a:pkh({C})),older(26352))",
    f"or_b(pk({A}),s:pk({B}))",
    f"and_b(pk({A}),s:pk({B}))",
    f"and_v(or_c(pk({B}),or_c(pk({C}),v:older(1000))),pk({A}))",
    f"andor(pk({A}),or_i(and_v(v:pkh({B}),hash160({DIGEST['hash160']})),older(10)),pk({C}))",
    f"or_d(pk({A}),and_v(v:pk({B}),or_d(pk({C}),and_v(v:ripemd160({DIGEST['ripemd160']}),older(5)))))",
]


def _nodes(root: Miniscript) -> list[Miniscript]:
    nodes = [root]
    for node in nodes:
        nodes.extend(node.subs)
    return nodes


def _meets(path: SpendingPath, signed: set[bytes], spend: SpendContext) -> bool:
    """Answer whether what a spend has is all the path asks."""
    preimages = {
        "sha256": spend.sha256_preimages,
        "hash256": spend.hash256_preimages,
        "ripemd160": spend.ripemd160_preimages,
        "hash160": spend.hash160_preimages,
    }
    return (
        all(
            sum(key.sec() in signed for key in quorum.keys) >= quorum.threshold
            for quorum in path.quorums
        )
        and (path.older is None or spend._older(path.older))
        and (path.after is None or spend._after(path.after))
        and all(digest in preimages[name] for name, digest in path.hashes)
    )


def _spends(root: Miniscript) -> list[tuple[set[bytes], SpendContext]]:
    """Return every set of signatures with every lock time and preimage."""
    nodes = _nodes(root)
    keys = sorted({key.sec() for key in root.key_expressions})
    sequences = [0, *(node.threshold for node in nodes if node.fragment == "older")]
    locktimes = [0, *(node.threshold for node in nodes if node.fragment == "after")]
    hashes = [(node.fragment, node.data) for node in nodes if node.fragment in HASHES]
    spends = []
    for signed, sequence, locktime, known in itertools.product(
        (set(s) for r in range(len(keys) + 1) for s in itertools.combinations(keys, r)),
        sequences,
        locktimes,
        (k for r in range(len(hashes) + 1) for k in itertools.combinations(hashes, r)),
    ):
        maps: dict[str, dict[bytes, bytes]] = {name: {} for name in HASHES}
        for name, digest in known:
            maps[name][digest] = PREIMAGES[0]
        spend = SpendContext(
            sha256_preimages=maps["sha256"],
            hash256_preimages=maps["hash256"],
            ripemd160_preimages=maps["ripemd160"],
            hash160_preimages=maps["hash160"],
            locktime=locktime,
            sequence=sequence,
        )
        spends.append((signed, spend))
    return spends


@pytest.mark.parametrize("expression", SANE)
def test_a_spend_satisfies_where_it_meets_a_path(expression: str) -> None:
    """The paths are every way to satisfy the expression, and no other."""
    node = parse_miniscript(expression)
    assert node.is_sane()
    paths = node.spending_paths
    for signed, spend in _spends(node):
        signatures: dict[Octets, Octets] = dict.fromkeys(signed, b"\xaa" * 72)
        try:
            node.satisfy(signatures, spend)
        except BTClibValueError:
            satisfied = False
        else:
            satisfied = True
        assert satisfied == any(_meets(path, signed, spend) for path in paths)


def test_an_expression_built_without_a_type_is_refused() -> None:
    """The paths of what `script` refuses would be a script that is not."""
    keys = [
        Miniscript("c:", P2WSH, (Miniscript("pk_k", P2WSH, (), (key,)),))
        for key in (KeyExpression(pub_key=bytes.fromhex(name)) for name in (A, B))
    ]
    node = Miniscript("and_v", P2WSH, tuple(keys))
    assert not node.is_valid
    with pytest.raises(BTClibValueError, match="invalid miniscript"):
        _ = node.spending_paths


def test_a_key_named_by_its_hash_is_refused() -> None:
    """A ``rawpkh()`` names no key a quorum could hold."""
    node = parse_miniscript(f"and_v(v:pk({A}),rawpkh({'11' * 20}))")
    with pytest.raises(BTClibValueError, match="names its key by its hash alone"):
        _ = node.spending_paths


def _thresh_of_preimages(threshold: int, count: int) -> Miniscript:
    """Return a thresh() of `count` preimages, a path per choice of them."""
    digests = [sha256(bytes([i]) * 32).hex() for i in range(count)]
    branches = [f"sha256({digests[0]})", *(f"a:sha256({d})" for d in digests[1:])]
    return parse_miniscript(f"thresh({threshold},{','.join(branches)})")


def test_the_bound_on_the_paths() -> None:
    """Five of fifteen preimages are too many choices to list; of twelve not."""
    assert len(_thresh_of_preimages(5, 12).spending_paths) == 792
    # the bound is on the paths a disjunction has, a path of both branches
    # being one
    twice = parse_miniscript(
        f"or_i({_thresh_of_preimages(5, 12)},{_thresh_of_preimages(5, 12)})"
    )
    assert len(twice.spending_paths) == 792
    with pytest.raises(BTClibValueError, match="more than 1000 spending paths"):
        _ = _thresh_of_preimages(5, 15).spending_paths


def test_a_choice_that_can_no_longer_complete_counts_toward_no_bound() -> None:
    """All of thirteen branches is one path, though fewer of them are many.

    Five of thirteen branches can be chosen in more ways than the bound
    allows, and none of those choices can still reach the threshold.
    """
    keys = [PrvKeyData(i).pub.sec.hex() for i in range(1, 40)]
    multis = [f"multi(2,{','.join(keys[3 * b : 3 * b + 3])})" for b in range(13)]
    node = parse_miniscript(f"thresh(13,{multis[0]},a:{',a:'.join(multis[1:])})")
    [path] = node.spending_paths
    assert [(q.threshold, len(q.keys)) for q in path.quorums] == [(2, 3)] * 13
    assert [str(q.keys[0]) for q in path.quorums] == keys[::3]


def test_a_branch_with_no_path_completes_no_choice() -> None:
    """Twelve of a 0 and fifteen preimages are the choices of twelve preimages.

    Eleven of the fifteen can be chosen in more ways than the bound allows,
    and the 0 brings none of those choices to the threshold.
    """
    digests = [sha256(bytes([i]) * 32).hex() for i in range(1, 16)]
    rest = ",".join(f"a:sha256({digest})" for digest in digests)
    node = parse_miniscript(f"thresh(12,0,{rest})")
    assert node.is_valid
    paths = node.spending_paths
    assert len(paths) == 455
    assert {len(path.hashes) for path in paths} == {12}


def test_the_work_of_a_disjunction_is_its_paths_times_their_quorums(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A path of many quorums is read once for all its rests.

    Paths of a hundred quorums of one key each, or a key: reading each
    rest whole hashes the square of a path's quorums, where one pass
    hashes their number.
    """
    keys = [PrvKeyData(i).pub.sec.hex()[2:] for i in range(1, 202)]
    conjunction = f"or_i(pk({keys[198]}),pk({keys[199]}))"
    for i in range(99):
        conjunction = (
            f"and_v(v:or_i(pk({keys[2 * i]}),pk({keys[2 * i + 1]})),{conjunction})"
        )
    node = parse_miniscript(
        f"or_i(and_v(v:{_preimage_thresh(5, 12, 8)},{conjunction}),pk({keys[200]}))",
        TAPSCRIPT,
    )
    hashed = [0]
    quorum_hash = Quorum.__hash__

    def counted(quorum: Quorum) -> int:
        hashed[0] += 1
        return quorum_hash(quorum)

    monkeypatch.setattr(Quorum, "__hash__", counted)
    paths = node.spending_paths
    assert {len(path.quorums) for path in paths} == {100, 1}
    assert hashed[0] <= 4 * len(paths) * 100


class _CountedDigest(bytes):
    """A digest that counts how often it is hashed."""

    hashed = 0

    @override
    def __hash__(self) -> int:
        _CountedDigest.hashed += 1
        return bytes.__hash__(self)


def test_a_path_s_locks_are_read_once_for_all_its_rests() -> None:
    """A rest's key holds a number for the path's locks, not its hashes.

    A path of fifty quorums of one of two keys and fifty hashes, under
    fifty disjunctions with a lock alone. Where no hash of a tuple is
    cached, a key holding the path's hashes would read each of them again
    for every quorum of one key.
    """
    count = 50
    keys = [PrvKeyData(i).pub.sec.hex()[2:] for i in range(1, 2 * count + 1)]
    expression = f"sha256({sha256(b'0').hex()})"
    for i in range(1, count):
        expression = f"and_v(v:sha256({sha256(bytes([i])).hex()}),{expression})"
    for i in range(count):
        either = f"or_i(pk({keys[2 * i]}),pk({keys[2 * i + 1]}))"
        expression = f"and_v(v:{either},{expression})"
    for _ in range(count):
        expression = f"or_i(older(1),{expression})"
    node = parse_miniscript(expression, TAPSCRIPT)
    stack = [node]
    while stack:
        sub = stack.pop()
        if sub.fragment == "sha256":
            object.__setattr__(sub, "data", _CountedDigest(sub.data))
        stack.extend(sub.subs)
    _CountedDigest.hashed = 0
    assert len(node.spending_paths) == 2
    assert _CountedDigest.hashed <= 8 * count * count


def test_a_path_hashes_its_keys_as_they_are_now() -> None:
    """A path keeps no hash of its own, which a key's origin could outgrow.

    The steps of a key's origin are a list, which a caller can change in
    place once the call has returned the path.
    """
    expression = f"and_v(v:pk([deadbeef/0]{A}),older(5))"
    [path] = parse_miniscript(expression).spending_paths
    origin = path.quorums[0].keys[0].origin
    assert origin is not None
    assert isinstance(origin.der_path, list)
    origin.der_path[0] = 1
    origin.assert_valid()
    [fresh] = parse_miniscript(expression.replace("/0]", "/1]")).spending_paths
    assert path == fresh
    fields = (path.quorums, path.older, path.after, path.hashes, path.leaf)
    assert hash(path) == hash(fields)


def _preimage_thresh(threshold: int, count: int, salt: int) -> str:
    """Return a thresh() of `count` preimages, `salt` telling digests apart."""
    digests = [sha256(bytes([salt, i]) * 16).hex() for i in range(count)]
    rest = ",".join(f"a:sha256({digest})" for digest in digests[1:])
    return f"thresh({threshold},sha256({digests[0]}),{rest})"


def test_a_pair_no_transaction_takes_is_no_path() -> None:
    """Paths in blocks against paths in time give no path, not too many."""
    blocks = f"and_v(v:{_preimage_thresh(3, 7, 1)},older(10))"
    seconds = f"and_v(v:{_preimage_thresh(3, 7, 2)},older(4194305))"
    assert len(parse_miniscript(blocks).spending_paths) == 35
    assert len(parse_miniscript(seconds).spending_paths) == 35
    assert parse_miniscript(f"and_v(v:{blocks},{seconds})").spending_paths == ()


def test_a_path_is_its_hashes_in_whatever_order_reached() -> None:
    """Two preimages revealed in either order are one path, in their order."""
    first, second = sha256(b"1").hex(), sha256(b"2").hex()
    node = parse_miniscript(
        f"or_i(and_v(v:sha256({first}),sha256({second})),"
        f"and_v(v:sha256({second}),sha256({first})))"
    )
    [path] = node.spending_paths
    assert path.hashes == (
        ("sha256", bytes.fromhex(first)),
        ("sha256", bytes.fromhex(second)),
    )


def test_a_quorum_is_its_keys_in_whatever_order_named() -> None:
    """multi(2,A,B) and multi(2,B,A) beside the same paths give them once."""
    rest = _preimage_thresh(5, 12, 3)
    node = parse_miniscript(
        f"or_i(and_v(v:multi(2,{A},{B}),{rest}),and_v(v:multi(2,{B},{A}),{rest}))"
    )
    paths = node.spending_paths
    assert len(paths) == 792
    assert {shape(path)[0] for path in paths} == {((2, "AB"),)}


# the refusal of a conjunction whose pairs would read too much
WORK = "more than 2000000 keys and hashes"


def _either_key(count: int, blocks: int) -> str:
    """Return `count` quorums of one of two keys, conjoined, then older()."""
    keys = [PrvKeyData(i).pub.sec.hex()[2:] for i in range(1, 2 * count + 1)]
    conjunction = f"older({blocks})"
    for i in range(count):
        either = f"or_i(pk({keys[2 * i]}),pk({keys[2 * i + 1]}))"
        conjunction = f"and_v(v:{either},{conjunction})"
    return conjunction


def _any_older(first: int, count: int) -> str:
    """Return a disjunction of `count` older(), from `first` up."""
    disjunction = f"older({first + count - 1})"
    for value in range(first + count - 2, first - 1, -1):
        disjunction = f"or_i(older({value}),{disjunction})"
    return disjunction


def test_the_bounds_of_a_conjunction() -> None:
    """Bounded: the paths that come out, the pairs, and what they read."""
    many = f"and_v(v:{_preimage_thresh(1, 33, 4)},{_preimage_thresh(1, 33, 5)})"
    with pytest.raises(BTClibValueError, match="more than 1000 spending paths"):
        _ = parse_miniscript(many).spending_paths
    pairs = f"and_v(v:{_preimage_thresh(5, 12, 6)},{_preimage_thresh(5, 12, 7)})"
    with pytest.raises(BTClibValueError, match="more than 100000 pairs"):
        _ = parse_miniscript(pairs).spending_paths
    # pairs whose locks never meet join nothing, and count what they may
    # read all the same. Each of 792 paths of six quorums of two keys and
    # five hashes meets each of 126 paths of a lock alone, under the
    # bound; one more quorum each takes them past it
    seconds = _any_older(4194305, 126)
    for count, refused in ((6, False), (7, True)):
        blocks = f"and_v(v:{_preimage_thresh(5, 12, 8)},{_either_key(count, 10)})"
        node = parse_miniscript(f"and_v(v:{blocks},{seconds})", TAPSCRIPT)
        if refused:
            with pytest.raises(BTClibValueError, match=WORK):
                _ = node.spending_paths
        else:
            assert node.spending_paths == ()


def _key_of_size(size: int, spelling: int) -> str:
    """Return a KEY expression whose hash reads `size` parts, spelled four ways.

    A ``musig()`` of its participants, a key with the steps of its origin,
    an xpub with the steps of its path, and a ``musig()`` whose first
    participant has an origin.
    """
    secs = [PrvKeyData(i).pub.sec.hex() for i in range(1, size)]
    steps = "/0" * (size - 1)
    return [
        f"musig({','.join(secs)})",
        f"[deadbeef{steps}]{secs[0][2:]}",
        f"{XPUB}{steps}",
        f"musig([deadbeef{'/0' * (size - 3)}]{secs[0]},{secs[1]})",
    ][spelling]


@pytest.mark.parametrize("spelling", range(4))
def test_a_key_is_as_big_as_what_its_hash_reads(spelling: int) -> None:
    """A key counts each participant and each step of its origin and path.

    Ordering and joining paths hashes their keys. A key's hash serializes
    its origin each time, and reads its path and its participants each
    time too where no hash of a tuple is cached. The pairs are those of
    the edge of `test_the_bounds_of_a_conjunction`, one key in place of
    its quorums' twelve: twelve parts are within the bound, thirteen past
    it.
    """
    seconds = _any_older(4194305, 126)
    for size, refused in ((12, False), (13, True)):
        key = _key_of_size(size, spelling)
        blocks = f"and_v(v:{_preimage_thresh(5, 12, 8)},and_v(v:pk({key}),older(10)))"
        node = parse_miniscript(f"and_v(v:{blocks},{seconds})", TAPSCRIPT)
        if refused:
            with pytest.raises(BTClibValueError, match=WORK):
                _ = node.spending_paths
        else:
            assert node.spending_paths == ()


def test_the_work_of_a_conjunction_is_its_pairs_times_their_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conjunction whose pairs would read too many keys reads none of them.

    Issue btclib-org/bip32-descriptors#365: the choices of five of twelve
    preimages, each with quorums of one of two keys, then with lock times
    that give the same paths again. The pairs are within their bound, and
    each would read every key of its path: the conjunction is refused
    before its first pair, fewer keys read than it has pairs.
    """
    node = parse_miniscript(
        f"and_v(v:and_v(v:{_preimage_thresh(5, 12, 9)},{_either_key(25, 1000)}),"
        f"{_any_older(1, 126)})",
        TAPSCRIPT,
    )
    read = [0]
    key_hash = KeyExpression.__hash__

    def counted(key: KeyExpression) -> int:
        read[0] += 1
        return key_hash(key)

    monkeypatch.setattr(KeyExpression, "__hash__", counted)
    with pytest.raises(BTClibValueError, match=WORK):
        _ = node.spending_paths
    assert read[0] < 792 * 126


def _joined(paths: str, links: int) -> str:
    """Return the paths joined `links` times in turn with 126 older().

    Which give the paths again where theirs is an older() of 126 or more.
    """
    for _ in range(links):
        paths = f"and_v(v:{paths},{_any_older(1, 126)})"
    return paths


def test_a_side_of_no_path_is_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """A conjunction with a side of no path reads neither side.

    thresh(50) of a hundred branches, the last a choice of preimages beside
    five quorums of one of two keys: read first, its paths are joined with
    each count no branch has reached yet, none of them a path. The keys
    the call reads are no more than its work counts.
    """
    keys = [PrvKeyData(i).pub.sec.hex()[2:] for i in range(1, 11)]
    branch = _preimage_thresh(5, 12, 9)
    for i in range(5):
        branch = f"and_b({branch},a:or_i(pk({keys[2 * i]}),pk({keys[2 * i + 1]})))"
    digests = [sha256(i.to_bytes(4, "big")).hex() for i in range(99)]
    rest = ",".join(f"a:sha256({digest})" for digest in digests[1:])
    node = parse_miniscript(
        f"thresh(50,sha256({digests[0]}),{rest},a:{branch})", TAPSCRIPT
    )
    read = [0]
    key_size = miniscript._key_size
    works: list[miniscript._Work] = []

    def counted(key: KeyExpression) -> int:
        read[0] += 1
        return key_size(key)

    class Kept(miniscript._Work):
        def __init__(self) -> None:
            super().__init__()
            works.append(self)

    monkeypatch.setattr(miniscript, "_key_size", counted)
    monkeypatch.setattr(miniscript, "_Work", Kept)
    with pytest.raises(BTClibValueError, match="more than 1000 spending paths"):
        _ = node.spending_paths
    [work] = works
    assert read[0] <= work.read


@pytest.mark.parametrize("quorums", [0, 6])
def test_the_work_of_a_call_is_bounded_however_often_its_paths_are_joined(
    monkeypatch: pytest.MonkeyPatch, quorums: int
) -> None:
    """The same paths joined again and again add up to one bound.

    Issue btclib-org/bip32-descriptors#367: the choices of five of twelve
    preimages, with no quorum or with six, joined forty times in turn
    with lock times that give the same paths again. Each conjunction is
    within every bound of its own. The call is refused once they add up
    past the bound, having joined at most half as many pairs, each pair
    reading two paths at least.
    """
    paths = f"and_v(v:{_preimage_thresh(5, 12, 11)},{_either_key(quorums, 1000)})"
    node = parse_miniscript(_joined(paths, 40), TAPSCRIPT)
    joined = [0]
    path_and = miniscript._path_and

    def counted(*args: Any) -> SpendingPath | None:
        joined[0] += 1
        return path_and(*args)

    monkeypatch.setattr(miniscript, "_path_and", counted)
    with pytest.raises(BTClibValueError, match=WORK):
        _ = node.spending_paths
    assert joined[0] <= 2000000 // 2


def test_the_leaves_of_a_tr_share_the_bound_on_the_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two leaves each within the bound are past it together.

    A leaf of a tr() is sane, and the shapes above are not, so the bound
    is set to what one leaf reads.
    """
    leaves = [
        f"or_d(pk({one[2:]}),and_v(v:pk({other[2:]}),older(144)))"
        for one, other in ((B, C), (D, E))
    ]
    work = miniscript._Work()
    _ = miniscript._miniscript_paths(parse_miniscript(leaves[0], TAPSCRIPT), work)
    monkeypatch.setattr(miniscript, "_MAX_PATH_WORK", work.read)
    for leaf in leaves:
        assert len(parse(f"tr({A[2:]},{leaf})").spending_paths) == 3
    descriptor = parse(f"tr({A[2:]},{{{leaves[0]},{leaves[1]}}})")
    with pytest.raises(BTClibValueError, match=f"more than {work.read} keys"):
        _ = descriptor.spending_paths


# (descriptor, its paths): the fragments that are not a miniscript
FRAGMENTS = [
    (f"pk({A})", [(((1, "A"),), None, None, (), None)]),
    (f"pkh({A})", [(((1, "A"),), None, None, (), None)]),
    (f"wpkh({A})", [(((1, "A"),), None, None, (), None)]),
    (f"sh(wpkh({A}))", [(((1, "A"),), None, None, (), None)]),
    (f"combo({A})", [(((1, "A"),), None, None, (), None)]),
    (f"rawtr({A[2:]})", [(((1, "A"),), None, None, (), None)]),
    (f"multi(1,{A},{B})", [(((1, "AB"),), None, None, (), None)]),
    (f"sh(sortedmulti(2,{D},{B}))", [(((2, "DB"),), None, None, (), None)]),
    (f"wsh(multi(2,{A},{B},{C}))", [(((2, "ABC"),), None, None, (), None)]),
    (f"sh(wsh(pkh({A})))", [(((1, "A"),), None, None, (), None)]),
    (f"unused({A})", []),
]


@pytest.mark.parametrize("descriptor, expected", FRAGMENTS)
def test_the_paths_of_a_fragment(descriptor: str, expected: list[Any]) -> None:
    """A fragment of one key has one path, a multisig one of its threshold."""
    assert shapes(parse(descriptor).spending_paths) == expected


@pytest.mark.parametrize(
    "descriptor",
    [
        "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)",
        "raw(51)",
        "sh(raw(51))",
        f"wsh(rawpkh({'11' * 20}))",
        f"tr({A[2:]},{{pk({B[2:]}),rawnode({'22' * 32})}})",
        f"tr({A[2:]},{{pk({B[2:]}),rawleaf(51,c0)}})",
    ],
)
def test_a_descriptor_not_naming_every_key_is_refused(descriptor: str) -> None:
    """Paths listed without the keys of some would say less than they seem."""
    with pytest.raises(BTClibValueError, match="names no key|does not name every key"):
        _ = parse(descriptor).spending_paths


def test_the_paths_of_a_tr() -> None:
    """The key path, then each leaf's paths, numbered as the tree lists them."""
    descriptor = parse(
        f"tr({A[2:]},{{{{pk({B[2:]}),multi_a(2,{C[2:]},{D[2:]})}},or_d(pk({E[2:]}),and_v(v:pk({F[2:]}),older(52560)))}})"
    )
    assert shapes(descriptor.spending_paths) == [
        (((1, "A"),), None, None, (), None),
        (((1, "B"),), None, None, (), 0),
        (((2, "CD"),), None, None, (), 1),
        (((1, "E"),), None, None, (), 2),
        (((1, "F"),), 52560, None, (), 2),
    ]


def test_a_tr_path_spends_its_leaf() -> None:
    """The signatures of a path's quorum alone spend through its leaf."""
    descriptor = parse(
        f"tr({A[2:]},{{and_v(v:pk({B[2:]}),older(10)),and_v(v:multi_a(2,{B[2:]},{C[2:]},{D[2:]}),after(100))}})"
    )
    assert isinstance(descriptor, TrDescriptor)
    tree = descriptor.taproot_tree()
    for path in descriptor.spending_paths:
        signatures: dict[Octets, Octets] = {
            key.sec(): b"\xbb" * 64
            for quorum in path.quorums
            for key in quorum.keys[: quorum.threshold]
        }
        spend = SpendContext(sequence=path.older or 0, locktime=path.after or 0)
        _, witness = descriptor.satisfy(signatures, spend=spend)
        if path.leaf is None:
            assert len(witness.stack) == 1
        else:
            assert witness.stack[-2] == tree[path.leaf][2]


@pytest.mark.parametrize(
    "key",
    [NUMS, f"{NUMS_XPUB}/0/*", f"[aabbccdd/1]{NUMS_XPUB}/1/*"],
)
def test_a_rawtr_nobody_can_sign_for_has_no_path(key: str) -> None:
    """A ``rawtr()`` of H, or of a key derived from it, is spent by nobody."""
    assert parse(f"rawtr({key})").spending_paths == ()


# each: a descriptor, the field of it or of a part of it an unpickled one
# holds, the value, and the refusal's field
FORGED: list[tuple[str, Callable[[Any], Any], str, object, str]] = [
    (f"tr({A[2:]})", lambda d: d, "internal_key", "garbage", "internal key"),
    (f"tr({A[2:]},pk({B[2:]}))", lambda d: d, "tree", 5, "script tree node"),
    (f"rawtr({A[2:]})", lambda d: d, "key", "garbage", "key"),
    (f"rawtr({A[2:]})", lambda d: d.key, "pub_key", 5, "pub_key"),
    (f"tr({A[2:]})", lambda d: d.internal_key, "pub_key", 5, "pub_key"),
    (f"tr({XPUB}/0/*)", lambda d: d.internal_key, "xkey", 5, "xkey"),
    (f"unused({A})", lambda d: d, "key", "garbage", "key"),
    (f"pkh({A})", lambda d: d, "key", None, "key"),
    (f"wsh(pk({A}))", lambda d: d, "inner", "garbage", "inner descriptor"),
    (f"sh(wpkh({A}))", lambda d: d, "inner", 5, "inner descriptor"),
    (f"wsh(multi(1,{A},{B}))", lambda d: d.inner, "keys", "garbage", "keys"),
    (f"wsh(and_v(v:pk({A}),older(5)))", lambda d: d.inner, "node", "x", "miniscript"),
    (f"wsh(and_v(v:pk({A}),older(5)))", lambda d: d.inner.node, "subs", "x", "subs"),
]


@pytest.mark.parametrize("descriptor, part, field, value, message", FORGED)
def test_an_unpickled_descriptor_is_asked_its_fields(
    descriptor: str,
    part: Callable[[Any], Any],
    field: str,
    value: object,
    message: str,
) -> None:
    """Unpickling skips the build, so the paths ask its fields again."""
    forged = pickle.loads(pickle.dumps(parse(descriptor)))  # noqa: S301
    object.__setattr__(part(forged), field, value)
    with pytest.raises(BTClibTypeError, match=message):
        _ = forged.spending_paths


def test_paths_whose_rest_keys_collide_are_compared_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rest key is a sum of hashes, so two that match are checked."""
    monkeypatch.setattr(Quorum, "__hash__", lambda _: 0)
    expression = (
        f"or_i(and_v(v:or_i(pk({A}),pk({B})),or_i(pk({C}),pk({D}))),"
        f"and_v(v:or_i(pk({E}),pk({F})),or_i(pk({G}),pk({H}))))"
    )
    assert shapes(parse_miniscript(expression).spending_paths) == [
        (((1, "AB"), (1, "CD")), None, None, (), None),
        (((1, "EF"), (1, "GH")), None, None, (), None),
    ]


def test_a_merge_into_a_path_held_already_lists_it_once() -> None:
    """Two paths whose merge another merge gave first are that path.

    (AB CD | EF) shares no rest as it comes in; (AB | GH) and (CD | GH)
    merge into (ABCD | GH), (CD | EFGH) and (AB | EFGH) into
    (ABCD | EFGH); then (ABCD | GH) merges with (ABCD | EF) first,
    into the path the second merge gave.
    """

    def either(*names: str) -> str:
        if len(names) == 1:
            return f"pk({names[0]})"
        half = len(names) // 2
        return f"or_i({either(*names[:half])},{either(*names[half:])})"

    def both(first: tuple[str, ...], second: tuple[str, ...]) -> str:
        return f"and_v(v:{either(*first)},{either(*second)})"

    left = (
        f"or_i(or_i({both((A, B, C, D), (E, F))},{both((A, B), (G, H))}),"
        f"{both((C, D), (E, F, G, H))})"
    )
    right = f"or_i({both((C, D), (G, H))},{both((A, B), (E, F, G, H))})"
    paths = parse_miniscript(f"or_i({left},{right})").spending_paths
    assert shapes(paths) == [(((1, "ABCD"), (1, "EFGH")), None, None, (), None)]


def test_an_unpickled_miniscript_is_asked_its_derived_fields() -> None:
    """A fragment changed under its cached type is refused, not read."""
    built = parse_miniscript(f"and_v(v:pk({A}),older(5))")
    node = pickle.loads(pickle.dumps(built))  # noqa: S301
    object.__setattr__(node, "fragment", "and_b")
    with pytest.raises(BTClibValueError, match="its build does not compute"):
        _ = node.spending_paths


def test_an_unpickled_miniscript_is_asked_its_nodes() -> None:
    """A node of the wrong type, or of the wrong shape, is refused first."""
    for field, value, message in (
        ("subs", ("x", "y"), "miniscript node"),
        ("data", 5, "data"),
    ):
        built = parse_miniscript(f"and_v(v:pk({A}),sha256({DIGEST['sha256']}))")
        node = pickle.loads(pickle.dumps(built))  # noqa: S301
        target = node if field == "subs" else node.subs[1]
        object.__setattr__(target, field, value)
        with pytest.raises(BTClibTypeError, match=message):
            _ = node.spending_paths


@pytest.mark.parametrize(
    "internal_key",
    [NUMS, f"03{NUMS}", f"{NUMS_XPUB}/0/*", f"[aabbccdd/1]{NUMS_XPUB}/1/*"],
)
def test_a_key_path_nobody_can_sign_is_left_out(internal_key: str) -> None:
    """BIP341's H, of either parity, and an extended key of it, as Liana's."""
    descriptor = parse(f"tr({internal_key},pk({B[2:]}))")
    assert shapes(descriptor.spending_paths) == [(((1, "B"),), None, None, (), 0)]


def test_a_musig_key_path_is_one_key() -> None:
    """The aggregate signs, whose participants are its own field."""
    descriptor = parse(f"tr(musig({A},{B}))")
    [path] = descriptor.spending_paths
    [quorum] = path.quorums
    [key] = quorum.keys
    assert key.is_aggregate
    assert [str(participant) for participant in key.participants] == [A, B]


def test_a_placeholder_key_path_is_listed() -> None:
    """A wallet-policy stand-in is no key of H."""
    key = KeyExpression(xkey="@0/**")
    descriptor = TrDescriptor(key)
    assert descriptor.spending_paths == (SpendingPath((Quorum(1, (key,)),)),)


def test_a_ranged_key_is_its_expression() -> None:
    """A path names KEY expressions, so one list holds at every index."""
    descriptor = parse(f"wsh(and_v(v:pk({XPUB}/0/*),older(144)))")
    [path] = descriptor.spending_paths
    assert [str(key) for key in path.quorums[0].keys] == [f"{XPUB}/0/*"]


def test_the_bound_on_the_paths_of_a_tr() -> None:
    """Leaves add up to the same bound a miniscript's paths do."""
    internal_key = KeyExpression(pub_key=bytes.fromhex(A))
    tree: Any = KeyExpression(pub_key=bytes.fromhex(B))
    for _ in range(9):
        tree = (tree, tree)
    assert len(TrDescriptor(internal_key, tree).spending_paths) == 513
    with pytest.raises(BTClibValueError, match="more than 1000 spending paths"):
        _ = TrDescriptor(internal_key, (tree, tree)).spending_paths


def test_a_tapscript_leaf_is_read_in_its_context() -> None:
    """A multi_a() of a tapscript miniscript is a quorum like a multi()."""
    node = parse_miniscript(
        f"and_v(v:multi_a(2,{A[2:]},{B[2:]},{C[2:]}),older(10))", TAPSCRIPT
    )
    assert shapes(node.spending_paths) == [(((2, "ABC"),), 10, None, (), None)]


KEY = KeyExpression(pub_key=bytes.fromhex(A))


@pytest.mark.parametrize(
    "build, error, message",
    [
        (lambda: Quorum(True, (KEY,)), BTClibTypeError, "invalid threshold type"),
        (lambda: Quorum(1, [KEY]), BTClibTypeError, "keys"),  # type: ignore[arg-type]
        (lambda: Quorum(1, (A,)), BTClibTypeError, "key"),  # type: ignore[arg-type]
        (lambda: Quorum(0, (KEY,)), BTClibValueError, "not from 1 to 1"),
        (lambda: Quorum(2, (KEY,)), BTClibValueError, "invalid quorum"),
        (lambda: Quorum(10**5000, (KEY,)), BTClibValueError, "invalid quorum"),
        (lambda: SpendingPath([]), BTClibTypeError, "quorums"),  # type: ignore[arg-type]
        (lambda: SpendingPath(((1, (KEY,)),)), BTClibTypeError, "quorum"),  # type: ignore[arg-type]
        (lambda: SpendingPath(older=True), BTClibTypeError, "invalid older type"),
        (lambda: SpendingPath(after=1.5), BTClibTypeError, "invalid after type"),  # type: ignore[arg-type]
        (lambda: SpendingPath(older=0), BTClibValueError, r"invalid older\(\) value"),
        (lambda: SpendingPath(older=10**5000), BTClibValueError, r"invalid older"),
        (
            lambda: SpendingPath(after=2**31),
            BTClibValueError,
            r"not from 1 to 2147483647",
        ),
        (lambda: SpendingPath(hashes=[]), BTClibTypeError, "hashes"),  # type: ignore[arg-type]
        (lambda: SpendingPath(hashes=(["sha256", b""],)), BTClibTypeError, "hash"),  # type: ignore[arg-type]
        (lambda: SpendingPath(hashes=(("sha256",),)), BTClibValueError, "a fragment"),  # type: ignore[arg-type]
        (lambda: SpendingPath(hashes=((1, b""),)), BTClibTypeError, "hash fragment"),  # type: ignore[arg-type]
        (lambda: SpendingPath(hashes=(("sha256", ""),)), BTClibTypeError, "digest"),  # type: ignore[arg-type]
        (lambda: SpendingPath(hashes=(("md5", b""),)), BTClibValueError, "unknown"),
        (
            lambda: SpendingPath(hashes=(("sha256", bytes(20)),)),
            BTClibValueError,
            "sha256 takes 32 bytes",
        ),
        (lambda: SpendingPath(leaf=False), BTClibTypeError, "invalid leaf type"),
        (lambda: SpendingPath(leaf=-1), BTClibValueError, "negative leaf"),
        (lambda: SpendingPath(leaf=-(10**5000)), BTClibValueError, "negative leaf"),
    ],
)
def test_a_path_refuses_what_no_path_holds(
    build: Callable[[], object], error: type[Exception], message: str
) -> None:
    """Each field is refused for its type, and then for its value."""
    with pytest.raises(error, match=message):
        build()


def test_a_path_holds_what_a_walk_gives() -> None:
    """The same fields the refusals are around, built by hand."""
    path = SpendingPath(
        (Quorum(1, (KEY,)),), 1, 2**31 - 1, (("hash160", bytes(20)),), 0
    )
    assert (path.older, path.after, path.leaf) == (1, 2**31 - 1, 0)
