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
from collections.abc import Callable
from typing import Any

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.key import PrvKeyData

from bip32_descriptors.bip32 import rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import (
    KeyExpression,
    Quorum,
    SpendContext,
    SpendingPath,
    TrDescriptor,
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
