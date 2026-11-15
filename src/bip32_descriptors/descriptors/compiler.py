# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# The compiler below is a port of sipa/miniscript's compiler.cpp, at
# 6806dfb15a1fafabf7dd28aae3c9d2bc49db01f1, under its notice:
#
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A spending policy compiled to a miniscript that enforces it, as sipa's is.

A policy says who may spend and from when: ``pk(KEY)``, ``after(N)``,
``older(N)``, the four hash locks, and ``and()``, ``or()`` and
``thresh()`` over them. ``or()`` weighs its two branches by how likely
each is to be the one spent, as in ``or(9@pk(A),pk(B))``, where a missing
weight is 1. The miniscript that enforces a policy is a choice among many
-- which fragment carries each ``and`` and ``or``, and which wrappers make
the types fit -- and `compile_policy` makes it as sipa's compiler does:
of the non-malleable P2WSH candidates its search builds that need a
signature, the one whose script plus its expected satisfaction costs
fewest bytes. The search does not build every miniscript, so one that
costs less can exist: ``and(pk(A),and(older(1),older(1)))`` compiles
to a script three bytes longer than ``and(pk(A),older(1))`` does, with
the same spending paths.

This is sipa/miniscript's compiler, the one behind its website. Its
grammar is the policy language here, except that a key is a KEY
expression, as in a descriptor, where sipa's names a key by a short
string. Its search is ported step for step, so that a policy compiles to
what sipa's compiler answers: each policy node gets a list of
strategies, each strategy is compiled for a pair of probabilities, and a
compilation keeps, per type, the cheapest result.

The compiler is P2WSH only, as sipa's is: it has no tapscript compiler,
and a ``tr()`` script tree needs one that also splits the policy into
leaves.

The search grows exponentially with nested ``or()``, as sipa's does,
and a ``thresh()`` that any one argument satisfies is such a nest: each
level compiles its branches for more pairs of probabilities than the
level above. So
`compile_policy` bounds it, as sipa does not: it refuses a policy nested
past `_MAX_NESTING` brackets or `_MAX_DEPTH` strategies, which keeps the
search's recursion inside Python's default limit, and a compilation past
`_MAX_STEPS` steps, which bounds its time.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from btclib.exceptions import BTClibValueError
from btclib.utils import assert_type

from bip32_descriptors.bip32.der_path import _int_from_digits
from bip32_descriptors.descriptors.key_expression import (
    KeyExpression,
    _parse_key,
    _split_arguments,
)
from bip32_descriptors.descriptors.miniscript import P2WSH, Miniscript

__all__ = ["compile_policy"]

# sipa's bound on the arguments of a policy thresh()
_MAX_THRESH_ARGUMENTS = 100

# the keys sipa's compiler still tries as one multi(): a thresh() of keys
# alone, up to multi()'s own bound
_MAX_MULTI_KEYS = 20

# a candidate whose cost passes this is dropped, as sipa drops it
_MAX_COST = 10000

# how deep a policy may nest, in brackets: the parser and the strategies
# recurse once per level
_MAX_NESTING = 80

# how deep the strategies may nest. The search recurses about twice per
# level: once per level of the policy and once per argument of a
# thresh() of one or of all of its arguments, which sipa compiles as a
# chain of or() or and(). This keeps it a few hundred frames deep, inside
# Python's default limit of a thousand
_MAX_DEPTH = 250

# the most steps a compilation takes, a step being a candidate node built,
# its type and bounds computed, or a compilation started. Each takes some
# microseconds, so this is a few seconds and some hundred megabytes. A
# thresh() of one of ten keys compiles within it, and one of eleven does not
_MAX_STEPS = 500_000

# the hash locks, and the size of the digest each takes
_HASHES = {"sha256": 32, "hash256": 32, "ripemd160": 20, "hash160": 20}

# the largest weight of an or() branch, where sipa caps it
_MAX_PROBABILITY = 0xFFFF

# 1 <= n < 2**31 for after() and older(), as sipa reads them
_MAX_TIMELOCK = 0x80000000

_INF = math.inf


@dataclass(frozen=True, eq=False)
class _Policy:
    """A node of a policy: its kind and its arguments.

    `subs` are the arguments of ``and()``, ``or()`` and ``thresh()``,
    `weights` the weight of each ``or()`` branch, `number` the lock time
    of ``after()`` and ``older()`` and the threshold of ``thresh()``,
    `key` the key of ``pk()`` and `data` the digest of a hash lock.
    Compared by identity, as sipa caches a strategy per node.
    """

    kind: str
    subs: tuple[_Policy, ...]
    weights: tuple[int, ...]
    number: int
    key: KeyExpression | None
    data: bytes


def _call(text: str) -> tuple[str, str]:
    """Return the name of a policy call and what its brackets hold."""
    opening = text.find("(")
    if opening < 1 or not text.endswith(")"):
        raise BTClibValueError("invalid policy: a call such as pk(KEY) expected")
    return text[:opening], text[opening + 1 : -1]


def _number(name: str, argument: str) -> int:
    """Return the number a lock time or a threshold is, as digits."""
    if not argument.isascii() or not argument.isdigit():
        raise BTClibValueError(f"invalid {name}() number: digits expected")
    return _int_from_digits(argument, f"{name}() number")


def _weighted(argument: str) -> tuple[int, str]:
    """Return the weight of an or() branch and the branch.

    sipa's ``ParseProb``: digits not starting with 0, then ``@``; a weight
    past `_MAX_PROBABILITY` is read as that.
    """
    at = argument.find("@")
    digits = argument[:at] if at > 0 else ""
    if not digits or not digits.isascii() or not digits.isdigit():
        return 1, argument
    if digits[0] == "0":
        raise BTClibValueError("invalid or() weight: it starts with 0")
    weight = _int_from_digits(digits, "or() weight")
    return min(weight, _MAX_PROBABILITY), argument[at + 1 :]


def _parse(text: str) -> _Policy:
    """Return the policy a text writes, refusing what sipa's parser refuses."""
    name, inner = _call(text)
    if name in {"and", "or", "thresh"}:
        return _parse_combination(name, inner)
    return _parse_leaf(name, inner)


def _parse_leaf(name: str, inner: str) -> _Policy:
    """Return a key, a lock time or a hash lock, from what its brackets hold."""
    if name == "pk":
        prv_keys: dict[str, str] = {}
        key = _parse_key(
            inner, prv_keys, x_only=False, compressed=True, musig_allowed=False
        )
        if prv_keys or key.wif_prefix:
            raise BTClibValueError("invalid policy: a private key in pk()")
        return _Policy("pk", (), (), 0, key, b"")
    if name in {"after", "older"}:
        number = _number(name, inner)
        if not 1 <= number < _MAX_TIMELOCK:
            raise BTClibValueError(f"invalid {name}() value: {number}")
        return _Policy(name, (), (), number, None, b"")
    if name in _HASHES:
        size = _HASHES[name]
        if len(inner) != 2 * size or not _is_hex(inner):
            raise BTClibValueError(f"invalid {name}() digest: {size} bytes of hex")
        return _Policy(name, (), (), 0, None, bytes.fromhex(inner))
    raise BTClibValueError("invalid policy: unknown call")


def _parse_combination(name: str, inner: str) -> _Policy:
    """Return an and(), an or() or a thresh(), from what its brackets hold."""
    if name in {"and", "or"}:
        arguments = _split_arguments(inner)
        if len(arguments) != 2:
            raise BTClibValueError(f"{name}() takes two arguments")
        if name == "and":
            subs = tuple(_parse(sub) for sub in arguments)
            return _Policy("and", subs, (), 0, None, b"")
        weighted = [_weighted(sub) for sub in arguments]
        subs = tuple(_parse(sub) for _, sub in weighted)
        weights = tuple(weight for weight, _ in weighted)
        return _Policy("or", subs, weights, 0, None, b"")
    threshold, *arguments = _split_arguments(inner)
    number = _number(name, threshold)
    if not arguments or len(arguments) > _MAX_THRESH_ARGUMENTS:
        err_msg = f"thresh() takes 1 to {_MAX_THRESH_ARGUMENTS} arguments"
        raise BTClibValueError(err_msg)
    if not 1 <= number <= len(arguments):
        err_msg = f"invalid thresh() threshold: {number} of {len(arguments)}"
        raise BTClibValueError(err_msg)
    subs = tuple(_parse(sub) for sub in arguments)
    return _Policy("thresh", subs, (), number, None, b"")


def _is_hex(text: str) -> bool:
    """Answer whether the text is hex digits and nothing else."""
    return text.isascii() and all(char in "0123456789abcdefABCDEF" for char in text)


def _assert_nesting(text: str) -> None:
    """Refuse a policy nested deeper than `_MAX_NESTING` brackets."""
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
            if depth > _MAX_NESTING:
                err_msg = f"policy nested deeper than {_MAX_NESTING} brackets"
                raise BTClibValueError(err_msg)
        elif char == ")":
            depth -= 1


class _Strategy:
    """A way to compile a policy node, sipa's strategy.

    `kind` is a fragment for the strategies that build one -- a leaf, a
    wrapper, a conjunction or a disjunction -- or one of three that
    combine others: ``alternatives`` compiles each of its `subs`;
    ``cache`` compiles its first and then improves the result with the
    rest, which refer back to it, until none improves it; and ``as``
    is the ``a:`` and ``s:`` wrappers together. `prob` is how likely
    the first branch of a disjunction is, `k` the threshold.
    """

    __slots__ = ("data", "depth", "k", "keys", "kind", "prob", "subs")

    def __init__(
        self,
        kind: str,
        subs: Sequence[_Strategy],
        keys: tuple[KeyExpression, ...],
        data: bytes,
        k: int,
        prob: float,
    ) -> None:
        self.kind = kind
        self.subs = list(subs)
        self.depth: int = 1 + max((sub.depth for sub in subs), default=0)
        self.keys = keys
        self.data = data
        self.k = k
        self.prob = prob


def _combined(kind: str, subs: Sequence[_Strategy], prob: float) -> _Strategy:
    """Return a strategy over others, as sipa makes one."""
    return _Strategy(kind, subs, (), b"", 0, prob)


def _leaf(kind: str, keys: tuple[KeyExpression, ...], data: bytes, k: int) -> _Strategy:
    """Return a strategy of a leaf, as sipa makes one."""
    return _Strategy(kind, (), keys, data, k, 0.0)


_STRATEGY_FALSE = _combined("cache", [_leaf("0", (), b"", 0)], 0.0)
_STRATEGY_TRUE = _combined("cache", [_leaf("1", (), b"", 0)], 0.0)


def _strategy(node: _Policy, cache: dict[_Policy, _Strategy]) -> _Strategy:
    """Return the strategy of a policy node, sipa's ``GetStrategy``."""
    found = cache.get(node)
    if found is None:
        found = cache[node] = _computed_strategy(node, cache)
    return found


def _computed_strategy(node: _Policy, cache: dict[_Policy, _Strategy]) -> _Strategy:
    """Return the strategies of a policy node, sipa's ``ComputeStrategy``.

    A cached choice among them, which the wrappers then improve: each of
    the last `subs` of the ``cache`` refers back to it.
    """
    kind = node.kind
    strategies: list[_Strategy] = []
    if kind == "pk" and node.key is not None:
        strategies.append(_leaf("pk", (node.key,), b"", 0))
    elif kind in {"after", "older"}:
        strategies.append(_leaf(kind, (), b"", node.number))
    elif kind in _HASHES:
        strategies.append(_leaf(kind, (), node.data, 0))
    elif kind == "and":
        left, right = (_strategy(sub, cache) for sub in node.subs)
        and_ = _combined("and", [left, right], 0.0)
        andor = _combined("andor", [left, right, _STRATEGY_FALSE], 1.0)
        strategies.extend((and_, andor))
    elif kind == "or":
        strategies.extend(_or_strategies(node, cache))
    else:
        strategies.extend(_thresh_strategies(node, cache))
    if len(strategies) != 1:
        strategies = [_combined("alternatives", strategies, 0.0)]
    ret = _combined("cache", strategies, 0.0)
    ret.subs.extend(
        (
            _combined("c:", [ret], 0.0),
            _combined("v:", [ret], 0.0),
            _combined("and", [ret, _STRATEGY_TRUE], 0.0),
            _combined("n:", [ret], 0.0),
            _combined("d:", [ret], 0.0),
            _combined("j:", [ret], 0.0),
            _combined("or", [ret, _STRATEGY_FALSE], 1.0),
            _combined("as", [ret], 0.0),
        )
    )
    return ret


def _or_strategies(node: _Policy, cache: dict[_Policy, _Strategy]) -> list[_Strategy]:
    """Return the strategies of an or(), and an andor() for an and() branch."""
    first, second = node.weights
    prob = first / (first + second)
    left, right = (_strategy(sub, cache) for sub in node.subs)
    strategies = []
    if node.subs[0].kind == "and":
        x, y = (_strategy(sub, cache) for sub in node.subs[0].subs)
        strategies.append(_combined("andor", [x, y, right], prob))
    if node.subs[1].kind == "and":
        x, y = (_strategy(sub, cache) for sub in node.subs[1].subs)
        strategies.append(_combined("andor", [x, y, left], 1.0 - prob))
    andor = _combined("andor", [left, _STRATEGY_TRUE, right], prob)
    strategies.extend((andor, _combined("or", [left, right], prob)))
    return strategies


def _thresh_strategies(
    node: _Policy, cache: dict[_Policy, _Strategy]
) -> list[_Strategy]:
    """Return the strategies of a thresh().

    A multi() where every argument is a key and there are few enough; a
    chain of or() for a threshold of one, and of and() for a threshold of
    all; and a thresh(). Where the threshold is all of more than one
    argument, sipa also tries a thresh() of the chain alone, under that
    threshold, which no build gives a type and which is left out here.
    """
    subs = [_strategy(sub, cache) for sub in node.subs]
    strategies = []
    if len(node.subs) <= _MAX_MULTI_KEYS and all(sub.kind == "pk" for sub in node.subs):
        keys = tuple(sub.key for sub in node.subs if sub.key is not None)
        strategies.append(_leaf("multi", keys, b"", node.number))
    if node.number in {1, len(node.subs)}:
        kind = "or" if node.number == 1 else "and"
        while len(subs) > 1:
            rep = _combined(kind, [subs[-2], subs[-1]], 1.0 / len(subs))
            del subs[-2:]
            subs.append(_combined("cache", [rep], 0.0))
        strategies.append(subs[0])
        if node.number != 1:
            return strategies
    prob = node.number / len(subs)
    strategies.append(_Strategy("thresh", subs, (), b"", node.number, prob))
    return strategies


# sipa's type bits, in its order: `_Compilation.query` sorts by them, so
# the order decides which of two equally good candidates is kept
_TYPE_BITS = {char: 1 << bit for bit, char in enumerate("BVKWzonduefsmxghijk")}


def _mask(text: str) -> int:
    """Return the type bits of a string of properties."""
    mask = 0
    for char in text:
        mask |= _TYPE_BITS[char]
    return mask


_MASKS: dict[frozenset[str], int] = {}


def _type(node: Miniscript) -> int:
    """Return the type bits of a node."""
    properties = node.properties
    mask = _MASKS.get(properties)
    if mask is None:
        mask = _MASKS[properties] = _mask("".join(properties))
    return mask


def _filter(text: str) -> tuple[int, int]:
    """Return a type filter, sipa's ``_mstf``: what it requires and what counts.

    A query keeps, per combination of the properties that count, the best
    result holding every property required.
    """
    required, _, counted = text.partition("/")
    return _mask(required), _mask(counted)


_M = _mask("m")
_K = _mask("k")


@dataclass(frozen=True)
class _Result:
    """A candidate: its node, its costs and its type."""

    node: Miniscript
    sat: float
    nsat: float
    cost: float
    type: int

    def compare(self, cost: float, node: Miniscript) -> int:
        """Return -1, 0 or 1 as this result is better, as good or worse.

        Cheaper is better; at equal cost, the larger script, its
        satisfaction being the cheaper.
        """
        if self.cost != cost:
            return -1 if self.cost < cost else 1
        if self.node.script_size != node.script_size:
            return -1 if self.node.script_size > node.script_size else 1
        return 0


def _mul(coef: float, value: float) -> float:
    """Return the product, zero where the coefficient is, sipa's ``Mul``."""
    return 0.0 if coef == 0 else coef * value


class _Compilation:
    """The best results of a strategy under one pair of probabilities.

    `p` is how likely the expression is to be satisfied and `q` to be
    dissatisfied, so its cost is its script plus `p` times its
    satisfaction and `q` times its dissatisfaction. `seq` counts the
    results added, which tells a ``cache`` when its improvements stop.
    """

    __slots__ = ("p", "q", "results", "seq")

    def __init__(self, p: float, q: float) -> None:
        self.p = p
        self.q = q
        self.results: list[_Result] = []
        self.seq = 0

    def add(self, sat: float, nsat: float, node: Miniscript) -> None:
        """Add a candidate, dropping it or the results it beats.

        A candidate that is malleable, mixes timelocks or passes P2WSH's
        limits is dropped, and so is one a result of a subtype beats.
        """
        if not node.properties or not node.is_within_resource_limits:
            return
        new_type = _type(node)
        if new_type & (_M | _K) != _M | _K:
            return
        cost = node.script_size + _mul(self.p, sat) + _mul(self.q, nsat)
        if cost > _MAX_COST:
            return
        for x in self.results:
            if new_type & ~x.type == 0 and x.compare(cost, node) <= 0:
                return
        self.results = [
            x
            for x in self.results
            if x.type & ~new_type != 0 or x.compare(cost, node) < 0
        ]
        self.results.append(_Result(node, sat, nsat, cost, new_type))
        self.seq += 1

    def query(self, type_filter: tuple[int, int]) -> list[_Result]:
        """Return the best result per type, of those the filter admits."""
        required, counted = type_filter
        best: dict[int, _Result] = {}
        for x in self.results:
            if required & ~x.type == 0:
                masked = x.type & counted
                kept = best.get(masked)
                if kept is None or x.compare(kept.cost, kept.node) < 0:
                    best[masked] = x
        return [best[masked] for masked in sorted(best)]


class _Search:
    """One compilation's cache, and the count of its steps."""

    __slots__ = ("cache", "steps")

    def __init__(self) -> None:
        self.cache: dict[tuple[_Strategy, float, float], _Compilation] = {}
        self.steps = 0

    def step(self) -> None:
        """Count a step, refusing the one past `_MAX_STEPS`."""
        self.steps += 1
        if self.steps > _MAX_STEPS:
            err_msg = f"policy too large to compile: past {_MAX_STEPS} steps"
            raise BTClibValueError(err_msg)


def _cost_pair(  # noqa: C901, PLR0911, PLR0912
    fragment: str, s: Sequence[_Result], left: float
) -> tuple[float, float]:
    """Return the costs of satisfying a node or not, sipa's ``CalcCostPair``.

    In bytes of witness, from those of its subexpressions; `left` is how
    likely the first branch of a disjunction is to be taken, sipa's ``l``.
    """
    right = 1.0 - left
    if fragment == "pk_k":
        return 73, 1
    if fragment == "pk_h":
        return 107, 35
    if fragment in {"older", "after", "1"}:
        return 0, _INF
    if fragment in _HASHES:
        return 33, 33
    if fragment in {"a:", "s:", "c:", "n:"}:
        return s[0].sat, s[0].nsat
    if fragment == "d:":
        return 2 + s[0].sat, 1
    if fragment == "v:":
        return s[0].sat, _INF
    if fragment == "j:":
        return s[0].sat, 1
    if fragment == "0":
        return _INF, 0
    if fragment == "and_v":
        return s[0].sat + s[1].sat, _INF
    if fragment == "and_b":
        return s[0].sat + s[1].sat, s[0].nsat + s[1].nsat
    if fragment == "or_b":
        return (
            _mul(left, s[0].sat + s[1].nsat) + _mul(right, s[0].nsat + s[1].sat),
            s[0].nsat + s[1].nsat,
        )
    if fragment in {"or_c", "or_d"}:
        return (
            _mul(left, s[0].sat) + _mul(right, s[0].nsat + s[1].sat),
            s[0].nsat + s[1].nsat,
        )
    if fragment == "or_i":
        return (
            _mul(left, s[0].sat + 2) + _mul(right, s[1].sat + 1),
            min(2 + s[0].nsat, 1 + s[1].nsat),
        )
    if fragment == "andor":
        return (
            _mul(left, s[0].sat + s[1].sat) + _mul(right, s[0].nsat + s[2].sat),
            s[0].nsat + s[2].nsat,
        )
    if fragment == "multi":
        return 1.0 + left * 73.0, 1.0 + left
    sat = 0.0
    nsat = 0.0
    for sub in s:
        sat += sub.sat
        nsat += sub.nsat
    return _mul(left, sat) + _mul(right, nsat), nsat


def _probabilities(  # noqa: PLR0911
    fragment: str, p: float, q: float, left: float, m: int
) -> tuple[list[float], list[float]]:
    """Return what each subexpression is compiled for, sipa's ``GetPQs``.

    How likely each is to be satisfied, and how likely dissatisfied,
    given those of the node and how likely its first branch is.
    """
    right = 1.0 - left
    if fragment in {"a:", "s:", "c:", "n:"}:
        return [p], [q]
    if fragment in {"d:", "v:", "j:"}:
        return [p], [0]
    if fragment in {"and_v", "and_b"}:
        return [p, p], [q, q]
    if fragment == "or_b":
        return [left * p, right * p], [right * p + q, left * p + q]
    if fragment == "or_d":
        return [left * p, right * p], [right * p + q, q]
    if fragment == "or_c":
        return [left * p, right * p], [right * p, 0]
    if fragment == "or_i":
        return [left * p, right * p], [q if m == 0 else 0, q if m == 1 else 0]
    # the one left, andor()
    return [left * p, left * p, right * p], [q + right * p, 0, q]


# sipa's ``GetTypeFilter``: for each fragment, the rows of what its
# subexpressions are queried for, one filter per subexpression
_FILTERS: dict[str, list[list[tuple[int, int]]]] = {
    "a:": [[_filter("B/udfems")]],
    "s:": [[_filter("Bo/udfemsx")]],
    "c:": [[_filter("K/onde")]],
    "d:": [[_filter("V/zfms")]],
    "v:": [[_filter("B/zonmsx")]],
    "j:": [[_filter("Bn/oufms")]],
    "n:": [[_filter("B/zondfems")]],
    "and_v": [
        [_filter("V/nzoms"), _filter("B/unzofmsx")],
        [_filter("V/nsoms"), _filter("K/unzofmsx")],
        [_filter("V/nzoms"), _filter("V/unzofmsx")],
    ],
    "and_b": [[_filter("B/zondfems"), _filter("W/zondfems")]],
    "or_b": [[_filter("Bde/zoms"), _filter("Wde/zoms")]],
    "or_d": [[_filter("Bdue/zoms"), _filter("B/zoudfems")]],
    "or_c": [[_filter("Bdue/zoms"), _filter("V/zoms")]],
    "or_i": [
        [_filter("V/zudfems"), _filter("V/zudfems")],
        [_filter("B/zudfems"), _filter("B/zudfems")],
        [_filter("K/zudfems"), _filter("K/zudfems")],
    ],
    "andor": [
        [_filter("Bdue/zoms"), _filter("B/zoufms"), _filter("B/zoudfems")],
        [_filter("Bdue/zoms"), _filter("K/zoufms"), _filter("K/zoudfems")],
        [_filter("Bdue/zoms"), _filter("V/zoufms"), _filter("V/zoudfems")],
    ],
}

_THRESH_B = _filter("Bemdu")
_THRESH_W = _filter("Wemdu")
_TOP = _filter("Bms")
_TOP_SIGLESS = _filter("Bm")


def _add_inner(
    compilation: _Compilation,
    search: _Search,
    fragment: str,
    resp: Sequence[_Result],
    prob: float,
    *,
    keys: tuple[KeyExpression, ...],
    k: int,
    data: bytes,
) -> None:
    """Build one candidate node and add it, sipa's ``AddInner``."""
    search.step()
    node = Miniscript(
        fragment,
        P2WSH,
        tuple(res.node for res in resp),
        keys=keys,
        threshold=k,
        data=data,
    )
    sat, nsat = _cost_pair(fragment, resp, prob)
    compilation.add(sat, nsat, node)


def _add_leaf(
    compilation: _Compilation,
    search: _Search,
    fragment: str,
    keys: tuple[KeyExpression, ...],
    k: int,
    data: bytes,
) -> None:
    """Add the node of a leaf, sipa's ``Add`` for a fragment of no arguments.

    A ``multi()`` is costed with its threshold where a disjunction is
    with its probability, as sipa costs it.
    """
    prob = float(k) if fragment == "multi" else 0.0
    _add_inner(compilation, search, fragment, [], prob, keys=keys, k=k, data=data)


def _add(
    compilation: _Compilation,
    search: _Search,
    fragment: str,
    subs: Sequence[_Strategy],
    prob: float,
    m: int,
) -> None:
    """Add every node of a fragment over the best results of its arguments.

    sipa's ``Add``: for each row of the fragment's type filters, each
    combination of what the queries of its subexpressions return. `m`
    tells the two ``or_i()`` apart, as its dissatisfaction is either
    branch's.
    """
    ps, qs = _probabilities(fragment, compilation.p, compilation.q, prob, m)
    for row in _FILTERS[fragment]:
        found = []
        combinations = 1
        for position, sub in enumerate(subs):
            sub_compilation = _compilation(sub, ps[position], qs[position], search)
            found.append(sub_compilation.query(row[position]))
            combinations *= len(found[-1])
        for combination in range(combinations):
            c = combination
            resp = []
            for results in found:
                resp.append(results[c % len(results)])
                c //= len(results)
            _add_inner(
                compilation, search, fragment, resp, prob, keys=(), k=0, data=b""
            )


def _compilation(
    strategy: _Strategy, p: float, q: float, search: _Search
) -> _Compilation:
    """Return what a ``cache`` strategy compiles to, sipa's ``GetCompilation``.

    Its first strategy compiled, then each improvement in turn until a
    whole round of them adds nothing.
    """
    key = (strategy, p, q)
    found = search.cache.get(key)
    if found is not None:
        return found
    search.step()
    result = _Compilation(p, q)
    _compile(strategy.subs[0], result, search)
    search.cache[key] = result
    if len(strategy.subs) > 1:
        last = pos = 1
        while True:
            seq = result.seq
            _compile(strategy.subs[pos], result, search)
            if result.seq != seq:
                last = pos
            pos += 1
            if pos == len(strategy.subs):
                pos = 1
            if pos == last:
                break
    return result


def _compile(  # noqa: C901
    strategy: _Strategy, compilation: _Compilation, search: _Search
) -> None:
    """Add the results of a strategy to a compilation, sipa's ``Compile``."""
    kind = strategy.kind
    subs = strategy.subs
    if kind == "alternatives":
        for sub in subs:
            _compile(sub, compilation, search)
    elif kind == "cache":
        found = _compilation(strategy, compilation.p, compilation.q, search)
        for x in list(found.results):
            compilation.add(x.sat, x.nsat, x.node)
    elif not subs:
        _compile_leaf(strategy, compilation, search)
    elif kind == "as":
        _add(compilation, search, "a:", subs, 0, 0)
        _add(compilation, search, "s:", subs, 0, 0)
    elif kind in {"c:", "d:", "n:", "j:", "v:"}:
        _add(compilation, search, kind, subs, 0, 0)
    elif kind == "and":
        rev = [subs[1], subs[0]]
        if compilation.q == 0:
            _add(compilation, search, "and_v", subs, 0, 0)
            _add(compilation, search, "and_v", rev, 0, 0)
        _add(compilation, search, "and_b", subs, 0, 0)
        _add(compilation, search, "and_b", rev, 0, 0)
    elif kind == "or":
        _compile_or(strategy, compilation, search)
    elif kind == "andor":
        _add(compilation, search, "andor", subs, strategy.prob, 0)
        swapped = [subs[1], subs[0], subs[2]]
        _add(compilation, search, "andor", swapped, strategy.prob, 0)
    else:
        _compile_thresh(strategy, compilation, search)


def _compile_leaf(
    strategy: _Strategy, compilation: _Compilation, search: _Search
) -> None:
    """Add the results of a key, a lock time, a hash lock, 0 or 1."""
    kind = strategy.kind
    if kind in {"0", "1"}:
        _add_leaf(compilation, search, kind, (), 0, b"")
    elif kind in {"after", "older"}:
        _add_leaf(compilation, search, kind, (), strategy.k, b"")
    elif kind in _HASHES:
        _add_leaf(compilation, search, kind, (), 0, strategy.data)
    elif kind == "pk":
        _add_leaf(compilation, search, "pk_k", strategy.keys, 0, b"")
        _add_leaf(compilation, search, "pk_h", strategy.keys, 0, b"")
    else:
        _add_leaf(compilation, search, "multi", strategy.keys, strategy.k, b"")


def _compile_or(
    strategy: _Strategy, compilation: _Compilation, search: _Search
) -> None:
    """Add the four disjunctions, each both ways round."""
    subs = strategy.subs
    rev = [subs[1], subs[0]]
    left = strategy.prob
    right = 1.0 - left
    if compilation.q == 0:
        _add(compilation, search, "or_c", subs, left, 0)
        _add(compilation, search, "or_c", rev, right, 0)
    for fragment in ("or_b", "or_d", "or_i"):
        _add(compilation, search, fragment, subs, left, 0)
        _add(compilation, search, fragment, rev, right, 0)
    _add(compilation, search, "or_i", subs, left, 1)
    _add(compilation, search, "or_i", rev, right, 1)


def _compile_thresh(
    strategy: _Strategy, compilation: _Compilation, search: _Search
) -> None:
    """Add the thresh() of the best "B" of one argument and "W" of the rest.

    The argument that is a "B" is the one whose "W" costs the most more
    than its "B", and it goes first.
    """
    p, q = compilation.p, compilation.q
    count = len(strategy.subs)
    ps = [p * strategy.prob] * count
    qs = [q + p * (1.0 - strategy.prob)] * count
    bs = []
    ws = []
    b_pos = -1
    cost_diff = -1.0
    for position, sub in enumerate(strategy.subs):
        sub_compilation = _compilation(sub, ps[position], qs[position], search)
        res_b = sub_compilation.query(_THRESH_B)
        if not res_b:
            return
        bs.append(res_b[0])
        res_w = sub_compilation.query(_THRESH_W)
        if not res_w:
            return
        ws.append(res_w[0])
        if ws[-1].cost - bs[-1].cost > cost_diff:
            cost_diff = ws[-1].cost - bs[-1].cost
            b_pos = position
    resp = [bs[b_pos]] + [ws[i] for i in range(count) if i != b_pos]
    _add_inner(
        compilation,
        search,
        "thresh",
        resp,
        strategy.prob,
        keys=(),
        k=strategy.k,
        data=b"",
    )


def compile_policy(policy: str) -> Miniscript:
    """Return the P2WSH miniscript sipa's compiler answers for a policy.

    The policy is sipa/miniscript's language, with KEY expressions for
    keys: ``pk(KEY)``, ``after(N)`` and ``older(N)`` for 1 <= N < 2**31,
    ``sha256(H)``, ``hash256(H)``, ``ripemd160(H)`` and ``hash160(H)`` with
    a digest in hex, ``and(X,Y)``, ``or(X,Y)`` and ``thresh(K,X,...)`` of
    up to 100 arguments. A branch of an ``or()`` may carry a weight,
    ``N@``, how likely it is to be the one spent relative to the other: 1
    where it carries none, read as 65535 past that. Not to be confused
    with BIP388's wallet policies, which are descriptors with their keys
    taken out.

    The answer is what sipa's compiler answers, the expression a ``wsh()``
    descriptor holds: sane, as `Miniscript.is_sane` asks, so non-malleable
    and requiring a signature. Of the sane candidates sipa's search
    builds, it is the cheapest by the size of its script plus that of its
    expected satisfaction; a miniscript the search does not build can
    cost less, as the module docstring shows. Its spending paths are the
    policy's.

    Refused where the search finds no sane miniscript for the policy: one
    that can be satisfied without a signature, one that names a key twice,
    one whose every compilation found is malleable, mixes timelocks or
    passes P2WSH's limits; and past this library's bounds on the policy's
    depth and the compiler's work, which the module docstring names.
    """
    assert_type(policy, str, "policy")
    _assert_nesting(policy)
    root = _strategy(_parse(policy), {})
    if root.depth > _MAX_DEPTH:
        err_msg = f"policy too deep to compile: past {_MAX_DEPTH} strategies"
        raise BTClibValueError(err_msg)
    search = _Search()
    top = _compilation(root, 1.0, 0.0, search)
    found = top.query(_TOP)
    if not found:
        if top.query(_TOP_SIGLESS):
            raise BTClibValueError("policy can be satisfied without a signature")
        err_msg = (
            "no compilation the search finds is non-malleable, free of mixed "
            "timelocks and within P2WSH's limits"
        )
        raise BTClibValueError(err_msg)
    node = found[0].node
    if node.has_duplicate_keys():
        raise BTClibValueError("policy names a key more than once")
    return node
