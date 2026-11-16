# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# WEBSITE and GRAMMAR below are sipa/miniscript's, under its notice:
#
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# RUST is transcribed from rust-miniscript, which is under CC0-1.0, as
# each of its source files says: it waives every right and asks for no
# notice, and is named here all the same.

"""`compile_policy` against sipa/miniscript and rust-miniscript.

Issue btclib-org/bip32-descriptors#357. `compile_policy` is a port of
sipa/miniscript's compiler, so what that compiler answers is what it has
to answer, miniscript for miniscript:

- `WEBSITE` holds the example policies of sipa/miniscript's website,
  `GRAMMAR` policies drawn from its test grammar, `test.gram`, and
  `COMPOSED` policies composed here, with weights, every hash lock and
  both kinds of lock time, which the grammar does not draw. Each holds
  the miniscript sipa's compiler answers, or None where it compiles
  none.
- `RUST` holds the policies of rust-miniscript's compiler tests that
  compile for P2WSH, with what each test asserts of its answer.
  `RUST_DIFFERS` holds the one where sipa's compiler answers otherwise,
  with both answers, and the port answers sipa's.

`tests/_data/README.md` says which revisions, and how to record the
answers again.

A key is a name, as both upstreams write it, and each name is the key
of a small private key, in the order the policy first names it. A hash
lock's ``H`` is sipa's: a digest of eights, or of nines for a 20-byte
one.

Each answer is also checked against the policy: it is sane, it reads
back from its own text, and its spending paths are the policy's.
"""

from __future__ import annotations

import itertools
import re

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData
from btclib.script import ScriptPubKey
from btclib.script.script import serialize
from btclib.tx.limits import LOCKTIME_THRESHOLD, SEQUENCE_LOCKTIME_TYPE_FLAG

from bip32_descriptors.descriptors import SpendingPath, compiler, parse
from bip32_descriptors.descriptors.compiler import compile_policy
from bip32_descriptors.descriptors.miniscript import P2WSH, Miniscript
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript

# sipa's website, index.html: each of its examples and what sipa's
# compiler answers
WEBSITE = [
    ("pk(key_1)", "pk(key_1)"),
    ("or(pk(key_1),pk(key_2))", "or_b(pk(key_1),s:pk(key_2))"),
    (
        "or(99@pk(key_likely),pk(key_unlikely))",
        "or_d(pk(key_likely),pkh(key_unlikely))",
    ),
    (
        "and(pk(key_user),or(99@pk(key_service),older(12960)))",
        "and_v(v:pk(key_user),or_d(pk(key_service),older(12960)))",
    ),
    (
        "thresh(3,pk(key_1),pk(key_2),pk(key_3),older(12960))",
        "thresh(3,pk(key_1),s:pk(key_2),s:pk(key_3),sln:older(12960))",
    ),
    (
        "or(pk(key_revocation),and(pk(key_local),older(1008)))",
        "andor(pk(key_local),older(1008),pk(key_revocation))",
    ),
    (
        "or(pk(key_revocation),and(pk(key_remote),or(pk(key_local),hash160(H))))",
        "t:or_c(pk(key_revocation),and_v(v:pk(key_remote),or_c(pk(key_local),v:hash160(H))))",
    ),
    (
        "or(pk(key_revocation),and(pk(key_remote),or(and(pk(key_local),hash160(H)),older(1008))))",
        "andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))",
    ),
]

# drawn from sipa's test.gram, each pk(C) of a draw named apart
GRAMMAR = [
    ("pk(K1)", "pk(K1)"),
    ("and(pk(K1),pk(K2))", "and_v(v:pk(K1),pk(K2))"),
    (
        "thresh(3,after(9),pk(K1),pk(K2),and(thresh(2,after(9),pk(K3),pk(K4),pk(K5),pk(K6)),thresh(2,pk(K7),pk(K8),pk(K9))))",
        "thresh(3,j:and_v(v:multi(2,K7,K8,K9),thresh(2,ndv:after(9),s:pk(K3),s:pk(K4),s:pk(K5),s:pk(K6))),sln:after(9),s:pk(K1),s:pk(K2))",
    ),
    ("and(sha256(H),pk(K1))", "and_v(v:pk(K1),sha256(H))"),
    (
        "thresh(3,sha256(H),sha256(H),pk(K1),thresh(2,pk(K2),thresh(4,pk(K3),pk(K4),pk(K5),pk(K6),pk(K7)),pk(K8),thresh(2,after(9),pk(K9),pk(K10))))",
        "thresh(3,thresh(2,multi(4,K3,K4,K5,K6,K7),s:pk(K2),s:pk(K8),autv:thresh(2,ln:after(9),s:pk(K9),s:pk(K10))),sjtv:sha256(H),sjtv:sha256(H),s:pk(K1))",
    ),
    (
        "thresh(2,thresh(2,sha256(H),pk(K1),pk(K2),thresh(3,after(9),pk(K3),pk(K4),pk(K5),pk(K6)),thresh(3,pk(K7),pk(K8),pk(K9),pk(K10),pk(K11))),pk(K12),pk(K13))",
        "thresh(2,ltv:thresh(2,utv:thresh(3,pkh(K3),sln:after(9),s:pk(K4),s:pk(K5),s:pk(K6)),sjtv:sha256(H),s:pk(K1),s:pk(K2),a:multi(3,K7,K8,K9,K10,K11)),s:pk(K12),s:pk(K13))",
    ),
    ("thresh(2,after(9),pk(K1),pk(K2))", "thresh(2,pk(K1),sln:after(9),s:pk(K2))"),
    (
        "or(99@pk(K1),3@and(pk(K2),thresh(2,thresh(2,pk(K3),pk(K4),pk(K5)),thresh(2,after(9),pk(K6),pk(K7),pk(K8)),pk(K9),pk(K10),pk(K11))))",
        "or_d(pk(K1),and_v(v:pkh(K2),thresh(2,thresh(2,pkh(K3),a:pkh(K4),a:pkh(K5)),autv:thresh(2,pkh(K6),sln:after(9),a:pkh(K7),a:pkh(K8)),a:pkh(K9),a:pkh(K10),a:pkh(K11))))",
    ),
    ("or(pk(K1),pk(K2))", "or_b(pk(K1),s:pk(K2))"),
    (
        "and(sha256(H),and(pk(K1),and(thresh(4,after(9),after(9),after(9),pk(K2),pk(K3)),pk(K4))))",
        "and_v(v:sha256(H),and_v(v:pk(K1),and_v(v:pk(K4),thresh(4,ln:after(9),sln:after(9),sln:after(9),s:pk(K2),s:pk(K3)))))",
    ),
    (
        "thresh(2,pk(K1),thresh(2,or(3@and(after(9),pk(K2)),thresh(2,pk(K3),pk(K4),pk(K5),pk(K6),pk(K7))),pk(K8),thresh(2,after(9),pk(K9),pk(K10))),pk(K11))",
        "thresh(2,thresh(2,andor(pk(K2),n:after(9),utv:thresh(2,pkh(K3),a:pkh(K4),a:pkh(K5),a:pkh(K6),a:pkh(K7))),s:pk(K8),autv:thresh(2,pk(K9),sln:after(9),s:pk(K10))),s:pk(K1),s:pk(K11))",
    ),
    (
        "thresh(3,sha256(H),pk(K1),pk(K2),and(thresh(4,after(9),after(9),after(9),after(9),pk(K3)),pk(K4)))",
        "thresh(3,j:and_v(v:pk(K4),thresh(4,ln:after(9),sln:after(9),sln:after(9),sln:after(9),s:pk(K3))),sjtv:sha256(H),s:pk(K1),s:pk(K2))",
    ),
    (
        "or(and(pk(K1),thresh(4,thresh(3,after(9),after(9),pk(K2),pk(K3)),thresh(2,pk(K4),pk(K5),pk(K6),pk(K7)),or(pk(K8),pk(K9)),pk(K10),pk(K11))),pk(K12))",
        "andor(pk(K1),thresh(4,ltv:thresh(3,ln:after(9),sln:after(9),s:pk(K2),s:pk(K3)),a:multi(2,K4,K5,K6,K7),a:or_i(tv:pkh(K8),pk(K9)),s:pk(K10),s:pk(K11)),pk(K12))",
    ),
    (
        "thresh(2,sha256(H),thresh(2,pk(K1),thresh(2,pk(K2),pk(K3),pk(K4),pk(K5)),thresh(3,pk(K6),pk(K7),pk(K8),pk(K9)),pk(K10),and(pk(K11),pk(K12))),pk(K13))",
        "thresh(2,thresh(2,multi(2,K2,K3,K4,K5),s:pk(K1),a:multi(3,K6,K7,K8,K9),s:pk(K10),aj:and_v(v:pkh(K11),pkh(K12))),sjtv:sha256(H),s:pk(K13))",
    ),
    (
        "and(pk(K1),thresh(2,thresh(3,thresh(2,pk(K2),pk(K3),pk(K4),pk(K5),pk(K6)),pk(K7),pk(K8),pk(K9),pk(K10)),thresh(2,pk(K11),pk(K12),pk(K13)),pk(K14)))",
        "and_v(v:pk(K1),thresh(2,thresh(3,multi(2,K2,K3,K4,K5,K6),s:pk(K7),s:pk(K8),s:pk(K9),s:pk(K10)),a:multi(2,K11,K12,K13),s:pk(K14)))",
    ),
    ("or(99@pk(K1),pk(K2))", "or_d(pk(K1),pkh(K2))"),
    ("and(after(9),pk(K1))", "and_v(v:pk(K1),after(9))"),
    (
        "thresh(2,sha256(H),pk(K1),and(after(9),thresh(4,thresh(4,pk(K2),pk(K3),pk(K4),pk(K5),pk(K6)),pk(K7),pk(K8),pk(K9),pk(K10))))",
        "thresh(2,l:and_v(v:thresh(4,multi(4,K2,K3,K4,K5,K6),s:pk(K7),s:pk(K8),s:pk(K9),s:pk(K10)),n:after(9)),sjtv:sha256(H),s:pk(K1))",
    ),
    (
        "thresh(3,pk(K1),pk(K2),pk(K3),and(thresh(3,after(9),pk(K4),pk(K5),pk(K6)),thresh(3,after(9),pk(K7),pk(K8),pk(K9))))",
        "thresh(3,l:and_v(v:thresh(3,ln:after(9),s:pk(K4),s:pk(K5),s:pk(K6)),thresh(3,ln:after(9),s:pk(K7),s:pk(K8),s:pk(K9))),s:pk(K1),s:pk(K2),s:pk(K3))",
    ),
    (
        "and(pk(K1),and(or(thresh(3,pk(K2),pk(K3),pk(K4),pk(K5)),99@pk(K6)),thresh(3,after(9),pk(K7),pk(K8),pk(K9))))",
        "and_v(v:pk(K1),and_v(or_c(pk(K6),v:thresh(3,pkh(K2),a:pkh(K3),a:pkh(K4),a:pkh(K5))),thresh(3,ln:after(9),s:pk(K7),s:pk(K8),s:pk(K9))))",
    ),
    ("or(pk(K1),99@pk(K2))", "or_d(pk(K2),pkh(K1))"),
    (
        "and(pk(K1),thresh(2,after(9),thresh(2,thresh(3,after(9),after(9),after(9),pk(K2)),pk(K3),pk(K4)),thresh(2,pk(K5),pk(K6),pk(K7))))",
        "and_v(v:pk(K1),thresh(2,ltv:thresh(2,ltv:thresh(3,ln:after(9),sln:after(9),sln:after(9),s:pk(K2)),s:pk(K3),s:pk(K4)),sln:after(9),a:multi(2,K5,K6,K7)))",
    ),
    ("or(3@pk(K1),99@pk(K2))", "or_d(pk(K2),pkh(K1))"),
    ("or(3@and(pk(K1),pk(K2)),pk(K3))", "c:andor(pk(K1),pk_k(K2),pk_h(K3))"),
    (
        "and(sha256(H),thresh(3,pk(K1),and(thresh(2,after(9),pk(K2),pk(K3),pk(K4)),pk(K5)),pk(K6),thresh(2,after(9),pk(K7),pk(K8),pk(K9))))",
        "and_v(v:sha256(H),thresh(3,j:and_v(v:pk(K5),thresh(2,ndv:after(9),s:pk(K2),s:pk(K3),s:pk(K4))),s:pk(K1),s:pk(K6),altv:thresh(2,ndv:after(9),s:pk(K7),s:pk(K8),s:pk(K9))))",
    ),
    (
        "thresh(2,or(3@thresh(2,or(3@and(pk(K1),pk(K2)),thresh(4,after(9),after(9),after(9),pk(K3),pk(K4))),pk(K5),pk(K6)),3@pk(K7)),pk(K8),pk(K9),pk(K10))",
        "thresh(2,or_i(tv:thresh(2,or_i(tv:thresh(4,pkh(K3),sln:after(9),sln:after(9),sln:after(9),a:pkh(K4)),j:and_v(v:pkh(K1),pkh(K2))),a:pkh(K5),a:pkh(K6)),pk(K7)),s:pk(K8),s:pk(K9),s:pk(K10))",
    ),
    (
        "thresh(2,sha256(H),pk(K1),and(thresh(3,or(pk(K2),pk(K3)),pk(K4),pk(K5),pk(K6)),thresh(2,after(9),pk(K7),pk(K8),pk(K9))))",
        "thresh(2,l:and_v(v:thresh(3,or_b(pk(K2),s:pk(K3)),s:pk(K4),s:pk(K5),s:pk(K6)),thresh(2,ndv:after(9),s:pk(K7),s:pk(K8),s:pk(K9))),sjtv:sha256(H),s:pk(K1))",
    ),
    (
        "and(pk(K1),thresh(4,after(9),thresh(2,after(9),after(9),pk(K2),pk(K3),pk(K4)),and(or(pk(K5),pk(K6)),pk(K7)),pk(K8),thresh(2,after(9),pk(K9),pk(K10),pk(K11))))",
        "and_v(v:pk(K1),thresh(4,ltv:thresh(2,ndv:after(9),sun:after(9),s:pk(K2),s:pk(K3),s:pk(K4)),sln:after(9),a:and_b(or_b(pk(K5),s:pk(K6)),s:pk(K7)),s:pk(K8),altv:thresh(2,ndv:after(9),s:pk(K9),s:pk(K10),s:pk(K11))))",
    ),
    (
        "thresh(2,pk(K1),pk(K2),or(3@pk(K3),99@thresh(2,after(9),thresh(2,after(9),pk(K4),pk(K5),pk(K6)),thresh(3,pk(K7),pk(K8),pk(K9),pk(K10)))))",
        "thresh(2,lt:or_i(v:pkh(K3),v:thresh(2,ltv:thresh(2,pk(K4),sln:after(9),s:pk(K5),s:pk(K6)),sln:after(9),a:multi(3,K7,K8,K9,K10))),s:pk(K1),s:pk(K2))",
    ),
    ("or(99@pk(K1),99@pk(K2))", "or_b(pk(K1),s:pk(K2))"),
    (
        "and(and(pk(K1),or(pk(K2),and(pk(K3),pk(K4)))),thresh(4,pk(K5),and(after(9),pk(K6)),thresh(2,pk(K7),pk(K8),pk(K9),pk(K10)),or(pk(K11),pk(K12)),pk(K13)))",
        "and_v(and_v(v:pk(K1),or_c(pk(K2),and_v(v:pk(K3),v:pk(K4)))),thresh(4,multi(2,K7,K8,K9,K10),s:pk(K5),sj:and_v(v:pk(K6),n:after(9)),a:or_b(pk(K11),s:pk(K12)),s:pk(K13)))",
    ),
    ("and(pk(K1),and(after(9),pk(K2)))", "and_v(v:pk(K1),and_v(v:pk(K2),after(9)))"),
    (
        "and(thresh(3,sha256(H),pk(K1),thresh(2,or(pk(K2),pk(K3)),pk(K4),pk(K5)),thresh(2,after(9),pk(K6),pk(K7))),pk(K8))",
        "and_v(v:pk(K8),thresh(3,thresh(2,or_b(pk(K2),s:pk(K3)),s:pk(K4),s:pk(K5)),sjtv:sha256(H),s:pk(K1),altv:thresh(2,ln:after(9),s:pk(K6),s:pk(K7))))",
    ),
    (
        "thresh(2,after(9),pk(K1),thresh(2,or(3@thresh(2,pk(K2),pk(K3),pk(K4),pk(K5)),99@pk(K6)),pk(K7),pk(K8),thresh(3,after(9),pk(K9),pk(K10),pk(K11),pk(K12))))",
        "thresh(2,thresh(2,or_i(tv:thresh(2,pkh(K2),a:pkh(K3),a:pkh(K4),a:pkh(K5)),pk(K6)),s:pk(K7),s:pk(K8),autv:thresh(3,ln:after(9),s:pk(K9),s:pk(K10),s:pk(K11),s:pk(K12))),sln:after(9),s:pk(K1))",
    ),
    (
        "thresh(2,sha256(H),pk(K1),and(sha256(H),thresh(3,thresh(2,after(9),after(9),pk(K2),pk(K3),pk(K4)),after(9),thresh(2,pk(K5),pk(K6),pk(K7)),pk(K8),pk(K9))))",
        "thresh(2,l:and_v(v:thresh(3,ltv:thresh(2,ndv:after(9),sun:after(9),s:pk(K2),s:pk(K3),s:pk(K4)),sln:after(9),a:multi(2,K5,K6,K7),s:pk(K8),s:pk(K9)),sha256(H)),sjtv:sha256(H),s:pk(K1))",
    ),
    ("or(pk(K1),3@pk(K2))", "or_d(pk(K2),pkh(K1))"),
    ("or(99@pk(K1),and(sha256(H),pk(K2)))", "or_d(pk(K1),and_v(v:pkh(K2),sha256(H)))"),
    (
        "and(pk(K1),or(thresh(2,thresh(4,pk(K2),pk(K3),pk(K4),pk(K5),pk(K6)),thresh(3,pk(K7),pk(K8),pk(K9),pk(K10),pk(K11)),or(pk(K12),pk(K13)),pk(K14)),pk(K15)))",
        "and_v(or_c(pk(K15),v:thresh(2,multi(4,K2,K3,K4,K5,K6),a:multi(3,K7,K8,K9,K10,K11),altvc:or_i(pk_h(K12),pk_h(K13)),s:pk(K14))),pk(K1))",
    ),
    (
        "and(and(pk(K1),thresh(2,thresh(4,after(9),after(9),pk(K2),pk(K3),pk(K4)),pk(K5),pk(K6),pk(K7),pk(K8))),pk(K9))",
        "and_v(and_v(v:pk(K1),v:thresh(2,utv:thresh(4,ln:after(9),sln:after(9),s:pk(K2),s:pk(K3),s:pk(K4)),s:pk(K5),s:pk(K6),s:pk(K7),s:pk(K8))),pk(K9))",
    ),
    (
        "thresh(2,after(9),and(after(9),thresh(4,thresh(2,after(9),after(9),pk(K1),pk(K2)),sha256(H),pk(K3),thresh(2,after(9),pk(K4),pk(K5)),pk(K6))),pk(K7))",
        "thresh(2,l:and_v(v:thresh(4,ltv:thresh(2,ndv:after(9),sln:after(9),s:pk(K1),s:pk(K2)),sjtv:sha256(H),s:pk(K3),altv:thresh(2,ln:after(9),s:pk(K4),s:pk(K5)),s:pk(K6)),n:after(9)),sln:after(9),s:pk(K7))",
    ),
]

# composed here, and what sipa's compiler answers
COMPOSED = [
    (
        "or(or(and(pk(K1),pk(K2)),18@pk(K3)),113@pk(K4))",
        "or_d(pk(K4),c:or_i(and_v(v:pkh(K1),pk_h(K2)),pk_h(K3)))",
    ),
    ("or(pk(K1),123@pk(K2))", "or_d(pk(K2),pkh(K1))"),
    (
        "thresh(3,thresh(2,pk(K1),pk(K2)),thresh(2,hash256(H),older(144)),and(pk(K3),after(500000000)))",
        "and_v(and_v(v:pk(K1),v:pk(K2)),and_v(and_v(v:hash256(H),v:older(144)),and_v(v:pk(K3),after(500000000))))",
    ),
    (
        "or(pk(K1),and(thresh(2,older(65535),pk(K2)),or(thresh(2,pk(K3),pk(K4)),older(65535))))",
        "or_d(pk(K1),and_v(and_v(v:older(65535),v:pk(K2)),or_i(and_v(v:pkh(K3),pkh(K4)),older(65535))))",
    ),
    (
        "and(and(thresh(2,pk(K1),after(500000000)),thresh(2,after(500000000),pk(K2))),pk(K3))",
        "and_v(v:pk(K3),and_v(and_v(v:pk(K1),v:after(500000000)),and_v(v:pk(K2),after(500000000))))",
    ),
    (
        "and(or(144@pk(K1),and(or(pk(K2),pk(K3)),pk(K4))),or(62@pk(K5),14@pk(K6)))",
        "and_v(or_c(pk(K1),and_v(v:pkh(K4),vc:or_i(pk_h(K2),pk_h(K3)))),or_d(pk(K5),pkh(K6)))",
    ),
    (
        "or(and(thresh(2,pk(K1),pk(K2)),hash256(H)),and(sha256(H),or(pk(K3),thresh(2,pk(K4),pk(K5)))))",
        "c:or_i(and_v(v:hash256(H),and_v(v:pk(K1),pk_k(K2))),and_v(v:sha256(H),or_i(pk_h(K3),and_v(v:pkh(K4),pk_h(K5)))))",
    ),
    (
        "and(or(pk(K1),93@pk(K2)),ripemd160(H))",
        "and_v(or_c(pk(K2),v:pkh(K1)),ripemd160(H))",
    ),
    (
        "or(thresh(2,pk(K1),sha256(H)),thresh(2,older(1),pk(K2)))",
        "or_i(and_v(v:pk(K1),sha256(H)),and_v(v:pk(K2),older(1)))",
    ),
    (
        "thresh(4,pk(K1),after(1000),pk(K2),pk(K3))",
        "and_v(v:pk(K1),and_v(and_v(v:pk(K2),v:pk(K3)),after(1000)))",
    ),
    (
        "and(pk(K1),thresh(4,older(1),pk(K2),after(500000000),hash160(H)))",
        "and_v(v:pk(K1),and_v(v:older(1),and_v(v:pk(K2),and_v(v:hash160(H),after(500000000)))))",
    ),
    ("and(sha256(H),pk(K1))", "and_v(v:pk(K1),sha256(H))"),
    (
        "and(thresh(4,pk(K1),hash160(H),ripemd160(H),pk(K2),after(1700000000)),pk(K3))",
        "and_v(v:pk(K3),thresh(4,pk(K1),sjtv:hash160(H),sjtv:ripemd160(H),s:pk(K2),sln:after(1700000000)))",
    ),
    (
        "thresh(3,after(1700000000),pk(K1),pk(K2),pk(K3),pk(K4))",
        "thresh(3,ln:after(1700000000),s:pk(K1),s:pk(K2),s:pk(K3),s:pk(K4))",
    ),
    (
        "thresh(3,pk(K1),pk(K2),hash160(H),pk(K3),after(1700000000))",
        "thresh(3,pk(K1),s:pk(K2),sjtv:hash160(H),s:pk(K3),sln:after(1700000000))",
    ),
    (
        "thresh(2,and(pk(K1),after(500000000)),and(older(144),older(144)))",
        "and_v(and_v(v:pk(K1),v:after(500000000)),and_v(v:older(144),older(144)))",
    ),
    ("thresh(2,older(65535),pk(K1))", "and_v(v:pk(K1),older(65535))"),
    (
        "thresh(1,and(pk(K1),after(9)),and(pk(K2),pk(K3)),or(pk(K4),pk(K5)))",
        "c:or_i(and_v(v:after(9),pk_k(K1)),or_i(and_v(v:pkh(K2),pk_h(K3)),or_i(pk_h(K4),pk_h(K5))))",
    ),
    ("or(and(older(144),pk(K1)),pk(K2))", "andor(pk(K1),older(144),pk(K2))"),
    (
        "and(thresh(2,ripemd160(H),pk(K1),pk(K2)),thresh(2,pk(K3),after(500000000)))",
        "and_v(v:thresh(2,jtv:ripemd160(H),s:pk(K1),s:pk(K2)),and_v(v:pk(K3),after(500000000)))",
    ),
    (
        "and(pk(K1),and(older(1),or(pk(K2),96@older(65535))))",
        "and_v(v:pk(K1),and_v(or_i(v:pkh(K2),v:older(65535)),older(1)))",
    ),
    ("thresh(2,after(1000),pk(K1))", "and_v(v:pk(K1),after(1000))"),
    (
        "and(thresh(2,pk(K1),pk(K2),after(1700000000),pk(K3)),or(81@and(sha256(H),pk(K4)),pk(K5)))",
        "and_v(v:thresh(2,pk(K1),s:pk(K2),sln:after(1700000000),s:pk(K3)),andor(pk(K4),sha256(H),pkh(K5)))",
    ),
    (
        "or(187@pk(K1),thresh(1,pk(K2),pk(K3)))",
        "or_d(pk(K1),c:or_i(pk_h(K2),pk_h(K3)))",
    ),
    ("thresh(2,pk(K1),ripemd160(H))", "and_v(v:pk(K1),ripemd160(H))"),
    (
        "thresh(1,or(pk(K1),pk(K2)),thresh(2,older(144),pk(K3)),and(after(500000000),pk(K4)))",
        "or_i(c:or_i(pk_h(K1),pk_h(K2)),or_i(and_v(v:pkh(K3),older(144)),and_v(v:pk(K4),after(500000000))))",
    ),
    (
        "or(pk(K1),thresh(2,pk(K2),after(1700000000)))",
        "or_d(pk(K1),and_v(v:pk(K2),after(1700000000)))",
    ),
    (
        "or(162@or(87@and(pk(K1),pk(K2)),23@pk(K3)),pk(K4))",
        "c:or_i(pk_h(K4),andor(pk(K1),pk_k(K2),pk_h(K3)))",
    ),
    (
        "and(thresh(2,pk(K1),pk(K2)),or(pk(K3),pk(K4)))",
        "and_v(or_c(pk(K3),v:pk(K4)),and_v(v:pk(K1),pk(K2)))",
    ),
    (
        "or(58@and(or(pk(K1),pk(K2)),or(or(47@pk(K3),pk(K4)),19@or(hash256(H),pk(K5)))),and(pk(K6),or(after(9),10@pk(K7))))",
        "c:or_i(and_v(or_c(pkh(K7),v:after(9)),pk_h(K6)),and_v(or_i(or_c(pkh(K3),v:pkh(K4)),or_c(pk(K5),v:hash256(H))),or_i(pk_k(K1),pk_k(K2))))",
    ),
    ("or(older(144),113@and(pk(K1),hash256(H)))", None),
    ("or(thresh(2,pk(K1),pk(K2)),or(131@pk(K3),55@hash256(H)))", None),
    (
        "or(191@or(82@and(pk(K1),and(thresh(2,pk(K2),pk(K3)),older(65535))),thresh(2,after(9),sha256(H))),178@or(141@pk(K4),pk(K5)))",
        None,
    ),
    (
        "or(thresh(1,pk(K1),hash160(H)),and(or(after(500000000),hash256(H)),after(500000000)))",
        None,
    ),
    (
        "or(thresh(1,and(ripemd160(H),after(500000000)),and(pk(K1),ripemd160(H))),17@and(pk(K2),or(186@pk(K3),after(9))))",
        None,
    ),
    ("and(after(1000),and(sha256(H),thresh(1,pk(K1),after(9))))", None),
    ("and(and(thresh(1,hash256(H),sha256(H)),pk(K1)),hash160(H))", None),
]

# what rust-miniscript's tests assert of a refusal, as the message here
# says it
REFUSALS = {
    "TopLevelSigless": "without a signature",
    "ImpossibleNonMalleableCompilation": "non-malleable",
    "LimitsExceeded": "non-malleable",
    "DuplicatePubKeys": "names a key more than once",
    "is_err": "non-malleable",
}


def _keys(numbers: range) -> str:
    """Return pk() of the key named K and each number, comma-separated."""
    return ",".join(f"pk(K{number})" for number in numbers)


# rust-miniscript's src/policy/compiler.rs, its tests compiling for
# Segwitv0: the test, the policy, and what the test asserts: a
# miniscript, "ok" for a compilation whose lift is the policy's, a script
# as a list of pushes and op codes, a script size, or a refusal
RUST: list[tuple[str, str, object]] = [
    ("compile_timelocks", "and(pk(A),and(after(9),after(1000000000)))", "is_err"),
    (
        "compile_timelocks",
        "and(pk(A),or(and(after(9),pk(B)),and(after(1000000000),pk(C))))",
        "ok",
    ),
    ("compile_basic", "pk(A)", "ok"),
    ("compile_basic", "after(9)", "TopLevelSigless"),
    ("compile_basic", "older(1)", "TopLevelSigless"),
    (
        "compile_basic",
        "sha256(1111111111111111111111111111111111111111111111111111111111111111)",
        "TopLevelSigless",
    ),
    ("compile_basic", "and(pk(A),pk(B))", "ok"),
    ("compile_basic", "or(pk(A),pk(B))", "ok"),
    ("compile_basic", "thresh(2,pk(A),pk(B),pk(C))", "ok"),
    ("compile_basic", "or(thresh(1,pk(A),pk(B)),pk(C))", "ok"),
    ("compile_basic", "thresh(2,after(9),after(9),pk(A))", "TopLevelSigless"),
    (
        "compile_basic",
        "and(pk(A),or(after(9),after(9)))",
        "ImpossibleNonMalleableCompilation",
    ),
    ("compile_misc", "pk(K0)", ["K0", "OP_CHECKSIG"]),
    (
        "compile_misc",
        f"and(older(10000),thresh(2,{_keys(range(5, 8))}))",
        [
            "OP_2",
            "K5",
            "K6",
            "K7",
            "OP_3",
            "OP_CHECKMULTISIGVERIFY",
            10000,
            "OP_CHECKSEQUENCEVERIFY",
        ],
    ),
    (
        "compile_misc",
        f"or(127@thresh(3,{_keys(range(5))}),1@and(older(10000),thresh(2,{_keys(range(5, 8))})))",
        "or_d(multi(3,K0,K1,K2,K3,K4),and_v(v:thresh(2,c:pk_h(K5),ac:pk_h(K6),ac:pk_h(K7)),older(10000)))",
    ),
    *(
        (
            "compile_thresh",
            f"thresh({k},{_keys(range(4))})",
            f"multi({k},K0,K1,K2,K3)",
        )
        for k in (2, 3)
    ),
    *(
        (
            "compile_thresh",
            f"thresh({k},{_keys(range(21))})",
            f"thresh({k},pk(K0)," + ",".join(f"s:pk(K{i})" for i in range(1, 21)) + ")",
        )
        for k in (10, 15)
    ),
    ("compile_thresh", f"thresh(21,{_keys(range(21))})", 21 * (1 + 33 + 1)),
    (
        "segwit_limits_1",
        f"or(1@thresh(52,{_keys(range(52))}),1@thresh(52,{_keys(range(52, 104))}))",
        "LimitsExceeded",
    ),
    ("segwit_limits_2", f"thresh(100,{_keys(range(100))})", "LimitsExceeded"),
    ("shared_limits", f"thresh(67,{_keys(range(68))})", "LimitsExceeded"),
    ("shared_limits", "or(1@pk(K0),1@pk(K0))", "DuplicatePubKeys"),
    (
        "compile_and_n_dissat_cost",
        "thresh(4,and(or(1@pk(A),1@pk(B)),sha256(H)),pk(C),pk(D),pk(E),pk(F))",
        "thresh(4,and_n(or_b(pk(A),s:pk(B)),sha256(H)),s:pk(C),s:pk(D),s:pk(E),s:pk(F))",
    ),
]

# the test, the policy, what rust-miniscript's test asserts, and what
# sipa's compiler answers
RUST_DIFFERS = [
    (
        "compile_thresh",
        f"thresh(1,{_keys(range(4))})",
        "multi(1,K0,K1,K2,K3)",
        "c:or_i(pk_k(K0),or_i(pk_h(K1),or_i(pk_h(K2),pk_h(K3))))",
    ),
]

# sipa's main.cpp expands an H hash lock to these digests
_DIGESTS = {
    "sha256": "88" * 32,
    "hash256": "88" * 32,
    "ripemd160": "99" * 20,
    "hash160": "99" * 20,
}
# a key name, where a fragment or a policy takes a key
_NAME = r"(?<=[(,]){}(?=[),])"


def _names(policy: str) -> list[str]:
    """Return the key names of a policy, in the order it first names them."""
    return list(dict.fromkeys(re.findall(r"pk\(([A-Za-z0-9_]+)\)", policy)))


def _expanded(text: str, keys: dict[str, str]) -> str:
    """Return a policy or a miniscript with its keys and H digests filled in."""
    for fragment, digest in _DIGESTS.items():
        text = text.replace(f"{fragment}(H)", f"{fragment}({digest})")
    for name, key in keys.items():
        text = re.sub(_NAME.format(re.escape(name)), key, text)
    return text


def _key_map(policy: str) -> dict[str, str]:
    """Return the key of each name: that of private key 1, 2, ... in order."""
    return {
        name: PrvKeyData(i).pub.sec.hex() for i, name in enumerate(_names(policy), 1)
    }


# a path as both sides are compared: its keys, its older(), its after()
# and its hash locks, quorums expanded into every set of keys they take
_Path = tuple[frozenset[str], int | None, int | None, frozenset[tuple[str, str]]]


def _joined(first: _Path, second: _Path) -> _Path | None:
    """Return the path needing both, None where no transaction takes it."""
    older = [x for x in (first[1], second[1]) if x is not None]
    after = [x for x in (first[2], second[2]) if x is not None]
    if len({x & SEQUENCE_LOCKTIME_TYPE_FLAG for x in older}) > 1:
        return None
    if len({x >= LOCKTIME_THRESHOLD for x in after}) > 1:
        return None
    return (
        first[0] | second[0],
        max(older, default=None),
        max(after, default=None),
        first[3] | second[3],
    )


def _conjunction(parts: list[set[_Path]]) -> set[_Path]:
    """Return the paths needing one path of each part."""
    paths: set[_Path] = {(frozenset(), None, None, frozenset())}
    for part in parts:
        joined = (_joined(x, y) for x in paths for y in part)
        paths = {path for path in joined if path is not None}
    return paths


def _split(arguments: str) -> list[str]:
    """Split at the commas outside brackets."""
    parts, depth, start = [], 0, 0
    for position, char in enumerate(arguments):
        depth += {"(": 1, ")": -1}.get(char, 0)
        if char == "," and depth == 0:
            parts.append(arguments[start:position])
            start = position + 1
    return [*parts, arguments[start:]]


def _policy_paths(policy: str) -> set[_Path]:
    """Return the paths of a policy written with names, read here alone."""
    policy = re.sub(r"^[0-9]+@", "", policy)
    name, _, rest = policy.partition("(")
    arguments = _split(rest[:-1])
    if name == "pk":
        return {(frozenset(arguments), None, None, frozenset())}
    if name in {"older", "after"}:
        value = int(arguments[0])
        return {
            (
                frozenset(),
                *((value, None) if name == "older" else (None, value)),
                frozenset(),
            )
        }
    if name in _DIGESTS:
        return {(frozenset(), None, None, frozenset({(name, arguments[0])}))}
    subs = [_policy_paths(sub) for sub in arguments[name == "thresh" :]]
    if name == "and":
        return _conjunction(subs)
    threshold = 1 if name == "or" else int(arguments[0])
    return {
        path
        for chosen in itertools.combinations(subs, threshold)
        for path in _conjunction(list(chosen))
    }


def _miniscript_paths(node: Miniscript, names: dict[str, str]) -> set[_Path]:
    """Return the paths `Miniscript.spending_paths` lists, quorums expanded."""
    digests = dict.fromkeys(_DIGESTS.values(), "H")
    paths = set()
    for path in node.spending_paths:
        hashes = frozenset(
            (fragment, digests.get(digest.hex(), digest.hex()))
            for fragment, digest in path.hashes
        )
        choices = [
            [
                frozenset(names[str(k)] for k in keys)
                for keys in itertools.combinations(q.keys, q.threshold)
            ]
            for q in path.quorums
        ]
        for chosen in itertools.product(*choices):
            keys = frozenset().union(*chosen)
            paths.add((keys, path.older, path.after, hashes))
    return paths


# the most keys whose paths are listed one set of keys at a time
_LISTED_KEYS = 20


def _assert_paths(node: Miniscript, policy: str, keys: dict[str, str]) -> None:
    """Assert the miniscript is sane, and its paths are the policy's.

    Past `_LISTED_KEYS` the policy is a thresh() of keys alone, whose sets
    of keys are too many to list: its path is one quorum of every key.
    """
    assert node.is_sane()
    names = {key: name for name, key in keys.items()}
    if len(names) <= _LISTED_KEYS:
        assert _miniscript_paths(node, names) == _policy_paths(policy)
        return
    threshold = int(policy[len("thresh(") : policy.index(",")])
    (path,) = node.spending_paths
    (quorum,) = path.quorums
    assert path == SpendingPath((quorum,))
    assert quorum.threshold == threshold
    assert {names[str(key)] for key in quorum.keys} == set(names.values())


def _assert_compiles_to(policy: str, expected: str) -> None:
    """Assert the policy compiles to the miniscript, which is the policy's.

    The miniscript also reads back from its own text.
    """
    keys = _key_map(policy)
    node = compile_policy(_expanded(policy, keys))
    assert node == parse_miniscript(_expanded(expected, keys), P2WSH)
    assert parse_miniscript(str(node), P2WSH) == node
    _assert_paths(node, policy, keys)


def _sipa_cases(
    cases: list[tuple[str, str | None]], compiled: bool
) -> list[tuple[str, str | None]]:
    return [
        (policy, expected)
        for policy, expected in cases
        if (expected is None) != compiled
    ]


SIPA = WEBSITE + GRAMMAR + COMPOSED


@pytest.mark.parametrize("policy, expected", _sipa_cases(SIPA, compiled=True))
def test_a_policy_compiles_to_what_sipa_answers(policy: str, expected: str) -> None:
    """The port answers sipa's compiler, and its answer is the policy's."""
    _assert_compiles_to(policy, expected)


@pytest.mark.parametrize("policy, expected", _sipa_cases(SIPA, compiled=False))
def test_a_policy_sipa_compiles_none_of_is_refused(policy: str, expected: None) -> None:
    """Where sipa's compiler answers nothing, the port refuses."""
    with pytest.raises(BTClibValueError):
        compile_policy(_expanded(policy, _key_map(policy)))


@pytest.mark.parametrize(
    "test, policy, asserted",
    RUST,
    ids=[f"{t}-{i}" for i, (t, _, _) in enumerate(RUST)],
)
def test_what_a_rust_miniscript_test_asserts(
    test: str, policy: str, asserted: object
) -> None:
    """The port answers what rust-miniscript's compiler tests assert."""
    keys = _key_map(policy)
    if isinstance(asserted, str) and asserted in REFUSALS:
        with pytest.raises(BTClibValueError, match=REFUSALS[asserted]):
            compile_policy(_expanded(policy, keys))
        return
    if isinstance(asserted, str) and asserted != "ok":
        _assert_compiles_to(policy, asserted)
        return
    node = compile_policy(_expanded(policy, keys))
    if isinstance(asserted, list):
        pushes = [bytes.fromhex(keys[x]) if x in keys else x for x in asserted]
        assert node.script() == serialize(pushes)
    elif isinstance(asserted, int):
        assert node.script_size == asserted
    _assert_paths(node, policy, keys)


@pytest.mark.parametrize("test, policy, rust, sipa", RUST_DIFFERS)
def test_where_rust_miniscript_answers_otherwise(
    test: str, policy: str, rust: str, sipa: str
) -> None:
    """The port answers as sipa does; rust-miniscript's answer has its paths."""
    _assert_compiles_to(policy, sipa)
    keys = _key_map(policy)
    _assert_paths(parse_miniscript(_expanded(rust, keys), P2WSH), policy, keys)


def test_the_comparison_of_paths_tells_a_wrong_answer() -> None:
    """A miniscript of other paths than the policy's fails the comparison."""
    policy = "or(pk(A),pk(B))"
    keys = _key_map(policy)
    names = {key: name for name, key in keys.items()}
    other = parse_miniscript(_expanded("and_v(v:pk(A),pk(B))", keys), P2WSH)
    assert _miniscript_paths(other, names) != _policy_paths(policy)
    right = parse_miniscript(_expanded("or_b(pk(A),s:pk(B))", keys), P2WSH)
    assert _miniscript_paths(right, names) == _policy_paths(policy)


@pytest.mark.parametrize(
    "policy", ["and(older(10),older(4194314))", "and(after(10),after(500000010))"]
)
def test_a_policy_path_that_mixes_lock_times_is_dropped(policy: str) -> None:
    """No transaction takes a path of both kinds of one lock time."""
    assert not _policy_paths(policy)


_A, _B, _C = (PrvKeyData(i).pub.sec.hex() for i in (1, 2, 3))


def _nested_and(levels: int) -> str:
    """Return an and() of a key and the next level, `levels` deep."""
    keys = [PrvKeyData(i).pub.sec.hex() for i in range(1, levels + 2)]
    policy = f"pk({keys[-1]})"
    for key in reversed(keys[:-1]):
        policy = f"and(pk({key}),{policy})"
    return policy


def test_a_policy_nested_past_the_bound_is_refused() -> None:
    """The brackets are counted before the policy is read."""
    within = _nested_and(compiler._MAX_NESTING - 1)
    assert compile_policy(within).is_sane()
    with pytest.raises(BTClibValueError, match="nested deeper than"):
        compile_policy(_nested_and(compiler._MAX_NESTING))


def test_strategies_nested_past_the_bound_are_refused() -> None:
    """A thresh() of all its arguments is a chain, one level per argument.

    Two such thresh(), one the last argument of the other, nest two
    brackets deep and past `_MAX_DEPTH` strategies.
    """
    keys = [PrvKeyData(i).pub.sec.hex() for i in range(1, 200)]
    inner = f"thresh(99,{','.join(f'pk({key})' for key in keys[:99])})"
    outer = f"thresh(100,{','.join(f'pk({key})' for key in keys[99:198])},{inner})"
    with pytest.raises(BTClibValueError, match="too deep to compile"):
        compile_policy(outer)


def test_the_deepest_policy_compiles_within_the_default_recursion_limit() -> None:
    """At the nesting bound the strategies are within theirs: no overflow."""
    policy = _nested_and(compiler._MAX_NESTING - 1)
    assert compiler._strategy(compiler._parse(policy), {}).depth <= compiler._MAX_DEPTH
    assert compile_policy(policy).script_size


def test_a_compilation_past_the_steps_bound_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compilation that takes one step more than the bound is refused."""
    policy = f"pk({_C})"
    for key in (_A, _B):
        policy = f"or(9@pk({key}),{policy})"
    searches = []
    search = compiler._Search

    def counted() -> compiler._Search:
        searches.append(search())
        return searches[-1]

    monkeypatch.setattr(compiler, "_Search", counted)
    expected = compile_policy(policy)
    steps = searches[-1].steps
    monkeypatch.setattr(compiler, "_MAX_STEPS", steps)
    assert compile_policy(policy) == expected
    monkeypatch.setattr(compiler, "_MAX_STEPS", steps - 1)
    with pytest.raises(BTClibValueError, match=f"past {steps - 1} steps"):
        compile_policy(policy)


@pytest.mark.parametrize(
    "policy, message",
    [
        ("pk", "a call such as pk"),
        ("pkh(02)", "unknown call"),
        (f"and(pk({_A}),pk({_B}),pk({_C}))", "takes two arguments"),
        (f"or(pk({_A}))", "takes two arguments"),
        (f"thresh(0,pk({_A}))", "invalid thresh"),
        (f"thresh(2,pk({_A}))", "invalid thresh"),
        (f"thresh(+1,pk({_A}))", "digits expected"),
        ("thresh(1)", "takes 1 to 100 arguments"),
        ("older(0)", "invalid older"),
        (f"older({2**31})", "invalid older"),
        ("after(-1)", "digits expected"),
        ("sha256(88)", "32 bytes of hex"),
        (f"hash160({'zz' * 20})", "20 bytes of hex"),
        (f"or(0@pk({_A}),pk({_B}))", "starts with 0"),
        ("pk(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)", "private key"),
        (
            "pk(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi)",
            "private key",
        ),
    ],
)
def test_a_malformed_policy_is_refused(policy: str, message: str) -> None:
    """What sipa's parser refuses is refused, and a private key too."""
    with pytest.raises(BTClibValueError, match=message):
        compile_policy(policy)


def test_a_policy_that_is_no_str_is_refused() -> None:
    """A policy is text."""
    with pytest.raises(BTClibTypeError):
        compile_policy(b"pk(A)")  # type: ignore[arg-type]


def test_a_weight_past_the_cap_is_read_as_the_cap() -> None:
    """A weight past 65535 is read as 65535, as sipa reads it."""
    capped = compile_policy(f"or(65535@pk({_A}),pk({_B}))")
    for weight in ("70000", "10000000000", "9" * 5000):
        assert compile_policy(f"or({weight}@pk({_A}),pk({_B}))") == capped


def test_the_answer_is_the_search_s_and_another_can_cost_less() -> None:
    """A miniscript the search does not build can enforce a policy for less.

    The example `compiler`'s docstring gives: three bytes of script more
    than another policy's answer, with the same spending paths.
    """
    longer = compile_policy(f"and(pk({_A}),and(older(1),older(1)))")
    shorter = compile_policy(f"and(pk({_A}),older(1))")
    assert longer.script_size == shorter.script_size + 3
    assert longer.spending_paths == shorter.spending_paths


def test_a_compiled_policy_is_a_wsh_descriptor() -> None:
    """What `compile_policy` answers is what a wsh() holds."""
    node = compile_policy(f"or(pk({_A}),and(pk({_B}),older(144)))")
    script_pub_key = ScriptPubKey.p2wsh(node.script())
    assert parse(f"wsh({node})").script_pub_key(0) == script_pub_key
