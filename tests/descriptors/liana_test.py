# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# The descriptors below are Liana's, under its licence, whose notice
# follows as Liana's LICENCE file writes it:
#
# BSD 3-Clause License
#
# Copyright (c) 2022, The Liana developers
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""`Descriptor.spending_paths` over the descriptors of Liana's tests.

`SpendingPath` and `Quorum` are modelled on Liana's `LianaPolicy` and
`PathInfo`, so Liana's descriptors are where the two have to agree: each
of Liana's spending paths is one path here, its `PathInfo` the path's one
quorum and its timelock the path's `older`. `tests/_data/README.md` says
which tests and which revision, and how to check the strings again.

A key is named by where it stands among the descriptor's
`key_expressions`, which a `tr()` opens with its internal key. A leaf is
numbered as `TrDescriptor.taproot_tree` lists the leaves.

Each descriptor carries Liana's checksum where Liana's test writes one,
and `multipath_descriptors` verifies it.

Each path is also held to spend: a quorum's first keys signing, with the
path's timelock met, satisfy the descriptor, and one key fewer does not.

`REFUSED_BY_LIANA` holds the descriptors Liana's tests expect refused
that `parse` reads. Liana reads a descriptor only where its paths are one
primary path and recovery paths behind timelocks; the paths are listed
here all the same, since a wallet reading the descriptor needs them.
`REFUSED_HERE` holds those `parse` refuses.
"""

from __future__ import annotations

from typing import Any

import pytest
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors import (
    Descriptor,
    KeyExpression,
    Quorum,
    SpendContext,
    SpendingPath,
    TrDescriptor,
    multipath_descriptors,
    parse,
)
from tests import vector_id

# the keys of analysis.rs's primary_path_key_merging test
KEY_A = "[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*"
KEY_B = "[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*"
KEY_C = "[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<0;1>/*"
KEY_D = "[aabb0014/48'/0'/0'/2']xpub69cP4Y7S9TWcbSNxmk6CEDBsoaqr3ZEdjHuZcHxEFFKGh569RsJNr2V27XGhsbH9FXgWUEmKXRN7c5wQfq2VPjt31xP9VsYnVUyU8HcVevm/<0;1>/*"

# each: the Liana test that holds it, the descriptor, and its paths, each
# path as its quorums, its older() and its leaf, a quorum as its threshold
# and the positions of its keys
ACCEPTED = [
    (
        "descriptor_creation",
        "wsh(or_d(pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),and_v(v:pkh([abcdef01]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*),older(52560))))#g7vk9r5l",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 52560, None),
        ],
    ),
    (
        "descriptor_creation",
        "tr([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*,and_v(v:pk([abcdef01]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*),older(52560)))#0mt7e93c",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 52560, 0),
        ],
    ),
    (
        "descriptor_creation",
        "wsh(or_i(and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*)),older(26352)),and_v(v:and_v(v:pk([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*),pk([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*)),pk([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*))))#c7nf353n",
        [
            (((2, (0, 1, 2)),), 26352, None),
            (((3, (3, 4, 5)),), None, None),
        ],
    ),
    (
        "descriptor_creation",
        "tr(xpub661MyMwAqRbcFERisZuMzFcfg3Ur3dKB17kb8iEG89ZJYMHTWqKQGRdLjTXC6Byr8kjKo6JabFfRCm3ETM4woq7DxUXuUxxRFHfog4Peh41/<0;1>/*,{and_v(v:multi_a(2,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*),older(26352)),and_v(v:and_v(v:pk([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*),pk([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*)),pk([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*))})#eey6zfhr",
        [
            (((2, (1, 2, 3)),), 26352, 0),
            (((3, (4, 5, 6)),), None, 1),
        ],
    ),
    (
        "descriptor_creation",
        "wsh(or_d(multi(3,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*),and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*)),older(26352))))",
        [
            (((3, (0, 1, 2)),), None, None),
            (((2, (3, 4, 5)),), 26352, None),
        ],
    ),
    (
        "descriptor_creation",
        "wsh(or_d(multi(3,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*),and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*)),older(26352))))",
        [
            (((3, (0, 1, 2)),), None, None),
            (((2, (3, 4, 5)),), 26352, None),
        ],
    ),
    (
        "descriptor_creation",
        "wsh(or_i(and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<2;3>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<2;3>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<2;3>/*)),older(26352)),and_v(v:and_v(v:pk([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),pk([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*)),pk([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<0;1>/*))))#tjdnx6vm",
        [
            (((2, (0, 1, 2)),), 26352, None),
            (((3, (3, 4, 5)),), None, None),
        ],
    ),
    (
        "descriptor_creation",
        "tr(xpub661MyMwAqRbcFERisZuMzFcfg3Ur3dKB17kb8iEG89ZJYMHTWqKQGRdLjTXC6Byr8kjKo6JabFfRCm3ETM4woq7DxUXuUxxRFHfog4Peh41/<0;1>/*,{and_v(v:multi_a(2,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<2;3>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<2;3>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<2;3>/*),older(26352)),and_v(v:and_v(v:pk([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),pk([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*)),pk([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<0;1>/*))})#d06ehu7c",
        [
            (((2, (1, 2, 3)),), 26352, 0),
            (((3, (4, 5, 6)),), None, 1),
        ],
    ),
    (
        "descriptor_creation",
        "wsh(or_d(pk([aabb0011/10/4893]xpub661MyMwAqRbcFG59fiikD8UV762quhruT8K8bdjqy6N2o3LG7yohoCdLg1m2HAY1W6rfBrtauHkBhbfA4AQ3iazaJj5wVPhwgaRCHBW2DBg/<0;1>/*),and_v(v:pkh([abcdef01]xpub661MyMwAqRbcFfxf71L4Dx4w5TmyNXrBicTEAM7vLzumxangwATWWgdJPb6xH1JHcJH9S3jNZx3fCnkkB1WyqrqGgavj1rehHcbythmruvZ/24/32/<0;1>/*),older(57600))))#ak4cm093",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 57600, None),
        ],
    ),
    (
        "descriptor_creation",
        "wsh(or_d(multi(1,[573fb35b/48'/1'/0'/2']tpubDFKp9T7WAYDcENSjoifkrpq1gMDF47KGJcJrpxzX23Qor8wuGbrEVs9utNq1MDS8E2WXJSBk1qoPQLpwyokW7DiUNPwFuxQkL7owNkLAb9W/<0;1>/*,[573fb35c/48'/1'/1'/2']tpubDFGezyzuHJPhdP3jHGW7v7Hwes4Hihqv5W2yyCmRY9VZJCRchETvxrMC8uECeJZdxQ14V4iD4DecoArkUSDwj8ogYE9WEv4MNZr12thNHCs/<0;1>/*),and_v(v:multi(2,[573fb35b/48'/1'/2'/2']tpubDDwxQauiaU964vPzt5Vd7jnDHEUtp2Vc34PaWpEXg5TQ3bRccxnc1MKKh88Hi7xiMeZo9Tm6fBcq4UGXqnDtGUniJLjqAD8SjQ8Eci3aSR7/<0;1>/*,[573fb35c/48'/1'/3'/2']tpubDE37XAVB5CQ1x85md3BQ5uHCoMwT5fgT8X13zzCUQ3x5o2jskYxKjj7Qcxt1Jpj4QB8tqspn2dooPCekRuQDYrDHov7J1ueUNu2wcvgRDxr/<0;1>/*),older(1000))))#fccaqlhh",
        [
            (((1, (0, 1)),), None, None),
            (((2, (2, 3)),), 1000, None),
        ],
    ),
    (
        "descriptor_unspendable_internal_key",
        "tr(tpubD6NzVbkrYhZ4YdBUPkUhDYj6Sd1QK8vgiCf5RwHnAnSNK5ozemAZzPTYZbgQq4diod7oxFJJYGa8FNRHzRo7URkixzQTuudh38xRRdSc4Hu/<0;1>/*,{and_v(v:multi_a(1,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<2;3>/*),older(2)),multi_a(2,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<0;1>/*)})",
        [
            (((1, (1, 2)),), 2, 0),
            (((2, (3, 4)),), None, 1),
        ],
    ),
    (
        "descriptor_unspendable_internal_key",
        "tr([00000000/1/2/3]tpubD6NzVbkrYhZ4YdBUPkUhDYj6Sd1QK8vgiCf5RwHnAnSNK5ozemAZzPTYZbgQq4diod7oxFJJYGa8FNRHzRo7URkixzQTuudh38xRRdSc4Hu/<0;1>/*,{and_v(v:multi_a(1,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<2;3>/*),older(2)),multi_a(2,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<0;1>/*)})",
        [
            (((1, (1, 2)),), 2, 0),
            (((2, (3, 4)),), None, 1),
        ],
    ),
    (
        "inheritance_descriptor_derivation",
        "wsh(andor(pk([abcdef01]tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/<0;1>/*),older(10000),pk([abcdef01]tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/<0;1>/*)))#2qj59a9y",
        [
            (((1, (0,)),), 10000, None),
            (((1, (1,)),), None, None),
        ],
    ),
    (
        "inheritance_descriptor_tl_value",
        "wsh(andor(pk([abcdef01]tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/<0;1>/*),older(1),pk([abcdef01]tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/<0;1>/*)))",
        [
            (((1, (0,)),), 1, None),
            (((1, (1,)),), None, None),
        ],
    ),
    (
        "inheritance_descriptor_tl_value",
        "wsh(andor(pk([abcdef01]tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/<0;1>/*),older(42000),pk([abcdef01]tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/<0;1>/*)))",
        [
            (((1, (0,)),), 42000, None),
            (((1, (1,)),), None, None),
        ],
    ),
    (
        "inheritance_descriptor_tl_value",
        "wsh(andor(pk([abcdef01]tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/<0;1>/*),older(65535),pk([abcdef01]tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/<0;1>/*)))",
        [
            (((1, (0,)),), 65535, None),
            (((1, (1,)),), None, None),
        ],
    ),
    (
        "inheritance_descriptor_sat_size",
        "wsh(or_d(pk([92162c45]tpubD6NzVbkrYhZ4WzTf9SsD6h7AH7oQEippXK2KP8qvhMMqFoNeN5YFVi7vRyeRSDGtgd2bPyMxUNmHui8t5yCgszxPPxMafu1VVzDpg9aruYW/<0;1>/*),and_v(v:pkh([abcdef01]tpubD6NzVbkrYhZ4Wdgu2yfdmrce5g4fiH1ZLmKhewsnNKupbi4sxjH1ZVAorkBLWSkhsjhg8kiq8C4BrBjMy3SjAKDyDdbuvUa1ToAHbiR98js/<0;1>/*),older(2))))#ravw7jw5",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 2, None),
        ],
    ),
    (
        "taproot_multisig_descriptor_sat_weight",
        "tr(tpubD6NzVbkrYhZ4WUdbVsXDYBCXS8EPSYG1cAN9g4uP6uLQHMHXRvHSFkQBXy7MBeAvV8PDVJJ4o3AwYMKJHp45ci2g69UCAKteVSAJ61CnGEV/<0;1>/*,{and_v(v:pk([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK/<2;3>/*),older(65535)),multi_a(2,[9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK/<0;1>/*,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM/<0;1>/*)})#ee0r4tw5",
        [
            (((1, (1,)),), 65535, 0),
            (((2, (2, 3)),), None, 1),
        ],
    ),
    (
        "roundtrip_descriptor",
        "wsh(or_d(pk([aabbccdd]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),and_v(v:pkh([aabbccdd]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*),older(52560))))#7437yjrs",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 52560, None),
        ],
    ),
    (
        "roundtrip_descriptor",
        "tr([8344c025]xpub661MyMwAqRbcG2SYC6YSRsUGvcSxXEZm1kjiQRTEaAqart1PQk1N1hVTTEsGfaBx6xQ5gDYXXtbourodE6ZE5qZTnaMgmehNs8GGEEY9YK6/<0;1>/*,and_v(v:pk([158fd0ef]xpub661MyMwAqRbcF2KsCnvJ4mqWXXrwd3799wCyQrLk2iNDC6CfK8UcfnABdeTpXyoJnBhRTybmtBLDAuTuHye1eQMq43BSLtR2miA6t9KqmWU/<0;1>/*),older(4242)))#zy3kddhj",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 4242, 0),
        ],
    ),
    (
        "roundtrip_descriptor",
        "wsh(or_d(multi(3,[aabbccdd]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*,[aabb0011/10/4893]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*,[aabb0022]xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<0;1>/*),and_v(v:multi(2,[aabbccdd]xpub69cP4Y7S9TWcbSNxmk6CEDBsoaqr3ZEdjHuZcHxEFFKGh569RsJNr2V27XGhsbH9FXgWUEmKXRN7c5wQfq2VPjt31xP9VsYnVUyU8HcVevm/<0;1>/*,[aabb0011]xpub6AA2N8RALRYgLD6jT1iXYCEDkndTeZndMtWPbtNX6sY5dPiLtf2T88ahdxrGXMUPoNadgR86sFhBXWQVgifPzDYbY9ZtwK4gqzx4y5Da1DW/<0;1>/*,[aabb0022/10/4893]xpub6AyxexvxizZJffF153evmfqHcE9MV88fCNCAtP3jQjXJHwrAKri71Tq9jWUkPxj9pja4u6AkCPHY7atgxzSEa2HtDwJfrRWKK4fsfQg4o77/<0;1>/*),older(26352))))#csjdk94l",
        [
            (((3, (0, 1, 2)),), None, None),
            (((2, (3, 4, 5)),), 26352, None),
        ],
    ),
    (
        "roundtrip_descriptor",
        "tr(xpub661MyMwAqRbcGg7oXkMMptXXJAGxQtVM7LZeqXNNdxPiWyEmuJdoyFD3NhRpL1YTo313XRWZmiUXTkcEK9EFQHrbie6NBNAvL2CZXp941Li/<0;1>/*,{and_v(v:multi_a(2,[6b882e01]xpub661MyMwAqRbcGRU9psMcDAPd2L2ShzwoenySSSjWpkd7u8Wv7PCPtH5fi6WYYbQAqSG4U3NbuYASCRMkWVYm7yb97iTY4MUKKZ3N8XwCERJ/<0;1>/*,[66b98303]xpub661MyMwAqRbcGicAwMZ5pHCWrB4DEMBGUtvkV2KMMLypR8dbr7g2uV9vzE9w3oDKRqtTV6HYTqHHvusxNwJUXAvRH6BFhKUPTgGMiLPnSmK/<0;1>/*,[9c04a03b]xpub661MyMwAqRbcFCBt8Gjs71UqoMe8V4PSHECuCowg1TR7EkGWLLbu2WanQtcWutzwahrTcicsuL25Q7r6EyfbEKF2jSoekmnw9soZfoiLZXu/<0;1>/*),older(42421)),multi_a(3,[30188cc2]xpub661MyMwAqRbcGeoYQgqUapNKDLBiNE7fcGs6ibKi39GjuiRmV1JgXcfAwHjt7PLLofmz4PPL66NTwAxaTwGtL8YB67RhRspAzbKgneqpenb/<0;1>/*,[aea08adc]xpub661MyMwAqRbcGVL3W5qKT8pjZ3BXcDEJghDj67rKLQYwmTaJLud8RWyYwZQ9LdzkcNtCSCHVypZdUUxd4z2k5hCfb6qprGgwAKqpmaKJTnS/<0;1>/*,[85e33ca4]xpub661MyMwAqRbcFHP9bmnRofzha8c4DHADC7ToPz3kYdov5DDDtgdBEQ3kVcwdjjqAGC8eJZ65CLF2cA9XHhUsJJqKxbE9asj8RUNmGjCJErX/<0;1>/*)})#zm4kj6yd",
        [
            (((2, (1, 2, 3)),), 42421, 0),
            (((3, (4, 5, 6)),), None, 1),
        ],
    ),
    (
        "roundtrip_descriptor",
        "wsh(or_d(pk([aabbccdd]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),and_v(v:multi(2,[aabbccdd]xpub69cP4Y7S9TWcbSNxmk6CEDBsoaqr3ZEdjHuZcHxEFFKGh569RsJNr2V27XGhsbH9FXgWUEmKXRN7c5wQfq2VPjt31xP9VsYnVUyU8HcVevm/<0;1>/*,[aabb0011]xpub6AA2N8RALRYgLD6jT1iXYCEDkndTeZndMtWPbtNX6sY5dPiLtf2T88ahdxrGXMUPoNadgR86sFhBXWQVgifPzDYbY9ZtwK4gqzx4y5Da1DW/<0;1>/*,[aabb0022/10/4893]xpub6AyxexvxizZJffF153evmfqHcE9MV88fCNCAtP3jQjXJHwrAKri71Tq9jWUkPxj9pja4u6AkCPHY7atgxzSEa2HtDwJfrRWKK4fsfQg4o77/<0;1>/*),older(26352))))#sc9gw0z0",
        [
            (((1, (0,)),), None, None),
            (((2, (1, 2, 3)),), 26352, None),
        ],
    ),
    (
        "roundtrip_descriptor",
        "tr([46f4cf22]xpub661MyMwAqRbcG22nAyuZc7MUXR559qKKkHVdi7TKy3Q8m91FKN9heKhP7jWj6SJdyAA9zfQgjQUNWkqjPGJdcH6uFD8mEWJnTps5emjoi9L/<0;1>/*,and_v(v:multi_a(2,[f9eb379c]xpub661MyMwAqRbcF2FpaYbnrN7K6uPhiwg5u1LiqmsMSTnphuhQzpPv9RGdERxDd7pnnrEC8hxttAPi4wbSVsKeJYiHYymfpuxSD7TALTXqjq6/<0;1>/*,[1fc462f2]xpub661MyMwAqRbcEtYavp2XsS9QfH93wyVQnkWenWxWuWdaxDtjBqfzFfWPY83z3da5oYv2XmwgTT97GhGwX9HUGDEP4FERzzgmwaGNAz1emZr/<0;1>/*,[ebcef2a0]xpub661MyMwAqRbcH3JihNDbpEqpmT9xjY5YWd9VwVWQqoWWrggurHs7wsvTXM7ggK5X3wwATxiijwJPe73y9beirtorQebMuL4hR7dbU7akrk7/<0;1>/*),older(124)))#rgrm8l4v",
        [
            (((1, (0,)),), None, None),
            (((2, (1, 2, 3)),), 124, 0),
        ],
    ),
    (
        "roundtrip_descriptor",
        "wsh(or_d(multi(3,[aabbccdd]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*,[aabb0011/10/4893]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*,[aabb0022]xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/<0;1>/*),and_v(v:pk([aabbccdd]xpub69cP4Y7S9TWcbSNxmk6CEDBsoaqr3ZEdjHuZcHxEFFKGh569RsJNr2V27XGhsbH9FXgWUEmKXRN7c5wQfq2VPjt31xP9VsYnVUyU8HcVevm/<0;1>/*),older(26352))))#kjajav3j",
        [
            (((3, (0, 1, 2)),), None, None),
            (((1, (3,)),), 26352, None),
        ],
    ),
    (
        "roundtrip_descriptor",
        "tr(xpub661MyMwAqRbcFWPZkATtyZ3cZboVifGEpVoDNLRotSvymYNbb652s75MJs7x6Dsh1K4WidtHAvWiyWu6ufbvP3RG9ozXYhZA83rAniyTAcQ/<0;1>/*,{and_v(v:pk([5c1f5207]xpub661MyMwAqRbcGjhDHfE45ivpxoBGywTdSJa5vWgB5L5BjUjfdvfwQr618o6hjLSCdLruGwu8WFLbgQa7179EC3HEiEUAceLSHArRgsUPRFe/<0;1>/*),older(42)),multi_a(2,[f25498f5]xpub661MyMwAqRbcEZKeQW5gkVY61KyFdmR2ntRmHdnoyWPE5PrgcpAFhotgSftuQVkw1DXoeE7wGQpXkaijczBFNVSFYs4UN2ZsN8tiBR2cffw/<0;1>/*,[0adab7f3]xpub661MyMwAqRbcGrUYLnLEAqJEjmy9NejNXvjneoochu285TgBszNaS5usEnosxKXQxPS5ppWp923EXmi4JgYJWZa4cwEzTX6n6aacG1bN99j/<0;1>/*,[78428935]xpub661MyMwAqRbcGqCdcSemPFvTbhm5swDzRYxP9azdQGPwgcAYumXhFuQUdNFLxaf61uRB7UdpxsYoP3hMW3sqQF7ErWQm5RznBbbVMm6z6wc/<0;1>/*)})#s235c44f",
        [
            (((1, (1,)),), 42, 0),
            (((2, (2, 3, 4)),), None, 1),
        ],
    ),
    (
        "roundtrip_descriptor",
        "wsh(or_i(and_v(v:thresh(1,pkh([19e064b0]xpub661MyMwAqRbcGRgGoZDVccAfLzLuvxkXevrGCq66XGV9mmRLfJ1aiAZNtVUTfxFMoSmPNJLmEywZn8yQXBzVHVENMRbj3VpVvdzCteCkgq6/<0;1>/*),a:pkh([00454cc2]xpub661MyMwAqRbcExaDFtcC1pVGounzi9bmVb4nBxVr3reFEsFpCTn5VVwuDiUFeJkJtppEC7Gzk3cW8htEB9Q3DcXV28SAHioi2oJZv6oTobF/<0;1>/*)),older(1678)),or_i(and_v(v:thresh(2,pkh([0143d6e6]xpub661MyMwAqRbcFuLKDCSKk2r3KKN7FWXZnx9s7V1xScv7N1qs7xXPxjrarBaPkuzV9ji7Hquwf4G6G12pXFmaeqwXWhKzwSp1j8JgLHTKUDn/<0;1>/*),a:pkh([cd1f0cf2]xpub661MyMwAqRbcGcFwqwdNkHojx6ffeQEXPfopamNscuf4CXaLrKVMkCTpffiFNJ3okep7bgNVx13N1rryW3nQNiPAsrkr5zL9T3vo2ww4fC8/<0;1>/*),a:pkh([d76af68c]xpub661MyMwAqRbcGVFCMA5yqLiF9xj6G9QoqFDQdqmnyCZDTFTfpfUgzevrohjSrMTjoBYyB5YvKjtEqqX9U6yjgDCYRT8e7DeYqLnu6DbFAgj/<0;1>/*)),older(43)),or_d(multi(2,[5b016400]xpub661MyMwAqRbcGZFpjHB8mvxGnDGDdEBetsFu25nC69SrGAJKJVctsFwNNY5VwPMVx7aXL6m1LKAeA5qAE3Wheh5cAKBdxqSFrRBd3Vf7eTX/<0;1>/*,[6b0a6b3f]xpub661MyMwAqRbcGzZBMBU1evaZmfwmEVkzU8oRhu4y7DSaaHHoQeHDbM47JNqeEbJRGGhMNd1Hp9oP2NdYbRHxxcd7YfABiNfULyVW9vDg5cx/<0;1>/*,[1c4eb5d3]xpub661MyMwAqRbcGFr2mWaBr1rX3xfnv75FbzP1hPW7LEzYMzDZV5wPVgcrYEZWxwu8ALUTRJ5ioutE3mz5dTQBWKEkvxCytV3QeNdm4cDHr6p/<0;1>/*),and_v(v:pkh([5c055660]xpub661MyMwAqRbcEqgeH5cqyxRwY4UG21ey1MBJkNBX2xSTmGS9dCRmGQezqHE9mXUXzs9HqFzNEN2KkNw5o8xpqAXw2XxsVhGVm1LbRaEnxyT/<0;1>/*),older(42))))))#hd246u4a",
        [
            (((1, (0, 1)),), 1678, None),
            (((2, (2, 3, 4)),), 43, None),
            (((2, (5, 6, 7)),), None, None),
            (((1, (8,)),), 42, None),
        ],
    ),
    (
        "roundtrip_descriptor",
        "tr(xpub661MyMwAqRbcGqmqNapgQ9kqrLcDeZLHPktzsBcZXTtNx7aEay8NKQPizKcpu2fUejNbZzhZQaZLeDWL3nt8zg9QbFLBUTRQu4qqcSzeEmF/<0;1>/*,{{and_v(v:multi_a(1,[b4e32970]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*,[c318e87f]xpub661MyMwAqRbcG2qnrFJ2MhKFSHehbVkK38gFfG7zXwasN51dKrL4kffj1HRd2zFhAZeQsjYKS8YaiN4sC4gVPHR28qXdQf7pf7nbYoefg6T/<0;1>/*),older(1678)),{and_v(v:pk([6c0d38a3]xpub661MyMwAqRbcF87hAvenL8GHW7qxhtn8Y9zHVkQbuTsd6RVtWkhBY5gh6m4Rua9ENmYDx7jTb8kbiyVB9iaLAbyRudxPFVTFoGPp6rTqoZn/<0;1>/*),older(42)),and_v(v:multi_a(2,[2e1370a6]xpub661MyMwAqRbcGRzCgSNLW7VFUFdwvC1dFXmKgWbZwQERj2QfNQuy5diCQSHNXuQYSS9FwXykLeWKtnZ5yRJ4ZHZzYqWf13FUY4PbDpBhipr/<0;1>/*,[fae2633e]xpub661MyMwAqRbcG9qKwZ7F363Mx3Ai3H2aMXAWTjvYCZrH4wqDEDLnsVghWFrwTKwpDGGzsSDCL7vPTiaiY7DhhdV2bY6RdPNGd7bF9om1MFz/<0;1>/*,[2ae87e33]xpub661MyMwAqRbcGw8ZvGfdLEjhCk4YC9hZrrUceKipiH32ANDMQccYFqq91kH8RpcwGiPnCbUWFo1S6ZGY2GxbVdJFsMYXqzpL1byJ1D3G2Mh/<0;1>/*),older(43))}},multi_a(2,[40f48611]xpub661MyMwAqRbcGUkDb45NBcMYwaaSE3fhsMNwvdf2psYhrqhFmRJY9n8irJuEB3juhK5LQPBiiqdr2gixMmC7Nmtg3Mwu4C5wbeagaAzbb9W/<0;1>/*,[a2bdfbe5]xpub661MyMwAqRbcH228eUBaJvc7Va1y7cGyEH9DZ5vPneKgZDX8eMsSd8PHS3uRYCFySyHPy3VfGfS8vKb5FzcS2MbNorNVv2c3Hn7AvVJJZ73/<0;1>/*,[028ece7a]xpub661MyMwAqRbcG9W1pZzs7rvWVtHeW1anzABj8iQRBbnz8yLf7vgUmYkVsydLf1hLffibgfzUjTBcrNCDKaBNnuqLtsp1xyiLSZJyLDtEjkF/<0;1>/*)})#xgzxdvrv",
        [
            (((1, (1, 2)),), 1678, 0),
            (((1, (3,)),), 42, 1),
            (((2, (4, 5, 6)),), 43, 2),
            (((2, (7, 8, 9)),), None, 3),
        ],
    ),
    (
        "partial_spend_info_p2wsh",
        "wsh(or_d(pk([f5acc2fd]tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T/<0;1>/*),and_v(v:pkh([8a64f2a9]tpubD6NzVbkrYhZ4WmzFjvQrp7sDa4ECUxTi9oby8K4FZkd3XCBtEdKwUiQyYJaxiJo5y42gyDWEczrFpozEjeLxMPxjf2WtkfcbpUdfvNnozWF/<0;1>/*),older(10))))#d72le4dr",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 10, None),
        ],
    ),
    (
        "partial_spend_info_p2wsh",
        "wsh(or_d(multi(2,[636adf3f/48'/1'/0'/2']tpubDEE9FvWbG4kg4gxDNrALgrWLiHwNMXNs8hk6nXNPw4VHKot16xd2251vwi2M6nsyQTkak5FJNHVHkCcuzmvpSbWHdumX3DxpDm89iTfSBaL/<0;1>/*,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*),and_v(v:multi(2,[636adf3f/48'/1'/1'/2']tpubDDvF2khuoBBj8vcSjQfa7iKaxsQZE7YjJ7cJL8A8eaneadMPKbHSpoSr4JD1F5LUvWD82HCxdtSppGfrMUmiNbFxrA2EHEVLnrdCFNFe75D/<0;1>/*,[ffd63c8d/48'/1'/1'/2']tpubDFMs44FD4kFt3M7Z317cFh5tdKEGN8tyQRY6Q5gcSha4NtxZfGmTVRMbsD1bWN469LstXU4aVSARDxrvxFCUjHeegfEY2cLSazMBkNCmDPD/<0;1>/*),older(2))))#xcf6jr2r",
        [
            (((2, (0, 1)),), None, None),
            (((2, (2, 3)),), 2, None),
        ],
    ),
    (
        "partial_spend_info_taproot",
        "tr([f5acc2fd]tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T/<0;1>/*,and_v(v:pkh([8a64f2a9]tpubD6NzVbkrYhZ4WmzFjvQrp7sDa4ECUxTi9oby8K4FZkd3XCBtEdKwUiQyYJaxiJo5y42gyDWEczrFpozEjeLxMPxjf2WtkfcbpUdfvNnozWF/<0;1>/*),older(10)))",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 10, 0),
        ],
    ),
    (
        "bip32_derivs_pruning",
        "wsh(or_i(and_v(v:thresh(3,pkh([636adf3f/48'/1'/0'/2']tpubDEE9FvWbG4kg4gxDNrALgrWLiHwNMXNs8hk6nXNPw4VHKot16xd2251vwi2M6nsyQTkak5FJNHVHkCcuzmvpSbWHdumX3DxpDm89iTfSBaL/<4;5>/*),a:pkh([172ba1bc/48'/1'/0'/2']tpubDEgTZEAraUrKmnbyKJuXYGFPzNCm82bjMqd2GRy2HKviJ1moLtEZrHoUeG2o6uyWLEGx4yBWpctAmxcBx1b5nrrrBo5LjskRxRMDmwkuKxq/<4;5>/*),a:pkh([903115ef/48'/1'/0'/2']tpubDF2Hqd3HXUn5bDMVa2gssqmdTjQsLm9Vc8CSSJFk4YwQg8PChCZiWopAeQ6ZCEWt21n1W8ApEGxEvtB8uPnWW6EG3fwPAFnFM8US4QmgKvp/<4;5>/*)),older(6)),or_d(multi(3,[636adf3f/48'/1'/0'/2']tpubDEE9FvWbG4kg4gxDNrALgrWLiHwNMXNs8hk6nXNPw4VHKot16xd2251vwi2M6nsyQTkak5FJNHVHkCcuzmvpSbWHdumX3DxpDm89iTfSBaL/<0;1>/*,[172ba1bc/48'/1'/0'/2']tpubDEgTZEAraUrKmnbyKJuXYGFPzNCm82bjMqd2GRy2HKviJ1moLtEZrHoUeG2o6uyWLEGx4yBWpctAmxcBx1b5nrrrBo5LjskRxRMDmwkuKxq/<0;1>/*,[903115ef/48'/1'/0'/2']tpubDF2Hqd3HXUn5bDMVa2gssqmdTjQsLm9Vc8CSSJFk4YwQg8PChCZiWopAeQ6ZCEWt21n1W8ApEGxEvtB8uPnWW6EG3fwPAFnFM8US4QmgKvp/<0;1>/*),and_v(v:thresh(2,pkh([636adf3f/48'/1'/0'/2']tpubDEE9FvWbG4kg4gxDNrALgrWLiHwNMXNs8hk6nXNPw4VHKot16xd2251vwi2M6nsyQTkak5FJNHVHkCcuzmvpSbWHdumX3DxpDm89iTfSBaL/<2;3>/*),a:pkh([172ba1bc/48'/1'/0'/2']tpubDEgTZEAraUrKmnbyKJuXYGFPzNCm82bjMqd2GRy2HKviJ1moLtEZrHoUeG2o6uyWLEGx4yBWpctAmxcBx1b5nrrrBo5LjskRxRMDmwkuKxq/<2;3>/*),a:pkh([903115ef/48'/1'/0'/2']tpubDF2Hqd3HXUn5bDMVa2gssqmdTjQsLm9Vc8CSSJFk4YwQg8PChCZiWopAeQ6ZCEWt21n1W8ApEGxEvtB8uPnWW6EG3fwPAFnFM8US4QmgKvp/<2;3>/*)),older(3)))))#jxya9h7u",
        [
            (((3, (0, 1, 2)),), 6, None),
            (((3, (3, 4, 5)),), None, None),
            (((2, (6, 7, 8)),), 3, None),
        ],
    ),
    (
        "unsigned_tx_max_weight_and_vbytes",
        "tr(tpubD6NzVbkrYhZ4WUdbVsXDYBCXS8EPSYG1cAN9g4uP6uLQHMHXRvHSFkQBXy7MBeAvV8PDVJJ4o3AwYMKJHp45ci2g69UCAKteVSAJ61CnGEV/<0;1>/*,{and_v(v:pk([9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK/<2;3>/*),older(65535)),multi_a(2,[9e1c1983/48'/1'/0'/2']tpubDEWCLCMncbStq4BLXkQUAPqzzrh2tQUgYeQPt4NrB5D7gRraMyGbRqzPTmQGvqfdaFsXDVGSQBRgfXuNjDyfU626pxSjpQZszFNY6CzogxK/<0;1>/*,[3b1913e1/48'/1'/0'/2']tpubDFeZ2ezf4VUuTnjdhxJ1DKhLa2t6vzXZNz8NnEgeT2PN4pPqTCTeWUcaxKHPJcf1C8WzkLA71zSjDwuo4zqu4kkiL91ZUmJydC8f1gx89wM/<0;1>/*)})#ee0r4tw5",
        [
            (((1, (1,)),), 65535, 0),
            (((2, (2, 3)),), None, 1),
        ],
    ),
    (
        "change_detection",
        "wsh(or_d(multi(3,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*),and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*)),older(26352))))",
        [
            (((3, (0, 1, 2)),), None, None),
            (((2, (3, 4, 5)),), 26352, None),
        ],
    ),
    (
        "change_detection",
        "tr(tpubD6NzVbkrYhZ4YdBUPkUhDYj6Sd1QK8vgiCf5RwHnAnSNK5ozemAZzPTYZbgQq4diod7oxFJJYGa8FNRHzRo7URkixzQTuudh38xRRdSc4Hu/<0;1>/*,{and_v(v:multi_a(1,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<2;3>/*),older(2)),multi_a(2,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<0;1>/*)})",
        [
            (((1, (1, 2)),), 2, 0),
            (((2, (3, 4)),), None, 1),
        ],
    ),
    (
        "descriptor_contains_fingerprint_in_primary_path_multi",
        "wsh(or_d(multi(3,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*),and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*)),older(26352))))",
        [
            (((3, (0, 1, 2)),), None, None),
            (((2, (3, 4, 5)),), 26352, None),
        ],
    ),
    (
        "descriptor_contains_fingerprint_in_primary_path_single_key",
        "wsh(or_d(pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*),and_v(v:thresh(1,pkh([bbcc2233/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*)),older(26352))))",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 26352, None),
        ],
    ),
    (
        "descriptor_contains_fingerprint_in_recovery_path_multi",
        "wsh(or_d(multi(3,[aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*,[aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/0/<0;1>/*,[aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/0/<0;1>/*),and_v(v:thresh(2,pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/1/<0;1>/*),a:pkh([aabb0012/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*),a:pkh([aabb0013/48'/0'/0'/2']xpub67zuTXF9Ln4731avKTBSawoVVNRuMfmRvkL7kLUaLBRqma9ZqdHBJg9qx8cPUm3oNQMiXT4TmGovXNoQPuwg17RFcVJ8YrnbcooN7pxVJqC/1/<0;1>/*)),older(26352))))",
        [
            (((3, (0, 1, 2)),), None, None),
            (((2, (3, 4, 5)),), 26352, None),
        ],
    ),
    (
        "descriptor_contains_fingerprint_in_recovery_path_single_key",
        "wsh(or_d(pkh([aabb0011/48'/0'/0'/2']xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/0/<0;1>/*),and_v(v:thresh(1,pkh([bbcc2233/48'/0'/0'/2']xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/1/<0;1>/*)),older(26352))))",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 26352, None),
        ],
    ),
    (
        "descriptor_contains_fingerprint_in_recovery_path_multiple_keys",
        "wsh(or_d(c:or_i(and_v(v:older(38305),and_v(v:pkh([d6bba22a/84'/1'/0']tpubDCwMfgJWBGfJuZFmgTAP9qdSwJeC4fEKaYXQx7CNiTzsB5WrpVSmySdPFnKDu8ChWZweYNh7MoAoFsCNY7gTRFSGtDYbG9s6vAKNKzT1Hii/<0;1>/*),pk_h([e9e6c583/48'/1'/0'/2']tpubDEWn2LRKdyREaweKHxj7XzSjcxXGTVbFkL5Qi5AWsJzGvN28cKQwGqCND9TP6EPtPaE13eK9SnyuiQ4qsfy5UuGD3p32Ew36mWfKmYCJRcz/<0;1>/*))),pk_k([de8abde2/48'/1'/0'/2']tpubDES5ZQEwEuj7Fpe6d6wkwD8SdequEa2cqq57QHQ43pb1x2HxbLp6anHwutDNzrMhDAbx1YgxCFAbRi6EhWwQLaGMSSmxJRaAzCUgn6VwpVD/<0;1>/*)),and_v(v:thresh(1,pkh([d6bba22a/84'/1'/0']tpubDCwMfgJWBGfJuZFmgTAP9qdSwJeC4fEKaYXQx7CNiTzsB5WrpVSmySdPFnKDu8ChWZweYNh7MoAoFsCNY7gTRFSGtDYbG9s6vAKNKzT1Hii/<2;3>/*),a:pkh([e9e6c583/48'/1'/0'/2']tpubDEWn2LRKdyREaweKHxj7XzSjcxXGTVbFkL5Qi5AWsJzGvN28cKQwGqCND9TP6EPtPaE13eK9SnyuiQ4qsfy5UuGD3p32Ew36mWfKmYCJRcz/<2;3>/*)),older(52596))))",
        [
            (((2, (0, 1)),), 38305, None),
            (((1, (2,)),), None, None),
            (((1, (3, 4)),), 52596, None),
        ],
    ),
    (
        "test_descriptor_keys",
        "tr(tpubD6NzVbkrYhZ4XokGX5s1FcKj2ozqibXqXc79NkzEbNQvT1j9F7YWe3fPp3eDeMVypHXocGWUkVaC6ZUqMqyQRS27XJcujQLbrqzpoYYLGW5/<0;1>/*,{and_v(v:multi_a(1,[37435aca/48'/1'/0'/2']tpubDEcZc7Um5KPZLF11qLYNgcteH1PH7CSKtTFTuTYuL6jqsP73gBHvLY42FuyvkTWN8C4q1YiDAUAeEuA78CDuuD2x17UKJymkBacCJz8P6NU/<2;3>/*,[05813578/48'/1'/0'/2']tpubDEymPgUFZDLzEePYsai2ZXc9ntsnZBohJvGuHgpZsY5bsUDJMD6de6tevVd1z1EdGPYLdNaPvD4Ck7NgcteYDUPWwExvscfaSUu19k48Mvp/<2;3>/*),older(52596)),and_v(v:pk([37435aca/48'/1'/0'/2']tpubDEcZc7Um5KPZLF11qLYNgcteH1PH7CSKtTFTuTYuL6jqsP73gBHvLY42FuyvkTWN8C4q1YiDAUAeEuA78CDuuD2x17UKJymkBacCJz8P6NU/<0;1>/*),pk([05813578/48'/1'/0'/2']tpubDEymPgUFZDLzEePYsai2ZXc9ntsnZBohJvGuHgpZsY5bsUDJMD6de6tevVd1z1EdGPYLdNaPvD4Ck7NgcteYDUPWwExvscfaSUu19k48Mvp/<0;1>/*))})#ffdmpxzr",
        [
            (((1, (1, 2)),), 52596, 0),
            (((2, (3, 4)),), None, 1),
        ],
    ),
    (
        "deserialization_recomputes_receive_and_change_descriptors",
        "wsh(or_d(pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),and_v(v:pkh([abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*),older(52560))))",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 52560, None),
        ],
    ),
    (
        "deserialization_recomputes_receive_and_change_descriptors",
        "wsh(or_d(pk([11111111]xpub69cP4Y7S9TWcbSNxmk6CEDBsoaqr3ZEdjHuZcHxEFFKGh569RsJNr2V27XGhsbH9FXgWUEmKXRN7c5wQfq2VPjt31xP9VsYnVUyU8HcVevm/<0;1>/*),and_v(v:pkh([22222222]xpub6AA2N8RALRYgLD6jT1iXYCEDkndTeZndMtWPbtNX6sY5dPiLtf2T88ahdxrGXMUPoNadgR86sFhBXWQVgifPzDYbY9ZtwK4gqzx4y5Da1DW/<0;1>/*),older(52560))))",
        [
            (((1, (0,)),), None, None),
            (((1, (1,)),), 52560, None),
        ],
    ),
    # A, B or C alone: Liana merges the keys into a one-of-three primary path
    (
        "primary_path_key_merging",
        f"wsh(or_i(pk({KEY_A}),or_i(pk({KEY_B}),or_i(pk({KEY_C}),and_v(v:pk({KEY_D}),older(42))))))",
        [
            (((1, (0, 1, 2)),), None, None),
            (((1, (3,)),), 42, None),
        ],
    ),
]

REFUSED_BY_LIANA = [
    (
        "descriptor_unspendable_internal_key",
        "tr(tpubDCaEmvN8YCgyfjNfX6j7r71h1Gx5pqVDAjT145hd46R4DhN8cuHUC39bqRXd43xnroUNKTUqFi9RGCLtxAxxwB6ysVhAh5k26q7AkNUxF7b/<0;1>/*,{and_v(v:multi_a(1,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<2;3>/*),older(2)),multi_a(2,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*,[da2ee873/48'/1'/0'/2']tpubDEbXY6RbN9mxAvQW797WxReGGkrdyRfdYcehVVaQQcQ3kyfhxSMcnU9qGpUVRHXXALvBtc99jcuxx5tkzcLaJbAukSNpP9h2ti4XFRosv1g/<0;1>/*)})",
        [
            (((1, (0,)),), None, None),
            (((1, (1, 2)),), 2, 0),
            (((2, (3, 4)),), None, 1),
        ],
    ),
    (
        "inheritance_descriptor_tl_value",
        "wsh(or_i(pk([abcdef01]tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/<0;1>/*),pk([abcdef01]tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/<0;1>/*)))",
        [
            (((1, (0, 1)),), None, None),
        ],
    ),
    (
        "deserialization_recomputes_receive_and_change_descriptors",
        "wpkh(xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*)",
        [
            (((1, (0,)),), None, None),
        ],
    ),
    # A and B, or C alone: Liana cannot merge C into a two-of-three primary path
    (
        "primary_path_key_merging",
        f"wsh(or_i(and_v(v:pk({KEY_A}),pk({KEY_B})),or_i(pk({KEY_C}),and_v(v:pk({KEY_D}),older(42)))))",
        [
            (((2, (0, 1)),), None, None),
            (((1, (2,)),), None, None),
            (((1, (3,)),), 42, None),
        ],
    ),
]

# each: the Liana test that holds it, the descriptor, and why `parse`
# refuses it. A testnet descriptor here takes testnet keys alone, as Bitcoin
# Core's does, where Liana's test mixes in mainnet ones
REFUSED_HERE = [
    (
        "partial_spend_info_p2wsh",
        "wsh(or_d(multi(2,[f5acc2fd]tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T/<0;1>/*,[00112233]xpub6FC8vmQGGfSuQGfKG5L73fZ7WjXit8TzfJYDKwTtHkhrbAhU5Kma41oenVq6aMnpgULJRXpQuxnVysyfdpRhVgD6vYe7XLbFDhmvYmDrAVq/<0;1>/*,[aabbccdd]xpub68XtbpvDM19d39wEKdvadHkZ4FGKf4tnryKzAacttp8BLX3uHj7eK8shRnFBhZ2UL83S9dwXe42Qm6eG6BkR1jy8XwUSNBcHKtET7j4V5FB/<0;1>/*),and_v(v:pkh([8a64f2a9]tpubD6NzVbkrYhZ4WmzFjvQrp7sDa4ECUxTi9oby8K4FZkd3XCBtEdKwUiQyYJaxiJo5y42gyDWEczrFpozEjeLxMPxjf2WtkfcbpUdfvNnozWF/<0;1>/*),older(10))))#2kgxuax5",
        "not a testnet key",
    ),
    (
        "unliftable_miniscript",
        "wsh(0)",
        "the miniscript is not satisfiable",
    ),
]

VECTORS = [
    pytest.param(descriptor, paths, id=vector_id(index, function))
    for index, (function, descriptor, paths) in enumerate(ACCEPTED + REFUSED_BY_LIANA)
]


def _descriptor(text: str) -> tuple[Descriptor, str]:
    """Return the receiving descriptor of a multipath one, and its network."""
    network = "testnet" if "tpub" in text else "mainnet"
    return parse(multipath_descriptors(text, network)[0], network), network


def _shape(descriptor: Descriptor, path: SpendingPath) -> tuple[Any, ...]:
    """Return a path as the vectors write it."""
    keys = [str(key) for key in descriptor.key_expressions]
    quorums = tuple(
        (quorum.threshold, tuple(keys.index(str(key)) for key in quorum.keys))
        for quorum in path.quorums
    )
    return quorums, path.older, path.leaf


@pytest.mark.parametrize("text, expected", VECTORS)
def test_the_paths_of_a_liana_descriptor(text: str, expected: list[Any]) -> None:
    """Liana's primary and recovery paths, in the order the script has them."""
    descriptor, _ = _descriptor(text)
    paths = descriptor.spending_paths
    assert [_shape(descriptor, path) for path in paths] == expected
    assert all(path.after is None and not path.hashes for path in paths)


@pytest.mark.parametrize(
    "text, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, function))
        for index, (function, descriptor, message) in enumerate(REFUSED_HERE)
    ],
)
def test_a_liana_descriptor_refused_here(text: str, message: str) -> None:
    """Refused for what `parse` refuses in any descriptor."""
    with pytest.raises(BTClibValueError, match=message):
        _descriptor(text)


def _signatures(
    path: SpendingPath, network: str, size: int, short: bool
) -> dict[Octets, Octets]:
    """Sign with the first keys of each quorum, one too few where `short`."""
    signatures: dict[Octets, Octets] = {}
    for number, quorum in enumerate(path.quorums):
        count = quorum.threshold - (short and number == 0)
        for key in quorum.keys[:count]:
            signatures[key.sec(0, network)] = b"\xaa" * size
    return signatures


@pytest.mark.parametrize("text, expected", VECTORS)
def test_a_liana_path_spends_alone(text: str, expected: list[Any]) -> None:
    """A path's quorum and timelock spend the output; a key fewer does not."""
    descriptor, network = _descriptor(text)
    is_tr = isinstance(descriptor, TrDescriptor)
    tree = descriptor.taproot_tree() if isinstance(descriptor, TrDescriptor) else []
    size = 64 if is_tr else 72
    for path in descriptor.spending_paths:
        spend = SpendContext(sequence=path.older or 0)
        signatures = _signatures(path, network, size, short=False)
        _, witness = descriptor.satisfy(signatures, spend=spend)
        if path.leaf is not None:
            assert witness.stack[-2] == tree[path.leaf][2]
        with pytest.raises(BTClibValueError):
            descriptor.satisfy(
                _signatures(path, network, size, short=True), spend=spend
            )


# each: a threshold, a number of keys, and whether Liana's liana_desc_keys
# test builds a path of them
QUORUMS = [
    (2, 1, False),
    (1, 2, True),
    (0, 2, False),
    (2, 2, True),
    (3, 2, False),
    (3, 28, True),
    (20, 28, True),
]


@pytest.mark.parametrize("threshold, count, valid", QUORUMS)
def test_a_quorum_is_what_liana_holds_a_path_to(
    threshold: int, count: int, valid: bool
) -> None:
    """A threshold from one to the number of keys, as Liana's PathInfo."""
    keys = tuple(
        KeyExpression(pub_key=PrvKeyData(i).pub.sec) for i in range(1, count + 1)
    )
    if valid:
        assert Quorum(threshold, keys).keys == keys
    else:
        with pytest.raises(BTClibValueError, match="invalid quorum"):
            Quorum(threshold, keys)
