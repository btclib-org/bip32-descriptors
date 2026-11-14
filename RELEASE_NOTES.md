# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.14

This release needs btclib 2026.11.10, ecc 2026.11.8 and base58-bech32
2026.10.23 or later, as v2026.11.13 does. The `secp256k1` extra installs
`ecc[secp256k1]` 2026.11.8 or later.

griffe and `api_gaps.py` find no break against v2026.11.13. The breaks
below are in what is refused and with which message, which neither
compares.

This breaks the API. `RawDescriptor(b"")` raises `BTClibValueError`
with `parse`'s message, `Raw script is not hex`. v2026.11.13 built it
and wrote `raw()`, a text `parse` refuses. `sh()` and `wsh()` refuse an
unpickled empty `raw()` the same way, where v2026.11.13 wrote `sh(raw())`
and `wsh(raw())`.

This breaks the API. A `MultiA`'s k, and the number of a `Miniscript`
node of `older()`, `after()`, `thresh()`, `multi()` or `multi_a()`,
built or changed with `replace`, are refused with the message `parse`
gives their text where they are negative or past the bounds `parse`
reads, still as `BTClibValueError`. A negative one reads, for example,
as `invalid multi_a() threshold: digits expected`, where v2026.11.13
read `invalid k in k-of-n multi_a: -1`, and as
`invalid older() number: digits expected`, where it read
`invalid older() value: -1`. One past the bounds `parse` reads is
refused as `more than 10 digits`, `past an int64_t` or
`not in 0..2**32-1`, as `parse` refuses that fragment's text. A
`thresh()` threshold of 0 reads as `invalid thresh() threshold: 0`,
where it read `invalid thresh() threshold: 0 of 2`.

A node of any other fragment, a wrapper included, built, changed with
`replace` or unpickled into a descriptor, refuses a number past ten
digits as `invalid pk_k() number: more than 10 digits` or
`invalid c: wrapper number: more than 10 digits`, where v2026.11.13 read
`pk_k takes no number:` or `c: takes no number:` and the number. A
number of ten digits or fewer still reads that way. None of the
messages above quotes a number of the size of a private key, which
v2026.11.13's quoted whole.

This breaks the API. `tr()`, `rawtr()`, `sh()`, `wsh()` and a bare
miniscript descriptor refuse more of what their build or `parse`
refuses in a hand-built or unpickled descriptor, key, leaf or node,
such as an unpickled `multi_a(0,K)` leaf, which v2026.11.13 built;
`tests/descriptors/hand_built_test.py` holds the cases. A key's own
fields are not all checked: a path step past 2**32-1 still builds, in a
plain key, a `multi_a()` leaf's key or a `musig()` participant
(issue #334).

## v2026.11.13

This release needs btclib 2026.11.10, ecc 2026.11.8 and base58-bech32
2026.10.23 or later, as v2026.11.12 does. The `secp256k1` extra installs
`ecc[secp256k1]` 2026.11.8 or later.

`BIP32KeyData` is the object a caller works with from a seed to a
derived key: `BIP32KeyData.from_seed` and `derive` answer one, and the
properties `q`, `sec`, `point_var` and `xpub` read the private key
scalar, the 33-byte compressed public key, the curve point and the
neutered key. `bip32.point_from_xkey` answers the curve point of either
half, where `point_from_xpub` still refuses an xprv. These only add
names: griffe and `api_gaps.py` find no break against v2026.11.12.

This breaks the API. `Miniscript` refuses `subs` that is no tuple with a
`BTClibTypeError` naming its type, as `invalid subs type: list`.
v2026.11.12 built a node from a list, and raised the built-in
`TypeError` for some other types, such as an `int`.

`parse` refuses a `multi_a()` or a `sortedmulti_a()` of more than 999
keys for its key count, as `invalid n in k-of-n multi_a: 1000`, whatever
its threshold, as Bitcoin Core does. v2026.11.12 named the threshold
where that was out of range too. A `MultiA` built by hand refuses it in
the same order.

`tr()`, `wsh()`, `sh(wsh())` and a bare miniscript descriptor check more
of an unpickled miniscript node, raising `BTClibValueError` or
`BTClibTypeError`. Its fragment, its subexpressions as a tuple and their
number, a multisig of the other context, and its threshold or lock time
are refused with the build's message. A type or bounds other than those
its build computes is refused as `and_v holds a type or bounds its build
does not compute`. v2026.11.12 built some such nodes, writing a text
`parse` refuses, such as `wsh(and_v(older(2),older(2)))`, and raised
the built-in `IndexError` for others, such as an `and_v` of one
subexpression. Where such a descriptor holds several faults, the one
named can differ from v2026.11.12's.

The attestations name `reusable-build.yml` at btclib-org/.github's
commit `cb5a79443399980ba717df2dea23dbedf6bdbc3a`, its tag v2026.11.12,
where v2026.11.12's named `5be973d6a2969cfc572be91df4637d71d7c56a11`.
The command `SECURITY.md` gives names the signer without a ref and
verifies both. A check that pins `--signer-workflow` to the old commit
fails: drop the ref.

## v2026.11.12

This release needs btclib 2026.11.10, ecc 2026.11.8 and base58-bech32
2026.10.23 or later, as v2026.11.11 does. The `secp256k1` extra installs
`ecc[secp256k1]` 2026.11.8 or later.

This breaks the API. `miniscript.from_script` reads a script holding a
key that is no curve point, as Bitcoin Core's signer does. v2026.11.11
refused it with ecc's `EccValueError`, as its notes say. `reads_back`
answers `True` for such a script, where v2026.11.11 answered `False`.
The `str()` of what `from_script` answers is a text `parse` refuses, as
Core's parser does, and a descriptor built from it refuses the key, with
`parse`'s message.

A descriptor or a miniscript node built by hand, or through
`dataclasses.replace`, refuses more of what `parse` refuses, with a
`BTClibValueError` or a `BTClibTypeError`. v2026.11.11 built these: a
`tr()`, a `rawtr()`, a `multi_a()` or a tapscript node holding an
uncompressed key; a `multi()` of more than three keys, at least one of
them uncompressed, whose redeem script is over the 520-byte push limit,
which `parse` refuses in every position; and a miniscript node whose
fragment is a `str` subclass.

`sh()`, `wsh()` and `tr()` check the descriptor or the miniscript node
they are given as `parse` reads it, also where it skipped its own check,
as an unpickled one does. Where v2026.11.11 built a value whose text
`parse` refuses, such as `wsh(multi(1))`, or raised a built-in
`IndexError`, `TypeError` or `AttributeError`, they raise
`BTClibValueError` or `BTClibTypeError`, or ecc's `EccValueError` for a
key that is no point. Where such a value holds several faults, the
refusal names the one `parse` names: an unpickled `multi(1,X,U)`, with X
an x-only key and U an uncompressed one, is refused for key 0 inside
`wsh()`, where v2026.11.11 named key 1.

`miniscript.from_script` refuses a `CHECKMULTISIG` key count of 0, or
a negative one other than `OP_1NEGATE`, for that count:
`BTClibValueError: invalid number of keys in multi: N`. `reads_back` then
answers `False`, and `infer_descriptor` of its P2WSH the `addr()`.
v2026.11.11 raised the built-in `IndexError` from all three for some such
counts, as -6 or below with no key before it, and named another fault
for others, as a count of 0 after a key.

## v2026.11.11

This release needs btclib 2026.11.10 and ecc 2026.11.8 or later, and
installs base58-bech32 2026.10.23 or later. The `secp256k1` extra
installs `ecc[secp256k1]` 2026.11.8 or later. Beside btclib 2026.11.10,
which has no `btclib.base58`, v2026.11.7's `bip32` and `descriptors`
modules fail to import.

This breaks the API. `crack_prv_key_var` is removed from
`bip32_descriptors.bip32`, with no alias: call `crack_prv_key`, which
takes the same arguments.

`parse` and `miniscript.parse` declare `prv_keys` a `MutableMapping`,
where v2026.11.7 declared a `dict`. They refuse a read-only mapping, such
as a `MappingProxyType`, with `BTClibTypeError`. v2026.11.7 accepted one
unless the text held an xprv, where it raised the built-in `TypeError`.
They also take `preimages` and `wifs` mappings, which the new
`private_string` writes back from, as it does from `prv_keys`.

A descriptor, a key expression or a miniscript node built by hand, or
through `dataclasses.replace`, refuses when built a field of a type
`parse` never produces and a value `parse` refuses there, with a
`BTClibTypeError` or a `BTClibValueError`. v2026.11.7 built it: a hash
fragment's digest given as a `bytearray`, and a `wpkh()` given an
uncompressed key by `replace`, whose `str()` `parse` refuses.
`miniscript.from_script` refuses a script holding a key that is no curve
point, with ecc's `EccValueError`, where v2026.11.7 read it.

`at_index` refuses an index at which a miniscript names one key twice,
with `BTClibValueError`: index 1 of `tr(K,and_v(v:pk(X/*),pk(X/1)))` or of
its `wsh()` form, which v2026.11.7 answered. Index 0 is answered.
`normalized` refuses a descriptor whose keys, once derived with
`prv_keys`, repeat one: `wsh(and_v(v:pk(X/1h/0),pk(C/0)))`, with C the
xpub at X/1h, or its `tr()` form, which v2026.11.7 normalized.

`parse` answers other objects for some texts, and `str()` writes the same
text. The `inner` of `wsh(c:pk_k(K))` and `wsh(c:pk_h(K))` is a
`PkDescriptor` and a `PkhDescriptor`, where v2026.11.7 answered a
`MiniscriptDescriptor`. The `tree` of `tr(K,c:pk_k(X))` is a
`KeyExpression`, where v2026.11.7 answered a `Miniscript`.

A key read from an odd-y WIF in `tr()`, `rawtr()` or a tapscript leaf has
the 0x02 `pub_key` of its x, where v2026.11.7 kept the WIF's 0x03 key.
`satisfy` finds no signature offered under that 0x03 key: offer it under
the x-only key or the 0x02 key. A tapscript leaf naming two keys of one x
is refused whatever their parity, where v2026.11.7 read
`and_v(v:pk(02X),pk(03X))`.

`multipath_descriptors` writes every path of a multipath key in the one
hardening symbol it chooses for the key: `wpkh(<xprv>/<0h;1'>/*)` gives
`wpkh(<xprv>/0'/*)` first, where v2026.11.7 gave `wpkh(<xprv>/0h/*)`.
The string and its checksum change.

Some refusals change their message, so code matching the old text has
to change: `parse` names a refused key by its position, as in
`key 0: uncompressed public keys are not allowed here`, and gives
Bitcoin Core's message and order in more places.

`parse` reads `unused(KEY)` at the top level, as an `UnusedDescriptor`,
and a hash fragment's `preimage(HEX)`, which it files in `preimages`.

## v2026.11.7

This release needs ecc 2026.11.6 or later. The `secp256k1` extra
installs `ecc[secp256k1]`, where v2026.11.4 named `btclib[secp256k1]`
and `btclib-secp256k1`: this package reaches the libsecp256k1 bindings
only through ecc.

`pub_key_derivation_tweaks` refuses a step at the point at infinity with
ecc's `EccValueError`, with or without the bindings. v2026.11.4 raised a
bare `ValueError` with the bindings and a `BTClibValueError` without
them. `EccValueError` is a `ValueError` but no `BTClibException`, so code
catching `BTClibValueError` there has to catch `EccValueError` from
`ecc.exceptions` too. `derive` still raises `BTClibValueError`.

`str()` of a key expression whose key path and wildcard harden with
different symbols writes the key path's symbol, as Bitcoin Core does:
`wpkh(<xprv>/0h/*')` is written `wpkh(<xpub>/0h/*h)`, where v2026.11.4
wrote `wpkh(<xpub>/0'/*')`. The string and its checksum change, so a
stored descriptor of that shape no longer matches what `str()` answers.

## v2026.11.4

Where `parse` does not read what `infer_descriptor` infers back to the
same script, `infer_descriptor` answers the `addr()` of the output, or
its `raw()` where the output has no address, such as a bare `multi()` or
a `pk()`. v2026.11.2 answered a descriptor that `parse` refuses: for
example, one holding a key that is no point, a `wsh()` of a miniscript
that cannot be satisfied, or a bare `multi()` of more than three keys.
Code that compares the answer with Core's `decodescript` or
`scantxoutset` has to expect these.

For a p2tr output, `infer_descriptor` writes out a repeated subtree only
where the tree then holds at most 1024 leaves. Past that, each repeat is
the `rawnode()` of its hash, where v2026.11.2 wrote every one out. Code
that expects the repeats written out meets `rawnode()` instead.

No workflow tests this release on x86_64 macOS: `os-macos.yml` and
`pypi-install.yml` run macOS on arm64 alone.

## v2026.11.2

`parse` reads `rawnode()`, `rawleaf()` and `rawpkh()`, and `raw()` inside
`sh()` and `wsh()`, which let a descriptor say what it knows of an output
it knows in part. Their classes are `RawNode`, `RawLeaf` and
`RawPkhDescriptor`.

This breaks the API. `DescriptorLeaf` gains `RawLeaf`, and
`DescriptorTree` gains `RawNode`, so code that walks the `tree` of a
`TrDescriptor` meets them. For a `tr()` whose tree holds a `rawnode()`,
`expansion()` gives the internal key, the merkle root and the known leaf
scripts, with `taproot_tree` None: such an expansion describes an input,
and an output's Updater has to refuse it.

`infer_descriptor` answers a `tr()` holding a `rawleaf()` or a
`rawnode()` where it cannot write every leaf as a descriptor, or knows
only part of the tree, where v2026.10.31 answered `rawtr()`.

`infer_descriptor` reads a script nested past the interpreter's recursion
limit, where v2026.10.31 raised `RecursionError`: a `tr()` leaf infers as
its miniscript, and a `wsh()` script past the ops limit as `addr()`.

`raw()` refuses an empty HEX and a HEX with whitespace, where
v2026.10.31 read `raw( 51)` as `raw(51)`.

Some refusals of `parse` change their message, so code matching the old
text has to change. Where Bitcoin Core's miniscript parser fails on a
wrapper, a number, a hash, an unbalanced bracket or trailing text,
`parse` gives Core's fallback: `A function is needed within P2WSH` in
`wsh()`, and `tr() leaf is not a valid descriptor function` in a `tr()`
leaf. For `sha256(zz)`, v2026.10.31 said
`invalid sha256() hash: hex expected`. A `tr()` tree is read leaf by
leaf, so a fault inside a leaf gets that leaf's refusal, such as
`not a key expression`, where v2026.10.31 could say `unbalanced braces`.

Where one fragment spells a key twice with two explicit origins,
`Descriptor.provider` gives the later one, where v2026.10.31 put the
later origin in front of the earlier one. `expansion()` keeps the first.

## v2026.10.31

The first release of `bip32-descriptors`: BIP32 keys, output script
descriptors and miniscript, imported as `bip32_descriptors`. There is no
earlier version of it to upgrade from.

The code is btclib-wallet's `bip32` and `descriptors` packages as of
btclib-wallet b8b5c9b. Every module keeps its name and its `__all__`
under the new prefix: `btclib_wallet.bip32` and
`btclib_wallet.descriptors` become `bip32_descriptors.bip32` and
`bip32_descriptors.descriptors`.

btclib-wallet still ships both packages. btclib-org/btclib-wallet#634
tracks removing them there, with no alias of the old names, and making
btclib-wallet depend on this package. Code that imports them from
`btclib_wallet` then imports them from `bip32_descriptors`.

Code coming from btclib-wallet v2026.10.29 meets these differences too.

In `wsh()` and in a `tr()` leaf, `parse` cuts a key, timelock or hash
fragment as Bitcoin Core's `Expr` does, counting `{` as a bracket
(btclib-org/btclib-wallet#607). Where a `{` stands in or after such a
fragment, the `BTClibValueError` for a key fragment is the key's own
refusal, such as `not a key expression` or `invalid key expression`,
where v2026.10.29 said `unbalanced brackets in <fragment>()` or
`invalid key expression`. For `older()` and `after()` it is
`A function is needed within P2WSH` in `wsh()` and
`tr() leaf is not a valid descriptor function` in a `tr()` leaf, and for
a hash fragment `invalid <fragment>() hash: hex expected`, where each was
`unbalanced brackets in <fragment>()`.

`account_descriptors` is in btclib-wallet's `bip44`, and
`update_psbt_input`, `update_psbt_output`, `miniscript_sizer`,
`satisfaction_sizer` and `miniscript_solver` are in its `psbt`; none of
them is in this package (btclib-org/btclib-wallet#620). There,
`update_psbt_input` and `update_psbt_output` are functions that take the
descriptor first, not methods of a descriptor.

The release attaches the wheel,
`bip32_descriptors-2026.10.31-py3-none-any.whl`, the sdist,
`bip32_descriptors-2026.10.31.tar.gz`,
`bip32_descriptors-2026.10.31.cdx.json` and `v2026.10.31.intoto.jsonl`;
*Supported versions* in [SECURITY.md](./SECURITY.md) has the
`gh attestation verify` command.
