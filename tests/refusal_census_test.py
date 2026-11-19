# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A lint: a refusal of the package formats no value the census does not trace.

Section 7 of the btclib-org standard, *A refusal carries no secret*, says
an argument in the wrong place may be a key. The census reads the sources
of the package with `ast` and runs none of them. It is a lint over the
shapes its controls show, the pairs of `_SHAPES` it traces and flags, and
not a proof: a shape no control holds may pass unseen. Each shape
measured to pass unseen is an open issue whose title starts "The refusal
census does not see", of btclib-org/btclib-wallet or of
btclib-org/bitcoin-core-rpc. Its tables of entries are empty.
`test_the_trusted_helpers_are_the_refusal_modules` guards the names it
trusts, as the last paragraph of this docstring says, and the `_UNSEEN`
modules of `test_census_reads_the_shapes_this_package_lacks` hold the
shapes this package's sources do not, so that every branch of the
census runs.

It reads as an exception the package builds each call of a name ending in
`Error` or `Exception`, or of a name a `class` statement, an assignment or
an import binds to such a class or to a class of the package that may be
an exception: one deriving, through classes of the package, from a base
that is neither one of them nor one of `_PLAIN_BASES`. A parameter of the
name, of any kind, binds it to what a caller passes: a call of it is a
site, whose arguments are traced, where its default or what a call of the
package passes there, read as for a parameter below, a method's own object
or class included, is such a class, or where the census cannot read what a
call passes there: a call that unpacks its arguments, a `@classmethod`
called on an object, or a method with another decorator, as below. What
it builds is taken for an exception only where every one of them is.

A call of a parameter is a site too where a caller the census does not
see may fill the parameter, or where a call passes a value it cannot
classify. The first is a parameter it reads by its default alone: of a
public function, of a lambda or of a function read as a value. There a
method's own object is a class only where its class derives from a base
from outside the package, which may be a metaclass such as `type`, and a
`@classmethod`'s own class is the class that defines it or one deriving
from it. The second is a value such as what a call, an `await` or a
`yield` answers, an attribute, an item of a container it cannot read
whole, or a local alias of one of them.

It reads the exception of each `raise` too, but not what a function of
the package returns, nor the exception an `except` around the `raise`
binds, nor a name each value of which its scope assigns is `None`, such a
call, or a call of a function of the package each of whose `return`s is
one; a bare annotation assigns it nothing. Every argument of each has
to be traced to values a refusal may print, and what the census cannot
trace is a finding. It traces

- a literal, a comparison, a name bound by a `def`, a `class` or an
  import but one of `_PROCESS_INPUT`, a builtin of `_PURE_BUILTINS` or
  one whose name ends in `Error`, `Exception` or `Warning`, and an
  attribute named in capitals;
- what `_code`, `_message_text`, `_quoted`, `_type_name`, `len` and
  `bool` answer;
- what `_hex_field` answers: a field of at most 4 bytes holding one of
  the values it is handed second, which section 7 lets a refusal print,
  where it traces those values, and for anything else what
  `_message_text` answers;
- what `_position` answers: an index or a count, and for anything else
  what `_message_text` answers. Where an `if` or an `if` expression
  around it, in the same function, compares what it is handed with a
  constant other than by `is`, or reads it for its truth, which compares
  it with 0, that is a finding: the `if` refuses the value for what it
  is, and `_quoted` describes it. So is a `_position` handed its value
  with `*` or `**`, which the census cannot compare;
- what the methods `bit_length`, `count`, `find` and `index` answer,
  where it traces what they are called on;
- what `_label` answers, where it traces the labels it is handed;
- the index `enumerate` counts from a start it traces, and each number a
  `range` counts, where it traces every argument of it;
- what a callable outside the package answers, where it is one of
  `_OUTSIDE_CALLS` or `_OUTSIDE_METHODS` and the census traces what it
  is handed and what it is called on: any other call outside the
  package is a finding, and so is a call of `_INPUT_READS`, which reads
  a file or a socket, and an attribute of `_PROCESS_INPUT`;
- an attribute or an item of what it traces; each element a loop or a
  comprehension takes from it, or `zip` pairs; and in a loop over rows
  written out, the column the name takes;
- a local or module name, where it traces every value the name is bound
  to, what a `with` binds traced as the call it makes, and every value
  put into it anywhere in the scope, by a method such as `append`, or by
  an assignment, a loop, a comprehension or a `with` that stores an item
  or an attribute of it;
- a parameter of a private function, where it traces what every call in
  the package passes there, and its default, read in the scope where the
  `def` stands;
- an exception the package builds, whose arguments are read where it is
  built;
- what a function of the package answers, where it traces every value
  the function returns or yields, or the item at the position a tuple is
  unpacked from.

A name called is the `def` of the scope that binds it, or the one of the
module of the package it is imported from; an attribute called is every
method of that name in the package, and what it is called on is traced
too, but for a method's own object or class and `super()`. A method takes
first what it is called on, or nothing where it is called through a class
of the package or through a `@classmethod`'s own class. A `@classmethod`
takes its class first however it is called, and a `@staticmethod` takes
nothing. Its decorator says which, not the name of its first parameter;
a decorator that is not provably one of those or of
`_KEEPING_DECORATORS`, taken from its home as `_decorator_name` reads
that, may hand it anything, anywhere. So the census does not trace a
parameter of a public function, of a lambda or of a method with such a
decorator, a method's own object or class, a function read as a value
rather than called, the exception an `except` binds, or what
`_PROCESS_INPUT` names. Each of these holds what a caller, a server or
another program handed over, and reaches a refusal only through `_code`,
`_message_text`, `_position` or `_quoted`, or not at all.

What a refusal still raises that the census does not trace is in `KEPT`,
an exception one function raises by name, each entry with its reason. An
entry no refusal uses fails the census. A `_position` the census finds
compared with a constant, and that writes what section 7 lets a refusal
print, such as a size the package measures, rather than a value a caller
handed over, is in `MEASURED`, each entry with its reason, and an entry
no finding uses fails the census too.

It takes three things on trust. A callable of `_OUTSIDE_CALLS` or
`_OUTSIDE_METHODS` answers a part of what it is handed and of what it is
called on, and nothing else. A builtin of `_PURE_BUILTINS` read by name
holds nothing the process was handed. And a value reaches an object only
through the name the census reads it under. Of a container a name is
bound to in its own scope, a list, a dict, a set or what a call of
`_CONTAINER_TYPES` builds, these places it is handed to are each a
finding: another name, an item of another container, and an argument of
a call other than a refusal, one of `_READERS`, or a function of the
package whose parameter neither has a value put into it nor is handed on
in turn, called without unpacking an argument and not a method with
another decorator, as above. A container reached any other way, through
an attribute or what a call answers, is not followed past the name the
census reads.

An exception that is not one of the package's classes may hold the input,
as a `UnicodeError` holds its bytes, so no refusal chains one or has it as
context, and no `except` raises one again. A class is the package's where
the scope that names it defines it, or imports it from a module of the
package that does: one of another package is not, whatever its name, nor
is a parameter of the name, of any kind, through which a caller can pass
any class. A `raise` inside an `except` of another class, or in a
`finally`, is a finding, and so is a `raise ... from` anything but `None`
or an exception of the package's classes. So is a call, inside such an
`except` or a `finally`, that may reach a `raise` of the package: of a
function of the package that holds one, or calls one that does, however
far down, or of a callee the census cannot name, a parameter, a local or
what is no name, there or in any function it reaches. There a method is
every method of that name in the package, whatever object it is called on,
except that a name called on a method's own object that the package
assigns as an attribute and defines no method of is unknown; a class of
the package called runs the `__init__`, `__new__` and `__post_init__` of
it and of each class of the package it derives from; a builtin, or a name
imported from outside the package, runs none of it. A call of `CLEANUPS`,
each entry with its reason, is not a finding, and an entry no finding uses
fails the census. A bare `raise`, or a `raise` of the name the `except`
binds, is a finding unless the `except` catches the package's classes,
`KeyboardInterrupt` and `SystemExit` alone, or is a cleanup: one that
catches everything, binds no name and has no way out but the bare `raise`
it ends in. What a cleanup relays passes on as it would with no `try`
around it. What a call outside the package raises, and an exception
another package raises that none of the package's `except` catches, are
not read by the census, nor a value attached to an exception with
`add_note`. A `type()` is not traced, nor a `__name__` or a `__qualname__`
of what is not: a class can be given any name, a key's hex among them, and
a metaclass can answer either. A `len` is traced, though a class can
answer it with any number.

`_code` and `_hex_field` are helpers of btclib-org/btclib-wallet that
this package does not define. The census trusts each describing helper
by its name, so `test_the_trusted_helpers_are_the_refusal_modules`
refuses any binding of either, by a `def`, an assignment, an import or
a parameter, and any binding of `_label`, `_message_text`, `_position`,
`_quoted` or `_type_name` but the `def` of `_refusal.py` and an import
of it from there under its own name. It reads the bindings the source
text shows: one made at run time, through `globals()`, `setattr` or the
`builtins` module, it does not see, nor one a wildcard import makes.
"""

from __future__ import annotations

import ast
import io
import itertools
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

_LIBRARY = Path(__file__).parents[1] / "src" / "bip32_descriptors"

# a call whose answer describes what it is handed and holds no byte of it
_DESCRIBING = frozenset(
    {"_code", "_message_text", "_quoted", "_type_name", "len", "bool"}
)
_DESCRIBING_METHODS = frozenset({"bit_length", "count", "find", "index"})
# the callables outside the package a refusal may call, each answering a
# part of what it is handed, or of what it is called on: both are traced
_OUTSIDE_CALLS = frozenset(
    {"fields", "frozenset", "next", "sorted", "str", "sum", "zip"}
)
_OUTSIDE_METHODS = frozenset({"fromkeys", "get", "hex", "items", "join"})
# what a module holds that the process was handed
_PROCESS_INPUT = frozenset(
    {
        "argv",
        "cwd",
        "environ",
        "environb",
        "expanduser",
        "getcwd",
        "getenv",
        "getenvb",
        "home",
        "input",
        "orig_argv",
        "stdin",
    }
)
# the calls that answer what a file or a socket holds, whatever defines them
_INPUT_READS = frozenset(
    {
        "fdopen",
        "read",
        "read1",
        "read_bytes",
        "read_text",
        "readline",
        "readlines",
        "recv",
        "recv_into",
    }
)
# the builtins a refusal may read by name: each is a function or a value
# of the interpreter, and a module's `__name__` is its own
_PURE_BUILTINS = frozenset(
    {
        "__name__",
        "abs",
        "all",
        "any",
        "bool",
        "bytes",
        "chr",
        "divmod",
        "dict",
        "enumerate",
        "float",
        "frozenset",
        "hex",
        "int",
        "isinstance",
        "issubclass",
        "len",
        "list",
        "max",
        "min",
        "ord",
        "range",
        "repr",
        "reversed",
        "round",
        "set",
        "sorted",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
        "zip",
    }
)
# bases outside the package that alone make no class an exception
_PLAIN_BASES = frozenset(
    {"ABC", "Enum", "Generic", "IntEnum", "NamedTuple", "Protocol", "list", "object"}
)
# what an `except` may raise again whose text is the interpreter's own
_INTERRUPTS = frozenset({"KeyboardInterrupt", "SystemExit"})
# a call whose answer is a field of at most 4 bytes, in hex
_FIELDS = frozenset({"_hex_field"})
# a call whose answer is an index or a count, in decimal
_POSITIONS = frozenset({"_position"})
# the methods that put values into a list, a set, a dict or a deque
_MUTATORS = frozenset(
    {
        "add",
        "append",
        "appendleft",
        "extend",
        "extendleft",
        "insert",
        "setdefault",
        "update",
    }
)
# what builds a container a value can be put into
_CONTAINERS = (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)
_CONTAINER_TYPES = frozenset(
    {"list", "dict", "set", "bytearray", "deque", "defaultdict", "OrderedDict"}
)
# what reads a container handed to it, and puts nothing into it
_READERS = frozenset(
    {
        *_DESCRIBING,
        *_FIELDS,
        *_POSITIONS,
        "_label",
        "all",
        "any",
        "enumerate",
        "frozenset",
        "isinstance",
        "iter",
        "join",
        "list",
        "max",
        "min",
        "reversed",
        "set",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
    }
)
_CONSTANT = re.compile(r"_*[A-Z][A-Z0-9_]*")
# the decorators of the package's methods that hand a method what it is
# called on first, as an undecorated one is handed it
_KEEPING_DECORATORS = frozenset({"abstractmethod", "override", "property"})
# the modules a method's decorator is imported from, by its name
_DECORATOR_HOMES = {
    "abstractmethod": ("abc",),
    "classmethod": ("builtins",),
    "override": ("typing", "typing_extensions"),
    "property": ("builtins",),
    "staticmethod": ("builtins",),
}
_FUNCTION = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSION = (ast.ListComp, ast.SetComp, ast.GeneratorExp)
_COMPREHENSIONS = (*_COMPREHENSION, ast.DictComp)
# what answers a value the census cannot read, as a call does
_ANSWERED = (ast.Await, ast.Yield, ast.YieldFrom)
# a `type` statement, which Python parses from 3.12 on
_TYPE_ALIAS = getattr(ast, "TypeAlias", ())
_BINDING = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)
_LOOP = (ast.For, ast.AsyncFor, ast.comprehension)
_DECLARED = (ast.Import, ast.ImportFrom, *_FUNCTION, ast.ClassDef)


def _private(name: str) -> bool:
    return name.startswith("_") and not name.endswith("__")


def _on_super(receiver: ast.expr) -> bool:
    """Return whether a method is called on what `super()` answers."""
    return (
        isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Name)
        and receiver.func.id == "super"
    )


def _called_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    return func.attr if isinstance(func, ast.Attribute) else None


def _positional(func: ast.AST) -> list[ast.arg]:
    args: ast.arguments = func.args  # type: ignore[attr-defined]
    return [*args.posonlyargs, *args.args]


def _arguments(func: ast.AST) -> list[ast.arg]:
    args: ast.arguments = func.args  # type: ignore[attr-defined]
    found = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    found.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return found


def _own_nodes(scope: ast.AST) -> list[ast.AST]:
    """Return the nodes of a scope, not entering a nested function or class.

    A function's or a class's own are those of its body: what `_read_around`
    returns of it is read in the scope around it, as is that of a nested
    function or class.
    """
    found: list[ast.AST] = []
    if isinstance(scope, ast.Lambda):
        todo: list[ast.AST] = [scope.body]
    elif isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        todo = list(scope.body)
    else:
        todo = list(ast.iter_child_nodes(scope))
    while todo:
        node = todo.pop()
        found.append(node)
        if isinstance(node, (*_FUNCTION, ast.ClassDef)):
            todo.extend(_read_around(node))
            continue
        todo.extend(ast.iter_child_nodes(node))
    return found


def _block_nodes(statements: list[ast.stmt]) -> list[ast.AST]:
    """Return what a block runs: its statements and the nodes they hold.

    A class's body runs where the class stands, so it is entered; a
    function's or a lambda's runs when it is called, so only what
    `_read_around` reads of it is.
    """
    found: list[ast.AST] = []
    todo: list[ast.AST] = list(statements)
    while todo:
        node = todo.pop()
        found.append(node)
        if isinstance(node, _FUNCTION):
            todo.extend(_read_around(node))
            continue
        todo.extend(ast.iter_child_nodes(node))
    return found


def _read_around(node: ast.AST) -> list[ast.AST]:
    """Return what the scope around a function or a class reads of it.

    Its decorators, the defaults of its parameters, a function's annotations
    and a class's bases and keywords. Python 3.11 to 3.13 run an annotation
    where the `def` stands, unless the module postpones it; the census reads
    it there whether or not it does.
    """
    found: list[ast.AST] = list(getattr(node, "decorator_list", []))
    args: ast.arguments | None = getattr(node, "args", None)
    if args is not None:
        found.extend(args.defaults)
        found.extend(d for d in args.kw_defaults if d is not None)
        found.extend(a.annotation for a in _arguments(node) if a.annotation)
    returns = getattr(node, "returns", None)
    if returns is not None:
        found.append(returns)
    found.extend(getattr(node, "bases", []))
    found.extend(getattr(node, "keywords", []))
    return found


def _cleanup(handler: ast.ExceptHandler) -> bool:
    """Return whether an `except` cleans up and relays what it caught.

    It catches everything, binds no name, ends in a bare `raise`, and has
    no other way out: no other `raise`, no `return`, `break`, `continue`
    or `yield`.
    """
    caught = handler.type
    everything = caught is None or (
        isinstance(caught, ast.Name) and caught.id == "BaseException"
    )
    last = handler.body[-1]
    exits = (ast.Raise, ast.Return, ast.Break, ast.Continue, ast.Yield, ast.YieldFrom)
    others = [
        node
        for node in _block_nodes(handler.body)
        if isinstance(node, exits) and node is not last
    ]
    return (
        everything
        and handler.name is None
        and isinstance(last, ast.Raise)
        and last.exc is None
        and not others
    )


def _function_name(module: _Module, node: ast.AST) -> str:
    """Return the name of the `def` a node is in, or `<module>`."""
    return next(
        (
            scope.name
            for scope in module.scopes(node)
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
        "<module>",
    )


def _enclosing_tests(module: _Module, node: ast.AST) -> list[ast.expr]:
    """Return the test of each `if` whose body or `else` holds the node.

    Up to the function the node is in, and an `if` expression's too.
    """
    found: list[ast.expr] = []
    child, current = node, module.parents.get(node)
    while current is not None and not isinstance(current, _FUNCTION):
        if isinstance(current, (ast.If, ast.IfExp)) and child is not current.test:
            found.append(current.test)
        child, current = current, module.parents.get(current)
    return found


def _constant(expr: ast.expr) -> bool:
    """Return whether an expression is made of literals and capitals alone."""
    if isinstance(expr, ast.Constant):
        return expr.value is not None
    if isinstance(expr, (ast.Name, ast.Attribute)):
        name = expr.id if isinstance(expr, ast.Name) else expr.attr
        return _CONSTANT.fullmatch(name) is not None
    parts: list[ast.expr] = []
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        parts = expr.elts
    elif isinstance(expr, ast.BinOp):
        parts = [expr.left, expr.right]
    elif isinstance(expr, ast.UnaryOp):
        parts = [expr.operand]
    return bool(parts) and all(_constant(part) for part in parts)


def _truths(test: ast.expr) -> list[ast.expr]:
    """Return what a test reads for its truth: `x`, `not x`, `x and y`."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _truths(test.operand)
    if isinstance(test, ast.BoolOp):
        return [truth for value in test.values for truth in _truths(value)]
    return [test]


def _compares_with_a_constant(test: ast.expr, value: ast.expr) -> bool:
    """Return whether a test compares the value with a constant, not by `is`.

    A test that reads the value for its truth compares it with 0.
    """
    shape = ast.dump(value)
    if any(ast.dump(truth) == shape for truth in _truths(test)):
        return True
    for node in ast.walk(test):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for op, left, right in zip(node.ops, operands[:-1], operands[1:], strict=True):
            if isinstance(op, (ast.Is, ast.IsNot)):
                continue
            if (ast.dump(left) == shape and _constant(right)) or (
                ast.dump(right) == shape and _constant(left)
            ):
                return True
    return False


def _names(target: ast.AST) -> list[str]:
    return [node.id for node in ast.walk(target) if isinstance(node, ast.Name)]


def _values(call: ast.Call) -> list[ast.expr]:
    return [*call.args, *(keyword.value for keyword in call.keywords)]


def _names_exception(name: str) -> bool:
    return name.rsplit(".", 1)[-1].endswith(("Error", "Exception"))


def _base_name(base: ast.expr) -> str:
    """Return the name a base of a class is read by, its subscript dropped."""
    while isinstance(base, ast.Subscript):
        base = base.value
    return _called_name(base) or ast.unparse(base)


def _builds_container(node: ast.AST) -> bool:
    """Return whether a binding assigns a container a value can be put into."""
    value = getattr(node, "value", None)
    if isinstance(node, ast.AugAssign) or value is None:
        return False
    if isinstance(value, _CONTAINERS):
        return True
    return isinstance(value, ast.Call) and _called_name(value.func) in _CONTAINER_TYPES


def _mutates(node: ast.AST, name: str) -> bool:
    """Return whether a node is a call putting values into a named container."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _MUTATORS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == name
    )


def _mutated(node: ast.AST) -> list[str]:
    """Return the names a node puts values into: by a call, or as a target.

    `x.append(v)` puts `v` into `x`, and so do `x[k] = v` and `x.k = v`, and
    a loop, a comprehension or a `with` whose target is `x[k]` or `x.k`.
    """
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _MUTATORS
            and isinstance(func.value, ast.Name)
        ):
            return [func.value.id]
        return []
    found: list[str] = []
    for target in _targets(node):
        for part in ast.walk(target):
            if isinstance(part, (ast.Subscript, ast.Attribute)):
                root = part.value
                while isinstance(root, (ast.Subscript, ast.Attribute)):
                    root = root.value
                if isinstance(root, ast.Name):
                    found.append(root.id)
    return found


def _targets(node: ast.AST) -> list[ast.expr]:
    """Return what an assignment, a loop, a comprehension or a `with` stores."""
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, *_LOOP)):
        return [node.target]
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return [i.optional_vars for i in node.items if i.optional_vars]
    return []


def _stores(target: ast.AST, name: str) -> bool:
    """Return whether a target stores the name, not an item or attribute."""
    return any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Store)
        for node in ast.walk(target)
    )


def _rebinds(node: ast.AST, name: str) -> bool:
    """Return whether a node makes a name refer to another object.

    A store of the name, by an assignment, a loop, a `with` or `:=`; an
    `except ... as`, a `def`, a `class`, a `type` statement or an import of
    it; and a pattern that captures it. Setting an attribute or an item of
    what the name holds, or putting a value into it, does not, nor does a
    bare annotation, a `global` or a `nonlocal`, which only declare it, nor
    the target of a comprehension, whose scope is its own.
    """
    if isinstance(node, (*_BINDING, ast.For, ast.AsyncFor)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        bare = isinstance(node, ast.AnnAssign) and node.value is None
        return not bare and any(_stores(target, name) for target in targets)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return any(
            item.optional_vars is not None and _stores(item.optional_vars, name)
            for item in node.items
        )
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return any((a.asname or a.name).split(".")[0] == name for a in node.names)
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    if isinstance(node, _TYPE_ALIAS):
        return _stores(getattr(node, "name"), name)  # noqa: B009
    return isinstance(
        node,
        (ast.ExceptHandler, ast.MatchAs, ast.MatchStar, *_FUNCTION, ast.ClassDef),
    ) and (getattr(node, "name", None) == name)


def _declares(node: ast.AST, name: str) -> bool:
    """Return whether a node declares a name `global` or `nonlocal`."""
    return isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names


def _unbinds(node: ast.AST, name: str) -> bool:
    """Return whether a node unbinds a name.

    A `del` of it, and an `except` that binds it: Python deletes that name
    where the `except` ends.
    """
    if isinstance(node, ast.Delete):
        return any(
            isinstance(part, ast.Name)
            and part.id == name
            and isinstance(part.ctx, ast.Del)
            for target in node.targets
            for part in ast.walk(target)
        )
    return isinstance(node, ast.ExceptHandler) and node.name == name


def _at(node: ast.AST, *, end: bool = False) -> tuple[int, int]:
    """Return where a node starts in the source, or where it ends."""
    if end:
        return getattr(node, "end_lineno", 0), getattr(node, "end_col_offset", 0)
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


def _inside(node: ast.AST, holders: list[ast.AST], module: _Module) -> bool:
    """Return whether a node is inside one of the holders."""
    parent = module.parents.get(node)
    while parent is not None:
        if any(parent is holder for holder in holders):
            return True
        parent = module.parents.get(parent)
    return False


def _binds_into(
    outer: ast.AST, inner: ast.AST, scope: ast.ClassDef, binds: set[int]
) -> tuple[int, int] | None:
    """Return where a block last binds a name before a node, or None.

    A statement of the block of `outer` that holds `inner`, before it, that
    binds the name, a loop aside, which may not run; or `outer` itself, a
    loop, a `with` or an `except` whose body holds `inner`. `binds` holds
    the ids of the nodes that bind the name.
    """
    found: tuple[int, int] | None = None
    for field_name in ("body", "orelse", "finalbody"):
        block = getattr(outer, field_name, None)
        if not isinstance(block, list) or all(s is not inner for s in block):
            continue
        for statement in block[: block.index(inner)]:
            if id(statement) in binds and not isinstance(
                statement, (ast.For, ast.AsyncFor)
            ):
                found = _at(statement)
        if outer is not scope and field_name == "body" and id(outer) in binds:
            found = _at(outer)
    return found


def _class_holds(
    scope: ast.ClassDef,
    read: ast.Name,
    binding: list[ast.AST],
    unbinding: list[ast.AST],
    module: _Module,
) -> tuple[bool, bool]:
    """Return whether a class body may hold a name where it reads it, and must.

    `binding` and `unbinding` are the nodes of the class body that bind the
    name, as `_rebinds` reads that, and that unbind it, as `_unbinds` does.
    It must hold the name where a block on the way to the read binds it,
    as `_binds_into` reads that, and where nothing unbinds it between that
    binding and the read, nor anywhere in a loop that holds the read inside
    that binding, which may run the read again. It may where it must, or
    where a node that binds the name starts before the read, or is in a
    loop that holds the read.
    """
    binds = {id(node) for node in binding}
    path: list[ast.AST] = [read]
    while path[-1] is not scope:
        path.append(module.parents[path[-1]])
    path.reverse()
    loops: list[ast.AST] = []
    # the loops that hold the read inside the binding found so far
    again: list[ast.AST] = []
    bound: tuple[int, int] | None = None
    for outer, inner in itertools.pairwise(path):
        if isinstance(outer, (ast.For, ast.AsyncFor, ast.While)):
            loops.append(outer)
            again.append(outer)
        found = _binds_into(outer, inner, scope, binds)
        if found is not None:
            bound, again = found, []
    where = _at(read)
    must = bound is not None and not any(
        bound < _at(node, end=isinstance(node, ast.ExceptHandler)) < where
        or _inside(node, again, module)
        for node in unbinding
    )
    may = must or any(
        _at(node) < where or _inside(node, loops, module) for node in binding
    )
    return may, must


def _comprehension_binding(expr: ast.Name, module: _Module) -> ast.AST | None:
    """Return the comprehension around a name that binds it, or None.

    A comprehension is a scope of its own, but for the iterable of its first
    `for`, which is read in the scope around it. A lambda between the name
    and the comprehension binds the name where the name is in its body,
    not in a default, and is a parameter of it or rebound in it, as
    `_rebinds` reads that; a `def` or a `class` ends the search.
    """
    path: list[ast.AST] = [expr]
    node = module.parents.get(expr)
    while node is not None and not isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    ):
        if isinstance(node, ast.Lambda):
            if node.body in path and (
                any(arg.arg == expr.id for arg in _arguments(node))
                or any(_rebinds(n, expr.id) for n in _own_nodes(node))
            ):
                return None
        elif (
            isinstance(node, _COMPREHENSIONS)
            and node.generators[0].iter not in path
            and any(_stores(each.target, expr.id) for each in node.generators)
        ):
            return node
        path.append(node)
        node = module.parents.get(node)
    return None


@dataclass
class _Module:
    name: str
    tree: ast.Module
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node

    def scopes(self, node: ast.AST) -> list[ast.AST]:
        """Return the enclosing functions and classes, innermost first.

        The module comes last. A default, an annotation or a decorator of a
        `def` or a lambda is read where it stands, so that `def` is not one
        of its scopes. A class body is a scope of its own statements, of the
        defaults, annotations and decorators of what it defines, and of the
        bases and keywords of a class it defines, but not of a function's
        body, a nested class's or a comprehension's, its first iterable
        aside.
        """
        found: list[ast.AST] = []
        # whether a function, a class or a comprehension shuts out a class body
        shut = False
        below: ast.AST | None = None
        child, current = node, self.parents.get(node)
        while current is not None:
            if isinstance(current, ast.Lambda):
                if child is current.body:
                    found.append(current)
                    shut = True
            elif (
                isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child in current.body
            ):
                found.append(current)
                shut = True
            elif isinstance(current, _COMPREHENSIONS):
                if below is not current.generators[0].iter:
                    shut = True
            elif isinstance(current, ast.ClassDef) and child in current.body:
                if not shut:
                    found.append(current)
                shut = True
            below, child, current = child, current, self.parents.get(current)
        found.append(self.tree)
        return found

    def where(self, node: ast.AST) -> str:
        return f"{self.name}:{getattr(node, 'lineno', 0)}"


# what a value is traced through: a name in the scope that binds it, a
# parameter of a function, or what a private function returns
_Key = tuple[str, int, str]


@dataclass
class _Census:
    modules: list[_Module]
    # the calls of each function of the package, and where it is read as a
    # value, keyed by the id of its `def`
    calls: dict[int, list[tuple[_Module, ast.Call]]] = field(default_factory=dict)
    reads: dict[int, list[tuple[_Module, ast.AST]]] = field(default_factory=dict)
    functions: dict[int, tuple[_Module, ast.AST]] = field(default_factory=dict)
    methods: dict[str, list[ast.AST]] = field(default_factory=dict)
    scopes: dict[int, tuple[_Module, ast.AST]] = field(default_factory=dict)
    nodes: dict[int, list[ast.AST]] = field(default_factory=dict)
    mutations: dict[int, dict[str, list[ast.AST]]] = field(default_factory=dict)
    global_bindings: dict[int, dict[str, list[ast.AST]]] = field(default_factory=dict)
    # the nodes of a class body that bind and unbind a name, by both
    class_names: dict[tuple[int, str], tuple[list[ast.AST], list[ast.AST]]] = field(
        default_factory=dict
    )
    edges: dict[_Key, tuple[list[str], set[_Key]]] = field(default_factory=dict)
    reached: dict[_Key, frozenset[str]] = field(default_factory=dict)
    # each class of the package by its name, the `def`s that may raise, and
    # the attributes the package assigns, the last two worked out once
    class_defs: dict[str, list[ast.ClassDef]] = field(default_factory=dict)
    raising: set[int] | None = None
    assigned: set[str] | None = None
    exceptions: set[str] | None = None
    # the entries of `CLEANUPS` and of `KEPT` a finding was hidden by
    used: set[tuple[str, str, str]] = field(default_factory=set)
    kept_used: set[tuple[str, str, str]] = field(default_factory=set)
    measured_used: set[tuple[str, str, str]] = field(default_factory=set)

    def __post_init__(self) -> None:  # noqa: C901
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.ClassDef):
                    self.class_defs.setdefault(node.name, []).append(node)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[id(node)] = (module, node)
                    if isinstance(module.parents.get(node), ast.ClassDef):
                        self.methods.setdefault(node.name, []).append(node)
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Call):
                    for func in self._resolve(node.func, module) or []:
                        self.calls.setdefault(id(func), []).append((module, node))
                elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(
                    node.ctx, ast.Load
                ):
                    parent = module.parents.get(node)
                    if not (isinstance(parent, ast.Call) and parent.func is node):
                        for func in self._resolve(node, module) or []:
                            self.reads.setdefault(id(func), []).append((module, node))

    def _resolve(self, func: ast.expr, module: _Module) -> list[ast.AST] | None:
        """Return the `def`s of the package a callee may be, None where unknown.

        A name is the `def` of the scope that binds it, or the one of the
        module it is imported from. An attribute is every method of that
        name.
        """
        if isinstance(func, ast.Attribute):
            return self.methods.get(func.attr)
        if not isinstance(func, ast.Name):
            return None
        bindings = self._rebindings(func, module)
        if not bindings:
            return None
        found: list[ast.AST] = []
        for binding in bindings:
            if isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append(binding)
            elif isinstance(binding, ast.ImportFrom):
                found.extend(self._imported(binding, func.id))
            else:
                return None
        return found or None

    def _local_scope(self, name: ast.Name, module: _Module) -> ast.AST | None:
        """Return the function, class or module that binds a name by its nodes.

        The scope `_binder` finds, but None where that is a comprehension,
        where the name is a parameter of it, or where a scope declares the
        name `global` or `nonlocal`: values a caller or another scope puts
        there are not among its nodes.
        """
        scope, declared = self._binder(name, module)
        if (
            scope is None
            or declared
            or isinstance(scope, _COMPREHENSIONS)
            or (
                isinstance(scope, _FUNCTION)
                and any(arg.arg == name.id for arg in _arguments(scope))
            )
        ):
            return None
        return scope

    def _rebindings(
        self, name: ast.Name, module: _Module, *, runs: bool = False
    ) -> list[ast.AST] | None:
        """Return the nodes binding a name where it is read, None where unknown.

        The nodes of the scopes `_read_from` finds that `_rebinds` reads,
        and none where nothing binds the name. A parameter, a
        comprehension's target and a name a scope declares `global` or
        `nonlocal` are unknown, and so is a builtin a class body may read,
        unless `runs` asks only what the read may run: a builtin runs
        nothing of the package.
        """
        if self._binder(name, module) == (None, []):
            return []
        scope = self._local_scope(name, module)
        if scope is None:
            return None
        scopes, builtin = self._read_from(scope, name, module)
        if builtin and not runs:
            return None
        return [
            n
            for each in scopes
            for n in self._scope_nodes(each)
            if _rebinds(n, name.id)
        ]

    def _read_from(
        self, scope: ast.AST, name: ast.Name, module: _Module
    ) -> tuple[list[ast.AST], bool]:
        """Return the scopes a name may be read from, and whether a builtin may.

        The scope `_binder` finds. Where that is a class body that need not
        hold the name where it reads it, as `_class_holds` says, Python reads
        the module next, and the builtins where the module does not bind
        the name, and never a function around the class. The class body is
        one of the scopes then only where it may hold the name.
        """
        if not isinstance(scope, ast.ClassDef):
            return [scope], False
        key = (id(scope), name.id)
        if key not in self.class_names:
            nodes = self._scope_nodes(scope)
            self.class_names[key] = (
                [n for n in nodes if _rebinds(n, name.id)],
                [n for n in nodes if _unbinds(n, name.id)],
            )
        may, must = _class_holds(scope, name, *self.class_names[key], module)
        if must:
            return [scope], False
        outside = any(_rebinds(n, name.id) for n in self._scope_nodes(module.tree))
        return [*([scope] if may else []), module.tree], not outside

    def _imported(self, node: ast.ImportFrom, name: str) -> list[ast.AST]:
        """Return the `def`s an import of the package binds to a name."""
        source = next(a.name for a in node.names if (a.asname or a.name) == name)
        path = f"{(node.module or '').replace('.', '/')}.py"
        package = path.removesuffix(".py") + "/__init__.py"
        return [
            func
            for module in self.modules
            if module.name in {path, package}
            for func in module.tree.body
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))
            and func.name == source
        ]

    def sites(self) -> list[tuple[_Module, ast.AST, list[ast.expr]]]:
        """Return each exception the package builds, and the values it holds.

        A call that builds one is the call, and its arguments. A `raise` of
        what a function of the package returns is not one: the exception
        that function builds is. A `raise` of an exception already built, a
        name or anything else that is no call, holds that exception, which
        is traced as a value; but the exception an enclosing `except`
        handles, raised again, and a name that holds only exceptions built
        at a site.
        """
        found: dict[int, tuple[_Module, ast.AST, list[ast.expr]]] = {}
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                    if self._resolve(node.exc.func, module) is None:
                        found[id(node.exc)] = (module, node.exc, _values(node.exc))
                elif isinstance(node, ast.Raise) and node.exc is not None:
                    if not (
                        self._handled(node, module)
                        or self._built_at_a_site(node.exc, module)
                    ):
                        found[id(node)] = (module, node, [node.exc])
                elif isinstance(node, ast.Call) and self._builds_exception(
                    node.func, module, maybe=True
                ):
                    found[id(node)] = (module, node, _values(node))
        return sorted(
            found.values(),
            key=lambda site: (site[0].name, getattr(site[1], "lineno", 0)),
        )

    def _local_filling(
        self, scope: ast.AST, name: ast.Name, module: _Module
    ) -> list[ast.AST] | None:
        """Return what `_filling` finds in the scopes a name is read from.

        `scope` is the one `_local_scope` returns, and the scopes are those
        `_read_from` finds; None where a builtin may be read.
        """
        scopes, builtin = self._read_from(scope, name, module)
        if builtin:
            return None
        return [node for each in scopes for node in self._filling(each, name.id)]

    def _built_at_a_site(self, exc: ast.expr, module: _Module) -> bool:
        """Return whether a name raised holds only exceptions built at a site.

        Each value its scope assigns it is `None`, a call that builds an
        exception, which is a site of its own, or a call of a function of
        the package each of whose `return`s is one. A builtin it may be is
        none of these.
        """
        if not isinstance(exc, ast.Name):
            return False
        scope = self._local_scope(exc, module)
        if scope is None:
            return False
        bindings = self._local_filling(scope, exc, module)
        return bool(bindings) and all(
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and self._builds_at_a_site(node.value, module)
            for node in bindings or []
        )

    def _builds_at_a_site(self, value: ast.expr | None, module: _Module) -> bool:
        """Return whether a value is `None` or an exception a site builds."""
        if isinstance(value, ast.Constant) and value.value is None:
            return True
        if not isinstance(value, ast.Call):
            return False
        if self._builds_exception(value.func, module):
            return True
        functions = self._resolve(value.func, module) or []
        returns = [
            (self.functions[id(function)][0], node)
            for function in functions
            for node in self._scope_nodes(function)
            if isinstance(node, ast.Return)
        ]
        return bool(returns) and all(
            isinstance(node.value, ast.Call)
            and self._builds_exception(node.value.func, returned_in)
            for returned_in, node in returns
        )

    def _handled(self, node: ast.Raise, module: _Module) -> bool:
        """Return whether a `raise` raises the exception an `except` binds."""
        exc = node.exc
        current = module.parents.get(node)
        while isinstance(exc, ast.Name) and current is not None:
            if isinstance(current, ast.ExceptHandler) and current.name == exc.id:
                return True
            if isinstance(current, (*_FUNCTION, ast.ClassDef)):
                break
            current = module.parents.get(current)
        return False

    def _builds_exception(
        self,
        func: ast.expr,
        module: _Module,
        seen: frozenset[tuple[int, str]] = frozenset(),
        *,
        maybe: bool = False,
    ) -> bool:
        """Return whether a callee is an exception class or a name bound to one.

        A name ending in `Error` or `Exception`, or a name a `class`
        statement, an assignment or an import binds to such a name or to an
        exception class of the package, as `_exception_classes` finds them,
        in the scopes it is read from, as `_read_from` finds them, or in a
        scope that declares it `global` or `nonlocal`. Short of that, a
        parameter of the name, of any kind, binds it to what a caller
        passes, which the outer scopes do not say: it is one where its
        default and what every call of the package passes there are, as
        `_passed` reads them. With `maybe` it may be one, and its arguments
        are traced: where any of them is, or where the census cannot say
        what a call passes, as `_parameter_builds` reads that. Otherwise it
        is not taken for one.
        """
        name = _called_name(func) or ""
        if name.endswith(("Error", "Exception")):
            return True
        if not isinstance(func, ast.Name):
            return False
        scope, declared = self._binder(func, module)
        # a scope that declares the name `global` or `nonlocal` binds it too,
        # whatever the scope that holds the name binds it to
        if any(
            self._binds_exception(binding, name)
            for each in declared
            for binding in self._scope_nodes(each)
        ):
            return True
        if isinstance(scope, _FUNCTION) and any(
            arg.arg == name for arg in _arguments(scope)
        ):
            return self._parameter_builds(scope, name, module, seen, maybe=maybe)
        if scope is None:
            return False
        return any(
            self._binds_exception(binding, name)
            for each in self._read_from(scope, func, module)[0]
            for binding in self._scope_nodes(each)
        )

    def _parameter_builds(
        self,
        func: ast.AST,
        name: str,
        module: _Module,
        seen: frozenset[tuple[int, str]],
        *,
        maybe: bool,
    ) -> bool:
        """Return whether a parameter holds an exception class, or may.

        It may where its default or a value a call passes may be one, as
        `_builds_exception` reads that; where `_passed` cannot say what a
        call passes; where a caller the census does not see may pass
        anything, as `_unseen` reads that; and where a call passes a value
        the census cannot classify, as `_unclassified` reads that.
        """
        if (id(func), name) in seen:
            return False
        passed = self._passed(func, name, module)
        if passed is None:
            return maybe
        if maybe and self._unseen(func, name, module):
            return True
        held = [
            self._builds_exception(
                value, caller, seen | {(id(func), name)}, maybe=maybe
            )
            or (maybe and self._unclassified(value, caller, seen | {(id(func), name)}))
            for caller, value in passed
        ]
        return any(held) if maybe else bool(held) and all(held)

    def _unseen(self, func: ast.AST, name: str, module: _Module) -> bool:
        """Return whether a caller the census does not see fills a parameter.

        A parameter `_passed` reads by its default alone: of a public
        function or of a lambda, or of a function read as a value, but not
        a starred one, which holds a tuple or a dict. A method's own object
        is a class only where the class that defines the method derives
        from a base from outside the package, as `_exception_classes` reads
        that, which may be a metaclass such as `type` or `ABCMeta`: its
        objects are classes. A `@classmethod`'s own class is the class that
        defines it or one deriving from it, as `_derived` reads that, and
        may be an exception where any of them may.
        """
        func_args: ast.arguments = func.args  # type: ignore[attr-defined]
        arg = next(arg for arg in _arguments(func) if arg.arg == name)
        if arg in {func_args.vararg, func_args.kwarg} or not (
            not _private(getattr(func, "name", "")) or id(func) in self.reads
        ):
            return False
        if arg is _receiver(func, module):
            holder = cast("ast.ClassDef", module.parents[func])
            if not _decorated(func, "classmethod", module):
                return holder.name in self._exception_classes()
            return bool(self._derived(holder.name) & self._exception_classes())
        return True

    def _derived(self, base: str) -> set[str]:
        """Return each class of the package that derives from a base, by name.

        The base itself too, as `_closure` reads that.
        """
        return self._closure({base})

    def _bases(self) -> dict[str, set[str]]:
        """Return the names of the bases of each class of the package."""
        return {
            name: {
                _base_name(base) for class_def in class_defs for base in class_def.bases
            }
            for name, class_defs in self.class_defs.items()
        }

    def _closure(self, seed: set[str]) -> set[str]:
        """Return the classes named and each class deriving from one of them.

        The names given, and then, until nothing changes, each class of the
        package one of whose bases is among them.
        """
        bases = self._bases()
        found = set(seed)
        changed = True
        while changed:
            changed = False
            for name, named in bases.items():
                if name not in found and named & found:
                    found.add(name)
                    changed = True
        return found

    def _unclassified(
        self, value: ast.expr, module: _Module, seen: frozenset[tuple[int, str]]
    ) -> bool:
        """Return whether a value passed may be an exception class unseen.

        One `_builds_exception` does not take for one, but which may be: what
        a call, an `await`, a `yield` or a `yield from` answers; an
        attribute, which an assignment the census does not follow may fill;
        an item of a container that may be, as `_items` reads it; a branch
        of an `if` expression, an operand of `and` or `or`, or the value of
        an `:=`, that may be; and a name a scope binds to a value that may
        be, or binds other than by assigning a value, a `def`, a `class` or
        an import. A literal, a lambda and a builtin are not, nor is any
        other expression.
        """
        if (id(value), "") in seen:
            return False
        seen |= {(id(value), "")}
        if isinstance(value, (ast.Call, ast.Attribute, *_ANSWERED)):
            return True
        if isinstance(value, ast.IfExp):
            parts: list[ast.expr] = [value.body, value.orelse]
        elif isinstance(value, ast.BoolOp):
            parts = value.values
        elif isinstance(value, ast.NamedExpr):
            parts = [value.value]
        elif isinstance(value, ast.Subscript):
            parts = self._items(value.value, module)
        elif isinstance(value, ast.Name):
            parts = self._assigned(value, module)
        else:
            return False
        return any(
            self._builds_exception(part, module, seen, maybe=True)
            or self._unclassified(part, module, seen)
            for part in parts
        )

    def _items(self, container: ast.expr, module: _Module) -> list[ast.expr]:
        """Return the items of a container where each binding writes them out.

        A list, a tuple or a dict written out, with no item or entry
        unpacked into it, and a name the scopes it is read from, as
        `_read_from` finds them, assign only such values to, put no value
        into, as `_mutations` reads that, and hand to no other name or call
        that may, as `_escapes` reads that.
        Otherwise the container itself, a call answering what the census
        cannot read: a name bound by a parameter, an import or nothing among
        them.
        """
        unknown: list[ast.expr] = [ast.Call(func=container, args=[], keywords=[])]
        values = [container]
        if isinstance(container, ast.Name):
            values = self._assigned(container, module)
            # a name `_assigned` gives a value for has a scope that binds it
            scope = cast("ast.AST", self._binder(container, module)[0])
            scopes = self._read_from(scope, container, module)[0]
            if not values or any(
                self._mutations(each).get(container.id)
                or self._escapes(each, container.id, module)
                for each in scopes
            ):
                return unknown
        found: list[ast.expr] = []
        for value in values:
            if isinstance(value, (ast.List, ast.Tuple)) and not any(
                isinstance(item, ast.Starred) for item in value.elts
            ):
                found.extend(value.elts)
            elif isinstance(value, ast.Dict) and None not in value.keys:
                found.extend(value.values)
            else:
                return unknown
        return found

    def _assigned(self, name: ast.Name, module: _Module) -> list[ast.expr]:
        """Return each value a name is assigned where it is read.

        By the scopes it is read from, as `_read_from` finds them, and by
        each scope around the read that declares it `global` or `nonlocal`,
        as `_binder` finds them. A
        binding of another kind but a `def`, a `class` or an import, an
        unpacking or a comprehension's `for` among them, gives a call, which
        answers what the census cannot read; a parameter, a builtin and a
        name the source does not bind give nothing.
        """
        scope, declared = self._binder(name, module)
        if scope is None:
            return []
        if isinstance(scope, _COMPREHENSIONS):
            return [ast.Call(func=name, args=[], keywords=[])]
        found: list[ast.expr] = []
        scopes = [*self._read_from(scope, name, module)[0], *declared]
        for node in (n for each in scopes for n in self._scope_nodes(each)):
            if not _rebinds(node, name.id) or isinstance(node, _DECLARED):
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and (
                node.value is not None
                and any(
                    isinstance(t, ast.Name) and t.id == name.id
                    for t in (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                )
            ):
                found.append(node.value)
            else:
                found.append(ast.Call(func=name, args=[], keywords=[]))
        return found

    def _passed(
        self, func: ast.AST, name: str, module: _Module
    ) -> list[tuple[_Module, ast.expr]] | None:
        """Return a parameter's default and what the package's calls pass.

        The calls are read as `_parameter` reads them: of a private
        function, to a parameter that is not starred; None where one
        unpacks what it passes, or where the function is a method with
        another decorator, as `_other_decorator` reads that. A method's own
        object is what each call is called on, or its first argument where
        it is called through a class; a `@classmethod`'s own class is what
        each call is called through, and None where it is called on an
        object, whose class the census does not name. A parameter of a
        public function or of a lambda, or of a function read as a value,
        has its default alone.
        """
        arg = next(arg for arg in _arguments(func) if arg.arg == name)
        func_args: ast.arguments = func.args  # type: ignore[attr-defined]
        positional = [*func_args.posonlyargs, *func_args.args]
        defaults: dict[ast.arg, ast.expr | None] = dict(
            zip(
                positional[len(positional) - len(func_args.defaults) :],
                func_args.defaults,
                strict=True,
            )
        )
        defaults |= zip(func_args.kwonlyargs, func_args.kw_defaults, strict=True)
        default = defaults.get(arg)
        found = [] if default is None else [(module, default)]
        if (
            not _private(getattr(func, "name", ""))
            or arg in {func_args.vararg, func_args.kwarg}
            or id(func) in self.reads
        ):
            return found
        if _other_decorator(func, module):
            return None
        for caller, call in self.calls.get(id(func), []):
            if _unpacks(call):
                return None
            found.extend((caller, k.value) for k in call.keywords if k.arg == name)
            if arg in positional:
                position = positional.index(arg) - self._handed(
                    func, module, call, caller
                )
                if position < 0:
                    # what the method is called on, which it takes first; a
                    # `@classmethod` takes it only where it is a class
                    value = cast("ast.Attribute", call.func).value
                    if _decorated(
                        func, "classmethod", module
                    ) and not self._through_class(value, caller):
                        return None
                    found.append((caller, value))
                elif position < len(call.args):
                    found.append((caller, call.args[position]))
        return found

    def _binds_exception(self, binding: ast.AST, name: str) -> bool:
        """Return whether a binding binds a name to an exception class."""
        classes = self._exception_classes()
        if isinstance(binding, ast.ClassDef):
            return binding.name == name and name in classes
        if isinstance(binding, (ast.Import, ast.ImportFrom)):
            return any(
                (a.asname or a.name) == name
                and (_names_exception(a.name) or a.name in classes)
                for a in binding.names
            )
        if isinstance(binding, (ast.Assign, ast.AnnAssign)) and _rebinds(binding, name):
            source = _called_name(binding.value) if binding.value else None
            return source is not None and (
                _names_exception(source) or source in classes
            )
        return False

    def _exception_classes(self) -> set[str]:
        """Return each class of the package that may be an exception, by name.

        A class one of whose bases is no class of the package nor one of
        `_PLAIN_BASES`, and then, until nothing changes, one deriving from
        any of them. A class with no base, or only plain ones, is not.
        """
        if self.exceptions is None:
            self.exceptions = self._closure(
                {
                    name
                    for name, named in self._bases().items()
                    if named - set(self.class_defs) - _PLAIN_BASES
                }
            )
        return self.exceptions

    def findings(
        self,
        cleanups: Mapping[tuple[str, str, str], str] | None = None,
        kept: Mapping[tuple[str, str, str], str] | None = None,
        measured: Mapping[tuple[str, str, str], str] | None = None,
    ) -> list[str]:
        """Return each exception built from a value the census cannot trace.

        And each `raise` that chains, or leaves as context, an exception
        that can hold the input, each call that may raise from the
        package while handling one, and each `_position` of a value an
        `if` refuses. A call `cleanups` names is not one, nor an exception
        `kept` names a `raise` of by its module, its function and its
        source, nor a `_position` `measured` names by its module, its
        function and its source; each entry that hides one is recorded as
        used.
        """
        cleanups = cleanups or {}
        found = self._untraced_sites(kept or {})
        found.extend(self._refused_positions(measured or {}))
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Raise) and node.exc is not None:
                    found.extend(self._chained(node, module))
                elif isinstance(node, ast.Raise):
                    found.extend(self._raised_again(node, module))
                elif isinstance(node, ast.ExceptHandler) and not self._own(
                    node.type, module
                ):
                    caught = (
                        "everything" if node.type is None else ast.unparse(node.type)
                    )
                    found.extend(
                        self._raising_calls(node.body, module, caught, cleanups)
                    )
                elif isinstance(node, (ast.Try, ast.TryStar)) and node.finalbody:
                    found.extend(
                        self._raising_calls(
                            node.finalbody,
                            module,
                            "whatever the try raised",
                            cleanups,
                        )
                    )
        return found

    def _refused_positions(
        self, measured: Mapping[tuple[str, str, str], str]
    ) -> list[str]:
        """Return each `_position` of a value an `if` around it refuses.

        The `if` is one whose body or `else` holds the call, in the same
        function, and whose test compares what the call is handed with a
        constant, other than by `is`: `index > MAX_INDEX`, `not 0 <= index
        < n`, `version not in {0, 2}`, `index and not ranged`. A call
        `measured` names by its module, its function and its source is not
        one, and is recorded as used. A call that hands its value with `*`
        or `**` is a finding wherever it is.
        """
        found: list[str] = []
        for module in self.modules:
            for node in ast.walk(module.tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in _POSITIONS
                ):
                    continue
                if _unpacks(node):
                    found.append(
                        f"{module.where(node)}: {ast.unparse(node)} hands its value"
                        " unpacked, which the census cannot compare"
                    )
                    continue
                handed = [*node.args[:1]]
                handed += [k.value for k in node.keywords if k.arg == "value"]
                tests = [
                    test
                    for test in _enclosing_tests(module, node)
                    for value in handed
                    if _compares_with_a_constant(test, value)
                ]
                if not tests:
                    continue
                key = (module.name, _function_name(module, node), ast.unparse(node))
                if key in measured:
                    self.measured_used.add(key)
                    continue
                lines = ", ".join(str(test.lineno) for test in tests)
                found.append(
                    f"{module.where(node)}: {ast.unparse(node)} writes what the"
                    f" `if` at line {lines} refuses, which `_quoted` describes"
                )
        return found

    def _untraced_sites(self, kept: Mapping[tuple[str, str, str], str]) -> list[str]:
        """Return each site that holds a value the census cannot trace.

        A `raise` `kept` names by its module, its function and the source
        of what it raises is not one, and is recorded as used.
        """
        found: list[str] = []
        for module, site, values in self.sites():
            if isinstance(site, ast.Raise) and site.exc is not None:
                key = (module.name, _function_name(module, site), ast.unparse(site.exc))
                if key in kept:
                    self.kept_used.add(key)
                    continue
            if untraced := sorted(self.untraced(values, module)):
                found.append(f"{module.where(site)}: " + "; ".join(untraced))
        return found

    def _raising_calls(
        self,
        body: list[ast.stmt],
        module: _Module,
        caught: str,
        cleanups: Mapping[tuple[str, str, str], str],
    ) -> list[str]:
        """Return each call in a block that may raise from the package.

        What a function of the package raises, itself or through any
        function of the package it calls, has the exception handled as
        context. A call whose callee the census cannot name is one too. A
        call `cleanups` names by its module, its function and its source is
        not, and is recorded as used.
        """
        found: list[str] = []
        for node in _block_nodes(body):
            if isinstance(node, ast.Call):
                callee = ast.unparse(node.func)
                callees = self._callees(node.func, module)
                if callees is None:
                    found.append(
                        f"{module.where(node)}: calls {callee}, which the census"
                        f" cannot name, while handling {caught}"
                    )
                elif any(id(function) in self._raising() for function in callees):
                    key = (module.name, _function_name(module, node), callee)
                    if key in cleanups:
                        self.used.add(key)
                        continue
                    found.append(
                        f"{module.where(node)}: calls {callee}, which raises,"
                        f" while handling {caught}"
                    )
        return found

    def _callees(self, func: ast.expr, module: _Module) -> list[ast.AST] | None:
        """Return the `def`s of the package a call may run, None where unknown.

        An attribute called is what `_method_callees` says. A name is the
        `def` of each scope it is read from, as `_rebindings` finds them,
        the one of the package it is imported from, or the constructor of a
        class of the package; a builtin, which a name nothing binds is and
        a class body may read, and a name imported by name from outside the
        package run none of it. A name bound any other way, a
        parameter or a local, is unknown, and so is a callee that is no
        name.
        """
        if isinstance(func, ast.Attribute):
            return self._method_callees(func, module)
        if not isinstance(func, ast.Name):
            return None
        bindings = self._rebindings(func, module, runs=True)
        if bindings is None:
            return None
        found: list[ast.AST] = []
        for binding in bindings:
            runs = self._runs(binding, func.id)
            if runs is None:
                return None
            found.extend(runs)
        return found

    def _method_callees(
        self, func: ast.Attribute, module: _Module
    ) -> list[ast.AST] | None:
        """Return the methods an attribute called may be, None where unknown.

        Every method of that name in the package, whatever it is called on.
        Called on a method's own object, a name that is no method of the
        package but an attribute the package assigns holds whatever was
        assigned, a function of the package included, and is unknown.
        """
        if (
            func.attr not in self.methods
            and self._is_self(func.value, module)
            and func.attr in self._assigned_attributes()
        ):
            return None
        return self.methods.get(func.attr, [])

    def _assigned_attributes(self) -> set[str]:
        """Return the name of each attribute the package assigns a value to."""
        if self.assigned is None:
            self.assigned = {
                node.attr
                for module in self.modules
                for node in ast.walk(module.tree)
                if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
            }
        return self.assigned

    def _runs(self, binding: ast.AST, name: str) -> list[ast.AST] | None:
        """Return what calling a name a node binds runs, None where unknown."""
        if isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [binding]
        if isinstance(binding, ast.ImportFrom):
            return [
                *self._imported(binding, name),
                *self._constructors(binding.names, name),
            ]
        if isinstance(binding, ast.ClassDef):
            return self._constructors([], binding.name)
        return None

    def _constructors(self, names: list[ast.alias], name: str) -> list[ast.AST]:
        """Return what building a class of the package of a name runs.

        Its own `__init__`, `__new__` and `__post_init__`, and those of each
        class of the package it derives from, which it may inherit.
        """
        source = next((a.name for a in names if (a.asname or a.name) == name), name)
        found: list[ast.AST] = []
        seen: set[str] = set()
        todo = [source]
        while todo:
            class_name = todo.pop()
            if class_name in seen:
                continue
            seen.add(class_name)
            for class_def in self.class_defs.get(class_name, []):
                todo.extend(_called_name(base) or "" for base in class_def.bases)
                found.extend(
                    method
                    for method in class_def.body
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and method.name in {"__init__", "__new__", "__post_init__"}
                )
        return found

    def _raising(self) -> set[int]:
        """Return the ids of the `def`s of the package that may raise.

        A `def` holding a `raise` of an exception, or a call the census
        cannot name, and then, until nothing changes, one calling any of
        them.
        """
        if self.raising is None:
            calls: dict[int, list[list[ast.AST]]] = {}
            raising: set[int] = set()
            for function_id, (module, function) in self.functions.items():
                calls[function_id] = []
                for node in self._scope_nodes(function):
                    if isinstance(node, ast.Raise) and node.exc is not None:
                        raising.add(function_id)
                    elif isinstance(node, ast.Call):
                        callees = self._callees(node.func, module)
                        if callees is None:
                            raising.add(function_id)
                        else:
                            calls[function_id].append(callees)
            changed = True
            while changed:
                changed = False
                for function_id, callee_lists in calls.items():
                    if function_id not in raising and any(
                        id(callee) in raising
                        for callees in callee_lists
                        for callee in callees
                    ):
                        raising.add(function_id)
                        changed = True
            self.raising = raising
        return self.raising

    def _is_self(self, expr: ast.expr, module: _Module) -> bool:
        """Return whether an expression is a method's own object or class."""
        return self._receiver_of(expr, module) is not None

    def _receiver_of(self, expr: ast.expr, module: _Module) -> ast.AST | None:
        """Return the method whose own object or class a name is, or None.

        The scope that binds the name, as `_binder` reads it, is that method,
        the name is its first parameter, and neither the method nor a scope
        that declares the name `nonlocal` on the way rebinds it, as
        `_rebinds` reads that.
        """
        if not isinstance(expr, ast.Name):
            return None
        scope, declared = self._binder(expr, module)
        if not isinstance(scope, _FUNCTION):
            return None
        own = _receiver(scope, module)
        rebound = any(
            _rebinds(n, expr.id)
            for each in [scope, *declared]
            for n in self._scope_nodes(each)
        )
        return scope if own is not None and own.arg == expr.id and not rebound else None

    def _handed(
        self, func: ast.AST, module: _Module, call: ast.Call, caller: _Module
    ) -> int:
        """Return how many parameters a call fills before its first argument.

        One where it hands a method what it is called on first, as the
        module's docstring says a method takes it, and none otherwise.
        """
        if _receiver(func, module) is None or not isinstance(call.func, ast.Attribute):
            return 0
        if _decorated(func, "classmethod", module):
            return 1
        return 0 if self._through_class(call.func.value, caller) else 1

    def _through_class(self, receiver: ast.expr, module: _Module) -> bool:
        """Return whether what a method is called on is a class, not an object.

        A class of the package, as `_own` finds one, or the class a
        `@classmethod` is handed first, as `_receiver_of` reads it.
        """
        method = self._receiver_of(receiver, module)
        if method is not None and _decorated(method, "classmethod", module):
            return True
        return self._own(receiver, module)

    def _chained(self, node: ast.Raise, module: _Module) -> list[str]:
        """Return what a `raise` chains that can hold the input.

        An exception is handled, and becomes the context of what is raised,
        in the body of each `except` around the `raise` and in a `finally`.
        One of the package's own classes holds what the census checks; any
        other may hold the input, as a `UnicodeError` holds its bytes.
        """
        found: list[str] = []
        handlers: list[ast.ExceptHandler] = []
        child: ast.AST = node
        parent = module.parents.get(node)
        while parent is not None and not isinstance(parent, (*_FUNCTION, ast.ClassDef)):
            if isinstance(parent, ast.ExceptHandler):
                handlers.append(parent)
            elif (
                isinstance(parent, (ast.Try, ast.TryStar)) and child in parent.finalbody
            ):
                found.append(f"{module.where(node)}: raised in a finally block")
            child, parent = parent, module.parents.get(parent)
        names = {handler.name for handler in handlers if handler.name}
        if isinstance(node.exc, ast.Name) and node.exc.id in names:
            # the exception handled, raised again, as a bare `raise` does
            handler = next(h for h in handlers if h.name == node.exc.id)
            return [*found, *self._relayed(node, handler, module)]
        for handler in handlers:
            if not self._own(handler.type, module):
                caught = (
                    "everything" if handler.type is None else ast.unparse(handler.type)
                )
                found.append(f"{module.where(node)}: raised while handling {caught}")
        cause = node.cause
        if not (
            cause is None
            or (isinstance(cause, ast.Constant) and cause.value is None)
            or (isinstance(cause, ast.Name) and cause.id in names)
            or self._own_kept(cause, module)
        ):
            found.append(f"{module.where(node)}: chains {ast.unparse(cause)}")
        return found

    def _own_kept(self, cause: ast.expr, module: _Module) -> bool:
        """Return whether a name, or an item of it, holds own exceptions alone.

        Each value put into it, in the scopes `_local_filling` reads, is an
        empty literal, None, or a name `_own_caught` says holds an exception
        of the package's own classes.
        """
        while isinstance(cause, ast.Subscript):
            cause = cause.value
        if not isinstance(cause, ast.Name):
            return False
        scope = self._local_scope(cause, module)
        if scope is None:
            return False
        values: list[ast.expr | None] = []
        for node in self._local_filling(scope, cause, module) or []:
            if _mutates(node, cause.id):
                call = cast("ast.Call", node)
                values.extend([*call.args, *(k.value for k in call.keywords)])
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                values.append(node.value)
            else:
                return False
        return bool(values) and all(
            (isinstance(value, (ast.List, ast.Tuple)) and not value.elts)
            or (isinstance(value, ast.Constant) and value.value is None)
            or (isinstance(value, ast.Name) and self._own_caught(value, module))
            for value in values
        )

    def _own_caught(self, name: ast.Name, module: _Module) -> bool:
        """Return whether a name holds an exception of own classes where read.

        Each `except` is read in the scope it binds the name in. Where the
        read is in the body of an `except` that binds the name, of its own
        scope, and nothing else in that `except` binds or unbinds the name,
        as `_rebinds` and `_unbinds` read that, it is that `except`'s.
        Otherwise each node that binds the name where it is read, as
        `_rebindings` finds them, is an `except` of own classes.
        """
        node: ast.AST | None = module.parents.get(name)
        while node is not None and not isinstance(
            node, (*_FUNCTION, ast.ClassDef, *_COMPREHENSIONS, ast.Module)
        ):
            if isinstance(node, ast.ExceptHandler) and node.name == name.id:
                if not any(
                    _rebinds(each, name.id) or _unbinds(each, name.id)
                    for each in _own_nodes(node)
                ):
                    return self._own(node.type, module)
                break
            node = module.parents.get(node)
        bindings = self._rebindings(name, module)
        return bool(bindings) and all(
            isinstance(binding, ast.ExceptHandler) and self._own(binding.type, module)
            for binding in bindings or []
        )

    def _raised_again(self, node: ast.Raise, module: _Module) -> list[str]:
        """Return what a bare `raise` relays: what the `except` caught."""
        parent = module.parents.get(node)
        while parent is not None and not isinstance(parent, (*_FUNCTION, ast.ClassDef)):
            if isinstance(parent, ast.ExceptHandler):
                return self._relayed(node, parent, module)
            parent = module.parents.get(parent)
        return []

    def _relayed(
        self, node: ast.Raise, handler: ast.ExceptHandler, module: _Module
    ) -> list[str]:
        """Return a finding where an exception raised again can hold the input.

        It cannot where each class the `except` catches is the package's or
        an interrupt, whose text is the interpreter's. Nor does a cleanup,
        an `except` of everything that binds no name and ends in a bare
        `raise`, with no other way out: what it relays passes on as it
        would with no `try` at all.
        """
        caught = handler.type
        each = caught.elts if isinstance(caught, ast.Tuple) else [caught]
        relayed = caught is not None and all(
            (isinstance(c, ast.Name) and c.id in _INTERRUPTS) or self._own(c, module)
            for c in each
        )
        if relayed or _cleanup(handler):
            return []
        what = "everything" if caught is None else ast.unparse(caught)
        return [f"{module.where(node)}: raises {what} again"]

    def _own(self, caught: ast.expr | None, module: _Module) -> bool:
        """Return whether an `except` catches the package's classes alone.

        A class is the package's where the scope that names it defines it,
        or imports it from a module of the package that does: a class of
        another package is not, whatever its name. Each node that binds the
        name where it is read, as `_rebindings` finds them, has to bind it to
        a class of the package: a parameter of the name, of any kind, is a
        class a caller passes, which may be any.
        """
        if isinstance(caught, ast.Tuple):
            return all(self._own(each, module) for each in caught.elts)
        if isinstance(caught, ast.Attribute) and isinstance(caught.value, ast.Name):
            # a class of a module of the package, read off the module
            source = self._module_bound(caught.value, module)
            return source is not None and self._defines(source, caught.attr, set())
        if not isinstance(caught, ast.Name):
            return False
        bindings = self._rebindings(caught, module)
        return bool(bindings) and all(
            self._is_class(binding, caught.id, set()) for binding in bindings or []
        )

    def _module_bound(self, name: ast.Name, module: _Module) -> _Module | None:
        """Return the module of the package an import binds to a name.

        Each node that binds the name where it is read, as `_rebindings`
        finds them, has to import that one module.
        """
        found: set[str] = set()
        for node in self._rebindings(name, module) or []:
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                return None
            alias = next(
                a for a in node.names if (a.asname or a.name).split(".")[0] == name.id
            )
            # `import a.b` binds `a`, the package
            dotted = alias.name if alias.asname else alias.name.split(".")[0]
            if isinstance(node, ast.ImportFrom):
                dotted = f"{node.module}.{alias.name}"
            found.add(dotted)
        return self._module_of(found.pop()) if len(found) == 1 else None

    def _module_of(self, dotted: str) -> _Module | None:
        """Return the package's module a dotted name is, None for another."""
        path = f"{dotted.replace('.', '/')}.py"
        package = path.removesuffix(".py") + "/__init__.py"
        return next((m for m in self.modules if m.name in {path, package}), None)

    def _defines(self, module: _Module, name: str, seen: set[tuple[str, str]]) -> bool:
        """Return whether a module binds a name to a class of the package."""
        if (module.name, name) in seen:
            return False
        seen.add((module.name, name))
        bindings = [n for n in self._scope_nodes(module.tree) if _rebinds(n, name)]
        return bool(bindings) and all(
            self._is_class(binding, name, seen) for binding in bindings
        )

    def _is_class(
        self, binding: ast.AST, name: str, seen: set[tuple[str, str]]
    ) -> bool:
        """Return whether a binding is a class the package defines.

        A `class` statement is one, and so is an import of a name from a
        module of the package that binds it to one.
        """
        if isinstance(binding, ast.ClassDef):
            return True
        if not isinstance(binding, ast.ImportFrom):
            return False
        source_name = next(
            a.name for a in binding.names if (a.asname or a.name) == name
        )
        source = self._module_of(binding.module or "")
        return source is not None and self._defines(source, source_name, seen)

    def untraced(self, exprs: list[ast.expr], module: _Module) -> set[str]:
        """Return each value the expressions hold that cannot be traced."""
        leaves: list[str] = []
        keys: set[_Key] = set()
        for expr in exprs:
            self._visit(expr, module, leaves, keys)
        found = set(leaves)
        for key in keys:
            found |= self._reach(key)
        return found

    # low-code-quality measures the complexity the noqa already declines
    def _visit(  # noqa: C901, PLR0911, PLR0912  # sourcery skip: low-code-quality
        self, expr: ast.AST | None, module: _Module, leaves: list[str], keys: set[_Key]
    ) -> None:
        """Sort what an expression holds into untraced values and keys."""
        if expr is None or isinstance(expr, (ast.Constant, ast.Compare)):
            # nothing, a literal, or a bool whatever it compares
            return
        if isinstance(expr, ast.Name):
            key, builtin = self._name_key(expr, module)
            if key is not None:
                keys.add(key)
            if (
                builtin
                and expr.id not in _PURE_BUILTINS
                and not expr.id.endswith(("Error", "Exception", "Warning"))
            ):
                # a builtin that reads what the process holds or was handed
                leaves.append(f"{module.where(expr)} {expr.id}, a builtin")
            return
        if isinstance(expr, ast.Call):
            func = expr.func
            name = _called_name(func) or ""
            if name in _INPUT_READS:
                # what a file or a socket holds, whoever defines the call
                leaves.append(f"{module.where(expr)} {ast.unparse(expr)}, read")
                return
            if (
                isinstance(func, ast.Name)
                and name in {"_label", *_FIELDS}
                and _unpacks(expr)
            ):
                # which argument is which is not in the source
                leaves.append(f"{module.where(expr)} {ast.unparse(expr)}, unpacked")
                return
            if isinstance(func, ast.Name) and name == "_label":
                # an element of the labels it is handed second, or what
                # `_quoted` answers: the labels are what is traced
                labels = [k.value for k in expr.keywords if k.arg != "value"]
                for child in [*expr.args[1:], *labels]:
                    self._visit(child, module, leaves, keys)
                return
            if isinstance(func, ast.Name) and name in _FIELDS:
                # a field holding one of the values it is handed second:
                # those values are what is traced
                defined = [k.value for k in expr.keywords if k.arg != "value"]
                for child in [*expr.args[1:], *defined]:
                    self._visit(child, module, leaves, keys)
                return
            if isinstance(func, ast.Name) and name in _DESCRIBING | _POSITIONS:
                return
            if isinstance(func, ast.Attribute) and name in _DESCRIBING_METHODS:
                self._visit(func.value, module, leaves, keys)
                return
            functions = self._resolve(func, module)
            if functions is not None:
                # what a function of the package answers: each value it
                # returns or yields, whichever `def` the call reaches
                keys.update(("returns", id(function), "") for function in functions)
                if isinstance(func, ast.Attribute) and not (
                    self._is_self(func.value, module) or _on_super(func.value)
                ):
                    # a method found by its name alone: what it is called
                    # on may be no object of the package, and is traced
                    self._visit(func.value, module, leaves, keys)
                return
            if self._builds_exception(func, module):
                # an exception, a site of its own whose arguments it traces
                return
            allowed = (
                _OUTSIDE_METHODS if isinstance(func, ast.Attribute) else _OUTSIDE_CALLS
            )
            if name not in allowed:
                leaves.append(f"{module.where(expr)} {ast.unparse(expr)}")
                return
            # what a method is called on, and not the name of a callable
            # `_OUTSIDE_CALLS` already allows
            receiver = [func] if isinstance(func, ast.Attribute) else []
            for child in [*receiver, *expr.args, *(k.value for k in expr.keywords)]:
                self._visit(child, module, leaves, keys)
            return
        if isinstance(expr, ast.Attribute):
            if _CONSTANT.fullmatch(expr.attr):
                return
            if expr.attr in _PROCESS_INPUT:
                leaves.append(f"{module.where(expr)} {ast.unparse(expr)}")
                return
            self._visit(expr.value, module, leaves, keys)
            return
        if isinstance(expr, (ast.Subscript, ast.NamedExpr, ast.Starred)):
            # an item of what is traced, whichever item
            self._visit(expr.value, module, leaves, keys)
            return
        if isinstance(expr, ast.DictComp):
            self._visit(expr.key, module, leaves, keys)
            self._visit(expr.value, module, leaves, keys)
            return
        if isinstance(expr, _COMPREHENSION):
            # its targets are bound in its own scope, which `_binder` reads
            self._visit(expr.elt, module, leaves, keys)
            return
        if isinstance(expr, ast.IfExp):
            # the test only chooses
            self._visit(expr.body, module, leaves, keys)
            self._visit(expr.orelse, module, leaves, keys)
            return
        if isinstance(
            expr,
            (
                ast.JoinedStr,
                ast.FormattedValue,
                ast.BinOp,
                ast.UnaryOp,
                ast.BoolOp,
                ast.Tuple,
                ast.List,
                ast.Set,
                ast.Dict,
                ast.Slice,
            ),
        ):
            for node in ast.iter_child_nodes(expr):
                if isinstance(node, ast.expr):
                    self._visit(node, module, leaves, keys)
            return
        leaves.append(f"{module.where(expr)} {ast.unparse(expr)}")

    def _mutations(self, scope: ast.AST) -> dict[str, list[ast.AST]]:
        """Return, by name, the nodes in a scope that put values into it."""
        if id(scope) not in self.mutations:
            found: dict[str, list[ast.AST]] = {}
            for node in ast.walk(scope):
                for name in _mutated(node):
                    found.setdefault(name, []).append(node)
            self.mutations[id(scope)] = found
        return self.mutations[id(scope)]

    def _filling(self, scope: ast.AST, name: str) -> list[ast.AST]:
        """Return the nodes that may put a value into a name a scope binds.

        In a comprehension, each `for` whose target stores it; elsewhere,
        each node of the scope that rebinds the name, as `_rebinds` reads
        that, or declares it `global` or `nonlocal`, so that another scope
        may put values into it. In a module, also what `_global_bindings`
        finds. Then each node of the scope, or of a function or a
        comprehension it holds, that puts a value into what the name holds,
        as `_mutated` reads that.
        """
        found: list[ast.AST]
        if isinstance(scope, _COMPREHENSIONS):
            found = [each for each in scope.generators if _stores(each.target, name)]
        else:
            found = [
                n
                for n in self._scope_nodes(scope)
                if _rebinds(n, name) or _declares(n, name)
            ]
        if isinstance(scope, ast.Module):
            found.extend(self._global_bindings(scope).get(name, []))
        seen = {id(n) for n in found}
        found.extend(
            n for n in self._mutations(scope).get(name, []) if id(n) not in seen
        )
        return found

    def _global_bindings(self, tree: ast.Module) -> dict[str, list[ast.AST]]:
        """Return, by name, the nodes that rebind a module's name elsewhere.

        Each node of a function or a class in the module that declares the
        name `global` and rebinds it there, as `_rebinds` reads that: the
        value it binds is the module's.
        """
        if id(tree) not in self.global_bindings:
            found: dict[str, list[ast.AST]] = {}
            for scope in ast.walk(tree):
                if not isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    continue
                nodes = self._scope_nodes(scope)
                declared = {
                    name
                    for node in nodes
                    if isinstance(node, ast.Global)
                    for name in node.names
                }
                for name in declared:
                    found.setdefault(name, []).extend(
                        n for n in nodes if _rebinds(n, name)
                    )
            self.global_bindings[id(tree)] = found
        return self.global_bindings[id(tree)]

    def _scope_nodes(self, scope: ast.AST) -> list[ast.AST]:
        if id(scope) not in self.nodes:
            self.nodes[id(scope)] = _own_nodes(scope)
        return self.nodes[id(scope)]

    def _binder(
        self, node: ast.Name, module: _Module
    ) -> tuple[ast.AST | None, list[ast.AST]]:
        """Return the scope that binds a name where it is read, or None.

        A comprehension around the name that binds it, as
        `_comprehension_binding` finds one; otherwise the innermost function
        whose parameter the name is, or the innermost scope that rebinds it,
        as `_rebinds` reads that. A scope that declares the name `nonlocal`
        hands it to the functions around it, and one that declares it
        `global` to the module, whether or not the module binds it. Each
        scope that declares it is returned too, innermost first. None binds
        a builtin, or a name the source does not bind.
        """
        comprehension = _comprehension_binding(node, module)
        if comprehension is not None:
            return comprehension, []
        declared: list[ast.AST] = []
        for scope in module.scopes(node):
            if isinstance(scope, _FUNCTION) and any(
                arg.arg == node.id for arg in _arguments(scope)
            ):
                return scope, declared
            nodes = self._scope_nodes(scope)
            declarations = [n for n in nodes if _declares(n, node.id)]
            if declarations and scope is not module.tree:
                declared.append(scope)
                if any(isinstance(n, ast.Global) for n in declarations):
                    return module.tree, declared
                continue
            if any(_rebinds(n, node.id) for n in nodes):
                return scope, declared
        return None, declared

    def _name_key(self, node: ast.Name, module: _Module) -> tuple[_Key | None, bool]:
        """Return the key that holds a name's values, and whether a builtin may.

        The key is the innermost scope's that declares the name, which is
        the one whose values the census cannot all see, or else the one's
        that binds it, as `_binder` reads them, and None where none does.
        A class body's key reads the module's too, so a class body that
        cannot hold the name where it reads it, as `_read_from` says, gives
        the module's. A builtin may be read where nothing binds the name,
        and where `_read_from` says so.
        """
        scope, declared = self._binder(node, module)
        holder = declared[0] if declared else scope
        if holder is None:
            return None, True
        builtin = False
        if not declared and isinstance(holder, ast.ClassDef):
            scopes, builtin = self._read_from(holder, node, module)
            holder = scopes[0]
        self.scopes[id(holder)] = (module, holder)
        return ("name", id(holder), node.id), builtin

    def _reach(self, start: _Key) -> frozenset[str]:  # noqa: C901, PLR0912
        """Return each untraced value a key reaches, through every key it reads.

        Tarjan's strongly connected components, iterative: a key on a cycle
        reaches what every key of the cycle reaches.
        """
        if start in self.reached:
            return self.reached[start]
        index: dict[_Key, int] = {}
        low: dict[_Key, int] = {}
        stack: list[_Key] = []
        on_stack: set[_Key] = set()
        work: list[tuple[_Key, list[_Key]]] = []

        def enter(key: _Key) -> None:
            index[key] = low[key] = len(index)
            stack.append(key)
            on_stack.add(key)
            work.append((key, sorted(self._edges(key)[1])))

        enter(start)
        while work:
            key, todo = work[-1]
            if todo:
                child = todo.pop()
                if child in self.reached:
                    continue
                if child not in index:
                    enter(child)
                else:
                    # a key whose component is complete is in `reached`, so
                    # one indexed and not there is on the stack
                    low[key] = min(low[key], index[child])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[key])
            if low[key] == index[key]:
                component: list[_Key] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == key:
                        break
                found: set[str] = set()
                for member in component:
                    leaves, children = self._edges(member)
                    found.update(leaves)
                    for child in children:
                        if child not in component:
                            found |= self.reached[child]
                for member in component:
                    self.reached[member] = frozenset(found)
        return self.reached[start]

    # low-code-quality measures the complexity the noqa already declines
    def _edges(self, key: _Key) -> tuple[list[str], set[_Key]]:  # noqa: C901, PLR0912  # sourcery skip: low-code-quality
        """Return the untraced values a key holds and the keys it reads."""
        if key not in self.edges:
            leaves: list[str] = []
            keys: set[_Key] = set()
            kind, scope_id, name = key
            if kind == "returns":
                module, func = self.functions[scope_id]
                for node in self._scope_nodes(func):
                    if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                        self._visit(node.value, module, leaves, keys)
            elif kind == "item":
                module, func = self.functions[scope_id]
                position, size = map(int, name.split("/"))
                for node in self._scope_nodes(func):
                    if isinstance(node, ast.Return):
                        value = node.value
                        if isinstance(value, ast.Tuple) and len(value.elts) == size:
                            value = value.elts[position]
                        elif isinstance(value, ast.Call) and (
                            callees := self._resolve(value.func, module)
                        ):
                            # that item of what the function it calls returns
                            keys.update(("item", id(c), name) for c in callees)
                            continue
                        self._visit(value, module, leaves, keys)
                    elif isinstance(node, (ast.Yield, ast.YieldFrom)):
                        self._visit(node.value, module, leaves, keys)
            elif kind == "parameter":
                module, func = self.scopes[scope_id]
                self._parameter(func, name, module, leaves, keys)
            else:
                module, scope = self.scopes[scope_id]
                if isinstance(scope, _FUNCTION) and any(
                    arg.arg == name for arg in _arguments(scope)
                ):
                    keys.add(("parameter", scope_id, name))
                if isinstance(scope, ast.ClassDef):
                    # a class body reads a name it has not bound yet from the
                    # module
                    self.scopes[id(module.tree)] = (module, module.tree)
                    keys.add(("name", id(module.tree), name))
                bindings = self._filling(scope, name)
                for node in bindings:
                    self._binding(node, name, module, leaves, keys)
                if any(_builds_container(node) for node in bindings):
                    leaves.extend(self._escapes(scope, name, module))
            self.edges[key] = (leaves, keys)
        return self.edges[key]

    # low-code-quality measures the complexity the noqa already declines
    def _binding(  # noqa: C901  # sourcery skip: low-code-quality
        self,
        node: ast.AST,
        name: str,
        module: _Module,
        leaves: list[str],
        keys: set[_Key],
    ) -> None:
        if _mutates(node, name):
            call = cast("ast.Call", node)
            for value in [*call.args, *(k.value for k in call.keywords)]:
                self._visit(value, module, leaves, keys)
        elif isinstance(node, _BINDING):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if name in _names(target):
                    self._element(target, node.value, name, module, leaves, keys)
        elif isinstance(node, _LOOP):
            self._element(node.target, node.iter, name, module, leaves, keys, loop=True)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            # what the context manager answers, traced as what makes it
            for item in node.items:
                if item.optional_vars is not None and name in _names(
                    item.optional_vars
                ):
                    self._visit(item.context_expr, module, leaves, keys)
        elif isinstance(node, (ast.Import, ast.ImportFrom)) and any(
            alias.name.rsplit(".", 1)[-1] in _PROCESS_INPUT
            and (alias.asname or alias.name).split(".")[0] == name
            for alias in node.names
        ):
            # what the process was handed, imported by name
            leaves.append(f"{module.where(node)} {name}, imported")
        elif not isinstance(node, _DECLARED):
            leaves.append(
                f"{module.where(node)} {name}, bound by {type(node).__name__}"
            )

    def _escapes(
        self, scope: ast.AST, name: str, module: _Module, depth: int = 0
    ) -> list[str]:
        """Return where a container a name is bound to is handed elsewhere.

        What is put into it through another name, or by what it is handed
        to, is not read: a name it is bound to, a container it is put
        into, and a call it is passed to are each a finding, but a refusal,
        a call that only reads it, and a function of the package whose
        parameter neither puts a value into it nor hands it on.
        """
        found: list[str] = []
        reads = [
            node
            for node in ast.walk(scope)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Load)
        ]
        for node in reads:
            parent = module.parents.get(node)
            if isinstance(parent, ast.Call) and node is not parent.func:
                callee = _called_name(parent.func) or ""
                if callee in _READERS or callee.endswith(("Error", "Exception")):
                    continue
                if self._only_read(parent, node, module, depth):
                    continue
            elif not isinstance(
                parent,
                (
                    ast.Assign,
                    ast.AnnAssign,
                    ast.AugAssign,
                    ast.NamedExpr,
                    ast.Call,
                    ast.keyword,
                    ast.Starred,
                    *_CONTAINERS,
                    ast.Tuple,
                    ast.Lambda,
                    ast.arguments,
                ),
            ) or (isinstance(parent, ast.AugAssign) and parent.target is node):
                continue
            found.append(
                f"{module.where(node)} {name}, handed to {type(parent).__name__}"
            )
        return found

    def _only_read(
        self, call: ast.Call, node: ast.Name, module: _Module, depth: int
    ) -> bool:
        """Return whether every package `def` a call runs only reads `node`.

        Where the parameter it is passed as has no value put into it in
        that `def`, and is handed nowhere else. Where the call unpacks an
        argument, or the `def` is a method with another decorator, as
        `_other_decorator` reads that, which parameter that is is not known.
        """
        functions = self._resolve(call.func, module)
        if (
            not functions
            or node not in call.args
            or _unpacks(call)
            or depth > len(self.functions)
        ):
            return False
        for function in functions:
            function_module = self.functions[id(function)][0]
            if _other_decorator(function, function_module):
                return False
            positional = _positional(function)
            position = call.args.index(node) + self._handed(
                function, function_module, call, module
            )
            if position >= len(positional):
                return False
            parameter = positional[position].arg
            if self._mutations(function).get(parameter) or self._escapes(
                function, parameter, function_module, depth + 1
            ):
                return False
        return True

    # low-code-quality measures the complexity the noqa already declines
    def _element(  # noqa: C901, PLR0911, PLR0912  # sourcery skip: low-code-quality
        self,
        target: ast.AST,
        value: ast.expr | None,
        name: str,
        module: _Module,
        leaves: list[str],
        keys: set[_Key],
        *,
        loop: bool = False,
    ) -> None:
        """Sort what the value a target takes the name from holds.

        Where `loop` is set the target takes each element of `value` in turn.
        """
        if loop and isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            counter, args = value.func.id, value.args
            if counter == "range":
                # each number it counts is made of its start, its stop and
                # its step
                for bound in [*args, *(k.value for k in value.keywords)]:
                    self._visit(bound, module, leaves, keys)
                return
            if counter == "enumerate" and args and isinstance(target, ast.Tuple):
                index, element = target.elts
                if name in _names(index):
                    # the index, counted from a start that has to be traced
                    for start in [*args[1:], *(k.value for k in value.keywords)]:
                        self._visit(start, module, leaves, keys)
                    return
                self._element(element, args[0], name, module, leaves, keys, loop=True)
                return
            if counter == "zip" and isinstance(target, ast.Tuple):
                for part, iterable in zip(target.elts, args, strict=False):
                    if name in _names(part):
                        self._element(
                            part, iterable, name, module, leaves, keys, loop=True
                        )
                        return
        if (
            loop
            and isinstance(target, ast.Tuple)
            and isinstance(value, (ast.Tuple, ast.List))
            and all(
                isinstance(row, ast.Tuple) and len(row.elts) == len(target.elts)
                for row in value.elts
            )
        ):
            # a loop over rows written out: the name takes its column
            position = next(
                i for i, part in enumerate(target.elts) if name in _names(part)
            )
            for row in value.elts:
                row_items = cast("ast.Tuple", row).elts
                self._element(
                    target.elts[position],
                    row_items[position],
                    name,
                    module,
                    leaves,
                    keys,
                )
            return
        if (
            not loop
            and isinstance(target, ast.Tuple)
            and isinstance(value, ast.Tuple)
            and len(target.elts) == len(value.elts)
        ):
            # the name is in the target, so in one of its parts
            part, item = next(
                (part, item)
                for part, item in zip(target.elts, value.elts, strict=True)
                if name in _names(part)
            )
            self._element(part, item, name, module, leaves, keys)
            return
        if not loop and isinstance(target, ast.Tuple) and isinstance(value, ast.Call):
            functions = self._resolve(value.func, module)
            position = next(
                (i for i, part in enumerate(target.elts) if name in _names(part)), 0
            )
            if functions is not None and isinstance(target.elts[position], ast.Name):
                # the item of each tuple a function returns, at that position
                keys.update(
                    ("item", id(function), f"{position}/{len(target.elts)}")
                    for function in functions
                )
                return
        self._visit(value, module, leaves, keys)

    # low-code-quality measures the complexity the noqa already declines
    def _parameter(  # noqa: C901  # sourcery skip: low-code-quality
        self,
        func: ast.AST,
        name: str,
        module: _Module,
        leaves: list[str],
        keys: set[_Key],
    ) -> None:
        """Sort what every call of the package passes to a parameter."""
        arg = next(arg for arg in _arguments(func) if arg.arg == name)
        func_name = getattr(func, "name", "a lambda")
        origin = f"{module.where(arg)} parameter {name} of {func_name}"
        func_args: ast.arguments = func.args  # type: ignore[attr-defined]
        positional = [*func_args.posonlyargs, *func_args.args]
        receiver = _receiver(func, module)
        if not _private(func_name) or arg in {func_args.vararg, func_args.kwarg}:
            leaves.append(origin)
            return
        if _other_decorator(func, module):
            # a method whose decorator may hand it anything, in any place
            leaves.append(f"{origin}, decorated")
            return
        if arg is receiver:
            # a method's own object or class, which the census does not
            # trace: a call on an object hands it that object, and a call
            # through the class hands it the first argument, which may be any
            leaves.append(origin)
            return
        if id(func) in self.reads:
            # read as a value, it is called where the census cannot see
            reader, read = self.reads[id(func)][0]
            leaves.append(f"{origin}, read at {reader.where(read)}")
            return
        # the default, which a call that passes nothing there takes
        defaults: dict[ast.arg, ast.expr | None] = dict(
            zip(
                positional[len(positional) - len(func_args.defaults) :],
                func_args.defaults,
                strict=True,
            )
        )
        defaults |= zip(func_args.kwonlyargs, func_args.kw_defaults, strict=True)
        default = defaults.get(arg)
        if default is not None:
            self._visit(default, module, leaves, keys)
        calls = self.calls.get(id(func), [])
        if not calls and default is None:
            leaves.append(f"{origin}, never called")
        for caller, call in calls:
            if _unpacks(call):
                leaves.append(f"{origin}, unpacked at {caller.where(call)}")
                continue
            passed = [k.value for k in call.keywords if k.arg == name]
            if arg in positional:
                position = positional.index(arg) - self._handed(
                    func, module, call, caller
                )
                if position < len(call.args):
                    passed.append(call.args[position])
            for value in passed:
                self._visit(value, caller, leaves, keys)


def _receiver(func: ast.AST, module: _Module) -> ast.arg | None:
    """Return a method's own object or class: its first positional parameter.

    A method here is a function a class body defines, and the decorator, not
    the name, says what it is handed first: a `@staticmethod` has none, and
    one with another decorator, as `_other_decorator` reads that, has none
    the census can name.
    """
    positional = _positional(func)
    if (
        not positional
        or not isinstance(module.parents.get(func), ast.ClassDef)
        or _other_decorator(func, module)
    ):
        return None
    return None if _decorated(func, "staticmethod", module) else positional[0]


def _decorator_name(decorator: ast.expr, module: _Module) -> str | None:
    """Return the decorator a method's decorator provably is, or None.

    One of `_DECORATOR_HOMES`, where its home is provably where it comes
    from. A name is the decorator it is named after where no scope it is
    read in binds it, and the one it imports where an absolute import from
    that decorator's home is all that binds it there, as
    `_decorator_bindings` finds what does; `X.attr` is `attr` where
    `import`s of the home of `attr`, in every clause that binds `X`, are all
    that binds it. Any other binding,
    a parameter and a `*` import from elsewhere included, makes it None, and
    so does any other decorator.
    """
    method = cast("ast.stmt", module.parents[decorator])
    scopes = [module.parents[method], *module.scopes(decorator)]
    if isinstance(decorator, ast.Attribute) and isinstance(decorator.value, ast.Name):
        homes = _DECORATOR_HOMES.get(decorator.attr, ())
        bindings = _decorator_bindings(decorator.value.id, scopes, method)
        return (
            decorator.attr
            if bindings
            and all(
                isinstance(n, ast.Import)
                # Python keeps the last clause, so every one binding `X` counts
                and all(
                    a.name in homes
                    for a in n.names
                    if (a.asname or a.name).split(".")[0] == decorator.value.id
                )
                for n in bindings
            )
            else None
        )
    if not isinstance(decorator, ast.Name):
        return None
    bindings = _decorator_bindings(decorator.id, scopes, method)
    if bindings is None:
        return None
    if names := [_imported_decorator(n, decorator.id) for n in bindings]:
        return names[0] if all(n == names[0] for n in names) else None
    return decorator.id


def _decorator_bindings(
    name: str, scopes: list[ast.AST], method: ast.stmt
) -> list[ast.AST] | None:
    """Return what binds a name in the first of the scopes that binds it.

    A node that rebinds it, as `_rebinds` reads that, a parameter of a
    function, and a `*` import, which may bind any name. None where the
    census cannot say which binding the method's decorator reads: the name
    is declared `global` or `nonlocal` anywhere in a scope, a function it
    holds included, which may rebind it there; or the class body, the first
    scope, binds it other than by a statement of its own before the method,
    so that Python may read it in the scopes around the class.
    """
    for scope in scopes:
        if any(_declares(n, name) for n in ast.walk(scope)):
            return None
        nodes = _own_nodes(scope)
        found: list[ast.AST] = [
            n
            for n in nodes
            if _rebinds(n, name)
            or (isinstance(n, ast.ImportFrom) and n.names[0].name == "*")
        ]
        if isinstance(scope, _FUNCTION):
            found.extend(a for a in _arguments(scope) if a.arg == name)
        if found and scope is scopes[0]:
            body: list[ast.stmt] = getattr(scope, "body", [])
            if any(n not in body[: body.index(method)] for n in found):
                return None
        if found:
            return found
    return []


def _imported_decorator(binding: ast.AST, name: str) -> str | None:
    """Return the decorator an absolute import from its home binds, or None.

    Every clause of the import that binds the name has to import the same
    decorator from its home.
    """
    if not isinstance(binding, ast.ImportFrom) or binding.level:
        return None
    found = [
        bound if binding.module in _DECORATOR_HOMES.get(bound, ()) else None
        for alias in binding.names
        for bound in [name if alias.name == "*" else alias.name]
        if (alias.asname or bound) == name
    ]
    return found[0] if found and all(f == found[0] for f in found) else None


def _decorated(func: ast.AST, decorator: str, module: _Module) -> bool:
    """Return whether a `def` carries a decorator `_decorator_name` names so."""
    return any(
        _decorator_name(d, module) == decorator
        for d in getattr(func, "decorator_list", [])
    )


def _other_decorator(func: ast.AST, module: _Module) -> bool:
    """Return whether a method carries a decorator the census does not know.

    One `_decorator_name` reads as none of `staticmethod`, `classmethod` and
    `_KEEPING_DECORATORS`: it may hand the method anything first, or
    nothing, so the census cannot say which parameter a call's argument
    lands in.
    """
    known = {"staticmethod", "classmethod", *_KEEPING_DECORATORS}
    return isinstance(module.parents.get(func), ast.ClassDef) and any(
        _decorator_name(d, module) not in known
        for d in getattr(func, "decorator_list", [])
    )


def _unpacks(call: ast.Call) -> bool:
    """Answer whether a call hands an argument with `*` or `**`."""
    return any(isinstance(a, ast.Starred) for a in call.args) or any(
        k.arg is None for k in call.keywords
    )


def _census(sources: dict[str, str]) -> _Census:
    return _Census([_Module(name, ast.parse(text)) for name, text in sources.items()])


def _library() -> dict[str, str]:
    return {
        path.relative_to(_LIBRARY.parent).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(_LIBRARY.rglob("*.py"))
    }


_PACKAGE = "bip32_descriptors"

#: A call in a cleanup, an `except` or a `finally`, that the census finds
#: may raise from the package, and that raises no refusal of it, keyed by
#: module, function and the call's source, each with its reason. The
#: census knows a method by its name alone, so an `append` called on a
#: list is every `append` of the package, and the one of miniscript's
#: `_Built` raises. None is needed here.
CLEANUPS: dict[tuple[str, str, str], str] = {}


#: An exception raised by a name the census does not trace, keyed by
#: module, function and the source of what is raised, each with its
#: reason. None is needed here.
KEPT: dict[tuple[str, str, str], str] = {}


#: A `_position` of a value an `if` compares with a constant, keyed by
#: module, function and the call's source, each with its reason: the value
#: is one section 7 lets a refusal print, such as a size the package
#: measures, and not one a caller handed over. None is needed here.
MEASURED: dict[tuple[str, str, str], str] = {}


def _cleanups() -> dict[tuple[str, str, str], str]:
    """Return `CLEANUPS` keyed by the module's name as the census names it."""
    return {(f"{_PACKAGE}/{m}", f, c): why for (m, f, c), why in CLEANUPS.items()}


def _kept() -> dict[tuple[str, str, str], str]:
    """Return `KEPT` keyed by the module's name as the census names it."""
    return {(f"{_PACKAGE}/{m}", f, c): why for (m, f, c), why in KEPT.items()}


def _measured() -> dict[tuple[str, str, str], str]:
    """Return `MEASURED` keyed by the module's name as the census names it."""
    return {(f"{_PACKAGE}/{m}", f, c): why for (m, f, c), why in MEASURED.items()}


def test_no_refusal_formats_a_value() -> None:
    """Each exception the package builds formats only what the census traces."""
    census = _census(_library())
    findings = census.findings(_cleanups(), _kept(), _measured())
    assert not findings, "\n".join(findings)
    # an entry no finding uses is one a change made stale
    assert set(_cleanups()) <= census.used, set(_cleanups()) - census.used
    assert set(_kept()) <= census.kept_used, set(_kept()) - census.kept_used
    measured = set(_measured())
    assert measured <= census.measured_used, measured - census.measured_used


# the helpers the census trusts by name, each a function `_refusal.py`
# defines, or one of btclib-org/btclib-wallet's that this package lacks
_TRUSTED = frozenset({"_label", "_message_text", "_position", "_quoted", "_type_name"})
_LACKED = frozenset({"_code", "_hex_field"})


def _bindings(tree: ast.AST) -> list[tuple[str, str]]:
    """Return each name a module binds, and how: "def", "import" or "other".

    "import" is an import of the name, under its own name, from the
    package's `_refusal` module; "other" is any other binding: an
    assignment, a loop, a `with`, an import from elsewhere or under
    another name, a parameter, a class, an `except` or a pattern.
    """
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append((node.name, "def"))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            own = (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module == f"{_PACKAGE}._refusal"
            )
            for alias in node.names:
                bound = (alias.asname or alias.name).split(".")[0]
                plain = own and alias.asname in {None, alias.name}
                found.append((bound, "import" if plain else "other"))
        elif name := _other_binding(node):
            found.append((name, "other"))
    return found


def _other_binding(node: ast.AST) -> str | None:
    """Return the name a node binds other than by a `def` or an import."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        return node.id
    if isinstance(node, ast.arg):
        return node.arg
    if isinstance(node, ast.MatchMapping):
        return node.rest
    if isinstance(node, (ast.ClassDef, ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name
    return None


def _trust_faults(sources: dict[str, str]) -> list[str]:
    """Return each binding of a helper the census trusts that it should not.

    A helper of `_TRUSTED` is bound by its `def` in `_refusal.py`, and by
    an import of it from there anywhere else; one of `_LACKED` nowhere.
    """
    refusal = f"{_PACKAGE}/_refusal.py"
    faults = []
    for module, source in sources.items():
        for name, how in _bindings(ast.parse(source)):
            allowed = "def" if module == refusal else "import"
            if name in _LACKED or (name in _TRUSTED and how != allowed):
                faults.append(f"{module}: {name} bound by {how}")
    return faults


def test_the_trusted_helpers_are_the_refusal_modules() -> None:
    """A helper trusted by name is bound, in the source, by `_refusal` alone."""
    library = _library()
    assert _trust_faults(library) == []
    defined = {
        name
        for name, how in _bindings(ast.parse(library[f"{_PACKAGE}/_refusal.py"]))
        if how == "def"
    }
    assert defined >= _TRUSTED


# a module binding a helper the census trusts by name, as a package may
_UNTRUSTED = {
    "a lambda": "_code = lambda v: v",
    "a builtin": "_hex_field = str",
    "an import from elsewhere": "from builtins import repr as _quoted",
    "an import under another name": (
        f"from {_PACKAGE}._refusal import _message_text as _position"
    ),
    "a def": "def _label(value, known):\n    return value",
    "a parameter": "def f(key, _quoted=repr):\n    raise ValueError(_quoted(key))",
    "a loop": "for _position in (repr,):\n    pass",
    "a class": "class _message_text:\n    pass",
    "an except": "try:\n    pass\nexcept ValueError as _code:\n    pass",
    "a capture pattern": "match 1:\n    case _position:\n        pass",
    "a mapping pattern": "match 1:\n    case {**_hex_field}:\n        pass",
}


@pytest.mark.parametrize("source", _UNTRUSTED.values(), ids=_UNTRUSTED)
def test_the_trust_guard_finds_a_planted_binding(source: str) -> None:
    """Each binding but the `def` and the plain import is a fault."""
    assert len(_trust_faults({f"{_PACKAGE}/m.py": source})) == 1


def test_the_trust_guard_takes_the_def_and_the_plain_import() -> None:
    """The control: `_refusal.py`'s `def`, and its import under its own name."""
    sources = {
        f"{_PACKAGE}/_refusal.py": "def _quoted(value):\n    return ''",
        f"{_PACKAGE}/m.py": f"from {_PACKAGE}._refusal import _quoted",
    }
    assert _trust_faults(sources) == []
    # the same `def` anywhere else is the fault
    moved = {f"{_PACKAGE}/m.py": sources[f"{_PACKAGE}/_refusal.py"]}
    assert _trust_faults(moved) == [f"{_PACKAGE}/m.py: _quoted bound by def"]


def test_library_is_read_whatever_the_locale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sources are read as UTF-8, whatever the locale's encoding.

    The patch makes a `Path` read that names no encoding decode as cp1252
    on every platform, as CPython does on the Windows runners outside UTF-8
    mode.
    """
    expected = _library()
    monkeypatch.setattr(io, "text_encoding", lambda encoding, *_: encoding or "cp1252")
    # the control: the patch reaches a read that names no encoding
    control = tmp_path / "control.py"
    control.write_text("# \N{RIGHT DOUBLE QUOTATION MARK}\n", encoding="utf-8")
    with pytest.raises(UnicodeDecodeError):
        control.read_text()
    assert _library() == expected


def test_kept_hides_its_own_entry_alone() -> None:
    """An entry hides one exception raised by name in one function."""
    refusal = "    error = key\n    raise error\n"
    census = _census({"m.py": f"def f(key):\n{refusal}def g(key):\n{refusal}"})
    assert len(census.findings()) == 2
    assert len(census.findings(kept={("m.py", "f", "error"): ""})) == 1
    assert census.kept_used == {("m.py", "f", "error")}


# shapes the sources of btclib-org/btclib-wallet hold and this package's
# do not, so that each branch of the census runs here too: the modules,
# and what the census finds in them
_UNSEEN: dict[str, tuple[dict[str, str], list[str]]] = {
    "an alias of an alias of itself": (
        {
            "m.py": (
                "def _make(key, kind):\n    return kind(key)\n"
                "def f(key):\n    a = b\n    b = a\n    raise _make(key, a)"
            )
        },
        [],
    ),
    "an attribute of a call assigned": (
        {"m.py": "def f(key):\n    d = []\n    g().x = d\n    raise ValueError(d)"},
        ["m.py:4: m.py:3 d, handed to Assign"],
    ),
    "a global": (
        {"m.py": "G = 'a'\ndef f():\n    global G\n    raise ValueError(G)"},
        ["m.py:4: m.py:3 G, bound by Global"],
    ),
    "an imported exception deriving from the package's": (
        {
            "errors.py": (
                "class Base(Exception):\n    pass\nclass Derived(Base):\n    pass"
            ),
            "m.py": (
                "from errors import Derived\n"
                "def f(key):\n    refused = Derived(key)\n    return refused"
            ),
        },
        ["m.py:3: m.py:2 parameter key of f"],
    ),
    "an attribute of its own object called twice": (
        {
            "m.py": (
                "class K:\n    def __init__(self, hook):\n        self.hook = hook\n"
                "    def f(self):\n        try:\n            pass\n"
                "        except ValueError:\n            self.hook()\n"
                "    def g(self):\n        try:\n            pass\n"
                "        except ValueError:\n            self.hook()"
            )
        },
        [
            (
                "m.py:8: calls self.hook, which the census cannot name,"
                " while handling ValueError"
            ),
            (
                "m.py:13: calls self.hook, which the census cannot name,"
                " while handling ValueError"
            ),
        ],
    ),
    "a class built of two bases of one base": (
        {
            "m.py": (
                "class D(Exception):\n    pass\nclass B(D):\n    pass\n"
                "class C(D):\n    pass\nclass A(B, C):\n    pass\n"
                "def f():\n    try:\n        pass\n    except ValueError:\n"
                "        A('a')"
            )
        },
        [],
    ),
    "a class bound by an assignment": (
        {
            "m.py": (
                "Error = make()\ndef f():\n    try:\n        pass\n"
                "    except Error:\n        raise"
            )
        },
        ["m.py:6: raises Error again"],
    ),
    "a loop over a call of no counter": (
        {
            "m.py": "def f(key):\n    for item in sorted(key):\n        raise ValueError(item)"
        },
        ["m.py:3: m.py:1 parameter key of f"],
    ),
}


@pytest.mark.parametrize("sources, found", _UNSEEN.values(), ids=_UNSEEN)
def test_census_reads_the_shapes_this_package_lacks(
    sources: dict[str, str], found: list[str]
) -> None:
    """The census finds in each module what the wallet's census finds."""
    assert _census(sources).findings() == found


def test_cleanups_hide_their_own_entries_alone() -> None:
    """An entry hides one call in one function, and no other."""
    module = (
        "def _g():\n    raise ValueError('a')\n"
        "def f(key):\n    try:\n        pass\n    except BaseException:\n"
        "        _g()\n        raise\n"
        "def h(key):\n    try:\n        pass\n    except BaseException:\n"
        "        _g()\n        raise"
    )
    census = _census({"m.py": module})
    assert len(census.findings()) == 2
    assert len(census.findings({("m.py", "f", "_g"): ""})) == 1
    assert census.used == {("m.py", "f", "_g")}
    # a cleanup of the module itself is named by `<module>`
    top = (
        "def _g():\n    raise ValueError('a')\n"
        "try:\n    pass\nexcept BaseException:\n    _g()\n    raise"
    )
    census = _census({"m.py": top})
    assert not census.findings({("m.py", "<module>", "_g"): ""})
    assert census.used == {("m.py", "<module>", "_g")}


def test_measured_hides_its_own_entry_alone() -> None:
    """An entry hides one `_position` in one function, and no other."""
    refusal = "    if key > LIMIT:\n        raise ValueError(_position(key))\n"
    census = _census({"m.py": f"def f(key):\n{refusal}def g(key):\n{refusal}"})
    assert len(census.findings()) == 2
    assert len(census.findings(measured={("m.py", "f", "_position(key)"): ""})) == 1
    assert census.measured_used == {("m.py", "f", "_position(key)")}


# a method called through its class, what `_make` hands `kind` first, a
# statement before the call, and one after the class
_THROUGH = (
    "class _C:\n    def _make(self, key, kind):\n        return kind({})\n"
    "    def f(self, key):\n{}        raise _C._make(self, key, ValueError)\n{}"
)
# a method called through a class method's class, what `_make` hands
# `kind` first, and a statement before the call
_ON_CLASS = (
    "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
    "        return kind({})\n    @classmethod\n    def f(cls, key):\n"
    "{}        raise cls._make(None, key, Refused)"
)
# a method called on its own object, and a statement before
_ON_SELF = (
    "class _C:\n    def _text(self):\n        return 'a'\n"
    "    def f(self, key):\n{}        raise ValueError(self._text())"
)

# one module per shape the docstring claims, each refusing `key`, a public
# function's parameter, or a value made from it: the census traces the
# first of each pair and flags the second
_SHAPES = {
    "literal": (
        "def f(key):\n    raise ValueError('a literal')",
        "def f(key):\n    raise ValueError(key)",
    ),
    "comparison": (
        "def f(key):\n    raise ValueError(f'{key == 1}')",
        "def f(key):\n    raise ValueError(f'{key + 1}')",
    ),
    "capitals": (
        "import m\ndef f(key):\n    raise ValueError(m.LIMIT)",
        "def f(key):\n    raise ValueError(key.limit)",
    ),
    "describing call": (
        (
            "def f(key):\n"
            "    raise ValueError(_quoted(key), len(key), _code(key), _position(key))"
        ),
        "def f(key):\n    raise ValueError(str(key))",
    ),
    "field": (
        "import m\ndef f(key):\n    raise ValueError(_hex_field(key, m.TYPES))",
        "def f(key):\n    raise ValueError(_hex_field(key, {key}))",
    ),
    "field unpacked": (
        "import m\ndef f(key):\n    raise ValueError(_hex_field(key, m.TYPES))",
        "def f(key):\n    raise ValueError(_hex_field(*(key, {key})))",
    ),
    "field unpacked by name": (
        "import m\ndef f(key):\n    raise ValueError(_hex_field(key, defined=m.TYPES))",
        "def f(key, kw):\n    raise ValueError(_hex_field(key, **kw))",
    ),
    "label unpacked": (
        "import m\ndef f(key):\n    raise ValueError(_label(key, m.NAMES))",
        "def f(key):\n    raise ValueError(_label(*(key, {key})))",
    ),
    "position compared": (
        "def f(key, n):\n    if key > n:\n        raise ValueError(_position(key))",
        "def f(key):\n    if key > LIMIT:\n        raise ValueError(_position(key))",
    ),
    "position in a range": (
        "def f(key, n):\n    if not key < n:\n        raise ValueError(_position(key))",
        (
            "def f(key, n):\n    if not 0 <= key < n:\n"
            "        raise ValueError(_position(key))"
        ),
    ),
    "position past a constant expression": (
        (
            "def f(key, n):\n    if key >= n + 1:\n"
            "        raise ValueError(_position(key))"
        ),
        ("def f(key):\n    if key >= 2**32:\n        raise ValueError(_position(key))"),
    ),
    "position below a negative constant": (
        "def f(key, n):\n    if key < -n:\n        raise ValueError(_position(key))",
        "def f(key):\n    if key < -1:\n        raise ValueError(_position(key))",
    ),
    "position in a set": (
        (
            "def f(key, keys):\n    if key not in keys:\n"
            "        raise ValueError(_position(key))"
        ),
        (
            "def f(key):\n    if key not in {0, 2}:\n"
            "        raise ValueError(_position(key))"
        ),
    ),
    "position by identity": (
        (
            "def f(key):\n    if key is not LIMIT:\n"
            "        raise ValueError(_position(key))"
        ),
        "def f(key):\n    if key != LIMIT:\n        raise ValueError(_position(key))",
    ),
    "position in an else": (
        (
            "def f(key, n):\n    if key < n:\n        pass\n    else:\n"
            "        raise ValueError(_position(key))"
        ),
        (
            "def f(key):\n    if key < LIMIT:\n        pass\n    else:\n"
            "        raise ValueError(_position(key))"
        ),
    ),
    "position in an if expression": (
        "def f(key, n):\n    raise ValueError(_position(key) if n else 'a')",
        "def f(key):\n    raise ValueError(_position(key) if key > LIMIT else 'a')",
    ),
    "position for its truth": (
        (
            "def f(key, i):\n    if key and not i:\n"
            "        raise ValueError(_position(len(key)))"
        ),
        (
            "def f(key, ranged):\n    if key and not ranged:\n"
            "        raise ValueError(_position(key))"
        ),
    ),
    "position unpacked": (
        "def f(key):\n    raise ValueError(_position(key))",
        ("def f(key):\n    if key > 10:\n        raise ValueError(_position(*(key,)))"),
    ),
    "position unpacked by name": (
        "def f(key):\n    raise ValueError(_position(value=key))",
        (
            "def f(key):\n    if key > 10:\n"
            '        raise ValueError(_position(**{"value": key}))'
        ),
    ),
    "position by keyword": (
        (
            "def f(key, i):\n    if key > LIMIT:\n"
            "        raise ValueError(_position(value=i))"
        ),
        (
            "def f(key):\n    if key > LIMIT:\n"
            "        raise ValueError(_position(value=key))"
        ),
    ),
    "position of another value": (
        ("def f(key, i):\n    if key > LIMIT:\n        raise ValueError(_position(i))"),
        "def f(key, i):\n    if i > LIMIT:\n        raise ValueError(_position(i))",
    ),
    "describing method": (
        "def f(key):\n    raise ValueError('a;b'.count(key), len(key).bit_length())",
        "def f(key):\n    raise ValueError(key.count(';'))",
    ),
    "name attribute": (
        "def f(key):\n    raise ValueError(_type_name(key))",
        "def f(key):\n    raise ValueError(key.__doc__)",
    ),
    "type name": (
        "def f(key):\n    raise ValueError(_type_name(key))",
        "def f(key):\n    raise ValueError(type(key).__name__)",
    ),
    "type qualified name": (
        "def f(key):\n    raise ValueError(_type_name(key))",
        "def f(key):\n    raise ValueError(type(key).__qualname__)",
    ),
    "class name": (
        "def f(key):\n    raise ValueError(_type_name(key))",
        "def f(key):\n    raise ValueError(key.__class__.__name__)",
    ),
    "type": (
        "def f(key):\n    raise ValueError(_type_name(key))",
        "def f(key):\n    raise ValueError(type(key))",
    ),
    "enumerate": (
        "def f(keys):\n    for i, key in enumerate(keys):\n        raise ValueError(i)",
        (
            "def f(keys):\n    for i, key in enumerate(keys):\n"
            "        raise ValueError(key)"
        ),
    ),
    "enumerate start": (
        (
            "def f(keys):\n    for i, key in enumerate(keys, 1):\n"
            "        raise ValueError(i)"
        ),
        (
            "def f(keys, start):\n    for i, key in enumerate(keys, start):\n"
            "        raise ValueError(i)"
        ),
    ),
    "range": (
        "def f(n):\n    for i in range(3):\n        raise ValueError(i)",
        "def f(n):\n    for i in range(n):\n        raise ValueError(i)",
    ),
    "range of a start": (
        "def f(n):\n    for i in range(1, 3):\n        raise ValueError(i)",
        "def f(n, start):\n    for i in range(start, 3):\n        raise ValueError(i)",
    ),
    "range of a step": (
        "def f(key):\n    for i in range(0, 6, 2):\n        raise ValueError(i)",
        (
            "def f(key):\n    for i in range(0, key * 2, key):\n        if i:\n"
            "            raise ValueError(i)"
        ),
    ),
    "zip": (
        (
            "def f(keys):\n    for name, key in zip(('a',), keys):\n"
            "        raise ValueError(name)"
        ),
        (
            "def f(keys):\n    for name, key in zip(('a',), keys):\n"
            "        raise ValueError(key)"
        ),
    ),
    "rows": (
        (
            "def f(key):\n    for value, name in ((key, 'a'),):\n"
            "        raise ValueError(name)"
        ),
        (
            "def f(key):\n    for value, name in ((key, 'a'),):\n"
            "        raise ValueError(value)"
        ),
    ),
    "comprehension": (
        "def f(keys):\n    raise ValueError([len(key) for key in keys])",
        "def f(keys):\n    raise ValueError([key for key in keys])",
    ),
    "local name": (
        "def f(key):\n    text = 'a'\n    raise ValueError(text)",
        "def f(key):\n    text = 'a'\n    text = key\n    raise ValueError(text)",
    ),
    "with": (
        (
            "def _open():\n    return 'a'\n"
            "def f(key):\n    with _open() as text:\n        raise ValueError(text)"
        ),
        "def f(key):\n    with open(key) as text:\n        raise ValueError(text)",
    ),
    "mutator": (
        (
            "def f(key):\n    names = []\n    names.append('a')\n"
            "    raise ValueError(names)"
        ),
        (
            "def f(key):\n    names = []\n    names.append(key)\n"
            "    raise ValueError(names)"
        ),
    ),
    "item assignment": (
        (
            "def f(key):\n    names = {}\n    names['a'] = 'b'\n"
            "    raise ValueError(names)"
        ),
        (
            "def f(key):\n    names = {}\n    def g():\n        names['a'] = key\n"
            "    raise ValueError(names)"
        ),
    ),
    "private parameter": (
        "def _g(text):\n    raise ValueError(text)\ndef f(key):\n    _g('a')",
        "def _g(text):\n    raise ValueError(text)\ndef f(key):\n    _g(key)",
    ),
    "never called": (
        "def _g(text):\n    raise ValueError(len(text))",
        "def _g(text):\n    raise ValueError(text)",
    ),
    "read as a value": (
        "def _g(text):\n    raise ValueError(len(text))\nTABLE = {'a': _g}",
        "def _g(text):\n    raise ValueError(text)\nTABLE = {'a': _g}",
    ),
    "lambda": (
        "def f(key):\n    g = lambda text: ValueError(len(text))",
        "def f(key):\n    g = lambda text: ValueError(text)",
    ),
    "self": (
        "class C:\n    def _m(self):\n        raise ValueError(_type_name(self))",
        "class C:\n    def _m(self):\n        raise ValueError(self)",
    ),
    "except": (
        (
            "def f(key):\n    try:\n        pass\n    except OSError as e:\n"
            "        name = _type_name(e)\n    raise ValueError(name)"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except OSError as e:\n"
            "        name = str(e)\n    raise ValueError(name)"
        ),
    ),
    "environment": (
        "import os\ndef f(key):\n    raise ValueError(len(os.environ))",
        "import os\ndef f(key):\n    raise ValueError(os.environ['HOME'])",
    ),
    "arguments": (
        "import sys\ndef f(key):\n    raise ValueError(len(sys.argv))",
        "import sys\ndef f(key):\n    raise ValueError(sys.argv[0])",
    ),
    "returns": (
        "def _g(key):\n    return 'a'\ndef f(key):\n    raise ValueError(_g(key))",
        "def _g(key):\n    return key\ndef f(key):\n    raise ValueError(_g(key))",
    ),
    "item": (
        (
            "def _g(key):\n    return 'a', key\ndef f(key):\n"
            "    name, value = _g(key)\n    raise ValueError(name)"
        ),
        (
            "def _g(key):\n    return 'a', key\ndef f(key):\n"
            "    name, value = _g(key)\n    raise ValueError(value)"
        ),
    ),
    "item forwarded": (
        (
            "def _g(key):\n    return 'a', key\ndef _h(key):\n    return _g(key)\n"
            "def f(key):\n    name, value = _h(key)\n    raise ValueError(name)"
        ),
        (
            "def _g(key):\n    return 'a', key\ndef _h(key):\n    return _g(key)\n"
            "def f(key):\n    name, value = _h(key)\n    raise ValueError(value)"
        ),
    ),
    "method": (
        (
            "class C:\n    def _m(self, text):\n        raise ValueError(text)\n"
            "def f(key, c):\n    c._m('a')"
        ),
        (
            "class C:\n    def _m(self, text):\n        raise ValueError(text)\n"
            "def f(key, c):\n    c._m(key)"
        ),
    ),
    "raise of a call": (
        (
            "def _error(key):\n    return ValueError(len(key))\n"
            "def f(key):\n    raise _error(key)"
        ),
        (
            "def _error(key):\n    return ValueError(key)\n"
            "def f(key):\n    raise _error(key)"
        ),
    ),
    "label": (
        "LABELS = ('a',)\ndef f(key):\n    raise ValueError(_label(key, LABELS))",
        "def f(key):\n    raise ValueError(_label(key, (key,)))",
    ),
    "error name": (
        "def f(key):\n    return KeyError('a')",
        "def f(key):\n    return KeyError(key)",
    ),
    "dict comprehension": (
        "def f(keys):\n    raise ValueError({len(k): len(k) for k in keys})",
        "def f(keys):\n    raise ValueError({k: 1 for k in keys})",
    ),
    "expression the census does not read": (
        "def f(key):\n    raise ValueError('a literal')",
        "def f(key):\n    raise ValueError(lambda: 1)",
    ),
    "chained assignment": (
        "def f(key):\n    a = b = len(key)\n    raise ValueError(a, b)",
        "def f(key):\n    a = b = key\n    raise ValueError(a, b)",
    ),
    "with of several items": (
        (
            "def _open(x):\n    return x\ndef f(key):\n"
            "    with _open('a') as h, lock():\n        raise ValueError(h)"
        ),
        (
            "def _open(x):\n    return x\ndef f(key):\n"
            "    with _open(key) as h, lock():\n        raise ValueError(h)"
        ),
    ),
    "zip of fewer iterables than names": (
        (
            "def f(key):\n    for a, b, c in zip((1,), (2,)):\n"
            "        raise ValueError(c)"
        ),
        (
            "def f(key):\n    for a, b, c in zip((1,), (key,)):\n"
            "        raise ValueError(c)"
        ),
    ),
    "tuple from a tuple": (
        "def f(key):\n    a, b = 1, len(key)\n    raise ValueError(b)",
        "def f(key):\n    a, b = 1, key\n    raise ValueError(b)",
    ),
    "tuple from a call outside the package": (
        "def f(key):\n    a, b = sorted((1, 2))\n    raise ValueError(a)",
        "def f(key):\n    a, b = sorted((key, 2))\n    raise ValueError(a)",
    ),
    "tuple from a generator": (
        (
            "def _g():\n    yield 1\n    yield 2\n"
            "def f(key):\n    a, b = _g()\n    raise ValueError(a)"
        ),
        (
            "def _g(key):\n    yield key\n    yield 2\n"
            "def f(key):\n    a, b = _g(key)\n    raise ValueError(a)"
        ),
    ),
    "arguments unpacked": (
        "def _g(x):\n    raise ValueError(x)\ndef f(keys):\n    _g(1)",
        "def _g(x):\n    raise ValueError(x)\ndef f(keys):\n    _g(*keys)",
    ),
    "environment variable": (
        "def f(key):\n    raise ValueError(str(len(key)))",
        "import os\ndef f(key):\n    raise ValueError(os.getenv('RPC_PASSWORD'))",
    ),
    "prompt": (
        "def f(key):\n    raise ValueError(sorted(('a', 'b')))",
        "import getpass\ndef f(key):\n    raise ValueError(getpass.getpass())",
    ),
    "input": (
        "def f(key):\n    raise ValueError(next(c for c in 'ab'))",
        "def f(key):\n    raise ValueError(input())",
    ),
    "file": (
        "def f(key):\n    raise ValueError('-'.join(('a', 'b')))",
        "from pathlib import Path\ndef f(key):\n    raise ValueError(Path('.cookie').read_text())",
    ),
    "subprocess": (
        "def f(key):\n    raise ValueError(sum((1, 2)))",
        (
            "import subprocess\ndef f(key):\n"
            "    raise ValueError(subprocess.run(['a'], capture_output=True).stdout)"
        ),
    ),
    "locals": (
        "def f(key):\n    raise ValueError(f'{frozenset((1,))}')",
        "def f(key):\n    raise ValueError(f'{locals()}')",
    ),
    "method found by its name": (
        (
            "class C:\n    def hex(self):\n        return 'a'\n"
            "    def _m(self):\n        raise ValueError(self.hex())"
        ),
        (
            "class C:\n    def hex(self):\n        return 'a'\n"
            "def f(key):\n    raise ValueError(key.hex())"
        ),
    ),
    "chained": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    try:\n"
            "        pass\n    except _OwnError as e:\n"
            "        raise ValueError('a') from e"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except ValueError as e:\n"
            "        raise ValueError('a') from e"
        ),
    ),
    "context": (
        (
            "def f(key):\n    failed = False\n    try:\n        pass\n"
            "    except ValueError:\n        failed = True\n"
            "    if failed:\n        raise ValueError('a')"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except ValueError:\n"
            "        raise ValueError('a') from None"
        ),
    ),
    "finally": (
        "def f(key):\n    try:\n        raise ValueError('a')\n    finally:\n        pass",
        "def f(key):\n    try:\n        pass\n    finally:\n        raise ValueError('a')",
    ),
    "cause kept": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    seen = []\n"
            "    try:\n        pass\n    except _OwnError as e:\n"
            "        seen.append(e)\n    raise ValueError('a') from seen[-1]"
        ),
        (
            "def f(key):\n    seen = []\n    try:\n        pass\n"
            "    except ValueError as e:\n        seen.append(e)\n"
            "    raise ValueError('a') from seen[-1]"
        ),
    ),
    "cause of a call": (
        "def f(key):\n    raise ValueError('a') from None",
        "def f(key):\n    raise ValueError('a') from g()",
    ),
    "cause a parameter holds": (
        "def f(key):\n    cause = None\n    raise ValueError('a') from cause",
        "def f(key, cause):\n    raise ValueError('a') from cause",
    ),
    "cause bound by a loop": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    last = None\n"
            "    try:\n        pass\n    except _OwnError as e:\n        last = e\n"
            "    raise ValueError('a') from last"
        ),
        (
            "def f(errors):\n    for last in errors:\n        pass\n"
            "    raise ValueError('a') from last"
        ),
    ),
    "raising call in an except": (
        (
            "class _OwnError(Exception):\n    pass\ndef _g():\n"
            "    raise ValueError('a')\ndef f(key):\n    try:\n        pass\n"
            "    except _OwnError:\n        _g()"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        pass\n    except ValueError:\n        _g()"
        ),
    ),
    "raised again": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    try:\n"
            "        pass\n    except _OwnError:\n        raise"
        ),
        "def f(key):\n    try:\n        pass\n    except ValueError:\n        raise",
    ),
    "raised again by its name": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    try:\n"
            "        pass\n    except _OwnError as e:\n        raise e"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except ValueError as e:\n"
            "        raise e"
        ),
    ),
    "interrupts raised again": (
        (
            "def f(key):\n    try:\n        pass\n"
            "    except (KeyboardInterrupt, SystemExit):\n        raise"
        ),
        (
            "def f(key):\n    try:\n        pass\n"
            "    except (KeyboardInterrupt, ValueError):\n        raise"
        ),
    ),
    "cleanup": (
        (
            "def f(key):\n    try:\n        pass\n    except BaseException:\n"
            "        g()\n        raise"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except Exception:\n"
            "        g()\n        raise"
        ),
    ),
    "cleanup with another way out": (
        "def f(key):\n    try:\n        pass\n    except:\n        g()\n        raise",
        (
            "def f(key):\n    try:\n        pass\n    except:\n"
            "        if g():\n            return\n        raise"
        ),
    ),
    "cleanup binding the exception": (
        (
            "def f(key):\n    try:\n        pass\n    except BaseException:\n"
            "        g()\n        raise"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except BaseException as e:\n"
            "        g(e)\n        raise"
        ),
    ),
    "bare raise outside an except": (
        "def f(key):\n    raise",
        "def f(key):\n    try:\n        pass\n    except ValueError:\n        raise",
    ),
    "class read off what no import binds": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    try:\n"
            "        pass\n    except _OwnError:\n        raise"
        ),
        (
            "def f(key, errors):\n    try:\n        pass\n"
            "    except errors.FetchError:\n        raise"
        ),
    ),
    "environment as bytes": (
        "import os\ndef f(key):\n    raise ValueError(len(os.environb))",
        "import os\ndef f(key):\n    raise ValueError(os.environb[b'HOME'])",
    ),
    "arguments of the interpreter": (
        "import sys\ndef f(key):\n    raise ValueError(len(sys.orig_argv))",
        "import sys\ndef f(key):\n    raise ValueError(sys.orig_argv[0])",
    ),
    "default of a parameter": (
        (
            "def f(key):\n    def _g(text='a'):\n        raise ValueError(text)\n"
            "    _g()"
        ),
        (
            "def f(key):\n    def _g(text=key):\n        raise ValueError(text)\n"
            "    _g()"
        ),
    ),
    "default of a keyword": (
        (
            "def f(key):\n    def _g(*, text='a'):\n        raise ValueError(text)\n"
            "    _g()"
        ),
        (
            "def f(key):\n    def _g(*, text=key):\n        raise ValueError(text)\n"
            "    _g()"
        ),
    ),
    "environment imported by name": (
        "from os import sep\ndef f(key):\n    raise ValueError(sep)",
        "from os import environ\ndef f(key):\n    raise ValueError(environ['HOME'])",
    ),
    "environment imported under another name": (
        "from os import sep as s\ndef f(key):\n    raise ValueError(s)",
        "from os import getenv as g\ndef f(key):\n    raise ValueError(g)",
    ),
    "a builtin read by name": (
        "def f(key):\n    raise ValueError(len)",
        "def f(key):\n    raise ValueError(vars)",
    ),
    "a read of a file": (
        (
            "class C:\n    def _text(self):\n        return 'a'\n"
            "    def _m(self):\n        raise ValueError(self._text())"
        ),
        (
            "class C:\n    def read(self):\n        return 'a'\n"
            "    def _m(self):\n        raise ValueError(self.read())"
        ),
    ),
    "a container put into through another name": (
        (
            "def f(key):\n    values = []\n    values.append('a')\n"
            "    raise ValueError(values)"
        ),
        (
            "def f(key):\n    values = []\n    alias = values\n"
            "    alias.append(key)\n    raise ValueError(values)"
        ),
    ),
    "a container handed to a call": (
        (
            "def f(key):\n    values = ['a']\n    sorted(values)\n"
            "    raise ValueError(values)"
        ),
        (
            "def f(key):\n    values = ['a']\n    g(values)\n"
            "    raise ValueError(values)"
        ),
    ),
    "a container handed to a function that only reads it": (
        (
            "def _g(items):\n    return len(items)\n"
            "def f(key):\n    values = ['a']\n    _g(values)\n"
            "    raise ValueError(values)"
        ),
        (
            "def _g(items, key):\n    items.append(key)\n"
            "def f(key):\n    values = ['a']\n    _g(values, key)\n"
            "    raise ValueError(values)"
        ),
    ),
    "a container handed on as one of many": (
        (
            "def _g(items):\n    return len(items)\n"
            "def f(key):\n    values = ['a']\n    _g(values)\n"
            "    raise ValueError(values)"
        ),
        (
            "def _g(*items):\n    return len(items)\n"
            "def f(key):\n    values = ['a']\n    _g(values)\n"
            "    raise ValueError(values)"
        ),
    ),
    "a container handed to a method through its class": (
        (
            "class _C:\n    def _g(self, items):\n        return len(items)\n"
            "    def f(self, key):\n        values = ['a']\n"
            "        _C._g(self, values)\n        raise ValueError(values)"
        ),
        (
            "class _C:\n    def _g(self, items, key):\n        items.append(key)\n"
            "    def f(self, key):\n        values = ['a']\n"
            "        _C._g(self, values, key)\n        raise ValueError(values)"
        ),
    ),
    "a container handed to a method on its object": (
        (
            "class _C:\n    def _g(self, items):\n        return len(items)\n"
            "    def f(self, key):\n        values = ['a']\n"
            "        self._g(values)\n        raise ValueError(values)"
        ),
        (
            "class _C:\n    def _g(self, items, key):\n        items.append(key)\n"
            "    def f(self, key):\n        values = ['a']\n"
            "        self._g(values, key)\n        raise ValueError(values)"
        ),
    ),
    "a container put into another": (
        (
            "def f(key):\n    values = ['a']\n    other = ('b',)\n"
            "    raise ValueError(values, other)"
        ),
        (
            "def f(key):\n    values = ['a']\n    other = [values]\n"
            "    other[0].append(key)\n    raise ValueError(values)"
        ),
    ),
    "a call that raises further down": (
        (
            "def _inner():\n    return 1\ndef _outer():\n    _inner()\n"
            "def f(action):\n    try:\n        action()\n    except OSError:\n"
            "        _outer()"
        ),
        (
            "def _inner():\n    raise ValueError('a')\ndef _outer():\n    _inner()\n"
            "def f(action):\n    try:\n        action()\n    except OSError:\n"
            "        _outer()"
        ),
    ),
    "a call the census cannot name": (
        (
            "def _g():\n    return 1\ndef f(action):\n    try:\n        pass\n"
            "    except OSError:\n        _g()"
        ),
        (
            "def f(action):\n    try:\n        pass\n    except OSError:\n"
            "        action()"
        ),
    ),
    "a method called on another object": (
        (
            "class C:\n    def _g(self):\n        return 1\n"
            "def f(key, other):\n    try:\n        pass\n    except OSError:\n"
            "        other._g()"
        ),
        (
            "class C:\n    def _g(self):\n        raise ValueError('a')\n"
            "def f(key, other):\n    try:\n        pass\n    except OSError:\n"
            "        other._g()"
        ),
    ),
    "an attribute of its own object called": (
        (
            "class C:\n    def __init__(self):\n        self.n = 1\n"
            "    def _f(self):\n        try:\n            pass\n"
            "        except OSError:\n            self._g()\n"
            "    def _g(self):\n        return 1"
        ),
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        try:\n            pass\n"
            "        except OSError:\n            self.g()"
        ),
    ),
    "an attribute of another object called": (
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "def f(key, other):\n    try:\n        pass\n    except OSError:\n"
            "        other.g()"
        ),
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self, other):\n        try:\n            pass\n"
            "        except OSError:\n            self.g()"
        ),
    ),
    "a constructor that raises": (
        (
            "class _E(Exception):\n    pass\n"
            "def f(key):\n    try:\n        pass\n    except OSError:\n"
            "        _E('a')"
        ),
        (
            "class _B(Exception):\n    def __init__(self, text):\n"
            "        raise ValueError('a')\nclass _E(_B):\n    pass\n"
            "def f(key):\n    try:\n        pass\n    except OSError:\n"
            "        _E('a')"
        ),
    ),
    "default read where the def stands": (
        "def f(key):\n    def _g(key='a'):\n        raise ValueError(key)\n    _g()",
        "def f(key):\n    def _g(key=key):\n        raise ValueError(key)\n    _g()",
    ),
    "keyword default read where the def stands": (
        "def f(key):\n    def _g(*, key='a'):\n        raise ValueError(key)\n    _g()",
        "def f(key):\n    def _g(*, key=key):\n        raise ValueError(key)\n    _g()",
    ),
    "default of a module name": (
        "key = 'a'\ndef _g(key=key):\n    raise ValueError(key)\n_g()",
        (
            "import os\nkey = os.environ['KEY']\ndef _g(key=key):\n"
            "    raise ValueError(key)\n_g()"
        ),
    ),
    "default of a lambda read where the lambda stands": (
        (
            "def _h():\n    return 'a'\ndef f(key):\n"
            "    pick = lambda _h=None, x=ValueError(_h()): x\n    return pick"
        ),
        (
            "def _h():\n    return 'a'\ndef f(key):\n"
            "    pick = lambda _h: ValueError(_h())\n    return pick"
        ),
    ),
    "exception class bound to another name": (
        (
            "Failure = ValueError\ndef f(key):\n    refusal = Failure('a')\n"
            "    raise refusal"
        ),
        (
            "Failure = ValueError\ndef f(key):\n    refusal = Failure(key)\n"
            "    raise refusal"
        ),
    ),
    "exception class imported under another name": (
        (
            "from builtins import ValueError as Failure\ndef f(key):\n"
            "    error = Failure('a')\n    raise error"
        ),
        (
            "from builtins import ValueError as Failure\ndef f(key):\n"
            "    error = Failure(key)\n    raise error"
        ),
    ),
    "class of the package bound to another name": (
        (
            "class _Own(Exception):\n    pass\nAlias = _Own\ndef f(key):\n"
            "    refusal = Alias('a')\n    raise refusal"
        ),
        (
            "class _Own(Exception):\n    pass\nAlias = _Own\ndef f(key):\n"
            "    refusal = Alias(key)\n    raise refusal"
        ),
    ),
    "class of the package deriving from no known plain base": (
        (
            "from typing import NamedTuple\nclass _Ref(NamedTuple):\n"
            "    n: int\nAlias = _Ref\ndef f(key):\n    Alias(key)\n"
            "    raise ValueError('a')"
        ),
        (
            "from x import Mystery\nclass _Ref(Mystery):\n    pass\n"
            "Alias = _Ref\ndef f(key):\n    Alias(key)\n    raise ValueError('a')"
        ),
    ),
    "exception raised by name": (
        "def f(key):\n    refusal = None\n    raise ValueError('a')",
        "def f(key):\n    raise key",
    ),
    "exception raised by a name that may hold None": (
        (
            "def f(key):\n    refusal = None\n    if key:\n"
            "        refusal = ValueError('a')\n    if refusal is not None:\n"
            "        raise refusal"
        ),
        (
            "def f(key):\n    refusal = None\n    if key:\n"
            "        refusal = key\n    if refusal is not None:\n"
            "        raise refusal"
        ),
    ),
    "exception declared by a bare annotation": (
        (
            "def f(key):\n    refusal: Exception\n    if key:\n"
            "        refusal = ValueError('a')\n    else:\n"
            "        refusal = TypeError('a')\n    raise refusal"
        ),
        (
            "def f(key):\n    refusal: Exception\n    if key:\n"
            "        refusal = key\n    else:\n"
            "        refusal = TypeError('a')\n    raise refusal"
        ),
    ),
    "exception a function of the package returns, raised by name": (
        (
            "def _make():\n    return ValueError('a')\n"
            "def f(key):\n    refusal = _make()\n    raise refusal"
        ),
        (
            "def _make(key):\n    return key\n"
            "def f(key):\n    refusal = _make(key)\n    raise refusal"
        ),
    ),
    "exception class a function of the package returns": (
        (
            "class Refused(Exception):\n    pass\ndef _make(key):\n    return Refused('a')\n"
            "def f(key):\n    raise _make(key)"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(key):\n    return Refused(key)\n"
            "def f(key):\n    raise _make(key)"
        ),
    ),
    "exception class a lambda's parameter shadows, which may hold one": (
        (
            "class Refused(Exception):\n    pass\ndef f(key):\n"
            "    build = lambda Refused: Refused('a')\n    return build(str)"
        ),
        (
            "class Refused(Exception):\n    pass\ndef f(key):\n"
            "    build = lambda Refused: Refused(key)\n    return build(str)"
        ),
    ),
    "exception class passed to a public function's parameter": (
        (
            "Refused = ValueError\ndef make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise make(key, Refused)"
        ),
        (
            "Refused = ValueError\ndef make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise make(key, Refused)"
        ),
    ),
    "exception class passed to a function read as a value": (
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ng = _make\ndef f(key):\n"
            "    raise g('a', Refused)"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ng = _make\ndef f(key):\n"
            "    raise g('a', Refused)"
        ),
    ),
    "exception class passed to a lambda's parameter": (
        (
            "Refused = ValueError\nmake = lambda key, kind: kind('a')\n"
            "def f(key):\n    raise make('a', Refused)"
        ),
        (
            "Refused = ValueError\nmake = lambda key, kind: kind(key)\n"
            "def f(key):\n    raise make('a', Refused)"
        ),
    ),
    "exception class passed as an item of a list written out": (
        (
            "KINDS = [ValueError]\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
        (
            "KINDS = [ValueError]\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
    ),
    "exception class passed through a local alias": (
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n    kind = Refused\n"
            "    raise _make(key, kind)"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n    kind = Refused\n"
            "    raise _make(key, kind)"
        ),
    ),
    "exception class passed as what a call answers": (
        (
            "def _kind():\n    return ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, _kind())"
        ),
        (
            "def _kind():\n    return ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, _kind())"
        ),
    ),
    "exception class passed as an item of a list a call answers": (
        (
            "def _kinds():\n    return [ValueError]\nKINDS = _kinds()\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
        (
            "def _kinds():\n    return [ValueError]\nKINDS = _kinds()\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
    ),
    "builtin passed to a parameter that builds": (
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, str)"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, ValueError)"
        ),
    ),
    "exception class passed from a comprehension's for": (
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    return [_make('a', k) for k in (ValueError,)]"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    return [_make(key, k) for k in (ValueError,)]"
        ),
    ),
    "exception class passed through a name a loop binds": (
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    for kind in (Refused,):\n        raise _make('a', kind)"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    for kind in (Refused,):\n        raise _make(key, kind)"
        ),
    ),
    "own class of a public classmethod, which may be an exception": (
        (
            "class _C:\n    @classmethod\n    def make(cls, key):\n"
            "        return cls(key)"
        ),
        (
            "class Refused(Exception):\n    @classmethod\n    def make(cls, key):\n"
            "        return cls(key)"
        ),
    ),
    "own object of a public method, which is no class": (
        "class _C:\n    def f(self, key):\n        return self(key)",
        "class _C:\n    def f(self, key, kind):\n        return kind(key)",
    ),
    "starred parameter of a public function, which holds no class": (
        ("def make(key, *kinds):\n    return kinds(key)"),
        ("def make(key, kinds):\n    return kinds(key)"),
    ),
    "exception class passed in a branch of an if expression": (
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, str if key else str)"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, str if key else ValueError)"
        ),
    ),
    "exception class passed as a value of a dict written out": (
        (
            "KINDS = {'a': str}\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
        (
            "KINDS = {'a': ValueError}\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
    ),
    "exception class passed as an item of a list among others": (
        (
            "KINDS = [str]\ndef _make(key, kind):\n    return kind(key)\n"
            "def f(key):\n    raise _make(key, KINDS[0])"
        ),
        (
            "KINDS = [str, ValueError]\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
    ),
    "exception class passed through a name an unpacking binds": (
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    kind, other = Refused, 1\n    raise _make('a', kind)"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    kind, other = Refused, 1\n    raise _make(key, kind)"
        ),
    ),
    "exception class passed as an item of a parameter": (
        (
            "def _make(key, kind):\n    return kind('a')\n"
            "def _pick(key, kinds):\n    return _make(key, kinds[0])\n"
            "def f(key):\n    raise _pick(key, [ValueError])"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\n"
            "def _pick(key, kinds):\n    return _make(key, kinds[0])\n"
            "def f(key):\n    raise _pick(key, [ValueError])"
        ),
    ),
    "item of a public function's parameter passed to one that builds": (
        (
            "def _make(key, kind):\n    return kind('a')\n"
            "def pick(key, kinds):\n    return _make(key, kinds[0])"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\n"
            "def pick(key, kinds):\n    return _make(key, kinds[0])"
        ),
    ),
    "exception class passed as an item of an imported name": (
        (
            "from kinds import KINDS\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
        (
            "from kinds import KINDS\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
    ),
    "exception class passed as an item appended to a list": (
        (
            "KINDS = [str]\nKINDS.append(ValueError)\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[1])"
        ),
        (
            "KINDS = [str]\nKINDS.append(ValueError)\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[1])"
        ),
    ),
    "exception class passed as an entry set in a dict": (
        (
            "KINDS = {}\nKINDS['a'] = ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
        (
            "KINDS = {}\nKINDS['a'] = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
    ),
    "exception class passed as an item set in a list": (
        (
            "KINDS = [str]\nKINDS[0] = ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
        (
            "KINDS = [str]\nKINDS[0] = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
    ),
    "exception class passed as an entry a dict is updated with": (
        (
            "KINDS = {'a': str}\nKINDS.update(a=ValueError)\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
        (
            "KINDS = {'a': str}\nKINDS.update(a=ValueError)\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
    ),
    "exception class passed as an item of a list unpacked into": (
        (
            "from kinds import BASE\nKINDS = [*BASE]\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
        (
            "from kinds import BASE\nKINDS = [*BASE]\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[0])"
        ),
    ),
    "exception class passed as an entry of a dict unpacked into": (
        (
            "from kinds import BASE\nKINDS = {**BASE}\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
        (
            "from kinds import BASE\nKINDS = {**BASE}\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS['a'])"
        ),
    ),
    "exception class passed as an operand of or": (
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n    other = None\n"
            "    raise _make(key, other or Refused)"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n    other = None\n"
            "    raise _make(key, other or Refused)"
        ),
    ),
    "exception class passed through an assignment expression": (
        (
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, (k := ValueError))"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, (k := ValueError))"
        ),
    ),
    "what a call answers passed through an assignment expression": (
        (
            "def _kind():\n    return ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, (k := _kind()))"
        ),
        (
            "def _kind():\n    return ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, (k := _kind()))"
        ),
    ),
    "exception class passed as an attribute of its own object": (
        (
            "def _make(key, kind):\n    return kind('a')\nclass _C:\n"
            "    def __init__(self):\n        self.kind = ValueError\n"
            "    def f(self, key):\n        raise _make(key, self.kind)"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\nclass _C:\n"
            "    def __init__(self):\n        self.kind = ValueError\n"
            "    def f(self, key):\n        raise _make(key, self.kind)"
        ),
    ),
    "exception class passed as an attribute of a module": (
        (
            "import errs\ndef _make(key, kind):\n    return kind('a')\n"
            "def f(key):\n    raise _make(key, errs.Refused)"
        ),
        (
            "import errs\ndef _make(key, kind):\n    return kind(key)\n"
            "def f(key):\n    raise _make(key, errs.Refused)"
        ),
    ),
    "exception class passed as a class attribute": (
        (
            "def _make(key, kind):\n    return kind('a')\nclass _C:\n"
            "    KIND = ValueError\n    def f(self, key):\n"
            "        raise _make(key, self.KIND)"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\nclass _C:\n"
            "    KIND = ValueError\n    def f(self, key):\n"
            "        raise _make(key, self.KIND)"
        ),
    ),
    "own class of a public classmethod a subclass may hand": (
        (
            "class _Base:\n    @classmethod\n    def make(cls, key):\n"
            "        return cls('a')\nclass Refused(_Base, ValueError):\n"
            "    pass"
        ),
        (
            "class _Base:\n    @classmethod\n    def make(cls, key):\n"
            "        return cls(key)\nclass Refused(_Base, ValueError):\n"
            "    pass"
        ),
    ),
    "own class of a public classmethod a subclass two down may hand": (
        (
            "class _Base:\n    @classmethod\n    def make(cls, key):\n"
            "        return cls('a')\nclass _Mid(_Base):\n    pass\n"
            "class Refused(_Mid, ValueError):\n    pass"
        ),
        (
            "class _Base:\n    @classmethod\n    def make(cls, key):\n"
            "        return cls(key)\nclass _Mid(_Base):\n    pass\n"
            "class Refused(_Mid, ValueError):\n    pass"
        ),
    ),
    "own object of a metaclass's public method, which is a class": (
        ("class _Meta(type):\n    def make(cls, key):\n        return cls('a')"),
        ("class _Meta(type):\n    def make(cls, key):\n        return cls(key)"),
    ),
    "exception class passed as an item of a name nothing binds": (
        (
            "def _make(key, kind):\n    return kind('a')\n"
            "def f(key):\n    raise _make(key, KINDS[0])"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\n"
            "def f(key):\n    raise _make(key, KINDS[0])"
        ),
    ),
    "exception class passed as an item of what a call answers": (
        (
            "def _kinds():\n    return [ValueError]\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n    raise _make(key, _kinds()[0])"
        ),
        (
            "def _kinds():\n    return [ValueError]\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n    raise _make(key, _kinds()[0])"
        ),
    ),
    "exception class passed as what an await answers": (
        (
            "async def _kind():\n    return ValueError\n"
            "def _make(key, kind):\n    return kind('a')\n"
            "async def f(key):\n    raise _make(key, await _kind())"
        ),
        (
            "async def _kind():\n    return ValueError\n"
            "def _make(key, kind):\n    return kind(key)\n"
            "async def f(key):\n    raise _make(key, await _kind())"
        ),
    ),
    "exception class passed as what a yield answers": (
        (
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    kind = yield\n    raise _make(key, kind)"
        ),
        (
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    kind = yield\n    raise _make(key, kind)"
        ),
    ),
    "exception class passed as what a yield from answers": (
        (
            "def _kinds():\n    yield\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    kind = yield from _kinds()\n    raise _make(key, kind)"
        ),
        (
            "def _kinds():\n    yield\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    kind = yield from _kinds()\n    raise _make(key, kind)"
        ),
    ),
    "own object of a method of a class deriving from ABCMeta": (
        (
            "from abc import ABCMeta\nclass _Meta(ABCMeta):\n"
            "    def make(cls, key):\n        return cls('a')"
        ),
        (
            "from abc import ABCMeta\nclass _Meta(ABCMeta):\n"
            "    def make(cls, key):\n        return cls(key)"
        ),
    ),
    "own object of a method of a class deriving from abc.ABCMeta": (
        (
            "import abc\nclass _Meta(abc.ABCMeta):\n"
            "    def make(cls, key):\n        return cls('a')"
        ),
        (
            "import abc\nclass _Meta(abc.ABCMeta):\n"
            "    def make(cls, key):\n        return cls(key)"
        ),
    ),
    "own object of a method of a class deriving from EnumType": (
        (
            "from enum import EnumType\nclass _Meta(EnumType):\n"
            "    def make(cls, key):\n        return cls('a')"
        ),
        (
            "from enum import EnumType\nclass _Meta(EnumType):\n"
            "    def make(cls, key):\n        return cls(key)"
        ),
    ),
    "exception class passed through a global a call result is assigned to": (
        (
            "kind = str\ndef _kind():\n    return ValueError\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    global kind\n    kind = _kind()\n"
            "    raise _make(key, kind)"
        ),
        (
            "kind = str\ndef _kind():\n    return ValueError\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    global kind\n    kind = _kind()\n"
            "    raise _make(key, kind)"
        ),
    ),
    "exception class passed through a nonlocal a call result is assigned to": (
        (
            "def _kind():\n    return ValueError\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n    kind = str\n"
            "    def g():\n        nonlocal kind\n        kind = _kind()\n"
            "        raise _make(key, kind)\n    return g"
        ),
        (
            "def _kind():\n    return ValueError\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n    kind = str\n"
            "    def g():\n        nonlocal kind\n        kind = _kind()\n"
            "        raise _make(key, kind)\n    return g"
        ),
    ),
    "exception class put into a list through another name": (
        (
            "KINDS = [str]\nalias = KINDS\nalias.append(ValueError)\n"
            "def _make(key, kind):\n    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[1])"
        ),
        (
            "KINDS = [str]\nalias = KINDS\nalias.append(ValueError)\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[1])"
        ),
    ),
    "exception class put into a list by a call it is handed to": (
        (
            "def _add(kinds):\n    kinds.append(ValueError)\n"
            "KINDS = [str]\n_add(KINDS)\ndef _make(key, kind):\n"
            "    return kind('a')\ndef f(key):\n"
            "    raise _make(key, KINDS[1])"
        ),
        (
            "def _add(kinds):\n    kinds.append(ValueError)\n"
            "KINDS = [str]\n_add(KINDS)\ndef _make(key, kind):\n"
            "    return kind(key)\ndef f(key):\n"
            "    raise _make(key, KINDS[1])"
        ),
    ),
    "global a function declares and leaves as assigned": (
        (
            "kind = str\ndef _kind():\n    return ValueError\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    global kind\n    raise _make(key, kind)"
        ),
        (
            "kind = str\ndef _kind():\n    return ValueError\n"
            "def _make(key, kind):\n    return kind(key)\ndef f(key):\n"
            "    global kind\n    kind = _kind()\n"
            "    raise _make(key, kind)"
        ),
    ),
    "class of the package a parameter shadows": (
        "class Refused(Exception):\n    pass\ndef f(key):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
        "class Refused(Exception):\n    pass\ndef f(key, Refused):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
    ),
    "class of the package a positional-only parameter shadows": (
        "class Refused(Exception):\n    pass\ndef f(key):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
        "class Refused(Exception):\n    pass\ndef f(key, Refused, /):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
    ),
    "class of the package a keyword-only parameter shadows": (
        "class Refused(Exception):\n    pass\ndef f(key):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
        "class Refused(Exception):\n    pass\ndef f(key, *, Refused):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
    ),
    "class of the package a starred parameter shadows": (
        "class Refused(Exception):\n    pass\ndef f(key):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
        "class Refused(Exception):\n    pass\ndef f(key, *Refused):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
    ),
    "class of the package a double-starred parameter shadows": (
        "class Refused(Exception):\n    pass\ndef f(key):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
        "class Refused(Exception):\n    pass\ndef f(key, **Refused):\n    try:\n        key.decode()\n    except Refused:\n        raise ValueError('a')",
    ),
    "exception class bound by assignment that a call passes to a parameter": (
        (
            "Refused = ValueError\ndef _make(key, Refused):\n"
            "    return Refused('a')\ndef f(key):\n    raise _make(key, Refused)"
        ),
        (
            "Refused = ValueError\ndef _make(key, Refused):\n"
            "    return Refused(key)\ndef f(key):\n    raise _make(key, Refused)"
        ),
    ),
    "exception class of the package every call passes to a parameter": (
        (
            "class Refused(Exception):\n    pass\ndef _make(Refused, key):\n    return Refused('a')\n"
            "def f(key):\n    raise _make(Refused, key)"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(Refused, key):\n    return Refused(key)\n"
            "def f(key):\n    raise _make(Refused, key)"
        ),
    ),
    "exception class a parameter takes by default": (
        "class Refused(Exception):\n    pass\ndef f(key, Refused=Refused):\n    return Refused('a')",
        "class Refused(Exception):\n    pass\ndef f(key, Refused=Refused):\n    return Refused(key)",
    ),
    "exception class a call passes to a keyword-only parameter": (
        (
            "Refused = ValueError\ndef _make(key, *, kind):\n    return kind('a')\n"
            "def f(key):\n    raise _make(key, kind=Refused)"
        ),
        (
            "Refused = ValueError\ndef _make(key, *, kind):\n    return kind(key)\n"
            "def f(key):\n    raise _make(key, kind=Refused)"
        ),
    ),
    "exception class a call may pass by unpacking": (
        (
            "Refused = ValueError\ndef _make(key, kind):\n    return kind('a')\n"
            "def f(key):\n    raise _make(*(key, Refused))"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind):\n    return kind(key)\n"
            "def f(key):\n    raise _make(*(key, Refused))"
        ),
    ),
    "exception class a call passes to a method's parameter": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    def f(self, key):\n"
            "        raise self._make(key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    def f(self, key):\n"
            "        raise self._make(key, Refused)"
        ),
    ),
    "exception class a call through the class passes to a method's parameter": (
        (
            "class _C:\n    def _make(self, key, kind):\n        return kind('a')\n"
            "    def f(self, key):\n        raise _C._make(self, key, ValueError)"
        ),
        (
            "class _C:\n    def _make(self, key, kind):\n        return kind(key)\n"
            "    def f(self, key):\n        raise _C._make(self, key, ValueError)"
        ),
    ),
    "exception class a call through a class method's class passes": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    @classmethod\n    def f(cls, key):\n"
            "        raise cls._make(None, key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    @classmethod\n    def f(cls, key):\n"
            "        raise cls._make(None, key, Refused)"
        ),
    ),
    "exception class a call passes to a method of a local object named cls": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    @classmethod\n    def f(cls, key):\n"
            "        def _g():\n            cls = _C()\n"
            "            raise cls._make(key, Refused)\n        _g()"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    @classmethod\n    def f(cls, key):\n"
            "        def _g():\n            cls = _C()\n"
            "            raise cls._make(key, Refused)\n        _g()"
        ),
    ),
    "exception class a call passes to a method called on a name nothing binds": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    def f(self, key):\n"
            "        raise unbound._make(key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    def f(self, key):\n"
            "        raise unbound._make(key, Refused)"
        ),
    ),
    "exception class a call on what super() answers passes to a method": (
        (
            "Refused = ValueError\nclass _B:\n    def _make(self, key, kind):\n"
            "        return kind('a')\nclass _C(_B):\n    def f(self, key):\n"
            "        raise super()._make(key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _B:\n    def _make(self, key, kind):\n"
            "        return kind(key)\nclass _C(_B):\n    def f(self, key):\n"
            "        raise super()._make(key, Refused)"
        ),
    ),
    "exception class a class method takes, called on an object": (
        (
            "class Refused(Exception):\n    @classmethod\n"
            "    def _make(kind, key):\n        return kind('a')\n"
            "def f(key):\n    refusal = Refused()\n    raise refusal._make(key)"
        ),
        (
            "class Refused(Exception):\n    @classmethod\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "def f(key):\n    refusal = Refused()\n    raise refusal._make(key)"
        ),
    ),
    "exception class a class method takes, called through it": (
        (
            "class _C:\n    @classmethod\n    def _make(kind, key):\n"
            "        return kind(key)\ndef f(key):\n    return _C._make(key)"
        ),
        (
            "class _C(Exception):\n    @classmethod\n    def _make(kind, key):\n"
            "        return kind(key)\ndef f(key):\n    return _C._make(key)"
        ),
    ),
    "a class method's class rebound before a call through it": (
        (
            "class _C:\n    def _m(self, text, unused):\n"
            "        raise ValueError(text)\n    @classmethod\n"
            "    def f(cls, key):\n        cls = _C()\n        cls._m('a', key)"
        ),
        (
            "class _C:\n    def _m(self, text, unused):\n"
            "        raise ValueError(text)\n    @classmethod\n"
            "    def f(cls, key):\n        cls = _C()\n        cls._m(key, 1)"
        ),
    ),
    "exception class a call through a class read off a module passes": (
        (
            "import m\nRefused = ValueError\nclass _C:\n"
            "    def _make(self, key, kind):\n        return kind('a')\n"
            "def f(key):\n    raise m._C._make(None, key, Refused)"
        ),
        (
            "import m\nRefused = ValueError\nclass _C:\n"
            "    def _make(self, key, kind):\n        return kind(key)\n"
            "def f(key):\n    raise m._C._make(None, key, Refused)"
        ),
    ),
    "what a method called on super() answers": (
        (
            "class _B:\n    def _text(self, key):\n        return 'a'\n"
            "class _C(_B):\n    def f(self, key):\n"
            "        raise ValueError(super()._text(key))"
        ),
        (
            "class _B:\n    def _text(self, key):\n        return key\n"
            "class _C(_B):\n    def f(self, key):\n"
            "        raise ValueError(super()._text(key))"
        ),
    ),
    "a method called on its own object of another name": (
        (
            "class _C:\n    def _text(this):\n        return 'a'\n"
            "    def _f(this, other):\n        raise ValueError(this._text())\n"
            "    def g(self, key):\n        self._f(key)"
        ),
        (
            "class _C:\n    def _text(this):\n        return 'a'\n"
            "    def _f(this, other):\n        raise ValueError(other._text())\n"
            "    def g(self, key):\n        self._f(key)"
        ),
    ),
    "a method called on its own object, rebound": (
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n        raise ValueError(self._text())"
        ),
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n        self = key\n"
            "        raise ValueError(self._text())"
        ),
    ),
    "a method called on a class method's class, rebound in a nested function": (
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    @classmethod\n    def f(cls, key):\n        def _g():\n"
            "            raise ValueError(cls._text())\n        _g()"
        ),
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    @classmethod\n    def f(cls, key):\n        def _g():\n"
            "            cls = key\n            raise ValueError(cls._text())\n"
            "        _g()"
        ),
    ),
    "a method called on its own object, an attribute of it set": (
        (
            "class C:\n    def _text(self):\n        return 'a'\n"
            "    def _m(self):\n        self.n = 1\n"
            "        raise ValueError(self._text())"
        ),
        (
            "class C:\n    def _text(self):\n        return 'a'\n"
            "    def _m(self, key):\n        self = key\n"
            "        raise ValueError(self._text())"
        ),
    ),
    "an attribute of its own object called, another attribute of it set": (
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        self.n = 1\n        try:\n            pass\n"
            "        except OSError:\n            self._g()\n"
            "    def _g(self):\n        return 1"
        ),
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        self.n = 1\n        try:\n            pass\n"
            "        except OSError:\n            self.g()"
        ),
    ),
    "an attribute of its own object called, an item of it set or put into it": (
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        self.pos += 1\n        self[0] = 1\n"
            "        self.append(1)\n        try:\n            pass\n"
            "        except OSError:\n            self._g()\n"
            "    def _g(self):\n        return 1"
        ),
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        self.pos += 1\n        self[0] = 1\n"
            "        self.append(1)\n        try:\n            pass\n"
            "        except OSError:\n            self.g()"
        ),
    ),
    "exception class a call through a class method's class passes, an attribute set": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    @classmethod\n    def f(cls, key):\n"
            "        cls.count += 1\n        raise cls._make(None, key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    @classmethod\n    def f(cls, key):\n"
            "        cls.count += 1\n        raise cls._make(None, key, Refused)"
        ),
    ),
    "exception class a call through the class passes, an attribute of it set": (
        _THROUGH.format("'a'", "        _C.count = 1\n", ""),
        _THROUGH.format("key", "        _C.count = 1\n", ""),
    ),
    "exception class a call through the class passes, an attribute of it added to": (
        _THROUGH.format("'a'", "        _C.n += 1\n", ""),
        _THROUGH.format("key", "        _C.n += 1\n", ""),
    ),
    "exception class a call through the class passes, an item of it set": (
        _THROUGH.format("'a'", "        _C.table['a'] = 0\n", ""),
        _THROUGH.format("key", "        _C.table['a'] = 0\n", ""),
    ),
    "exception class a call through the class passes, the module setting it": (
        _THROUGH.format("'a'", "", "_C.count = 1\n"),
        _THROUGH.format("key", "", "_C.count = 1\n"),
    ),
    "exception class a call through a class read off a module passes, set": (
        (
            "import m\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n_C.count = 1\n"
            "def f(key):\n    raise m._C._make(None, key, ValueError)"
        ),
        (
            "import m\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n_C.count = 1\n"
            "def f(key):\n    raise m._C._make(None, key, ValueError)"
        ),
    ),
    "a class of the package caught, an attribute of it set": (
        (
            "class _E(Exception):\n    pass\ndef f(key):\n    try:\n        pass\n"
            "    except _E:\n        _E.n = 1\n        raise"
        ),
        (
            "class _E(Exception):\n    pass\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        _E.n = 1\n        raise"
        ),
    ),
    "a method called on its own object, annotated": (
        _ON_SELF.format("        self: _C\n"),
        _ON_SELF.format("        self: _C = key\n"),
    ),
    "exception class a call through a class method's class passes, annotated": (
        _ON_CLASS.format("'a'", "        cls: type\n"),
        _ON_CLASS.format("key", "        cls: type\n"),
    ),
    "a method called on its own object, a comprehension binding its name": (
        _ON_SELF.format("        _ = [self for self in ()]\n"),
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n"
            "        raise ValueError([self._text() for self in key])"
        ),
    ),
    "an attribute of its own object called in a comprehension's first iterable": (
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        try:\n            pass\n"
            "        except OSError:\n            _ = [1 for self in self._g()]\n"
            "    def _g(self):\n        return 1"
        ),
        (
            "class C:\n    def __init__(self, factory):\n        self.g = factory\n"
            "    def _f(self):\n        try:\n            pass\n"
            "        except OSError:\n            _ = [1 for self in self.g()]"
        ),
    ),
    "exception class a call through a class method's class passes, a comprehension": (
        _ON_CLASS.format("'a'", "        _ = [cls for cls in ()]\n"),
        _ON_CLASS.format("key", "        _ = [cls for cls in ()]\n"),
    ),
    "exception class a call passes to a method of a comprehension's target": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    def f(self, key):\n"
            "        raise [_C._make(key, Refused) for _C in ()][0]"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    def f(self, key):\n"
            "        raise [_C._make(key, Refused) for _C in ()][0]"
        ),
    ),
    "a function of the package an attribute of which is set, called": (
        (
            "def f(key):\n    def show():\n        return 'a'\n"
            "    show.kind = ValueError\n    raise ValueError(show())"
        ),
        (
            "def f(key):\n    def show():\n        return key.hex()\n"
            "    show.kind = ValueError\n    raise ValueError(show())"
        ),
    ),
    "a function of the package an attribute of which the module sets": (
        (
            "def _text(key):\n    return 'a'\n_text.cache = {}\n"
            "def f(key):\n    raise ValueError(_text(key))"
        ),
        (
            "def _text(key):\n    return key\n_text.cache = {}\n"
            "def f(key):\n    raise ValueError(_text(key))"
        ),
    ),
    "a function of the package an attribute of which is set, called handling": (
        (
            "def _g():\n    return 1\n_g.n = 1\ndef f(key):\n    try:\n"
            "        pass\n    except OSError:\n        _g()"
        ),
        (
            "def _g():\n    raise ValueError('a')\n_g.n = 1\ndef f(key):\n    try:\n"
            "        pass\n    except OSError:\n        _g()"
        ),
    ),
    "a function of the package annotated before its def": (
        (
            "_text: object\ndef _text(key):\n    return 'a'\n"
            "def f(key):\n    raise ValueError(_text(key))"
        ),
        (
            "_text: object\ndef _text(key):\n    return key\n"
            "def f(key):\n    raise ValueError(_text(key))"
        ),
    ),
    "a function of the package whose name a comprehension binds": (
        (
            "def _text(key):\n    return 'a'\n_ = [_text for _text in ()]\n"
            "def f(key):\n    raise ValueError(_text(key))"
        ),
        (
            "def _text(key):\n    return key\n_ = [_text for _text in ()]\n"
            "def f(key):\n    raise ValueError(_text(key))"
        ),
    ),
    "a local whose name a comprehension binds": (
        "def f(key):\n    x = 'a'\n    _ = [x for x in key]\n    raise ValueError(x)",
        "def f(key):\n    x = 'a'\n    raise ValueError([x for x in key])",
    ),
    "a module name a parameter shadows, a method called through it": (
        (
            "import m\nRefused = ValueError\nclass _C:\n"
            "    def _make(self, key, kind):\n        return kind('a')\n"
            "class _Box:\n    def __init__(self):\n        self._C = _C()\n"
            "def _f(m, key):\n    raise m._C._make(key, Refused)\n"
            "def g(key):\n    _f(_Box(), key)"
        ),
        (
            "import m\nRefused = ValueError\nclass _C:\n"
            "    def _make(self, key, kind):\n        return kind(key)\n"
            "class _Box:\n    def __init__(self):\n        self._C = _C()\n"
            "def _f(m, key):\n    raise m._C._make(key, Refused)\n"
            "def g(key):\n    _f(_Box(), key)"
        ),
    ),
    "a module name a local shadows, a method called through it": (
        (
            "import m\nRefused = ValueError\nclass _C:\n"
            "    def _make(self, key, kind):\n        return kind('a')\n"
            "class _Box:\n    def __init__(self):\n        self._C = _C()\n"
            "def g(key):\n    m = _Box()\n    raise m._C._make(key, Refused)"
        ),
        (
            "import m\nRefused = ValueError\nclass _C:\n"
            "    def _make(self, key, kind):\n        return kind(key)\n"
            "class _Box:\n    def __init__(self):\n        self._C = _C()\n"
            "def g(key):\n    m = _Box()\n    raise m._C._make(key, Refused)"
        ),
    ),
    "a module name a parameter shadows, a class caught off it": (
        (
            "import m\nclass _E(Exception):\n    pass\ndef f(key):\n    try:\n"
            "        pass\n    except m._E:\n        raise"
        ),
        (
            "import m\nclass _E(Exception):\n    pass\ndef _f(m, key):\n    try:\n"
            "        pass\n    except m._E:\n        raise\ndef g(key):\n    _f(key, key)"
        ),
    ),
    "a method called through a name a comprehension binds, in a lambda": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    def f(self, key):\n"
            "        return [lambda: _C._make(key, Refused) for _C in (self,)]"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    def f(self, key):\n"
            "        return [lambda: _C._make(key, Refused) for _C in (self,)]"
        ),
    ),
    "a method called on its own object, declared nonlocal": (
        _ON_SELF.format(
            "        def _g():\n            nonlocal self\n"
            "            raise ValueError(self._text())\n        _g()\n"
        ),
        _ON_SELF.format(
            "        def _g():\n            nonlocal self\n            self = key\n"
            "            raise ValueError(self._text())\n        _g()\n"
        ),
    ),
    "a method called on its own object, rebound in a default": (
        _ON_SELF.format("        def _g(x=(other := key)):\n            pass\n"),
        _ON_SELF.format("        def _g(x=(self := key)):\n            pass\n"),
    ),
    "a method called on its own object, rebound in a lambda's default": (
        _ON_SELF.format("        _ = lambda x=(other := key): x\n"),
        _ON_SELF.format("        _ = lambda x=(self := key): x\n"),
    ),
    "a method called on its own object, rebound in a class's bases": (
        _ON_SELF.format("        class _D((other := object)):\n            pass\n"),
        _ON_SELF.format("        class _D((self := key)):\n            pass\n"),
    ),
    "a method called on its own object, stored in a class body": (
        _ON_SELF.format("        class _D:\n            self = key\n"),
        _ON_SELF.format("        self = key\n"),
    ),
    "a method called on a dict comprehension's target named as its object": (
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n"
            "        raise ValueError({1: self._text() for k in key})"
        ),
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n"
            "        raise ValueError({1: self._text() for self in key})"
        ),
    ),
    "a method called on a comprehension's second target named as its object": (
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n"
            "        raise ValueError([self._text() for k in key for j in k])"
        ),
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key):\n"
            "        raise ValueError([self._text() for k in key for self in k])"
        ),
    ),
    "a parameter a nested function puts a value into": (
        (
            "def f(key):\n    def _g():\n        key.append(1)\n"
            "        raise ValueError('a')\n    _g()"
        ),
        (
            "def f(key):\n    def _g():\n        key.append(1)\n"
            "        raise ValueError(key)\n    _g()"
        ),
    ),
    "a parameter a nested function sets an attribute of": (
        (
            "def f(key):\n    def _g():\n        key.n = 1\n"
            "        raise ValueError('a')\n    _g()"
        ),
        (
            "def f(key):\n    def _g():\n        key.n = 1\n"
            "        raise ValueError(key)\n    _g()"
        ),
    ),
    "a parameter a nested function indexes a container by": (
        (
            "def f(key):\n    def _g():\n        d = {}\n        d[key] = 1\n"
            "        raise ValueError('a')\n    _g()"
        ),
        (
            "def f(key):\n    def _g():\n        d = {}\n        d[key] = 1\n"
            "        raise ValueError(key)\n    _g()"
        ),
    ),
    "a call of a comprehension's target while handling": (
        (
            "def f(key, actions):\n    try:\n        pass\n    except OSError:\n"
            "        _ = [len(action) for action in actions]"
        ),
        (
            "def f(key, actions):\n    try:\n        pass\n    except OSError:\n"
            "        _ = [action() for action in actions]"
        ),
    ),
    "a local an attribute of which is set to an exception class, called": (
        "def f(key):\n    show = ValueError\n    raise ValueError(show())",
        (
            "def f(key):\n    show = lambda: key.hex()\n"
            "    show.kind = ValueError\n    raise ValueError(show())"
        ),
    ),
    "a lambda's parameter a comprehension around it also binds": (
        "def f(key):\n    return [lambda: ValueError(x) for x in ('a',)]",
        "def f(key):\n    return [lambda x: ValueError(x) for x in ('a',)]",
    ),
    "a method called on its own object, stored in its own default": (
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key, x=(self := 1)):\n"
            "        raise ValueError(self._text())"
        ),
        (
            "class _C:\n    def _text(self):\n        return 'a'\n"
            "    def f(self, key, x=(other := 1)):\n        self = key\n"
            "        raise ValueError(self._text())"
        ),
    ),
    "a class built while handling, whose body calls a raising function": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        class _D:\n            _g()"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        class _D:\n            _g()"
        ),
    ),
    "a function defined while handling, whose body calls a raising one": (
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        pass\n    except OSError:\n        def _h():\n            _g()"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        pass\n    except OSError:\n        def _h():\n            _g()\n"
            "        _h()"
        ),
    ),
    "a class built in a finally, whose body calls a raising function": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        pass\n"
            "    finally:\n        class _D:\n            _g()"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n        pass\n"
            "    finally:\n        class _D:\n            _g()"
        ),
    ),
    "exception class a function declares global": (
        "Refused = ValueError\ndef f(key):\n    global Refused\n    return Refused('a')",
        "Refused = ValueError\ndef f(key):\n    global Refused\n    return Refused(key)",
    ),
    "exception class a nested function declares nonlocal": (
        (
            "def f(key):\n    Refused = ValueError\n    def _g():\n"
            "        nonlocal Refused\n        return Refused('a')\n    return _g()"
        ),
        (
            "def f(key):\n    Refused = ValueError\n    def _g():\n"
            "        nonlocal Refused\n        return Refused(key)\n    return _g()"
        ),
    ),
    "a lambda's default naming its own parameter, in a comprehension": (
        "def f(key):\n    return [lambda x=ValueError(x): 0 for x in ('a',)]",
        "def f(key):\n    return [lambda x=ValueError(key): 0 for x in ('a',)]",
    ),
    "a method called on its own object, rebound in a decorator": (
        _ON_SELF.format(
            "        @(other := key)\n        def _g():\n            pass\n"
        ),
        _ON_SELF.format(
            "        @(self := key)\n        def _g():\n            pass\n"
        ),
    ),
    "a method called on its own object, rebound in a keyword-only default": (
        _ON_SELF.format("        def _g(*, x=(other := key)):\n            pass\n"),
        _ON_SELF.format("        def _g(*, x=(self := key)):\n            pass\n"),
    ),
    "a method called on its own object, rebound in a class keyword": (
        _ON_SELF.format(
            "        class _D(metaclass=(other := type)):\n            pass\n"
        ),
        _ON_SELF.format(
            "        class _D(metaclass=(self := key)):\n            pass\n"
        ),
    ),
    "an exception raised by name, an attribute of it set": (
        "def f(key):\n    e = ValueError('a')\n    raise e",
        "def f(key):\n    e = ValueError('a')\n    e.args = (key,)\n    raise e",
    ),
    "a class of the package caught, declared global": (
        (
            "class _E(Exception):\n    pass\ndef f(key):\n    try:\n        pass\n"
            "    except _E:\n        raise"
        ),
        (
            "class _E(Exception):\n    pass\ndef f(key):\n    global _E\n"
            "    try:\n        pass\n    except _E:\n        raise"
        ),
    ),
    "a class caught off a package a dotted import binds": (
        (
            "import m.sub\nclass _E(Exception):\n    pass\ndef f(key):\n    try:\n"
            "        pass\n    except m._E:\n        raise"
        ),
        (
            "import os.path\ndef f(key):\n    try:\n        pass\n"
            "    except os.error:\n        raise"
        ),
    ),
    "exception class a call passes to a method called on a class method's argument": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind('a')\n    @classmethod\n    def f(cls, obj, key):\n"
            "        raise obj._make(key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(self, key, kind):\n"
            "        return kind(key)\n    @classmethod\n    def f(cls, obj, key):\n"
            "        raise obj._make(key, Refused)"
        ),
    ),
    "a method called on a static method's parameter named cls": (
        (
            "class _C:\n    @staticmethod\n    def _g(cls):\n"
            "        raise ValueError(cls._text())\n    def _text(self):\n"
            "        return 'a'\n    def f(self, key):\n        self._g('a')"
        ),
        (
            "class _C:\n    @staticmethod\n    def _g(cls):\n"
            "        raise ValueError(cls._text())\n    def _text(self):\n"
            "        return 'a'\n    def f(self, key):\n        self._g(key)"
        ),
    ),
    "exception class a call passes to a class method's parameter": (
        (
            "Refused = ValueError\nclass _C:\n    @classmethod\n"
            "    def _make(klass, key, kind):\n        return kind('a')\n"
            "    def f(self, key):\n        raise _C._make(key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    @classmethod\n"
            "    def _make(klass, key, kind):\n        return kind(key)\n"
            "    def f(self, key):\n        raise _C._make(key, Refused)"
        ),
    ),
    "exception class a call passes to a static method's parameter named cls": (
        (
            "class Refused(Exception):\n    pass\nclass _C:\n    @staticmethod\n"
            "    def _make(cls, key):\n        return cls('a')\n"
            "    def f(self, key):\n        raise self._make(Refused, key)"
        ),
        (
            "class Refused(Exception):\n    pass\nclass _C:\n    @staticmethod\n"
            "    def _make(cls, key):\n        return cls(key)\n"
            "    def f(self, key):\n        raise self._make(Refused, key)"
        ),
    ),
    "exception class a call passes to a method whose object has another name": (
        (
            "Refused = ValueError\nclass _C:\n    def _make(this, key, kind):\n"
            "        return kind('a')\n    def f(self, key):\n"
            "        raise self._make(key, Refused)"
        ),
        (
            "Refused = ValueError\nclass _C:\n    def _make(this, key, kind):\n"
            "        return kind(key)\n    def f(self, key):\n"
            "        raise self._make(key, Refused)"
        ),
    ),
    "exception class a chain of calls may pass by unpacking": (
        (
            "class Refused(Exception):\n    pass\ndef _make(kind, key):\n"
            "    return kind('a')\ndef _mid(kind, key):\n    return _make(kind, key)\n"
            "def f(kind, key):\n    raise _mid(*(kind, key))"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(kind, key):\n"
            "    return kind(key)\ndef _mid(kind, key):\n    return _make(kind, key)\n"
            "def f(kind, key):\n    raise _mid(*(kind, key))"
        ),
    ),
    "call of a parameter a chain of calls passes, whose result a refusal prints": (
        (
            "class Refused(Exception):\n    pass\ndef _make(kind):\n    return kind('a')\n"
            "def _mid(kind):\n    return _make(kind)\n"
            "def f():\n    raise ValueError(_mid(Refused))"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(kind):\n    return kind('a')\n"
            "def _mid(kind):\n    return _make(kind)\n"
            "def f(kind):\n    raise ValueError(_mid(*(kind,)))"
        ),
    ),
    "exception class a call through the class passes to a method's object": (
        (
            "class _C:\n    def _make(self, key):\n        return self('a')\n"
            "    def f(self, key):\n        raise _C._make(ValueError, key)"
        ),
        (
            "class _C:\n    def _make(self, key):\n        return self(key)\n"
            "    def f(self, key):\n        raise _C._make(ValueError, key)"
        ),
    ),
    "call of a method's object a call through the class passes, printed": (
        (
            "class _C:\n    def _make(self):\n        return self('a')\n"
            "    def f(self, key):\n        raise ValueError(_C._make(ValueError))"
        ),
        (
            "class _C:\n    def _make(self):\n        return self('a')\n"
            "    def f(self, key):\n"
            "        raise ValueError(_C._make(ValueError), self._make())"
        ),
    ),
    "a method's own object": (
        (
            "class _C:\n    def _g(self):\n        raise ValueError('a')\n"
            "    def f(self):\n        self._g()"
        ),
        (
            "class _C:\n    def _g(self):\n        raise ValueError(self)\n"
            "    def f(self):\n        self._g()"
        ),
    ),
    "a starred parameter of a method": (
        (
            "class _C:\n    def _m(*args):\n        raise ValueError('a')\n"
            "    def f(self):\n        self._m(1)"
        ),
        (
            "class _C:\n    def _m(*args):\n        raise ValueError(args)\n"
            "    def f(self):\n        self._m(1)"
        ),
    ),
    "a function's parameter named self": (
        "def _g(self, key):\n    raise ValueError(self)\ndef f(key):\n    _g(1, key)",
        "def _g(self, key):\n    raise ValueError(self)\ndef f(key):\n    _g(key, key)",
    ),
    "exception class a parameter a call leaves takes by default": (
        (
            "Refused = ValueError\ndef _make(key, kind=Refused):\n    return kind('a')\n"
            "def f(key):\n    raise _make(key)"
        ),
        (
            "Refused = ValueError\ndef _make(key, kind=Refused):\n    return kind(key)\n"
            "def f(key):\n    raise _make(key)"
        ),
    ),
    "call of a parameter whose result a refusal prints, a call unpacking": (
        (
            "class Refused(Exception):\n    pass\ndef _make(kind):\n    return kind('a')\n"
            "def f():\n    raise ValueError(_make(Refused))"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(kind):\n    return kind('a')\n"
            "def f(kind):\n    raise ValueError(_make(*(kind,)))"
        ),
    ),
    "call of a parameter whose result a refusal prints, one call a class": (
        (
            "class Refused(Exception):\n    pass\ndef _make(kind):\n    return kind('a')\n"
            "def f():\n    raise ValueError(_make(Refused))\n"
            "def g():\n    raise _make(Refused)"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(kind):\n    return kind('a')\n"
            "def f(kind):\n    raise ValueError(_make(kind))\n"
            "def g():\n    raise _make(Refused)"
        ),
    ),
    "exception class passed to a function's parameter named cls": (
        (
            "class Refused(Exception):\n    pass\ndef _make(cls, key):\n    return cls('a')\n"
            "def f(key):\n    raise _make(Refused, key)"
        ),
        (
            "class Refused(Exception):\n    pass\ndef _make(cls, key):\n    return cls(key)\n"
            "def f(key):\n    raise _make(Refused, key)"
        ),
    ),
    "exception handed to a function that raises it": (
        (
            "def _raise(refusal):\n    raise refusal\n"
            "def f(key):\n    _raise(ValueError('a'))"
        ),
        "def _raise(refusal):\n    raise refusal\ndef f(key):\n    _raise(key)",
    ),
    "exception raised out of a container": (
        "def f(key):\n    errors = [ValueError('a')]\n    raise errors[0]",
        "def f(key):\n    errors = [key]\n    raise errors[0]",
    ),
    "a value a class's own bases bind in the scope around it": (
        (
            "def f(key, c):\n    x = 'b'\n    class _D((x := 'a') if c else object):\n"
            "        raise ValueError(x)"
        ),
        (
            "def f(key, c):\n    x = key\n    class _D((x := 'a') if c else object):\n"
            "        raise ValueError(x)"
        ),
    ),
    "a call a class body makes before it binds the name": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        class _D:\n            _g()\n"
            "            def _g():\n                return 1"
        ),
        (
            "_g = print\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        class _D:\n            _g()\n"
            "            def _g():\n                return 1"
        ),
    ),
    "a value a class body reads before it binds the name": (
        (
            "x = 'b'\ndef f(key):\n    class _D:\n        raise ValueError(x)\n"
            "        x = 'a'"
        ),
        (
            "import sys\nx = sys.argv\ndef f(key):\n    class _D:\n"
            "        raise ValueError(x)\n        x = 'a'"
        ),
    ),
    "an exception a class body raises before it binds the name": (
        (
            "e = ValueError('b')\ndef f(key):\n    class _D:\n        raise e\n"
            "        e = ValueError('a')"
        ),
        (
            "import sys\ne = sys.argv\ndef f(key):\n    class _D:\n"
            "        raise e\n        e = ValueError('a')"
        ),
    ),
    "an exception a class body builds before it binds the name": (
        (
            "E = ValueError\ndef f(key):\n    class _D:\n        x = E('a')\n"
            "        E = int"
        ),
        (
            "E = ValueError\ndef f(key):\n    class _D:\n        x = E(key)\n"
            "        E = int"
        ),
    ),
    "a value a function puts into a module name it declares global": (
        (
            "x = None\ndef g(key):\n    global x\n    x = 'a'\n"
            "def f():\n    raise ValueError(x)"
        ),
        (
            "x = None\ndef g(key):\n    global x\n    x = key\n"
            "def f():\n    raise ValueError(x)"
        ),
    ),
    "a value a class body reads from a module name a function declares global": (
        (
            "x = None\ndef f(key):\n    global x\n    x = 'a'\n    class _D:\n"
            "        y = ValueError(x)\n        x = 'a'"
        ),
        (
            "x = None\ndef f(key):\n    global x\n    x = key\n    class _D:\n"
            "        y = ValueError(x)\n        x = 'a'"
        ),
    ),
    "a call a class body makes before it binds a name the module does not": (
        (
            "def vars():\n    return 'safe'\ndef f(key):\n    class C:\n"
            "        secret = key\n        text = vars()\n"
            "        def vars():\n            return 'safe'\n"
            "        raise ValueError(text)"
        ),
        (
            "def f(key):\n    class C:\n        secret = key\n        text = vars()\n"
            "        def vars():\n            return 'safe'\n"
            "        raise ValueError(text)"
        ),
    ),
    "an exception a class body keeps, a module handler binding its name": (
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    pass\n"
            "except _OwnError as err:\n    pass\ndef f(key, saved):\n"
            "    class C:\n        saved = []\n        try:\n            key.decode()\n"
            "        except _OwnError as err:\n            saved.append(err)\n"
            "        raise ValueError('a') from saved[0]"
        ),
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    pass\n"
            "except _OwnError as err:\n    pass\ndef f(key, saved):\n"
            "    class C:\n        saved = []\n        try:\n            key.decode()\n"
            "        except UnicodeError as err:\n            saved.append(err)\n"
            "        raise ValueError('a') from saved[0]"
        ),
    ),
    "a builtin a class body reads before it binds the name": (
        (
            "input = 'b'\ndef f(key):\n    class C:\n        raise ValueError(input)\n"
            "        input = 'a'"
        ),
        "def f(key):\n    class C:\n        raise ValueError(input)\n        input = 'a'",
    ),
    "an exception class a class body passes before it binds the name": (
        (
            "import os\nE = int\ndef _build(kind, key):\n    return kind(key)\n"
            "def f(key):\n    class C:\n        _build(E, key)\n"
            "        E = getattr(os, 'x')"
        ),
        (
            "import os\nE = getattr(os, 'x')\ndef _build(kind, key):\n"
            "    return kind(key)\ndef f(key):\n    class C:\n        _build(E, key)\n"
            "        E = int"
        ),
    ),
    "an item a class body passes before it binds the name": (
        (
            "import os\nKINDS = [int]\ndef _build(kind, key):\n    return kind(key)\n"
            "def f(key):\n    class C:\n        _build(KINDS[0], key)\n"
            "        KINDS = [getattr(os, 'x')]"
        ),
        (
            "import os\nKINDS = [getattr(os, 'x')]\ndef _build(kind, key):\n"
            "    return kind(key)\ndef f(key):\n    class C:\n"
            "        _build(KINDS[0], key)\n        KINDS = [int]"
        ),
    ),
    "an item of a module name a class body passes, the module filling it": (
        (
            "import os\nKINDS = [int]\nOTHER = []\nOTHER.append(getattr(os, 'x'))\n"
            "def _build(kind, key):\n    return kind(key)\ndef f(key):\n"
            "    class C:\n        _build(KINDS[0], key)\n        KINDS = [int]"
        ),
        (
            "import os\nKINDS = [int]\nKINDS.append(getattr(os, 'x'))\n"
            "def _build(kind, key):\n    return kind(key)\ndef f(key):\n"
            "    class C:\n        _build(KINDS[0], key)\n        KINDS = [int]"
        ),
    ),
    "an exception a class body keeps from the function around it": (
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    pass\n"
            "except _OwnError as err:\n    pass\ndef f(key):\n    try:\n"
            "        key.decode()\n    except _OwnError as err:\n        class C:\n"
            "            saved = []\n            saved.append(err)\n"
            "            raise ValueError('a') from saved[0]"
        ),
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    pass\n"
            "except _OwnError as err:\n    pass\ndef f(key):\n    try:\n"
            "        key.decode()\n    except UnicodeError as err:\n        class C:\n"
            "            saved = []\n            saved.append(err)\n"
            "            raise ValueError('a') from saved[0]"
        ),
    ),
    "an exception a class body keeps in a module name it binds later": (
        (
            "class _OwnError(Exception):\n    pass\nsaved = []\ntry:\n"
            "    b''.decode()\nexcept _OwnError as err:\n    saved.append(err)\n"
            "def f(key):\n    class C:\n        try:\n            key.decode()\n"
            "        except UnicodeError as err:\n            pass\n"
            "        raise ValueError('a') from saved[0]\n        saved = []"
        ),
        (
            "class _OwnError(Exception):\n    pass\nsaved = []\ntry:\n"
            "    b''.decode()\nexcept UnicodeError as err:\n    saved.append(err)\n"
            "def f(key):\n    class C:\n        try:\n            key.decode()\n"
            "        except _OwnError as err:\n            pass\n"
            "        raise ValueError('a') from saved[0]\n        saved = []"
        ),
    ),
    "an exception a class body keeps before its handler binds the name": (
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    b''.decode()\n"
            "except UnicodeError as caught:\n    err = caught\ndef f(key):\n"
            "    class C:\n        saved = []\n        try:\n            key.decode()\n"
            "        except _OwnError as err:\n            saved.append(err)\n"
            "        raise ValueError('a') from saved[0]"
        ),
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    b''.decode()\n"
            "except UnicodeError as caught:\n    err = caught\ndef f(key):\n"
            "    class C:\n        saved = []\n        saved.append(err)\n"
            "        try:\n            key.decode()\n"
            "        except _OwnError as err:\n            pass\n"
            "        raise ValueError('a') from saved[0]"
        ),
    ),
    "an exception a class body keeps after its handler ends": (
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    b''.decode()\n"
            "except UnicodeError as caught:\n    err = caught\ndef f(key):\n"
            "    class C:\n        saved = []\n        try:\n            key.decode()\n"
            "        except _OwnError as err:\n            saved.append(err)\n"
            "        raise ValueError('a') from saved[0]"
        ),
        (
            "class _OwnError(Exception):\n    pass\ntry:\n    b''.decode()\n"
            "except UnicodeError as caught:\n    err = caught\ndef f(key):\n"
            "    class C:\n        saved = []\n        try:\n            key.decode()\n"
            "        except _OwnError as err:\n            pass\n"
            "        saved.append(err)\n        raise ValueError('a') from saved[0]"
        ),
    ),
    "an exception kept from one of two handlers that bind its name": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    saved = []\n"
            "    try:\n        key.decode()\n    except _OwnError as err:\n"
            "        saved.append(err)\n    except UnicodeError as err:\n"
            "        pass\n    raise ValueError('a') from saved[0]"
        ),
        (
            "class _OwnError(Exception):\n    pass\ndef f(key):\n    saved = []\n"
            "    try:\n        key.decode()\n    except _OwnError as err:\n"
            "        pass\n    except UnicodeError as err:\n"
            "        saved.append(err)\n    raise ValueError('a') from saved[0]"
        ),
    ),
    "a call a class body makes after it deletes the name": (
        (
            "def f(key):\n    class C:\n        secret = key\n        def vars():\n"
            "            return 'safe'\n        text = vars()\n        del vars\n"
            "        raise ValueError(text)"
        ),
        (
            "def f(key):\n    class C:\n        secret = key\n        def vars():\n"
            "            return 'safe'\n        del vars\n        text = vars()\n"
            "        raise ValueError(text)"
        ),
    ),
    "a call in an except of a class body, before and after it binds the name": (
        (
            "def f(key):\n    try:\n        pass\n    except OSError:\n        class C:\n"
            "            len('a')\n            def len(x):\n"
            "                raise ValueError('b')"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except OSError:\n        class C:\n"
            "            def len(x):\n                raise ValueError('b')\n"
            "            len('a')"
        ),
    ),
    "a value a class body reads in a loop that binds it later": (
        (
            "x = 'b'\ndef f(key):\n    class C:\n        for _ in range(2):\n"
            "            y = ValueError(x)\n            x = 'a'"
        ),
        (
            "x = 'b'\ndef f(key):\n    class C:\n        for _ in range(2):\n"
            "            y = ValueError(x)\n            x = key"
        ),
    ),
    "a call a class body makes in a loop that deletes the name": (
        (
            "def f(key):\n    class C:\n        secret = key\n        def vars():\n"
            "            return 'safe'\n        text = ''\n"
            "        for _ in range(2):\n"
            "            text = vars()\n        del vars\n        raise ValueError(text)"
        ),
        (
            "def f(key):\n    class C:\n        secret = key\n        def vars():\n"
            "            return 'safe'\n        text = ''\n"
            "        for _ in range(2):\n"
            "            text = vars()\n            del vars\n"
            "        raise ValueError(text)"
        ),
    ),
    "a cause a class body reads before it binds the name": (
        (
            "saved = []\ndef f(key):\n    class C:\n"
            "        raise ValueError('a') from saved[0]\n        saved = [None]"
        ),
        (
            "def f(key):\n    class C:\n        raise ValueError('a') from saved[0]\n"
            "        saved = [None]"
        ),
    ),
    "an exception kept from a handler whose body rebinds its name": (
        (
            "class _OwnError(Exception):\n    pass\ndef f(key, other):\n"
            "    saved = []\n    try:\n        key.decode()\n"
            "    except _OwnError as err:\n        saved.append(err)\n"
            "    raise ValueError('a') from saved[0]"
        ),
        (
            "class _OwnError(Exception):\n    pass\ndef f(key, other):\n"
            "    saved = []\n    try:\n        key.decode()\n"
            "    except _OwnError as err:\n        err = other\n"
            "        saved.append(err)\n    raise ValueError('a') from saved[0]"
        ),
    ),
    "a call of a name the class body binds": (
        (
            "def _g():\n    return 1\ndef f(key, action):\n    try:\n"
            "        pass\n    except OSError:\n        class _D:\n"
            "            _g()"
        ),
        (
            "def _g():\n    return 1\ndef f(key, action):\n    try:\n"
            "        pass\n    except OSError:\n        class _D:\n"
            "            _g = action\n            _g()"
        ),
    ),
    "raising call in a finally": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        int(key)\n"
            "    finally:\n        _g()"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        int(key)\n    finally:\n        _g()"
        ),
    ),
    "exception class a function binds where it declares it global": (
        (
            "def f(key):\n    global Refused\n    Refused = ValueError\n"
            "    return Refused('a')"
        ),
        (
            "def f(key):\n    global Refused\n    Refused = ValueError\n"
            "    return Refused(key)"
        ),
    ),
    "exception class a function binds where it declares it nonlocal": (
        (
            "def f(key):\n    Refused = None\n    def _g():\n"
            "        nonlocal Refused\n        Refused = ValueError\n"
            "        return Refused('a')\n    return _g()"
        ),
        (
            "def f(key):\n    Refused = None\n    def _g():\n"
            "        nonlocal Refused\n        Refused = ValueError\n"
            "        return Refused(key)\n    return _g()"
        ),
    ),
    "exception class a function binds where it declares nonlocal a parameter": (
        (
            "def f(key, Refused=None):\n    def _g():\n        nonlocal Refused\n"
            "        Refused = ValueError\n        return Refused('a')\n    return _g()"
        ),
        (
            "def f(key, Refused=None):\n    def _g():\n        nonlocal Refused\n"
            "        Refused = ValueError\n        return Refused(key)\n    return _g()"
        ),
    ),
    "exception class an outer nonlocal binds, called under an inner one": (
        (
            "def f(key):\n    Refused = None\n    def _g():\n"
            "        nonlocal Refused\n        Refused = ValueError\n"
            "        def _h():\n            nonlocal Refused\n"
            "            return Refused('a')\n        return _h()\n    return _g()"
        ),
        (
            "def f(key):\n    Refused = None\n    def _g():\n"
            "        nonlocal Refused\n        Refused = ValueError\n"
            "        def _h():\n            nonlocal Refused\n"
            "            return Refused(key)\n        return _h()\n    return _g()"
        ),
    ),
    "raising call in a parameter's annotation of a def in an except": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        def h(x: _g()):\n            pass"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        pass\n    except OSError:\n        def h(x: _g()):\n"
            "            pass"
        ),
    ),
    "raising call in the return annotation of a def in an except": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        pass\n"
            "    except OSError:\n        def h(x) -> _g():\n            pass"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        pass\n    except OSError:\n        def h(x) -> _g():\n"
            "            pass"
        ),
    ),
    "raising call in a starred parameter's annotation of a def in a finally": (
        (
            "def _g():\n    return 1\ndef f(key):\n    try:\n        pass\n"
            "    finally:\n        def h(*x: _g()):\n            pass"
        ),
        (
            "def _g():\n    raise ValueError('a')\ndef f(key):\n    try:\n"
            "        pass\n    finally:\n        def h(*x: _g()):\n            pass"
        ),
    ),
    "name a lambda in a comprehension binds with :=": (
        (
            "def f(key):\n"
            "    return [lambda: ((x := 'a'), ValueError(x))[1] for x in (key,)]"
        ),
        (
            "def f(key):\n"
            "    return [lambda: ((x := key), ValueError(x))[1] for x in ('a',)]"
        ),
    ),
    "item a loop stores": (
        (
            "def f(key):\n    bucket = [None]\n    for bucket[0] in ('a',):\n"
            "        pass\n    raise ValueError(bucket[0])"
        ),
        (
            "def f(key):\n    bucket = [None]\n    for bucket[0] in (key,):\n"
            "        pass\n    raise ValueError(bucket[0])"
        ),
    ),
    "item a comprehension stores": (
        (
            "def f(key):\n    bucket = [None]\n    _ = [0 for bucket[0] in ('a',)]\n"
            "    raise ValueError(bucket[0])"
        ),
        (
            "def f(key):\n    bucket = [None]\n    _ = [0 for bucket[0] in (key,)]\n"
            "    raise ValueError(bucket[0])"
        ),
    ),
    "item a with stores": (
        (
            "def _open(x):\n    return x\ndef f(key):\n    bucket = [None]\n"
            "    with _open('a') as bucket[0]:\n        pass\n"
            "    raise ValueError(bucket[0])"
        ),
        (
            "def _open(x):\n    return x\ndef f(key):\n    bucket = [None]\n"
            "    with _open(key) as bucket[0]:\n        pass\n"
            "    raise ValueError(bucket[0])"
        ),
    ),
    "container handed through a class with an unpacked argument": (
        (
            "class _C:\n    def _g(self, unused, items, key):\n"
            "        return len(items)\n    def f(self, key):\n        values = []\n"
            "        _C._g(self, 0, values, key)\n        raise ValueError(values)"
        ),
        (
            "class _C:\n    def _g(self, unused, items, key):\n"
            "        return len(items)\n    def f(self, key):\n        values = []\n"
            "        _C._g(*(self, 0), values, key)\n        raise ValueError(values)"
        ),
    ),
    "staticmethod imported under another name": (
        (
            "from builtins import staticmethod as static\nclass _C:\n    @static\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, 'a')"
        ),
        (
            "from builtins import staticmethod as static\nclass _C:\n    @static\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "classmethod imported under another name": (
        (
            "from builtins import classmethod as klass\nclass _C:\n    @klass\n"
            "    def _make(kind, key):\n        return ValueError(key)\n"
            "    def f(self, key):\n        raise _C._make('a')"
        ),
        (
            "from builtins import classmethod as klass\nclass _C:\n    @klass\n"
            "    def _make(kind, key):\n        return ValueError(key)\n"
            "    def f(self, key):\n        raise _C._make(key)"
        ),
    ),
    "parameter of a method with a decorator the census does not know": (
        (
            "def _deco(f):\n    return staticmethod(f)\nclass _C:\n    @_deco\n"
            "    def _make(kind):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError)"
        ),
        (
            "def _deco(f):\n    return staticmethod(f)\nclass _C:\n    @_deco\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator a module defines under the name of a typing one": (
        (
            "def override(f):\n    return staticmethod(f)\nclass _C:\n    @override\n"
            "    def _make(kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "def override(f):\n    return staticmethod(f)\nclass _C:\n    @override\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator a module defines under the name of a builtin one": (
        (
            "def staticmethod(f):\n    return f\nclass _C:\n    @staticmethod\n"
            "    def _make(self, kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "def staticmethod(f):\n    return f\nclass _C:\n    @staticmethod\n"
            "    def _make(self, kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator read as an attribute of a module other than its home": (
        (
            "import mylib\nclass _C:\n    @mylib.override\n"
            "    def _make(kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "import mylib\nclass _C:\n    @mylib.override\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator named after a typing one under a star import from elsewhere": (
        (
            "from mylib import *\nclass _C:\n    @override\n"
            "    def _make(kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "from mylib import *\nclass _C:\n    @override\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator a parameter around the class binds under a typing name": (
        (
            "def _mk(override):\n    class _C:\n        @override\n"
            "        def _make(kind, key):\n            return kind('a')\n"
            "        def f(self, key):\n            raise self._make(ValueError, key)\n"
            "    return _C"
        ),
        (
            "def _mk(override):\n    class _C:\n        @override\n"
            "        def _make(kind, key):\n            return kind(key)\n"
            "        def f(self, key):\n            raise self._make(ValueError, key)\n"
            "    return _C"
        ),
    ),
    "decorator imported from elsewhere under the name of a typing one": (
        (
            "from mylib import override\nclass _C:\n    @override\n"
            "    def _make(kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "from mylib import override\nclass _C:\n    @override\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator a class body defines under the name of a builtin one": (
        (
            "class _C:\n    def staticmethod(f):\n        return f\n    @staticmethod\n"
            "    def _make(self, kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "class _C:\n    def staticmethod(f):\n        return f\n    @staticmethod\n"
            "    def _make(self, kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorators imported from their homes under other names": (
        (
            "from abc import abstractmethod as a\nfrom typing import override as o\n"
            "from typing_extensions import override as e\nclass _C:\n    @a\n"
            "    def _g(self, x):\n        raise ValueError(x)\n    @o\n"
            "    def _h(self, x):\n        raise ValueError(x)\n    @e\n"
            "    def _i(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')\n        self._h('a')\n"
            "        self._i('a')"
        ),
        (
            "from abc import abstractmethod as a\nfrom typing import override as o\n"
            "from mylib import override as e\nclass _C:\n    @a\n"
            "    def _g(self, x):\n        raise ValueError(x)\n    @o\n"
            "    def _h(self, x):\n        raise ValueError(x)\n    @e\n"
            "    def _i(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')\n        self._h('a')\n"
            "        self._i('a')"
        ),
    ),
    "decorator name an import from its home and an assignment both bind": (
        (
            "def _d(f):\n    return f\n"
            "from builtins import staticmethod as static\nclass _C:\n"
            "    @static\n    def _make(self, kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, ValueError, 'a')"
        ),
        (
            "def _d(f):\n    return f\nstatic = _d\n"
            "from builtins import staticmethod as static\nclass _C:\n"
            "    @static\n    def _make(self, kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, ValueError, 'a')"
        ),
    ),
    "decorator read as an attribute of its home imported under another name": (
        (
            "import typing as t\nclass _C:\n    @t.override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
        (
            "import typing as t\nclass _C:\n    @typing.override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
    ),
    "decorator read as an attribute of a name imported from elsewhere": (
        (
            "import typing\nclass _C:\n    @typing.override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
        (
            "from mylib import typing\nclass _C:\n    @typing.override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
    ),
    "decorator named after a typing one under a star import from its home": (
        (
            "from typing import *\nclass _C:\n    @override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
        (
            "from mylib import *\nclass _C:\n    @override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
    ),
    "decorator imported from its home by a relative import": (
        (
            "from builtins import staticmethod as mode\nclass _C:\n    @mode\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
        (
            "from .builtins import staticmethod as mode\nclass _C:\n    @mode\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
    ),
    "decorator one import binds twice, to two decorators": (
        (
            "from builtins import staticmethod as mode\nclass _C:\n    @mode\n"
            "    def _g(cls, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
        (
            "from builtins import staticmethod as mode, classmethod as mode\n"
            "class _C:\n    @mode\n"
            "    def _g(cls, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
    ),
    "decorator a class body imports only on one branch": (
        (
            "def mode(f):\n    return f\nclass _C:\n"
            "    from builtins import staticmethod as mode\n    @mode\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
        (
            "def mode(f):\n    return f\nclass _C:\n    if len('a'):\n"
            "        from builtins import staticmethod as mode\n    @mode\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
    ),
    "decorator a class body imports after the method": (
        (
            "def mode(f):\n    return f\nclass _C:\n"
            "    from builtins import staticmethod as mode\n    @mode\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
        (
            "def mode(f):\n    return f\nclass _C:\n    @mode\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')\n"
            "    from builtins import staticmethod as mode"
        ),
    ),
    "decorator a class body declares global": (
        (
            "def mode(f):\n    return f\ndef _mk():\n    from builtins import staticmethod as mode\n"
            "    class _C:\n        @mode\n"
            "        def _g(self, text, unused='a'):\n            raise ValueError(text)\n"
            "        def f(self, key):\n            self._g(key, 'a')\n    return _C"
        ),
        (
            "def mode(f):\n    return f\ndef _mk():\n    from builtins import staticmethod as mode\n"
            "    class _C:\n        global mode\n        @mode\n"
            "        def _g(self, text, unused='a'):\n            raise ValueError(text)\n"
            "        def f(self, key):\n            self._g(key, 'a')\n    return _C"
        ),
    ),
    "decorator named after a builtin one a class body declares global": (
        (
            "class _C:\n    @staticmethod\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
        (
            "class _C:\n    global staticmethod\n    @staticmethod\n"
            "    def _g(self, text, unused='a'):\n        raise ValueError(text)\n"
            "    def f(self, key):\n        self._g(key, 'a')"
        ),
    ),
    "decorator's module an import binds twice, to its home and elsewhere": (
        (
            "import typing, mylib as typing\nclass _C:\n"
            "    @typing.override\n    def _make(kind, key):\n"
            "        return kind('a')\n    def f(self, key):\n"
            "        raise self._make(ValueError, key)"
        ),
        (
            "import typing, mylib as typing\nclass _C:\n"
            "    @typing.override\n    def _make(kind, key):\n"
            "        return kind(key)\n    def f(self, key):\n"
            "        raise self._make(ValueError, key)"
        ),
    ),
    "decorator a function around the class lets a sibling rebind": (
        (
            "def _id(f):\n    return f\ndef _mk():\n"
            "    from builtins import staticmethod as mode\n"
            "    def _set():\n        nonlocal mode\n        mode = _id\n"
            "    _set()\n    class _C:\n        @mode\n"
            "        def _make(self, kind, key):\n"
            "            return kind('a')\n        def f(self, key):\n"
            "            raise self._make(ValueError, key)\n    return _C"
        ),
        (
            "def _id(f):\n    return f\ndef _mk():\n"
            "    from builtins import staticmethod as mode\n"
            "    def _set():\n        nonlocal mode\n        mode = _id\n"
            "    _set()\n    class _C:\n        @mode\n"
            "        def _make(self, kind, key):\n"
            "            return kind(key)\n        def f(self, key):\n"
            "            raise self._make(ValueError, key)\n    return _C"
        ),
    ),
    "decorator named after a builtin one a function declares global": (
        (
            "def _id(f):\n    return f\ndef _set():\n"
            "    global staticmethod\n    staticmethod = _id\n_set()\n"
            "class _C:\n    @staticmethod\n"
            "    def _make(self, kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n"
            "        raise self._make(ValueError, key)"
        ),
        (
            "def _id(f):\n    return f\ndef _set():\n"
            "    global staticmethod\n    staticmethod = _id\n_set()\n"
            "class _C:\n    @staticmethod\n"
            "    def _make(self, kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n"
            "        raise self._make(ValueError, key)"
        ),
    ),
    "decorator read as an attribute of a package a submodule import binds": (
        (
            "import mylib.sub\nclass _C:\n    @mylib.override\n"
            "    def _make(kind, key):\n        return kind('a')\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
        (
            "import mylib.sub\nclass _C:\n    @mylib.override\n"
            "    def _make(kind, key):\n        return kind(key)\n"
            "    def f(self, key):\n        raise self._make(ValueError, key)"
        ),
    ),
    "decorator of a method a call answers": (
        (
            "def _wrap():\n    return lambda f: f\nclass _C:\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
        (
            "def _wrap():\n    return lambda f: f\nclass _C:\n    @_wrap()\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
    ),
    "decorator of a method read as an attribute of its home": (
        (
            "import typing\nclass _C:\n    @typing.override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
        (
            "import mylib\nclass _C:\n    @mylib.override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
    ),
    "own object of a method with a decorator the census does not know": (
        (
            "def _deco(f):\n    return f\nclass _C:\n    def _text(self):\n"
            "        return 'a'\n    @property\n    def f(self):\n"
            "        raise ValueError(self._text())"
        ),
        (
            "def _deco(f):\n    return f\nclass _C:\n    def _text(self):\n"
            "        return 'a'\n    @_deco\n    def f(self):\n"
            "        raise ValueError(self._text())"
        ),
    ),
    "container handed to a method with a decorator the census does not know": (
        (
            "def _deco(f):\n    return f\nclass _C:\n"
            "    def _g(self, items, key):\n        return len(items)\n"
            "    def f(self, key):\n        values = []\n        self._g(values, key)\n"
            "        raise ValueError(values)"
        ),
        (
            "def _deco(f):\n    return f\nclass _C:\n    @_deco\n"
            "    def _g(self, items, key):\n        return len(items)\n"
            "    def f(self, key):\n        values = []\n        self._g(values, key)\n"
            "        raise ValueError(values)"
        ),
    ),
    "argument of a method with a decorator the census does not know": (
        (
            "def _deco(f):\n    return f\nclass _C:\n    @override\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
        (
            "def _deco(f):\n    return f\nclass _C:\n    @_deco\n"
            "    def _g(self, x):\n        raise ValueError(x)\n"
            "    def f(self, key):\n        self._g('a')"
        ),
    ),
    "exception class handed to a method with a decorator the census does not know": (
        (
            "def _deco(f):\n    return f\nclass _C:\n    @override\n"
            "    def _make(self, kind, other):\n        err = kind('a')\n"
            "        raise err\n    def f(self, key):\n"
            "        self._make(ValueError, ValueError)"
        ),
        (
            "def _deco(f):\n    return f\nclass _C:\n    @_deco\n"
            "    def _make(self, kind, other):\n        err = kind('a')\n"
            "        raise err\n    def f(self, key):\n"
            "        self._make(ValueError, ValueError)"
        ),
    ),
    "parameter of a decorated function that is not a method": (
        (
            "def _deco(f):\n    return f\n@_deco\ndef _g(x):\n"
            "    raise ValueError(x)\ndef f(key):\n    _g('a')"
        ),
        (
            "def _deco(f):\n    return f\n@_deco\ndef _g(x):\n"
            "    raise ValueError(x)\ndef f(key):\n    _g(key)"
        ),
    ),
}


@pytest.mark.parametrize("traced, flagged", _SHAPES.values(), ids=_SHAPES)
def test_census_controls(traced: str, flagged: str) -> None:
    """The census traces one module of a shape and flags the other."""
    assert not _census({"m.py": traced}).findings()
    assert _census({"m.py": flagged}).findings()


@pytest.mark.parametrize(
    "rebinding",
    [
        "self = key",
        "self += key",
        "self: _C = key",
        "self, other = key",
        "*self, other = key",
        "for self in key:\n            pass",
        "async for self in key:\n            pass",
        "with key as self:\n            pass",
        "async with key as self:\n            pass",
        "(self := key)",
        "try:\n            pass\n        except OSError as self:\n            pass",
        "try:\n            pass\n        except* OSError as self:\n            pass",
        (
            "def _g():\n            global self\n"
            "            raise ValueError(self._text())\n        _g()"
        ),
        "def self():\n            pass",
        "async def self():\n            pass",
        "class self:\n            pass",
        "import self",
        "import self.sub",
        "from os import path as self",
        pytest.param(
            "type self = int",
            marks=pytest.mark.skipif(
                sys.version_info < (3, 12), reason="a `type` statement is 3.12's"
            ),
        ),
        "match key:\n            case self:\n                pass",
        "match key:\n            case [*self]:\n                pass",
        "match key:\n            case {**self}:\n                pass",
    ],
)
def test_census_reads_a_rebound_receiver(rebinding: str) -> None:
    """A method's own object rebound holds what the method does not own.

    Each module compiles, so `async for` and `async with` stand in an
    `async def`.
    """
    source = _ON_SELF.format(f"        {rebinding}\n")
    if rebinding.startswith("async"):
        source = source.replace("def f(", "async def f(")
    compile(source, "m.py", "exec")
    assert _census({"m.py": source}).findings()


_ERRORS = "class FetchError(Exception):\n    pass"
_RELAY = "def f(key):\n    try:\n        pass\n    except {}:\n        raise"


@pytest.mark.parametrize(
    "imports, caught",
    [
        ("from errors import FetchError", "FetchError"),
        ("from errors import FetchError as Refused", "Refused"),
        ("import errors", "errors.FetchError"),
        ("from errors import FetchError", "(FetchError, KeyboardInterrupt)"),
    ],
)
def test_census_knows_a_class_by_its_import(imports: str, caught: str) -> None:
    """A class is the package's by where it comes from, not by its name.

    `errors` is a module of the package, `outside` another package's: a
    class of the same name imported from it is not the package's.
    """
    own = {"errors.py": _ERRORS, "m.py": f"{imports}\n{_RELAY.format(caught)}"}
    assert not _census(own).findings()
    foreign = imports.replace("errors", "outside")
    other = {
        "errors.py": _ERRORS,
        "m.py": f"{foreign}\n{_RELAY.format(caught.replace('errors', 'outside'))}",
    }
    assert _census(other).findings()


def test_census_finds_no_class_in_an_import_cycle() -> None:
    """A name two modules import from each other is bound to no class."""
    sources = {
        "a.py": "from b import FetchError",
        "b.py": "from a import FetchError",
        "m.py": f"from a import FetchError\n{_RELAY.format('FetchError')}",
    }
    assert _census(sources).findings()
