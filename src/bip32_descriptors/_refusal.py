# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How a refusal shows the value it refuses.

Section 7 of the btclib-org standard, *A refusal carries no secret*, says
an argument in the wrong place may be a key. A refusal describes such a
value with `_message_text`, names its type with `_type_name`, and quotes
a value refused where a name belongs only up to `_QUOTED_MAX`
characters, too short for a key. It says where an item is, or how many
there are, with `_position`, how many items a value holds with `_size`,
and which of its own texts a refusal it caught was with `_relayed`.

The helpers that describe a value call no method a caller's class can
define: a value is read through the built-in type its type derives
from, and a type's name through `type`'s own descriptor, which a
metaclass does not reach. `_relayed` does call the `__str__` of the
exception it caught, and what that answers only chooses among the
package's own texts.

They reach only the refusals the package writes. A refusal btclib or
Python writes is not the package's, and still names a caller's class as
the class names itself: btclib's refusal of a type, and Python's "object
is not iterable", "has no attribute" and "object is not callable".
"""

import re
from collections.abc import Collection, Iterable

__all__: list[str] = []

_QUOTED_MAX = 16
# the built-in types whose own `__len__` a refusal reads a length with
_SIZED = (
    str,
    bytes,
    bytearray,
    memoryview,
    tuple,
    list,
    dict,
    set,
    frozenset,
    range,
)
# the descriptor `type` reads a class's name with, whatever its metaclass
_TYPE_NAME = vars(type)["__name__"]

# each slot of a text `_relayed` knows, escaped, and what it matches
_SLOTS = ((r"\{,\}", "[0-9]+(?:, [0-9]+)*"), (r"\{\}", "[0-9]+"))


def _exact_int(value: int) -> int:
    """Return the value of an int or int subclass as an int.

    `int.__or__` with 0 reads the value's digits and none of its
    methods, on CPython and on PyPy alike. `int()` calls the value's own
    `__int__`, and on PyPy so do `int.__index__` and, for some values,
    `int.__abs__`.
    """
    return int.__or__(value, 0)


def _position(value: object) -> str:
    """Return where an item is, or how many there are, for a refusal.

    An index or a depth says where; a count, a size or a limit says how
    many. Section 7 lets a refusal say which item failed by where it is.
    A value refused for what it is goes to `_quoted` instead, which
    describes an int. An int of at most `_QUOTED_MAX` digits, a bool
    excepted, is written in decimal, so that a key handed here by mistake
    is not; anything else is described as `_message_text` describes it.
    """
    kind = type(value)
    if issubclass(kind, int) and kind is not bool and isinstance(value, int):
        number = _exact_int(value)
        if -(10**_QUOTED_MAX) < number < 10**_QUOTED_MAX:
            return repr(number)
    return _message_text(value)


def _quoted(value: object) -> str:
    """Return a refused parameter as a refusal may print it.

    A str is quoted up to `_QUOTED_MAX` characters, and described by its
    length past them: section 7 lets a refusal quote a name that short. A
    bool is written as True or False. Anything else, an int included, is
    described as `_message_text` describes it: an int refused for what it
    is may be a key in the wrong place.
    """
    # issubclass on the type decides. isinstance asks a value of another
    # type for its `__class__`, which can claim bool, int or str, or raise,
    # so it runs only where the type already decided, to narrow it for
    # mypy. An exact str copied from the value is what is then measured
    # and written: a subclass can override the length and the formatting
    kind = type(value)
    if kind is bool:
        # bool's own repr, True or False, which holds no key
        return repr(value)
    if issubclass(kind, str) and isinstance(value, str):
        # concatenation with "" returns an exact str, on CPython and on PyPy,
        # and reads none of the value's methods
        text = str.__add__(value, "")
        if len(text) > _QUOTED_MAX:
            return f"a value of {len(text)} characters"
        return repr(text)
    return _message_text(value)


def _label(value: object, known: Collection[str]) -> str:
    """Return a label a refusal names an item by, as a refusal may print it.

    Section 7 says which item failed by where it is: the network, the
    fragment, the context. A helper taking that label as a parameter
    prints it where it is one of `known`, the package's own labels, which
    hold no byte of a caller's value; anything else is shown as `_quoted`
    shows it. The label printed is the element of `known`, not the value.
    """
    kind = type(value)
    if issubclass(kind, str) and isinstance(value, str):
        text = str.__add__(value, "")
        for label in known:
            if label == text:
                return label
    return _quoted(value)


def _relayed(
    error: BaseException, known: Iterable[tuple[str, str]], default: str
) -> str:
    """Return the package's own text for a caught refusal it recognizes.

    A refusal that names where a fault is, as "key 2: ...", relays the
    refusal it caught, and that may be another package's, or one a
    caller's object raised in the form of one of this package's. So
    nothing of the caught text is written out: `known` pairs each text
    the package raises with the text written for it, the caught text
    only chooses among them, and `default` is written where it matches
    none or cannot be read. In a text raised, `{}` matches a number in
    ASCII digits and `{,}` such numbers joined by ", ": no text written
    holds one, the caught text being no measurement.
    """
    # an exact copy of the text: a subclass can define `__str__` to answer
    # a str subclass, or to raise, which only chooses `default`
    try:
        text = "".join((str(error),))
    except Exception:  # noqa: BLE001
        return default
    for template, written in known:
        if template == text:
            return written
        pattern = re.escape(template)
        for slot, digits in _SLOTS:
            pattern = digits.join(pattern.split(slot))
        if re.fullmatch(pattern, text):
            return written
    return default


def _message_text(value: object) -> str:
    """Return the description of a value for a refusal's message, never raising.

    No value is written out: an argument in the wrong place may be a key,
    in an int, a str of its hex, a Decimal or a float of its digits, or
    its bytes. Section 7 lets a refusal print a value's type name and
    length, and not its digits or characters.

    An int, a bool excepted, is described by its sign and bit length.
    Anything else, a bool included, is described by its type name, and
    by its length where `_length` gives one: "a str of length 64", "an
    object". The article is "an" before a name whose first letter, past
    any underscore, is a vowel. A name `_type_name` does not print is
    described by its length alone.

    Neither reads the value's `str()`. That of an int past
    `sys.get_int_max_str_digits()` digits raises ValueError, which would
    leave through the refusal the description is for.
    """
    kind = type(value)
    if issubclass(kind, int) and kind is not bool and isinstance(value, int):
        # the type as `_position` reads it, and the value as `_exact_int`
        # returns it: a subclass can override the comparison and bit_length
        number = _exact_int(value)
        sign = "a negative" if number < 0 else "an"
        return f"{sign} int of {number.bit_length()} bits"
    name = _type_name(value)
    if not name.isidentifier():
        # what `_type_name` writes for a name it does not print
        return f"a value of {name}"
    article = "an" if name.lstrip("_")[:1].lower() in tuple("aeiou") else "a"
    description = f"{article} {name}"
    length = _length(value)
    return description if length is None else f"{description} of length {length}"


# the names of this package's classes longer than `_QUOTED_MAX`, which a
# refusal prints whole: they are the package's own text
_LONG_TYPE_NAMES = ("MiniscriptDescriptor",)


def _type_name(value: object) -> str:
    """Return the name of a value's type, as a refusal may print it.

    Read through `type`'s own descriptor and not `type(value).__name__`,
    which a metaclass can answer, and copied to an exact str: a class's
    name can be a str subclass. A class can be given any name, a key's
    hex among them, so a name is printed where it is an ASCII identifier
    of at most `_QUOTED_MAX` characters, as `_quoted` quotes a name, or
    one of `_LONG_TYPE_NAMES`; any other is described by its length.
    """
    name = "".join((_TYPE_NAME.__get__(type(value), type),))
    printed = len(name) <= _QUOTED_MAX and name.isascii() and name.isidentifier()
    if printed or name in _LONG_TYPE_NAMES:
        return name
    return f"a type whose name has {len(name)} characters"


def _size(value: object) -> str:
    """Return how many items a value holds, for a refusal's message.

    Written as `_position` writes a count, where the value is of one of
    `_SIZED`, measured by that type's own `__len__`; anything else is
    described as `_message_text` describes it.
    """
    length = _length(value)
    return _message_text(value) if length is None else _position(length)


def _length(value: object) -> int | None:
    """Return the length of a value of one of `_SIZED`, else None.

    The first of `_SIZED` its type derives from measures it, with its
    own `__len__`, not the one a subclass defines; a length that type
    cannot measure, as that of a released memoryview, is None too.
    """
    kind = type(value)
    for base in _SIZED:
        if issubclass(kind, base):
            # every Exception: no failure to measure a value may replace
            # the refusal the measure is for
            try:
                return base.__len__(value)  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001
                return None
    return None
