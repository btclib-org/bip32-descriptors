# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the shards of the descriptors mutation profile owe each other.

`.github/mutation/descriptors.toml`'s header states two rules, and a
break of either one leaves the weekly run green:

- every shard file copies that file's `test-command` and `timeout`, so a
  shard that drifts judges its mutants by another command or another
  clock, and nothing reports the difference;
- each mutant of the package is judged by one shard. A pattern of a
  numbered shard edited without its module's `-rest` file either skips
  a mutant in every shard, which the counts lines show only as more
  skipped, or judges it twice.

A shard is a configuration under `.github/mutation/` whose modules lie
in the directory `descriptors.toml` mutates. Which modules a shard
covers is its `module-path` less its `excluded-modules`, read off the
tree as cosmic-ray reads them; which operators it runs is what its
`exclude-operators` does not match, compiled the way cosmic-ray's
operator filter compiles them.

The operator names are cosmic-ray's registered names at the version
uv.lock pins, transcribed below from its operator modules: the suite
runs under the `test` group, which does not install cosmic-ray, so they
cannot be read from it here. `_INVENTED` holds names a later release
could add, so that the partition is checked for those too.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).parents[1]
_PROFILES = _ROOT / ".github" / "mutation"
_PROFILE = "descriptors.toml"

# the keys every shard file copies from descriptors.toml
_COPIED = ("test-command", "timeout")

_BINARY = (
    "Add",
    "BitAnd",
    "BitOr",
    "BitXor",
    "Div",
    "FloorDiv",
    "LShift",
    "Mod",
    "Mul",
    "Pow",
    "RShift",
    "Sub",
)
_COMPARISON = ("Eq", "Gt", "GtE", "Is", "IsNot", "Lt", "LtE", "NotEq")
_UNARY = (
    "Delete_Invert",
    "Delete_Not",
    "Delete_USub",
    "Invert_Not",
    "Invert_UAdd",
    "Invert_USub",
    "UAdd_Invert",
    "UAdd_Not",
    "UAdd_USub",
    "USub_Invert",
    "USub_Not",
    "USub_UAdd",
)
_OTHERS = (
    "AddNot",
    "ExceptionReplacer",
    "NumberReplacer",
    "RemoveDecorator",
    "ReplaceAndWithOr",
    "ReplaceBreakWithContinue",
    "ReplaceContinueWithBreak",
    "ReplaceFalseWithTrue",
    "ReplaceOrWithAnd",
    "ReplaceTrueWithFalse",
    "VariableInserter",
    "VariableReplacer",
    "ZeroIterationForLoop",
)
_REGISTERED = (
    [f"core/ReplaceBinaryOperator_{a}_{b}" for a in _BINARY for b in _BINARY if a != b]
    + [
        f"core/ReplaceComparisonOperator_{a}_{b}"
        for a in _COMPARISON
        for b in _COMPARISON
        if a != b
    ]
    + [f"core/ReplaceUnaryOperator_{pair}" for pair in _UNARY]
    + [f"core/{name}" for name in _OTHERS]
)

# a new target for an operator a shard splits by target, a new source
# for one it takes whole, a name extending an anchored one, and names
# of no family at all
_INVENTED = (
    "core/ReplaceBinaryOperator_BitOr_MatMult",
    "core/ReplaceBinaryOperator_MatMult_BitOr",
    "core/ReplaceBinaryOperator_BitAnd_MatMult",
    "core/ReplaceBinaryOperator_Add_MatMult",
    "core/ReplaceBinaryOperator_Sub_MatMult",
    "core/ReplaceComparisonOperator_Eq_In",
    "core/ReplaceComparisonOperator_In_Eq",
    "core/NumberReplacerWide",
    "core/AddNotTwice",
    "core/ReplaceWithNone",
    "plugin/Other",
)


def _read(path: Path) -> dict[str, Any]:
    """Return the `[cosmic-ray]` table of a configuration."""
    with path.open("rb") as handle:
        table: dict[str, Any] = tomllib.load(handle)["cosmic-ray"]
    return table


def _modules(config: dict[str, Any], root: Path) -> set[Path]:
    """Return the modules a configuration mutates, as cosmic-ray finds them.

    `module-path` is one path or a list of them, each a module or a
    directory searched for modules; `excluded-modules` are globs taken
    away from what that finds.
    """
    found: set[Path] = set()
    paths = config["module-path"]
    for name in [paths] if isinstance(paths, str) else paths:
        path = root / name
        found |= {path} if path.is_file() else set(path.glob("**/*.py"))
    for pattern in config.get("excluded-modules", ()):
        found -= set(root.glob(pattern))
    return found


def _runs(config: dict[str, Any], operator: str) -> bool:
    """Whether a configuration's operator filter leaves `operator` to run.

    cosmic-ray's operator filter joins the patterns into one alternation,
    each wrapped as `(:?pattern)`, skips a mutant whose operator name the
    result matches with `re.match`, and skips nothing for an empty list.
    """
    patterns = (
        config.get("filters", {})
        .get("operators-filter", {})
        .get("exclude-operators", [])
    )
    if not patterns:
        return True
    joined = re.compile("|".join(f"(:?{pattern})" for pattern in patterns))
    return joined.match(operator) is None


def _judges(
    shards: dict[str, dict[str, Any]], root: Path, operators: Iterable[str]
) -> dict[tuple[str, str], list[str]]:
    """Return, for each module and operator, the shards that judge it."""
    covered = {name: _modules(config, root) for name, config in shards.items()}
    modules: set[Path] = set().union(*covered.values())
    return {
        (module.relative_to(root).as_posix(), operator): sorted(
            name
            for name, config in shards.items()
            if module in covered[name] and _runs(config, operator)
        )
        for module in modules
        for operator in operators
    }


_PACKAGE = _modules(_read(_PROFILES / _PROFILE) | {"excluded-modules": []}, _ROOT)
_CONFIGS = {path.name: _read(path) for path in sorted(_PROFILES.glob("*.toml"))}
_SHARDS = {
    name: config
    for name, config in _CONFIGS.items()
    if _modules(config, _ROOT) <= _PACKAGE
}


def test_the_shards_were_read() -> None:
    """A check over an empty set of shards or names is true of nothing."""
    assert _PACKAGE, "descriptors.toml mutates no module at all"
    assert _PROFILE in _SHARDS
    assert len(_SHARDS) > 1, f"descriptors.toml is the only shard: {sorted(_SHARDS)}"
    assert len(set(_REGISTERED)) == len(_REGISTERED)
    assert not set(_INVENTED) & set(_REGISTERED)


def test_every_shard_copies_the_profile_settings() -> None:
    """A shard judged by another command or another clock goes unseen."""
    profile = _SHARDS[_PROFILE]
    drifted = {
        (name, key): config.get(key)
        for name, config in _SHARDS.items()
        for key in _COPIED
        if config.get(key) != profile[key]
    }
    assert not drifted, f"a shard differs from {_PROFILE}: {drifted}"


def test_each_operator_of_each_module_is_judged_by_one_shard() -> None:
    """The registered names and the invented ones, module by module."""
    judges = _judges(_SHARDS, _ROOT, [*_REGISTERED, *_INVENTED])
    modules = {module for module, _ in judges}

    assert modules == {path.relative_to(_ROOT).as_posix() for path in _PACKAGE}
    wrong = {key: names for key, names in judges.items() if len(names) != 1}
    assert not wrong, f"judged by no shard or by more than one: {wrong}"


def test_the_readers_follow_cosmic_ray(tmp_path: Path) -> None:
    """The shapes the readers above have to get right, on literal input.

    A list for `module-path`, a directory less an excluded module, a
    filter that is a negative lookahead and one that names its
    operators, and a split that leaves an operator to no shard.
    """
    (tmp_path / "pkg").mkdir()
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / "pkg" / name).write_text("", encoding="utf-8")
    listed = {"module-path": ["pkg/a.py", "pkg/b.py"]}
    rest = {"module-path": "pkg", "excluded-modules": ["pkg/b.py"]}
    only = {"filters": {"operators-filter": {"exclude-operators": ["(?!core/A$)"]}}}
    skip = {"filters": {"operators-filter": {"exclude-operators": ["core/A$"]}}}

    assert _modules(listed, tmp_path) == {
        tmp_path / "pkg" / n for n in ("a.py", "b.py")
    }
    assert _modules(rest, tmp_path) == {tmp_path / "pkg" / n for n in ("a.py", "c.py")}
    assert _runs(only, "core/A")
    assert not _runs(only, "core/B")
    assert not _runs(skip, "core/A")
    assert _runs(skip, "core/AB")
    assert _runs({}, "core/A")

    shards = {
        "one": {"module-path": "pkg/a.py"} | only,
        "two": {"module-path": "pkg/a.py"} | only,
    }
    judges = _judges(shards, tmp_path, ["core/A", "core/B"])
    assert judges == {
        ("pkg/a.py", "core/A"): ["one", "two"],
        ("pkg/a.py", "core/B"): [],
    }
