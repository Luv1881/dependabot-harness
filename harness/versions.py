"""Ecosystem-aware version comparison."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_NUMERIC = re.compile(r"^\d+$")
_LEADING_V = re.compile(r"^[vV]")
_EPOCH = re.compile(r"^\d+:")


class VersionError(ValueError):
    """Version string could not be parsed into comparable components."""


@total_ordering
@dataclass(frozen=True)
class Version:
    release: tuple[int, ...]
    prerelease: tuple[str | int, ...] = ()
    raw: str = ""

    @property
    def major(self) -> int:
        return self.release[0] if self.release else 0

    @property
    def minor(self) -> int:
        return self.release[1] if len(self.release) > 1 else 0

    @property
    def patch(self) -> int:
        return self.release[2] if len(self.release) > 2 else 0

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def _key(self) -> tuple[tuple[int, ...], int, tuple[tuple[int, str | int], ...]]:
        padded = self.release + (0,) * (4 - len(self.release))
        stable_rank = 0 if self.prerelease else 1
        parts = tuple(
            (0, part) if isinstance(part, int) else (1, part) for part in self.prerelease
        )
        return (padded[:4], stable_rank, parts)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __str__(self) -> str:
        return self.raw or ".".join(str(n) for n in self.release)


def parse(raw: str) -> Version:
    if raw is None:
        raise VersionError("version is None")
    text = _EPOCH.sub("", _LEADING_V.sub("", str(raw).strip()))
    if not text:
        raise VersionError("empty version string")

    build_split = text.split("+", 1)[0]
    if "-" in build_split:
        core, _, pre = build_split.partition("-")
    else:
        core, pre = build_split, ""

    release: list[int] = []
    for segment in core.split("."):
        cleaned = segment.strip()
        if _NUMERIC.match(cleaned):
            release.append(int(cleaned))
            continue
        head = re.match(r"^(\d+)", cleaned)
        if head is None:
            if not release:
                raise VersionError(f"unparsable version: {raw!r}")
            pre = f"{cleaned}.{pre}" if pre else cleaned
            break
        release.append(int(head.group(1)))
        remainder = cleaned[head.end() :]
        if remainder:
            pre = f"{remainder}.{pre}" if pre else remainder
        break

    if not release:
        raise VersionError(f"unparsable version: {raw!r}")

    prerelease: list[str | int] = []
    for chunk in pre.replace("_", ".").split("."):
        token = chunk.strip()
        if not token:
            continue
        prerelease.append(int(token) if _NUMERIC.match(token) else token.lower())

    return Version(release=tuple(release), prerelease=tuple(prerelease), raw=str(raw).strip())


def try_parse(raw: str | None) -> Version | None:
    if raw is None:
        return None
    try:
        return parse(raw)
    except VersionError:
        return None


def at_or_above(resolved: str | None, target: str | None) -> bool | None:
    """None when either side is unparsable: undecidable is not False."""
    left, right = try_parse(resolved), try_parse(target)
    if left is None or right is None:
        return None
    return left >= right


def is_patch_level_bump(resolved: str | None, patched: str | None) -> bool | None:
    """True when the fix changes only the patch component or lower."""
    left, right = try_parse(resolved), try_parse(patched)
    if left is None or right is None:
        return None
    if right <= left:
        return False
    return (left.major, left.minor) == (right.major, right.minor)
