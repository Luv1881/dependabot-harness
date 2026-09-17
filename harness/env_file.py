"""Opt-in ``.env`` loading.

The harness reads the process environment. This module adds exactly one explicit way to
populate it from a file, because the shell incantation for doing so is not portable:
``set -a; . ./.env; set +a`` is bash and zsh, and under fish it is a set of errors — fish
has no ``allexport``, and a sourced file cannot contain a bare ``KEY=value``.

**Explicit, never implicit.** Nothing is loaded unless the operator names the file with
``--env-file``. That keeps "secrets come from the environment" true and auditable, and it
means a stray ``.env`` in a working directory cannot quietly change what a run does.

Values are never logged, never echoed, and never written to the database. Only counts and
parse errors are reported.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXPORT = "export "


class EnvFileError(ValueError):
    """The file exists but is not a usable ``.env``."""


@dataclass(frozen=True)
class EnvFileReport:
    """What happened, without ever carrying a value."""

    path: str
    set: tuple[str, ...] = ()
    kept: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        parts = [f"{len(self.set)} variable(s) set from {self.path}"]
        if self.kept:
            parts.append(
                f"{len(self.kept)} already present in the environment and left alone: "
                f"{', '.join(self.kept)}"
            )
        return "; ".join(parts)


def parse_env_file(path: str | Path) -> dict[str, str]:
    """Parse a ``.env`` file into a mapping. Never touches the environment.

    Supported: blank lines, ``#`` comments, an optional ``export`` prefix, and single- or
    double-quoted values. Deliberately **not** supported: ``$VAR`` interpolation. A
    secret containing a ``$`` is then taken literally, which is the behaviour that cannot
    silently corrupt a credential.

    Lines that are not ``NAME=value`` raise rather than being skipped. A typo'd line in a
    credentials file that is silently ignored produces a confusing authentication failure
    much later, in a place with no connection to the file.
    """
    source = Path(path)
    if not source.is_file():
        raise EnvFileError(f"env file not found: {source}")

    try:
        text = source.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise EnvFileError(f"cannot read env file {source}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise EnvFileError(f"env file {source} is not valid UTF-8: {exc}") from exc

    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(_EXPORT):
            line = line[len(_EXPORT) :].lstrip()
        name, separator, value = line.partition("=")
        if not separator:
            raise EnvFileError(
                f"{source} line {number}: expected NAME=value, got a line without '='"
            )
        name = name.strip()
        if not _NAME.match(name):
            raise EnvFileError(
                f"{source} line {number}: {name!r} is not a valid variable name"
            )
        values[name] = _unquote(value.strip(), source=source, number=number)
    return values


def _unquote(value: str, *, source: Path, number: int) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        if value[0] == '"':
            # Only the escapes that change meaning inside a double-quoted shell string.
            return inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        return inner
    # An empty slice is a substring of every string, so both ends must be checked for
    # presence before their membership is tested. `A=` is a valid — if empty — value.
    if value and (value[0] in "\"'" or value[-1] in "\"'"):
        raise EnvFileError(
            f"{source} line {number}: unbalanced quote in value (value not shown)"
        )
    return value


def load_env_file(path: str | Path, *, environ: dict[str, str] | None = None) -> EnvFileReport:
    """Load a ``.env`` into the environment, without overwriting what is already set.

    Existing values win, matching the convention every other dotenv loader follows: an
    environment set by the platform is authoritative and a file is a convenience. It also
    means ``DEEPSEEK_API_KEY=... harness ...`` on the command line beats the file, which
    is what an operator overriding one value expects.
    """
    target = os.environ if environ is None else environ
    values = parse_env_file(path)
    set_names: list[str] = []
    kept: list[str] = []
    for name, value in values.items():
        if target.get(name):
            kept.append(name)
            continue
        target[name] = value
        set_names.append(name)
    return EnvFileReport(
        path=str(path), set=tuple(sorted(set_names)), kept=tuple(sorted(kept))
    )


def names_defined_in(path: str | Path) -> frozenset[str]:
    """Variable *names* a file defines, for a hint. Values are never returned.

    Used to tell an operator that the variable a run is missing is already sitting in a
    file they have, rather than making them read the error and a README to connect them.
    """
    try:
        return frozenset(parse_env_file(path))
    except (EnvFileError, OSError):
        return frozenset()
