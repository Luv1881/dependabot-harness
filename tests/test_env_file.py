"""Opt-in ``.env`` loading.

The shell incantation for exporting a dotenv file is not portable — `set -a; . ./.env;
set +a` is bash, and under fish it is three separate errors — so the harness accepts the
file directly and the shell stops mattering. Explicitly, never implicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.env_file import (
    EnvFileError,
    load_env_file,
    names_defined_in,
    parse_env_file,
)


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(text)
    return path


class TestParsing:
    def test_simple_pairs(self, tmp_path: Path) -> None:
        parsed = parse_env_file(write(tmp_path, "A=1\nB=two\n"))
        assert parsed == {"A": "1", "B": "two"}

    def test_comments_and_blank_lines_are_ignored(self, tmp_path: Path) -> None:
        text = "# a comment\n\nA=1\n\n   # indented comment\nB=2\n"
        assert parse_env_file(write(tmp_path, text)) == {"A": "1", "B": "2"}

    def test_an_export_prefix_is_accepted(self, tmp_path: Path) -> None:
        """Half the dotenv files in the world are shell fragments; accepting them costs
        nothing and rejecting them is a papercut with no security benefit."""
        assert parse_env_file(write(tmp_path, "export A=1\n")) == {"A": "1"}

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ('A="quoted value"', "quoted value"),
            ("A='quoted value'", "quoted value"),
            ("A=  spaced  ", "spaced"),
            ('A="has=equals"', "has=equals"),
            ("A=", ""),
            ("A=''", ""),
        ],
    )
    def test_values_are_unwrapped(self, tmp_path: Path, line: str, expected: str) -> None:
        assert parse_env_file(write(tmp_path, line + "\n"))["A"] == expected

    def test_no_variable_interpolation(self, tmp_path: Path) -> None:
        """A secret containing `$` is taken literally. Interpolating would silently corrupt
        any credential that happens to contain one."""
        parsed = parse_env_file(write(tmp_path, "A=$HOME/thing\nB=${OTHER}\n"))
        assert parsed == {"A": "$HOME/thing", "B": "${OTHER}"}

    def test_a_key_that_looks_like_a_secret_is_returned_verbatim(self, tmp_path: Path) -> None:
        parsed = parse_env_file(write(tmp_path, "DEEPSEEK_API_KEY=sk-not-a-real-key\n"))
        assert parsed["DEEPSEEK_API_KEY"] == "sk-not-a-real-key"

    def test_last_definition_wins(self, tmp_path: Path) -> None:
        assert parse_env_file(write(tmp_path, "A=1\nA=2\n")) == {"A": "2"}


class TestErrorsAreLoud:
    """A typo'd line in a credentials file that is silently skipped produces an
    authentication failure much later, in a place with no connection to the file."""

    def test_a_line_without_an_equals_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(EnvFileError, match="line 2"):
            parse_env_file(write(tmp_path, "A=1\nOOPS\n"))

    def test_an_invalid_name_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(EnvFileError, match="not a valid variable name"):
            parse_env_file(write(tmp_path, "1BAD=1\n"))

    def test_an_unbalanced_quote_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(EnvFileError, match="unbalanced quote"):
            parse_env_file(write(tmp_path, 'A="oops\n'))

    def test_a_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(EnvFileError, match="not found"):
            parse_env_file(tmp_path / "absent")

    def test_the_error_never_contains_the_value(self, tmp_path: Path) -> None:
        with pytest.raises(EnvFileError) as exc:
            parse_env_file(write(tmp_path, 'SECRET="unbalanced\n'))
        assert "unbalanced" not in str(exc.value).replace("unbalanced quote", "")


class TestLoading:
    def test_values_are_written_into_the_environment(self, tmp_path: Path) -> None:
        environ: dict[str, str] = {}
        report = load_env_file(write(tmp_path, "A=1\nB=2\n"), environ=environ)
        assert environ == {"A": "1", "B": "2"}
        assert set(report.set) == {"A", "B"}
        assert report.kept == ()

    def test_the_existing_environment_wins(self, tmp_path: Path) -> None:
        """An environment set by the platform is authoritative and the file is a
        convenience; it also means an inline `VAR=... command` beats the file."""
        environ = {"A": "from-shell"}
        report = load_env_file(write(tmp_path, "A=from-file\nB=2\n"), environ=environ)
        assert environ == {"A": "from-shell", "B": "2"}
        assert report.kept == ("A",)
        assert report.set == ("B",)

    def test_an_empty_existing_value_is_filled(self, tmp_path: Path) -> None:
        environ = {"A": ""}
        load_env_file(write(tmp_path, "A=from-file\n"), environ=environ)
        assert environ["A"] == "from-file"

    def test_the_report_never_carries_a_value(self, tmp_path: Path) -> None:
        report = load_env_file(
            write(tmp_path, "DEEPSEEK_API_KEY=sk-not-a-real-key\n"), environ={}
        )
        assert "sk-not-a-real-key" not in report.summary

    def test_the_summary_names_what_it_did(self, tmp_path: Path) -> None:
        report = load_env_file(write(tmp_path, "A=1\n"), environ={"B": "x"})
        assert "1 variable(s) set" in report.summary


class TestNamesOnlyHelper:
    def test_it_reports_names_without_values(self, tmp_path: Path) -> None:
        path = write(tmp_path, "DEEPSEEK_API_KEY=sk-secret\nGH_TOKEN=ghp_secret\n")
        assert names_defined_in(path) == {"DEEPSEEK_API_KEY", "GH_TOKEN"}

    def test_a_broken_file_yields_nothing_rather_than_raising(self, tmp_path: Path) -> None:
        """This is used to build a hint on an error path; it must never become the error."""
        assert names_defined_in(write(tmp_path, "GARBAGE\n")) == frozenset()

    def test_a_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        assert names_defined_in(tmp_path / "absent") == frozenset()
