from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from harness.ecosystems import (
    GoAdapter,
    JavaAdapter,
    NpmAdapter,
    PythonAdapter,
    ReachabilityLevel,
    ReachabilityResult,
    RustAdapter,
    Scope,
    get_adapter,
    supported_ecosystems,
)
from harness.ecosystems.base import Dependency, UnparsableManifest


class TestRegistry:
    @pytest.mark.parametrize(
        ("github_name", "expected"),
        [("GO", "go"), ("gomod", "go"), ("PIP", "pip"), ("RUST", "cargo"), ("MAVEN", "maven")],
    )
    def test_alias_resolution(self, github_name: str, expected: str) -> None:
        adapter = get_adapter(github_name)
        assert adapter is not None
        assert adapter.ecosystem == expected

    def test_unsupported_returns_none_not_a_default(self) -> None:
        """An unsupported ecosystem must surface, not silently get a permissive stub."""
        assert get_adapter("cocoapods") is None

    def test_all_registered(self) -> None:
        assert set(supported_ecosystems()) == {"go", "pip", "npm", "maven", "cargo"}


class TestCeilings:
    def test_ordering_matches_spec(self) -> None:
        assert GoAdapter().confidence_ceiling() == 0.95
        assert RustAdapter().confidence_ceiling() == 0.90
        assert PythonAdapter().confidence_ceiling() == 0.75
        assert JavaAdapter().confidence_ceiling() == 0.70
        assert NpmAdapter().confidence_ceiling() == 0.55


class TestClamp:
    def test_confidence_never_exceeds_ceiling(self) -> None:
        adapter = NpmAdapter()
        result = adapter.clamp(
            ReachabilityResult(ReachabilityLevel.PATH_FROM_ENTRY, 0.99, "ts-callgraph"),
            symbols_known=True,
        )
        assert result.confidence == 0.55

    def test_unknown_symbols_caps_level_and_confidence(self) -> None:
        """§14.5 — no symbol data means level<=2 and confidence<=0.5."""
        adapter = GoAdapter()
        result = adapter.clamp(
            ReachabilityResult(ReachabilityLevel.ATTACKER_CONTROLLED, 0.95, "govulncheck"),
            symbols_known=False,
        )
        assert result.level == ReachabilityLevel.IMPORTED
        assert result.confidence == 0.5

    def test_toolchain_failure_is_zero_confidence_not_absent(self) -> None:
        """§14.3 — 'we couldn't tell' must never render as 'it's safe'."""
        failure = ReachabilityResult.failed("govulncheck", "exit 1: no go.sum")
        clamped = GoAdapter().clamp(failure, symbols_known=True)
        assert clamped.method == "failed"
        assert clamped.confidence == 0.0
        assert clamped.is_failure


class TestGoScope:
    MOD = """
module example.com/app

go 1.22

require (
\tgithub.com/direct/dep v1.0.0
\tgithub.com/indirect/dep v2.0.0 // indirect
)
"""

    def test_direct(self) -> None:
        result = GoAdapter().resolve_scope(self.MOD, "github.com/direct/dep")
        assert result.is_direct is True
        assert result.scope == Scope.RUNTIME

    def test_indirect(self) -> None:
        result = GoAdapter().resolve_scope(self.MOD, "github.com/indirect/dep")
        assert result.is_direct is False

    def test_absent_is_unknown_not_runtime(self) -> None:
        result = GoAdapter().resolve_scope(self.MOD, "github.com/other/dep")
        assert result.scope == Scope.UNKNOWN
        assert result.is_direct is None

    def test_single_line_require(self) -> None:
        result = GoAdapter().resolve_scope("require github.com/x/y v1.0.0\n", "github.com/x/y")
        assert result.is_direct is True


class TestNpmScope:
    PKG = """
    {
      "dependencies": {"lodash": "^4.17.21"},
      "devDependencies": {"jest": "^29.0.0"},
      "optionalDependencies": {"fsevents": "*"}
    }
    """

    def test_runtime(self) -> None:
        assert NpmAdapter().resolve_scope(self.PKG, "lodash").scope == Scope.RUNTIME

    def test_dev(self) -> None:
        result = NpmAdapter().resolve_scope(self.PKG, "jest")
        assert result.scope == Scope.DEVELOPMENT
        assert result.is_direct is True

    def test_optional_counts_as_runtime(self) -> None:
        assert NpmAdapter().resolve_scope(self.PKG, "fsevents").scope == Scope.RUNTIME

    def test_transitive_scope_is_unknown_not_runtime(self) -> None:
        result = NpmAdapter().resolve_scope(self.PKG, "minimist")
        assert result.scope == Scope.UNKNOWN
        assert result.is_direct is False

    def test_unparsable_manifest_is_unknown(self) -> None:
        assert NpmAdapter().resolve_scope("{not json", "lodash").scope == Scope.UNKNOWN


class TestPythonScope:
    PYPROJECT = """
[project]
name = "app"
dependencies = ["requests>=2.31", "Flask-Login==0.6.3"]

[project.optional-dependencies]
dev = ["pytest>=8"]
server = ["gunicorn"]
"""

    def test_runtime_dependency(self) -> None:
        assert PythonAdapter().resolve_scope(self.PYPROJECT, "requests").scope == Scope.RUNTIME

    def test_pep503_normalization(self) -> None:
        """`Flask-Login`, `flask_login`, and `flask.login` are the same project."""
        adapter = PythonAdapter()
        for name in ("flask_login", "Flask-Login", "flask.login"):
            assert adapter.resolve_scope(self.PYPROJECT, name).scope == Scope.RUNTIME

    def test_dev_extra_is_development(self) -> None:
        assert PythonAdapter().resolve_scope(self.PYPROJECT, "pytest").scope == Scope.DEVELOPMENT

    def test_non_dev_extra_stays_runtime(self) -> None:
        assert PythonAdapter().resolve_scope(self.PYPROJECT, "gunicorn").scope == Scope.RUNTIME

    def test_requirements_directness_is_unknown(self) -> None:
        """A pinned requirements file cannot distinguish direct from transitive."""
        result = PythonAdapter().resolve_scope("requests==2.31.0\nurllib3==2.0.0\n", "urllib3")
        assert result.scope == Scope.RUNTIME
        assert result.is_direct is None


class TestJavaScope:
    POM = """<?xml version="1.0"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <dependencies>
        <dependency>
          <groupId>com.fasterxml.jackson.core</groupId>
          <artifactId>jackson-databind</artifactId>
        </dependency>
        <dependency>
          <groupId>junit</groupId>
          <artifactId>junit</artifactId>
          <scope>test</scope>
        </dependency>
        <dependency>
          <groupId>javax.servlet</groupId>
          <artifactId>servlet-api</artifactId>
          <scope>provided</scope>
        </dependency>
      </dependencies>
    </project>
    """

    def test_default_scope_is_runtime(self) -> None:
        result = JavaAdapter().resolve_scope(
            self.POM, "com.fasterxml.jackson.core:jackson-databind"
        )
        assert result.scope == Scope.RUNTIME
        assert result.is_direct is True

    def test_test_scope_is_development(self) -> None:
        assert JavaAdapter().resolve_scope(self.POM, "junit:junit").scope == Scope.DEVELOPMENT

    def test_provided_scope_is_development(self) -> None:
        """`provided` is supplied by the container and never ships in the artifact."""
        result = JavaAdapter().resolve_scope(self.POM, "javax.servlet:servlet-api")
        assert result.scope == Scope.DEVELOPMENT

    def test_namespaced_and_non_namespaced_pom_both_parse(self) -> None:
        plain = self.POM.replace(' xmlns="http://maven.apache.org/POM/4.0.0"', "")
        assert JavaAdapter().resolve_scope(plain, "junit:junit").scope == Scope.DEVELOPMENT


class TestRustScope:
    CARGO = """
[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
"""

    def test_runtime(self) -> None:
        assert RustAdapter().resolve_scope(self.CARGO, "serde").scope == Scope.RUNTIME

    def test_dev(self) -> None:
        assert RustAdapter().resolve_scope(self.CARGO, "criterion").scope == Scope.DEVELOPMENT

    def test_build_dependency_never_ships(self) -> None:
        assert RustAdapter().resolve_scope(self.CARGO, "cc").scope == Scope.DEVELOPMENT


class TestReachabilityNotImplemented:
    """An unimplemented adapter must raise, never return a permissive default.

    A stub answering 'not reachable' would be the trust-destroying bug: it reads as a
    clearance while measuring nothing.
    """

    @pytest.mark.parametrize("adapter", [NpmAdapter(), JavaAdapter(), RustAdapter()])
    def test_unimplemented_ecosystems_raise(self, adapter: object) -> None:
        with pytest.raises(NotImplementedError):
            adapter.reachability(Path("/nonexistent"), None)  # type: ignore[attr-defined]

    @pytest.mark.parametrize("adapter", [GoAdapter(), PythonAdapter()])
    def test_implemented_ecosystems_report_failure_not_absence(
        self, adapter: object, tmp_path: Path
    ) -> None:
        result = adapter.reachability(tmp_path, None)  # type: ignore[attr-defined]
        assert result.method == "failed"
        assert result.confidence == 0.0


class TestNpmLockfileShapes:
    """Both lockfile shapes are in the wild and both must be read.

    `lockfileVersion` 1 nests dependencies by install path; 2 and 3 use a flat map. A
    reader that understands only the modern shape finds zero dependencies in the older
    one and reports complete coverage over a file full of vulnerable packages — found by
    scanning a real repository whose lockfile is version 1.
    """

    V1: ClassVar[dict[str, Any]] = {
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.20"},
            "mkdirp": {
                "version": "0.5.1",
                "dependencies": {"minimist": {"version": "0.0.8", "dev": True}},
            },
            "nested-again": {
                "version": "1.0.0",
                "dependencies": {
                    "deeper": {
                        "version": "2.0.0",
                        "dependencies": {"deepest": {"version": "3.0.0"}},
                    }
                },
            },
        },
    }

    def test_a_v1_lockfile_yields_its_nested_dependencies(self) -> None:
        found = {
            (d.name, d.version) for d in NpmAdapter().parse_dependencies(json.dumps(self.V1))
        }
        assert found == {
            ("lodash", "4.17.20"),
            ("mkdirp", "0.5.1"),
            ("minimist", "0.0.8"),
            ("nested-again", "1.0.0"),
            ("deeper", "2.0.0"),
            ("deepest", "3.0.0"),
        }

    def test_a_v1_nested_dev_dependency_stays_dev(self) -> None:
        parsed = {d.name: d for d in NpmAdapter().parse_dependencies(json.dumps(self.V1))}
        assert parsed["minimist"].scope == Scope.DEVELOPMENT
        assert parsed["lodash"].scope == Scope.RUNTIME

    def test_a_v2_lockfile_still_uses_the_flat_map(self) -> None:
        payload = {
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/a/node_modules/lodash": {"version": "4.17.21"},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
            },
            "dependencies": {"lodash": {"version": "4.17.15"}},
        }
        found = {(d.name, d.version) for d in NpmAdapter().parse_dependencies(json.dumps(payload))}
        assert found == {("lodash", "4.17.15"), ("lodash", "4.17.21"), ("jest", "29.0.0")}

    def test_two_versions_of_the_same_package_are_both_kept(self) -> None:
        """A v1 tree legitimately holds several versions. Collapsing them would hide the
        vulnerable one whenever a fixed copy is installed elsewhere in the tree."""
        text = json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "a": {
                        "version": "1.0.0",
                        "dependencies": {"lodash": {"version": "4.17.15"}},
                    },
                    "lodash": {"version": "4.17.21"},
                },
            }
        )
        versions = {
            d.version for d in NpmAdapter().parse_dependencies(text) if d.name == "lodash"
        }
        assert versions == {"4.17.15", "4.17.21"}

    def test_an_unrecognised_lockfile_is_refused_not_reported_empty(self) -> None:
        """Returning `[]` here would be counted as a repository with no dependencies,
        keeping `coverage_complete` true over a file nobody understood."""
        text = json.dumps({"lockfileVersion": 4, "entries": {"a": {"version": "1.0.0"}}})
        with pytest.raises(UnparsableManifest, match="neither a 'packages' map"):
            NpmAdapter().parse_dependencies(text)

    def test_an_empty_lockfile_is_legitimately_empty(self) -> None:
        assert NpmAdapter().parse_dependencies("{}") == []

    def test_a_deeply_nested_v1_tree_is_refused_rather_than_truncated(self) -> None:
        """Truncating would drop exactly the transitive dependencies most likely to be
        vulnerable while still reporting complete coverage."""
        node: dict[str, object] = {"leaf": {"version": "1.0.0"}}
        for index in range(250):
            node = {f"p{index}": {"version": "1.0.0", "dependencies": node}}
        with pytest.raises(UnparsableManifest, match="nested deeper"):
            NpmAdapter().parse_dependencies(
                json.dumps({"lockfileVersion": 1, "dependencies": node})
            )

    def test_a_v1_entry_that_is_not_a_mapping_is_ignored(self) -> None:
        text = json.dumps({"lockfileVersion": 1, "dependencies": {"a": "not-a-dict"}})
        assert NpmAdapter().parse_dependencies(text) == []


class TestIsPinned:
    """A version that is not a version cannot be matched against an affected range.

    Querying OSV for `latest` returns nothing, and nothing is then counted as 'checked
    and clean'. Excluding these keeps an unanswerable query from reading as an answer.
    """

    @pytest.mark.parametrize(
        "version",
        ["1.2.3", "v1.2.3", "2026.1", "0.0.1", "1.0.0-rc.1", "1.0.0-rc.1+build", "1.2.3.4"],
    )
    def test_a_concrete_version_is_pinned(self, version: str) -> None:
        assert Dependency(name="x", version=version).is_pinned is True

    @pytest.mark.parametrize(
        "version",
        [
            "latest",
            "next",
            "*",
            "2.x",
            "1.2.x",
            "1.2.X",
            "^1.2.3",
            "~1.2",
            ">=1.0",
            "file:../local-pkg",
            "git+https://github.com/a/b.git",
            "npm:other@1.0.0",
            "workspace:*",
            "",
            " 1.2.3 ",
        ],
    )
    def test_a_range_or_reference_is_not_pinned(self, version: str) -> None:
        assert Dependency(name="x", version=version).is_pinned is False
