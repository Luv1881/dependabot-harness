from __future__ import annotations

from pathlib import Path

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
