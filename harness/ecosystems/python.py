"""Python adapter. `osv-scanner --call-analysis=all` plus an `ast`-based call graph.

Python resolves names at runtime, so a negative result is weaker here than in Go. The
0.75 ceiling reflects that, and a scan that could not run reports `method="failed"` with
zero confidence rather than a low reachability level.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from ..analysis.pycallgraph import analyze
from .base import (
    CallSite,
    Dependency,
    EcosystemAdapter,
    ReachabilityLevel,
    ReachabilityResult,
    Scope,
    ScopeResult,
)

OSV_SCANNER = "osv-scanner"
_TIMEOUT_SECONDS = 600

_REQ_LINE = re.compile(r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<spec>[<>=!~].*)?$")
_DEV_FILE_HINTS = ("dev", "test", "lint", "doc", "ci")


def normalize(name: str) -> str:
    """PEP 503 normalization — `Foo.Bar_baz` and `foo-bar-baz` are the same project."""
    return re.sub(r"[-_.]+", "-", name).lower()


class PythonAdapter(EcosystemAdapter):
    ecosystem = "pip"
    manifests = ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.py")

    def __init__(self, runner: Any | None = None) -> None:
        self._run = runner or _run_command

    def confidence_ceiling(self) -> float:
        return 0.75

    def dev_scope_is_conclusive(self) -> bool:
        return False

    def reachability(self, repo_path: Path, alert: Any) -> ReachabilityResult:
        """Combines osv-scanner call analysis with a local AST pass.

        The AST pass is what produces citable call sites; osv-scanner supplies the
        authoritative package-level answer. Neither alone is enough, and if the AST pass
        parsed nothing there is no measurement to report.
        """
        analysis = analyze(repo_path)
        if not analysis.scanned:
            return ReachabilityResult.failed("ast", f"no parsable Python sources under {repo_path}")

        package = _package_from_purl(getattr(alert, "purl", "") or "")
        symbols = list(getattr(alert, "symbols", None) or [])
        scanner = self._osv_scan(repo_path, alert)

        if not analysis.imports_module(package):
            level = ReachabilityLevel.PRESENT
            sites: list[CallSite] = []
        else:
            references = [r for symbol in symbols for r in analysis.references_symbol(symbol)]
            sites = [CallSite(file=r.file, line=r.line, symbol=r.symbol) for r in references[:50]]
            level = (
                ReachabilityLevel.SYMBOL_REFERENCED if references else ReachabilityLevel.IMPORTED
            )

        if (
            scanner is not None
            and scanner.get("called")
            and level < ReachabilityLevel.PATH_FROM_ENTRY
        ):
            level = ReachabilityLevel.PATH_FROM_ENTRY

        confidence = 0.75 if level >= ReachabilityLevel.SYMBOL_REFERENCED else 0.6
        if analysis.uses_dynamic_import:
            confidence = min(confidence, 0.5)

        return ReachabilityResult(
            level=level,
            confidence=confidence,
            method="osv-scanner+ast" if scanner is not None else "ast",
            tool_version=str((scanner or {}).get("version", "")),
            call_sites=sites,
        )

    def _osv_scan(self, repo_path: Path, alert: Any) -> dict[str, Any] | None:
        """Package-level call analysis. None when the tool is unavailable or failed."""
        if shutil.which(OSV_SCANNER) is None:
            return None
        try:
            result = self._run(
                [OSV_SCANNER, "--format", "json", "--call-analysis=all", str(repo_path)],
                cwd=repo_path,
                timeout=_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return None
        if result.returncode not in (0, 1):
            return None
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return None
        return {"called": _osv_called(payload, getattr(alert, "ghsa_id", "")), "version": ""}

    def parse_dependencies(self, manifest_text: str) -> list[Dependency]:
        """Only `==` pins are usable; a range cannot be matched against an advisory."""
        out: list[Dependency] = []
        for line in manifest_text.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("-"):
                continue
            head = stripped.split(";", 1)[0].strip()
            if "==" not in head:
                continue
            name, _, version = head.partition("==")
            version = version.strip().split(",")[0]
            if name and version:
                out.append(
                    Dependency(name=normalize(name.strip()), version=version, scope=Scope.RUNTIME)
                )
        return out

    def resolve_scope(self, manifest_text: str, package: str) -> ScopeResult:
        target = normalize(package)
        stripped = manifest_text.lstrip()
        if stripped.startswith("[") or "[project]" in manifest_text:
            result = self._from_pyproject(manifest_text, target)
            if result is not None:
                return result
        return self._from_requirements(manifest_text, target)

    def _from_pyproject(self, text: str, target: str) -> ScopeResult | None:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return None
        project = data.get("project") or {}
        for spec in project.get("dependencies") or []:
            if normalize(_req_name(str(spec))) == target:
                return ScopeResult(Scope.RUNTIME, True, "pyproject:project.dependencies")
        for group, specs in (project.get("optional-dependencies") or {}).items():
            for spec in specs:
                if normalize(_req_name(str(spec))) == target:
                    scope = (
                        Scope.DEVELOPMENT
                        if any(h in group.lower() for h in _DEV_FILE_HINTS)
                        else Scope.RUNTIME
                    )
                    return ScopeResult(scope, True, f"pyproject:optional-dependencies.{group}")
        for group, specs in (data.get("dependency-groups") or {}).items():
            for spec in specs:
                if isinstance(spec, str) and normalize(_req_name(spec)) == target:
                    return ScopeResult(
                        Scope.DEVELOPMENT, True, f"pyproject:dependency-groups.{group}"
                    )
        return None

    def _from_requirements(self, text: str, target: str) -> ScopeResult:
        for line in text.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("-"):
                continue
            match = _REQ_LINE.match(stripped.split(";", 1)[0].strip())
            if match and normalize(match["name"]) == target:
                return ScopeResult(Scope.RUNTIME, None, "requirements:listed")
        return ScopeResult(Scope.UNKNOWN, None, "requirements:absent")


def _req_name(spec: str) -> str:
    return re.split(r"[<>=!~\[; ]", spec.strip(), maxsplit=1)[0]


def _run_command(args: list[str], *, cwd: Path, timeout: int | None = None) -> Any:
    from .golang import CommandResult

    proc = subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout
    )
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def _package_from_purl(purl: str) -> str:
    body = purl.split(":", 1)[1] if ":" in purl else purl
    name = body.split("/", 1)[1] if "/" in body else body
    return normalize(name)


def _osv_called(payload: dict[str, Any], ghsa_id: str) -> bool:
    """Whether osv-scanner reported the advisory as reached by a call path."""
    for result in payload.get("results") or []:
        for package in result.get("packages") or []:
            for vulnerability in package.get("vulnerabilities") or []:
                aliases = set(vulnerability.get("aliases") or [])
                if ghsa_id and ghsa_id not in aliases and vulnerability.get("id") != ghsa_id:
                    continue
                groups = package.get("groups") or []
                if any(group.get("experimentalAnalysis") for group in groups):
                    return True
    return False
