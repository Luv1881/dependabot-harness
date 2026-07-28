"""Go adapter. ``govulncheck`` (SSA + VTA call graph, symbol-level) — authoritative.

A toolchain that fails to run yields ``method="failed"`` and ``confidence=0.0``. It never
yields a low reachability level: "we could not tell" and "it is not reachable" are
different answers and conflating them is the failure that destroys trust in the system.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .base import (
    CallSite,
    Dependency,
    DependencyTree,
    EcosystemAdapter,
    ReachabilityLevel,
    ReachabilityResult,
    Scope,
    ScopeResult,
)

_REQUIRE_BLOCK = re.compile(r"require\s*\((.*?)\)", re.DOTALL)
_REQUIRE_LINE = re.compile(r"^\s*(?P<mod>[^\s]+)\s+(?P<ver>[^\s]+)(?P<rest>.*)$")

GOVULNCHECK = "govulncheck"
_TIMEOUT_SECONDS = 900


class GoAdapter(EcosystemAdapter):
    ecosystem = "go"
    manifests = ("go.mod",)

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._run = runner or _run_command

    def confidence_ceiling(self) -> float:
        return 0.95

    def dev_scope_is_conclusive(self) -> bool:
        return False

    def resolve_scope(self, manifest_text: str, package: str) -> ScopeResult:
        """go.mod has no dev/runtime split; directness comes from the `// indirect` marker."""
        for module, _version, rest in _iter_requires(manifest_text):
            if module == package or package.startswith(f"{module}/"):
                return ScopeResult(
                    scope=Scope.RUNTIME,
                    is_direct="// indirect" not in rest,
                    source="go.mod:require",
                )
        return ScopeResult(scope=Scope.UNKNOWN, is_direct=None, source="go.mod:absent")

    def parse_dependencies(self, manifest_text: str) -> list[Dependency]:
        return [
            Dependency(
                name=module,
                version=version,
                scope=Scope.RUNTIME,
                is_direct="// indirect" not in rest,
            )
            for module, version, rest in _iter_requires(manifest_text)
        ]

    def resolve_tree(self, repo_path: Path) -> DependencyTree:
        result = self._run(["go", "mod", "graph"], cwd=repo_path)
        tree = DependencyTree(root=_module_path(repo_path) or str(repo_path))
        if result.returncode != 0:
            return tree
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            parent, child = _strip_version(parts[0]), parts[1]
            child_module, _, child_version = child.partition("@")
            tree.edges.setdefault(parent, []).append(child_module)
            if child_version:
                tree.resolved[child_module] = child_version
        return tree

    def reachability(self, repo_path: Path, alert: Any) -> ReachabilityResult:
        if shutil.which(GOVULNCHECK) is None:
            return ReachabilityResult.failed(GOVULNCHECK, "not installed on PATH")
        if not (repo_path / "go.mod").is_file():
            return ReachabilityResult.failed(GOVULNCHECK, "no go.mod at checkout root")

        try:
            result = self._run(
                [GOVULNCHECK, "-format", "json", "./..."],
                cwd=repo_path,
                timeout=_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return ReachabilityResult.failed(GOVULNCHECK, f"timed out after {_TIMEOUT_SECONDS}s")

        if result.returncode not in (0, 3):
            return ReachabilityResult.failed(
                GOVULNCHECK, f"exit {result.returncode}: {result.stderr.strip()[:300]}"
            )

        try:
            report = parse_govulncheck(result.stdout)
        except ValueError as exc:
            return ReachabilityResult.failed(GOVULNCHECK, f"unparsable output: {exc}")

        return report.to_result(
            vuln_ids=_alert_ids(alert),
            tool_version=report.tool_version,
        )

    def call_sites(self, repo_path: Path, symbols: list[str]) -> list[CallSite]:
        result = self.reachability(repo_path, _SymbolQuery(symbols))
        return result.call_sites


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def __call__(
        self, args: list[str], *, cwd: Path, timeout: int | None = None
    ) -> CommandResult: ...


def _run_command(args: list[str], *, cwd: Path, timeout: int | None = None) -> CommandResult:
    proc = subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout
    )
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


@dataclass
class GovulncheckFinding:
    """One govulncheck finding.

    Frames are emitted vulnerable-symbol first and entry-point last, verified against
    govulncheck v1.6.0 output: trace[0] carries the vulnerable function and its source
    position, trace[-1] is the program entry point.
    """

    osv_id: str
    module: str | None
    package: str | None
    function: str | None
    entry_point: str | None
    file: str | None
    line: int
    trace_modules: list[str]

    @property
    def level(self) -> ReachabilityLevel:
        """govulncheck traces from a program entry point, so a function frame is a path."""
        if self.function:
            return ReachabilityLevel.PATH_FROM_ENTRY
        if self.package:
            return ReachabilityLevel.IMPORTED
        return ReachabilityLevel.PRESENT


@dataclass
class GovulncheckReport:
    """Parsed govulncheck output.

    ``aliases`` is keyed by every advisory govulncheck actually evaluated during the
    scan. An advisory absent from that set was never assessed, which is why
    :meth:`to_result` refuses to answer for it.
    """

    findings: list[GovulncheckFinding]
    aliases: dict[str, set[str]]
    tool_version: str = ""

    def names_for(self, osv_id: str) -> set[str]:
        return {osv_id} | self.aliases.get(osv_id, set())

    def evaluated(self, vuln_ids: set[str]) -> bool:
        """Whether govulncheck considered this advisory at all."""
        return any(self.names_for(osv_id) & vuln_ids for osv_id in self.aliases)

    def findings_for(self, vuln_ids: set[str]) -> list[GovulncheckFinding]:
        return [f for f in self.findings if self.names_for(f.osv_id) & vuln_ids]

    def to_result(self, vuln_ids: set[str], tool_version: str = "") -> ReachabilityResult:
        if not self.evaluated(vuln_ids):
            return ReachabilityResult.failed(
                GOVULNCHECK,
                "advisory absent from the govulncheck database for this build; "
                "reachability was never assessed",
            )

        matched = self.findings_for(vuln_ids)
        if not matched:
            return ReachabilityResult(
                level=ReachabilityLevel.PRESENT,
                confidence=0.9,
                method=GOVULNCHECK,
                tool_version=tool_version,
            )

        best = max(matched, key=lambda f: f.level)
        sites = [
            CallSite(
                file=f.file or "",
                line=f.line,
                symbol=f.function or f.package or f.module or "",
                nearest_entry_point=f.entry_point,
            )
            for f in matched
            if f.function and f.file
        ]
        return ReachabilityResult(
            level=best.level,
            confidence=0.95 if best.level >= ReachabilityLevel.PATH_FROM_ENTRY else 0.9,
            method=GOVULNCHECK,
            tool_version=tool_version,
            call_sites=sites,
            dependency_path=best.trace_modules,
        )


def parse_govulncheck(stdout: str) -> GovulncheckReport:
    """Parse the streaming JSON message sequence govulncheck emits."""
    findings: list[GovulncheckFinding] = []
    aliases: dict[str, set[str]] = {}
    tool_version = ""

    for message in _iter_json_messages(stdout):
        if "config" in message:
            config = message["config"]
            tool_version = str(config.get("scanner_version") or config.get("version") or "")
        if "osv" in message:
            osv = message["osv"]
            osv_id = str(osv.get("id", ""))
            if osv_id:
                aliases.setdefault(osv_id, set()).update(str(a) for a in osv.get("aliases") or [])
        if "finding" in message:
            parsed = _parse_finding(message["finding"])
            if parsed is not None:
                findings.append(parsed)

    return GovulncheckReport(findings=findings, aliases=aliases, tool_version=tool_version)


def _iter_json_messages(stdout: str) -> Iterator[dict[str, Any]]:
    decoder = json.JSONDecoder()
    index = 0
    text = stdout.strip()
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return
        try:
            message, offset = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise ValueError(str(exc)) from exc
        index = offset
        if isinstance(message, dict):
            yield message


def _parse_finding(finding: dict[str, Any]) -> GovulncheckFinding | None:
    osv_id = str(finding.get("osv", ""))
    if not osv_id:
        return None
    trace = finding.get("trace") or []
    if not trace:
        return GovulncheckFinding(osv_id, None, None, None, None, None, 0, [])

    vulnerable = trace[0]
    entry = trace[-1] if len(trace) > 1 else None
    position = vulnerable.get("position") or {}
    modules = [str(frame.get("module")) for frame in reversed(trace) if frame.get("module")]

    return GovulncheckFinding(
        osv_id=osv_id,
        module=vulnerable.get("module"),
        package=vulnerable.get("package"),
        function=vulnerable.get("function"),
        entry_point=_frame_symbol(entry),
        file=position.get("filename"),
        line=int(position.get("line") or 0),
        trace_modules=list(dict.fromkeys(modules)),
    )


def _frame_symbol(frame: dict[str, Any] | None) -> str | None:
    if not frame:
        return None
    package = frame.get("package") or frame.get("module")
    function = frame.get("function")
    if package and function:
        return f"{package}.{function}"
    return function or package


@dataclass(frozen=True)
class _SymbolQuery:
    symbols: list[str]

    @property
    def ghsa_id(self) -> str:
        return ""

    @property
    def cve_id(self) -> None:
        return None


def _alert_ids(alert: Any) -> set[str]:
    ids = {getattr(alert, "ghsa_id", "") or "", getattr(alert, "cve_id", "") or ""}
    return {i for i in ids if i}


def _iter_requires(text: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    bodies = _REQUIRE_BLOCK.findall(text)
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ") and "(" not in stripped:
            bodies.append(stripped[len("require ") :])
    for body in bodies:
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            match = _REQUIRE_LINE.match(stripped)
            if match:
                out.append((match["mod"], match["ver"], match["rest"]))
    return out


def _module_path(repo_path: Path) -> str | None:
    go_mod = repo_path / "go.mod"
    if not go_mod.is_file():
        return None
    for line in go_mod.read_text(errors="replace").splitlines():
        if line.startswith("module "):
            return line[len("module ") :].strip()
    return None


def _strip_version(module_at_version: str) -> str:
    return module_at_version.partition("@")[0]
