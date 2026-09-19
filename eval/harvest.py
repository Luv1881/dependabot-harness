#!/usr/bin/env python
"""Harvest and label eval cases from real repositories.

The M4 gate wants hand-labeled cases, and a label produced by the pipeline would measure
the pipeline against itself. So this tool keeps two things strictly apart:

* the **facts** a golden case must carry — the scanner's module list, the version pair, the
  advisory's symbol list. Those are *inputs* to the rules, so carrying the pipeline's own
  scanner output is correct rather than circular.
* the **label**, assigned from an independent evidence digest built by
  :mod:`harness.evaluation.reachability`, which reads file types and import forms the
  pipeline's scanners do not.

Labelling protocol, applied by :func:`propose_label` and recorded as a rationale on every
case so the reasoning is auditable:

1. ``resolved >= patched``            -> **not_reachable**. The vulnerable version is not
   installed. Verifiable arithmetic.
2. dev-scope in an ecosystem whose build system structurally excludes it
                                      -> **not_reachable**. Not in the artifact.
3. directly imported, advisory symbols known:
   a. a symbol is referenced          -> **reachable**.
   b. no symbol is referenced         -> **not_reachable**.
4. directly imported, symbols unknown -> **unsure**. The name is in the tree; whether the
   vulnerable function is called is not determinable from the source alone.
5. not imported, but a *directly imported* package depends on it (**unsure**). Its code
   ships inside that dependent, so an import index cannot establish absence from the
   artifact. This is the case the ``not_imported`` rule gets wrong.
6. not imported, no dependency graph  -> **unsure**. Without the graph, "nothing imports it"
   is not evidence about what is in the bundle.
7. not imported, graph says nothing depends on it -> **not_reachable**. Decisive.

Output is a *review* file. ``eval/label.py`` turns reviewed entries into the dataset and
refuses any entry without a label and a rationale.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.analysis.imports import build_scanner
from harness.analysis.shipped import _closure
from harness.ecosystems import get_adapter
from harness.ecosystems.base import ReachabilityLevel
from harness.evaluation.reachability import (
    Evidence,
    gather,
    npm_dependency_graph,
    transitive_dependents,
)
from harness.fsutil import iter_repo_files
from harness.sources.github import RawAlert
from harness.sources.local import LocalRepo, local_repo_label
from harness.sources.osv import OsvClient
from harness.sources.osv_scan import OsvAlertSource, ScanStats, discover_dependencies
from harness.versions import at_or_above, try_parse

DECONCLUSIVE_DEV_ECOSYSTEMS = frozenset({"maven", "cargo"})

DIRECT_IMPORT_SUFFIXES = {
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "pip": (".py", ".pyi"),
    "go": (".go",),
    "cargo": (".rs",),
}


def _app_seeds(root: Path, ecosystem: str, packages: set[str]) -> set[str]:
    """Which of the declared packages the application itself pulls in.

    Deliberately restricted to packages the lockfile knows about, so a bare word in a
    comment cannot seed the traversal.
    """
    suffixes = DIRECT_IMPORT_SUFFIXES.get(ecosystem, ())
    if not suffixes:
        return set()
    found: set[str] = set()
    for path in iter_repo_files(root):
        if path.suffix.lower() not in suffixes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in re.finditer(r"""(?:require|from|import)\s*\(?\s*['"]([^'"]+)['"]""", text):
            module = match.group(1)
            if not module or module.startswith((".", "/", "http")):
                continue
            parts = module.split("/")
            found.add("/".join(parts[:2]) if module.startswith("@") else parts[0])
        for match in re.finditer(r"^\s*(?:import|from)\s+([A-Za-z_][\w]*)", text, re.MULTILINE):
            found.add(match.group(1).lower())
    return found & packages


def propose_label(
    *,
    resolved: str | None,
    patched: str | None,
    ecosystem: str,
    dep_scope: str | None,
    symbols: list[str],
    evidence: Evidence,
) -> tuple[str, str]:
    """The protocol in the module docstring, as code."""
    if at_or_above(resolved, patched) is True:
        return "not_reachable", f"resolved {resolved} >= patched {patched}; not installed"

    adapter = get_adapter(ecosystem)
    if (
        dep_scope == "development"
        and adapter is not None
        and adapter.dev_scope_is_conclusive()
    ):
        return "not_reachable", f"development scope excluded from the artifact by {ecosystem}"

    if evidence.directly_imported:
        if symbols:
            if evidence.symbol_hits:
                hit = evidence.symbol_hits[0]
                return (
                    "reachable",
                    f"imported and symbol referenced at {hit.file}:{hit.line}",
                )
            return "not_reachable", "imported but no advisory symbol appears in the source"
        return (
            "unsure",
            "imported, and the advisory lists no symbols, so symbol reachability is not "
            "determinable from the source",
        )

    if evidence.shipped_through_a_dependent:
        return (
            "unsure",
            "not directly imported, but shipped inside "
            + ", ".join(evidence.transitive_dependents[:3])
            + ", which the application does load — an import index cannot establish absence",
        )

    if not evidence.graph_available:
        return (
            "unsure",
            "not directly imported, and no dependency graph is available to show whether "
            "anything that is imported depends on it",
        )

    return (
        "not_reachable",
        "nothing imports it and no imported package depends on it",
    )


def _dump_key(root: Path) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", str(root.resolve())).strip("-")[-60:]


def govulncheck_levels(
    root: Path, *, dump_dir: Path | None = None
) -> dict[str, tuple[int, float, str]]:
    """Advisory -> (level, confidence, method) from one whole-program analysis.

    Run once per repository rather than once per alert: govulncheck re-analyses the whole
    module, and a per-alert invocation would take minutes per case for an identical answer.

    Returns an empty mapping when the tool is absent or the module does not build, which
    the caller records as an absent measurement rather than as a clean result.
    """
    import subprocess

    if not (root / "go.mod").is_file():
        return {}
    try:
        proc = subprocess.run(
            ["govulncheck", "-format", "json", "./..."],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode not in (0, 3):
        return {}

    key = _dump_key(root)
    if dump_dir is not None:
        # Keep the raw analysis. `eval/label.py` reads these rather than re-running the
        # tool, so the labels and the evidence facts come from one identical analysis
        # instead of two runs whose inputs could have moved between them.
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / f"{key}.json").write_text(proc.stdout)

    from harness.ecosystems.golang import _iter_json_messages

    aliases: dict[str, set[str]] = {}
    levels: dict[str, int] = {}
    for message in _iter_json_messages(proc.stdout):
        if "osv" in message:
            osv = message["osv"]
            ids = {str(osv.get("id", ""))}
            ids.update(str(a) for a in osv.get("aliases") or ())
            aliases[str(osv.get("id", ""))] = {i for i in ids if i}
        elif "finding" in message:
            finding = message["finding"]
            osv_id = str(finding.get("osv", ""))
            frame_functions = [
                f.get("function") for f in finding.get("trace") or () if f.get("function")
            ]
            if frame_functions:
                # govulncheck only reports call paths it can trace from a program entry
                # point, so a function frame *is* such a path. Recording it as
                # SYMBOL_REFERENCED would understate it and make every Go alert abstain.
                levels[osv_id] = int(ReachabilityLevel.PATH_FROM_ENTRY)
            else:
                levels.setdefault(osv_id, int(ReachabilityLevel.PRESENT))

    out: dict[str, tuple[int, float, str]] = {}
    for osv_id, level in levels.items():
        # Mirrors `GovulncheckReport.to_result` so the case carries what the pipeline
        # would have recorded, rather than a second opinion about the same output.
        confidence = 0.95 if level >= ReachabilityLevel.PATH_FROM_ENTRY else 0.9
        for identifier in aliases.get(osv_id, {osv_id}):
            out[identifier] = (level, confidence, "govulncheck")
    return out


def harvest(
    root: Path, *, label: str | None = None, limit: int = 0, dump_dir: Path | None = None
) -> list[dict[str, object]]:
    root = root.resolve()
    repo = label or local_repo_label(root)
    host = LocalRepo(root)
    source = OsvAlertSource(host, root)
    osv = OsvClient(root.parent / "harvest-cache")
    stats = ScanStats()

    list(discover_dependencies(root, stats))  # populates stats for the report
    lockfile = _lockfile_text(root)
    graph = npm_dependency_graph(lockfile) if lockfile else {}
    seeds = _app_seeds(root, "npm", set(graph)) if graph else set()
    shipped = sorted(_closure(graph, seeds)) if graph else None
    gov_cache: dict[Path, dict[str, tuple[int, float, str]]] = {}

    out: list[dict[str, object]] = []
    scanner_cache: dict[str, set[str] | None] = {}
    try:
        for alert in source.iter_alerts(repo):
            scanner = build_scanner(alert.ecosystem)
            if alert.ecosystem not in scanner_cache:
                scanner_cache[alert.ecosystem] = (
                    sorted(scanner.scan(root).modules) if scanner is not None else None
                )
            advisory = osv.fetch(alert.ghsa_id)
            symbols = list(advisory.symbols) if advisory else []
            purl = _purl(alert)
            evidence = gather(
                root,
                ecosystem=alert.ecosystem,
                package=alert.package_name,
                manifest_path=alert.manifest_path,
                symbols=symbols,
            )
            if graph and alert.ecosystem == "npm":
                evidence.graph_available = True
                evidence.transitive_dependents = transitive_dependents(
                    graph, alert.package_name, seeds
                )
            resolved = _resolved(alert)
            proposed, rationale = propose_label(
                resolved=resolved,
                patched=alert.patched_version,
                ecosystem=alert.ecosystem,
                dep_scope=(alert.scope_hint or "").lower() or None,
                symbols=symbols,
                evidence=evidence,
            )
            out.append(
                {
                    "case_id": (
                        f"{repo.split('/')[-1][:12]}-{alert.ghsa_id}-{_slug(alert.manifest_path)}"
                    ),
                    "repo": repo,
                    "ghsa_id": alert.ghsa_id,
                    "cve_id": alert.cve_id,
                    "ecosystem": alert.ecosystem,
                    "purl": purl,
                    "resolved_version": resolved,
                    "patched_version": alert.patched_version,
                    "manifest_path": alert.manifest_path,
                    "dep_scope": (alert.scope_hint or "").lower() or None,
                    "is_direct": None,
                    "cvss_score": alert.cvss_score,
                    "severity": alert.severity,
                    "symbols": symbols,
                    "imports_scanned": scanner_cache[alert.ecosystem],
                    # The fact that makes a clearance justified: what is in the artifact.
                    "shipped_packages": shipped if alert.ecosystem == "npm" else None,
                    "superseded_by": None,
                    **_evidence_facts(alert, root, gov_cache, dump_dir),
                    "_review": {
                        "evidence": evidence.to_dict(),
                        "symbols_known": bool(symbols),
                        "summary": (advisory.summary if advisory else "")[:200],
                        "proposed_label": proposed,
                        "rationale": rationale,
                    },
                }
            )
            if limit and len(out) >= limit:
                break
    finally:
        source.close()
    annotate_superseded(out)
    return out


def _module_dir(root: Path, manifest_path: str) -> Path:
    """The directory govulncheck should analyse for a Go manifest.

    A repository can hold several modules — airflow ships a Go SDK beside its Python — and
    analysing the root would answer a question about code the alert is not in. govulncheck
    is also whole-program, so running it once per module and caching by directory is the
    difference between one analysis and one per alert.
    """
    if not manifest_path:
        return root
    parent = (root / manifest_path).parent
    return parent if parent.is_dir() and parent != root else root


def _evidence_facts(
    alert: RawAlert,
    root: Path,
    gov_cache: dict[Path, dict[str, tuple[int, float, str]]],
    dump_dir: Path | None = None,
) -> dict[str, object]:
    """What the tooling measured for this alert, as the case's evidence facts.

    An unmeasured alert records nothing rather than a level of zero: a zero is a claim that
    the package is absent, and "the tool did not answer" is a different statement. The
    evaluator already distinguishes them, and feeding it a synthetic zero would manufacture
    a clearance that no tool produced.
    """
    if alert.ecosystem in {"go", "gomod"}:
        module = _module_dir(root, alert.manifest_path)
        if module not in gov_cache:
            gov_cache[module] = govulncheck_levels(module, dump_dir=dump_dir)
        levels = gov_cache[module]
        # Which module's analysis this is. govulncheck is whole-program, so "the vulnerable
        # symbol is called" is a statement about one module's build, not about the advisory.
        # The labeller needs the same key to avoid reading the main module's reachability
        # onto a submodule case where the symbol is never called.
        module_key = _dump_key(module)
        for identifier in (alert.ghsa_id, alert.cve_id):
            if identifier and identifier in levels:
                level, confidence, method = levels[identifier]
                return {
                    "reachability_level": level,
                    "reachability_confidence": confidence,
                    "reachability_method": method,
                    "_govulncheck_key": module_key,
                }
        # A Go alert govulncheck did not mention is an absence of measurement, not a
        # measurement of absence. Recording nothing is what makes the evaluator abstain.
        return {}
    adapter = get_adapter(alert.ecosystem)
    if adapter is None:
        return {}
    try:
        result = adapter.reachability(root, alert)
    except NotImplementedError:
        return {}
    except Exception:
        return {}
    if result.is_failure or result.confidence <= 0:
        return {}
    return {
        "reachability_level": int(result.level),
        "reachability_confidence": float(result.confidence),
        "reachability_method": result.method,
    }


def _lockfile_text(root: Path) -> str | None:
    candidate = root / "package-lock.json"
    if candidate.is_file():
        try:
            return candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    return None


def annotate_superseded(cases: list[dict[str, object]]) -> None:
    """Fill in `superseded_by` where a newer advisory covers the same package.

    Computed over the harvested set rather than the database so the label pipeline stays
    independent of the pipeline being measured. Without it the `superseded` rule never
    fires on the golden set, and a rule with no case cannot be gated.
    """
    groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for case in cases:
        groups.setdefault((str(case["purl"]), str(case["manifest_path"])), []).append(case)
    for group in groups.values():
        for case in group:
            mine = try_parse(case.get("patched_version"))  # type: ignore[arg-type]
            if mine is None:
                continue
            newer: list[tuple[object, str]] = []
            for other in group:
                if other is case or not other.get("ghsa_id"):
                    continue
                theirs = try_parse(other.get("patched_version"))  # type: ignore[arg-type]
                if theirs is not None and theirs > mine:
                    newer.append((theirs, str(other["ghsa_id"])))
            if newer:
                case["superseded_by"] = max(newer)[1]


def _purl(alert: RawAlert) -> str:
    eco = {"gomod": "go", "go": "golang", "pip": "pypi", "rust": "cargo"}.get(
        alert.ecosystem, alert.ecosystem
    )
    name = alert.package_name.replace(":", "/") if eco == "maven" else alert.package_name
    return f"pkg:{eco}/{name}"


def _resolved(alert: RawAlert) -> str | None:
    req = (alert.requirements or "").strip()
    if req.startswith("= "):
        return req[2:].strip()
    if req.startswith("="):
        return req[1:].strip()
    return None


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-") or "root"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    parser.add_argument("--label")
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dump-govulncheck", help="write the raw analyses here")
    args = parser.parse_args()

    cases = harvest(
        Path(args.path),
        label=args.label,
        limit=args.limit,
        dump_dir=Path(args.dump_govulncheck) if args.dump_govulncheck else None,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as handle:
        for case in cases:
            handle.write(json.dumps(case) + "\n")
    counts = Counter(c["_review"]["proposed_label"] for c in cases)
    print(f"{out}: {len(cases)} candidate(s) {dict(counts)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
