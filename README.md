# Dependabot Triage & Recon Harness

Consumes vulnerability alerts across a fleet of repositories and produces, for each one, a
defensible verdict:

> *Is this vulnerability actually reachable and exploitable in this codebase, in
> production, right now — and what is the evidence?*

Output is a machine-readable OpenVEX statement plus a human-readable rationale, pushed
back as a SARIF finding, a PR comment, or a gated auto-dismissal.

## What it does not do

- **No vulnerability discovery.** Dependabot (or OSV) is the discovery engine. The
  harness never hunts for novel bugs.
- **No exploit generation, no PoC, no fuzzing, no sandbox execution.**
- **No automated fixing.** It may *recommend* a version bump. It never opens a fix PR or
  edits source.
- **No test execution of the target repo.**

## The governing principle

**"We could not tell" and "it is safe" are different answers, and the system never
collapses one into the other.**

A toolchain that fails to run reports `confidence: 0.0, method: "failed"` — never a low
reachability level. An unreadable manifest yields `unknown` scope, not `runtime`. An
advisory the scanner never evaluated is not a clearance. An unverifiable dismissal is
rejected while an unverifiable escalation is allowed through, because an unverified
escalation costs an afternoon and an unverified dismissal costs a breach.

`not_affected` and `could_not_determine` are distinct verdicts and are never merged.

## Pipeline

| Stage | Kind | What it does |
|---|---|---|
| 1 Ingest | deterministic | Alerts + OSV symbols + EPSS + KEV; manifest-resolved scope |
| 2 Policy | deterministic | Six rules that terminate an alert before any model runs |
| 3 Dedup | index + agent | Inverted index shortlist, then one narrow question |
| 4 Recon | agent | Repo architecture, cached per `structure_hash` |
| 5 Evidence | deterministic | Real SCA tooling (`govulncheck`, `osv-scanner`) |
| 6 Judgment | agent | Bounded tool loop, schema-constrained verdict |
| 7 Validation | checks + agent | Mechanical rejection, then an adversarial pass |
| 8 Emit | deterministic | OpenVEX, SARIF, PR comment, gated dismissal |

Deterministic code does everything it possibly can. A model is invoked only where
judgment is genuinely required.

## Design constraints

- **State is external.** Every stage writes to SQLite before returning. A crash costs the
  in-flight task and nothing else; `resume --run-id` redoes no completed stage.
- **Context ceiling: 25%.** No agent invocation exceeds a quarter of the model's context
  window. Context is assembled deterministically — agents never "read all the files".
- **Nothing grades its own homework.** The validator runs on a different model, enforced
  at startup, and its response schema has `additionalProperties: false` with only three
  fields, so it has no structural ability to file a finding of its own.
- **Budget per repo, not per run.** One pathological repository cannot consume the fleet
  budget.
- **Models are interchangeable.** All provider access goes through `harness/models/client.py`.
  No provider SDK type escapes that boundary.

## Ecosystem support

| Ecosystem | Tooling | Confidence ceiling |
|---|---|---|
| Go | `govulncheck` (SSA + VTA, symbol-level) | 0.95 |
| Python | `osv-scanner --call-analysis=all` + `ast` pass | 0.75 |
| Rust / Java / npm | scope resolution only | 0.90 / 0.70 / 0.55 |

Ceilings are enforced centrally, so an adapter cannot exceed its own limit. npm is
deliberately last: dynamic import, monkey-patching and bundling make it the least
reliable ecosystem, and it must never produce a high-confidence `not_affected`.

## Usage

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"

export GH_TOKEN=...                      # or GH_APP_ID + GH_INSTALLATION_ID + GH_PRIVATE_KEY_PATH
export ANTHROPIC_API_KEY=...             # only needed for the agent stages

harness run                              # full pipeline over config/harness.yaml
harness resume --run-id <id>             # continue, redoing nothing completed
harness report                           # metrics for the latest run
```

### Scanning a public repository without Dependabot access

Dependabot's alert API needs admin scope on the target repository. To triage a project you
do not own, point the harness at OSV instead — same advisory data, any public repo:

```bash
harness scan-public --repo golang/go --ref master
```

## Evaluation

The eval harness gates every prompt, rule and threshold change.

```bash
python eval/build_seed_set.py            # synthetic bootstrap set
python eval/run_eval.py                  # exits 2 unless the set is hand-labeled
```

**False-negative rate is the metric that matters most** — wrongly dismissing a live
vulnerability is worse than having no tool at all. A change that improves cost while
raising FN rate is rejected outright.

It is also not enough on its own: a pipeline can drive its FN rate to zero by answering
`could_not_determine` everywhere. `abstention_on_reachable_rate` measures exactly that,
and the gate rejects any change that raises it. Reports carry a dataset fingerprint so
two runs over different case sets cannot be compared into a false improvement.

20% of the set is held out. `run_eval.py` will not score it without an explicit
`--holdout` flag, and warns when it does.

## Verified against real tooling

Two accept gates were checked against the actual tools rather than mocks:

- **Evidence** — parsed against real `govulncheck v1.6.0` output from a module that calls
  a vulnerable symbol. Fixture: `tests/fixtures/govulncheck_real.json`.
- **Emit** — a real `grype` run consumed a VEX document produced by this harness and
  suppressed exactly the finding marked `not_affected`, leaving the other three reported.
  Fixtures: `tests/fixtures/grype_*.json`.

## Development

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check harness tests eval
.venv/bin/python -m mypy harness
```

Python 3.11+. Type hints throughout, `ruff` and `mypy --strict` clean. The codebase uses
docstrings rather than inline comments.
