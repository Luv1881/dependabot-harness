# Validation against real open-source projects

The harness was run end to end against two large, unrelated projects — one Go, one
Python — neither of which the operator administers.

Dependabot's alert API needs admin scope on the target repository, so a project you do
not own cannot be triaged through it. The `scan-public` command derives the same alerts
from the committed manifests and OSV, yielding the identical `RawAlert` shape, so every
stage downstream of ingest is unchanged.

```bash
harness --config out/scan.yaml scan-public --repo prometheus/prometheus
harness --config out/scan.yaml scan-public --repo apache/airflow
```

Both runs cost **$0.00** in model spend: the deterministic half of the pipeline needs no
model at all.

### prometheus/prometheus

At commit `ab225f6ef5a8`. Coverage complete: **True**.

| Stage | Outcome |
|---|---|
| Discovery | 5 manifests, **537 dependencies** resolved, 0 unpinned skipped, 0 unchecked |
| Ingest | **48 advisories** matched, 48 ingested, 0 failed |
| Policy | 32 evaluated, **22 cleared deterministically (68.75%)**, 10 reaching analysis |
| Dedup | 4 clusters, **5 judgment invocations saved**; 45 all-pairs comparisons reduced to 25 |
| Evidence | 5 analysed, **0 toolchain failures**, shallow: none |
| Emit | 20 OpenVEX statements, 0 auto-dismissed, **20 dismissals blocked** |

Rules that cleared the backlog: `{"trivial_patch": 4, "superseded": 2, "not_imported": 16}`

| Advisory | Package | Version | Reachability | Confidence | Method |
|---|---|---|---|---|---|
| `GHSA-8rm2-7qqf-34qm` | `github.com/prometheus/prometheus` | v0.308.1 → 0.311.3 | 1 — present, never imported | 0.5 | `govulncheck` |
| `GHSA-fw8g-cg8f-9j28` | `github.com/prometheus/prometheus` | v0.308.1 → 0.311.3 | 1 — present, never imported | 0.5 | `govulncheck` |
| `GHSA-wg65-39gg-5wfj` | `github.com/prometheus/prometheus` | v0.308.1 → 0.311.3 | 1 — present, never imported | 0.5 | `govulncheck` |
| `GO-2026-5970` | `golang.org/x/text` | v0.38.0 → 0.39.0 | 1 — present, never imported | 0.9 | `govulncheck` |
| `GHSA-hrxh-6v49-42gf` | `google.golang.org/grpc` | v1.81.1 → 1.82.1 | 2 — imported, vulnerable symbol not referenced | 0.5 | `govulncheck` |

### apache/airflow

At commit `f5d7c8a0548a`. Coverage complete: **True**.

| Stage | Outcome |
|---|---|
| Discovery | 6 manifests, **102 dependencies** resolved, 1 unpinned skipped, 0 unchecked |
| Ingest | **9 advisories** matched, 9 ingested, 0 failed |
| Policy | 8 evaluated, **5 cleared deterministically (62.5%)**, 3 reaching analysis |
| Dedup | 0 clusters, **0 judgment invocations saved**; 3 all-pairs comparisons reduced to 3 |
| Evidence | 3 analysed, **0 toolchain failures**, shallow: none |
| Emit | 5 OpenVEX statements, 0 auto-dismissed, **5 dismissals blocked** |

Rules that cleared the backlog: `{"not_imported": 5}`

| Advisory | Package | Version | Reachability | Confidence | Method |
|---|---|---|---|---|---|
| `GHSA-2jv5-9r88-3w3p` | `fastapi` | 0.95.1 → 9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc | 2 — imported, vulnerable symbol not referenced | 0.5 | `ast` |
| `PYSEC-2024-161` | `pyarrow` | 14.0.1 → 801de2fbcf5bcbce0c019ed4b35ff3fc863b141b | 2 — imported, vulnerable symbol not referenced | 0.5 | `ast` |
| `GHSA-r374-rxx8-8654` | `paramiko` | 3.4.0 → None | 2 — imported, vulnerable symbol not referenced | 0.5 | `ast` |


## What these runs demonstrated

**Nothing was auto-dismissed.** Every dismissal was blocked, because the gate requires
explicit validator agreement and the agent stages were disabled. A missing validator is
not a passing validator.

**A missing toolchain was reported as a failure, not a clearance.** The first Prometheus
run was performed with `govulncheck` absent from `PATH`. Every alert came back
`method: "failed", confidence: 0.0`, the repository was flagged `shallow`, and all
dismissals were blocked. Adding `govulncheck` to `PATH` produced five real measurements.
That is the system's central invariant working on real data: it refused to say "safe"
when it meant "could not tell".

**The unknown-symbols cap is visible in the output.** Several advisories carry no
`ecosystem_specific.imports` symbol list. Where `govulncheck` located real call frames for
one of them, the call sites are retained as evidence but the level is held at 2 and
confidence at 0.5 — the evidence is kept, the claim is not made.

## Bugs these runs surfaced

Six defects that no synthetic fixture had caught:

1. **`git init` ran with a path relative to the wrong working directory**, so the staging
   checkout was created in the wrong place and every clone failed. Tests had always faked
   the checkout manager.
2. **The alert schema rejected OSV-native advisory identifiers.** Go advisories are
   frequently `GO-2026-5932` with no GHSA alias; the schema required `^GHSA-`, so 12 of 48
   real Prometheus advisories were discarded at ingest.
3. **CVSS vectors were never scored.** OSV records a vector far more often than a numeric
   score, and the score is what the severity thresholds and the `kev_direct_critical` rule
   compare against — so that rule could never fire on OSV data.
4. **Flagging a repository `shallow` overwrote the diagnostic** explaining why the
   toolchain produced nothing, leaving an operator knowing only that something went wrong.
5. **`shallow` fired on healthy repositories.** It treated "no reachability found" as a
   broken toolchain, but when advisories carry no symbol data the unknown-symbols cap
   holds every level at 2 by design and there was never anything to find. Both projects
   were wrongly flagged until the check learned to distinguish the two causes.
6. **A failed OSV batch read as an all-clear.** Dependencies in a batch that errored were
   silently dropped, so an outage would have looked like a clean repository. The scan now
   reports `coverage_complete: false` and names how many dependencies went unchecked.

The CVSS implementation is differential-tested against the `cvss` reference library over
all 3,888 vectors in the v3.1 base metric space.
