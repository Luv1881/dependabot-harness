# Validation against a real open-source project

The harness was run end to end against [prometheus/prometheus](https://github.com/prometheus/prometheus)
at commit `ab225f6ef5a8`.

Dependabot's alert API needs admin scope on the target repository, so a project you do not
own cannot be triaged through it. The `scan-public` command derives the same alerts from
the committed manifests and OSV, and yields the identical `RawAlert` shape — every stage
downstream of ingest is unchanged.

```bash
harness --config out/scan.yaml scan-public --repo prometheus/prometheus
```

## Results

| Stage | Outcome |
|---|---|
| Discovery | 5 manifests, **537 dependencies** resolved, 0 unpinned skipped |
| Ingest | **48 advisories** matched, 48 ingested, 0 failed |
| Policy | 32 evaluated, **22 cleared deterministically (68.75%)**, 10 reaching analysis |
| Dedup | 4 clusters, **5 judgment invocations saved**; 45 all-pairs comparisons reduced to 25 |
| Evidence | 5 analysed by `govulncheck v1.6.0`, **0 toolchain failures** |
| Emit | 20 OpenVEX statements, 0 auto-dismissed, **20 dismissals blocked by the gate** |

Total model spend: **$0.0** — the deterministic half of the pipeline needs no
model at all.

### Which rules cleared the backlog

{
  "trivial_patch": 4,
  "superseded": 2,
  "not_imported": 16
}

`not_imported` did the heavy lifting: 16 of 32 alerts were for packages that appear
nowhere in any import statement in the repository.

### Reachability actually measured

| Advisory | Package | Version | Level | Confidence |
|---|---|---|---|---|
| `GHSA-8rm2-7qqf-34qm` | `github.com/prometheus/prometheus` | v0.308.1 → 0.311.3 | 1 — present, never imported | 0.5 |
| `GHSA-fw8g-cg8f-9j28` | `github.com/prometheus/prometheus` | v0.308.1 → 0.311.3 | 1 — present, never imported | 0.5 |
| `GHSA-wg65-39gg-5wfj` | `github.com/prometheus/prometheus` | v0.308.1 → 0.311.3 | 1 — present, never imported | 0.5 |
| `GO-2026-5970` | `golang.org/x/text` | v0.38.0 → 0.39.0 | 1 — present, never imported | 0.9 |
| `GHSA-hrxh-6v49-42gf` | `google.golang.org/grpc` | v1.81.1 → 1.82.1 | 2 — imported, vulnerable symbol not referenced | 0.5 |

The `grpc` entry is the interesting one. `govulncheck` located real call frames
(`internal/transport/client_stream.go:80`, reached from `tsdb/wlog.Read`), but the
advisory carries no `ecosystem_specific.imports` symbol list — so the level is capped at 2
and confidence at 0.5 rather than being reported as a proven call path. The call sites are
retained as evidence; the *claim* is not made. That cap is the rule described in the
README as "an advisory with no symbol data caps level at 2 and confidence at 0.5".

## What this run demonstrated

**Nothing was auto-dismissed.** All 20 dismissals were blocked, because the gate requires
validator agreement and the agent stages were disabled for this run. A missing validator
is not a passing validator.

**A missing toolchain was reported as a failure, not a clearance.** The first run was
performed with `govulncheck` absent from `PATH`. Every alert came back
`method: "failed", confidence: 0.0`, the repository was flagged `shallow`, and all
dismissals were blocked. Adding `govulncheck` to `PATH` and re-running produced
5 real measurements and cleared the shallow flag. That is the system's
central invariant working on real data: it refused to say "safe" when it meant
"could not tell".

## Bugs this run surfaced

Three defects that no synthetic fixture had caught:

1. **`git init` ran with a path relative to the wrong working directory**, so the staging
   checkout was created in the wrong place and every clone failed. Tests had always faked
   the checkout manager.
2. **The alert schema rejected OSV-native advisory identifiers.** Go advisories are
   frequently `GO-2026-5932` with no GHSA alias; the schema required `^GHSA-`, so 12 of 48
   real advisories were discarded at ingest.
3. **CVSS vectors were never scored.** OSV records a vector far more often than a numeric
   score, and the score is what the severity thresholds and the `kev_direct_critical` rule
   compare against — so that rule could never fire on OSV data. `harness/cvss.py` now
   derives the v3.1 base score from the vector.

A fourth was found in the same run: flagging a repository `shallow` overwrote the
diagnostic explaining *why* the toolchain produced nothing, leaving an operator knowing
only that something had gone wrong.
