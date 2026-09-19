# Security hardening

A full audit of the harness against its own threat model. Every finding below is fixed and
pinned by a test; the test names are given so a regression is caught rather than
re-discovered. The first round is a review of the code. The second is what running it
against real repositories on a real provider turned up, which the review had not.

## Threat model

Two assets, two adversaries.

**Assets.** (1) The operator's GitHub credential and model API key. (2) The integrity of a
verdict — a `not_affected` that is wrong is a breach, not a bug.

**Adversary A: the scanned repository.** The harness clones and parses source, manifests
and lockfiles from repositories it does not administer (`scan-public`), and from within an
organisation it may not fully trust. Git faithfully materialises whatever symlinks a
repository contains. Manifests are arbitrary bytes with arbitrary nesting.

**Adversary B: the model.** The judgment agent reads repository content, so prompt
injection inside a README or a source comment is available to anyone who can commit to a
scanned repository. Model output is therefore untrusted input to the dismissal gate, and
model-supplied *tool arguments* are untrusted input to the tool surface.

## Findings

### 1. The agent's `grep` tool could read outside the checkout — critical

`Toolbox._grep` passed a model-controlled glob straight to `Path.rglob`. A glob of `../*`
walked out of the checkout and returned file contents to the model:

```
glob='../*.txt'  ->  '../outside.txt:1: SECRET_TOKEN=supersecretvalue'
```

Combined with adversary B this is a path from *commit a README containing an instruction*
to *read the operator's `~/.aws/credentials`*, with the result laundered back through the
verdict and into the emitted PR comment.

**Fixed by** confining the walk in `harness/fsutil.py`: a glob containing `..`, a leading
`~`, or an absolute prefix is refused outright rather than normalised, directory symlinks
are never descended into, and every candidate file is resolved and re-checked against the
checkout root before it is opened.

`tests/test_judgment.py::TestToolbox::test_grep_refuses_globs_that_leave_the_checkout`,
`::test_grep_does_not_follow_a_symlink_out_of_the_checkout`,
`::test_grep_does_not_descend_into_a_symlinked_directory`

### 2. Unbounded reads of hostile files — high

`_read_file`, `_grep` and the recon excerpt pass all read whole files. A repository
containing a 5 GB file is enough to exhaust memory before a single line is examined. The
recon pass truncated its *output* to 6 000 characters but still loaded the whole file.

**Fixed by** a 2 MB per-file cap and an 8 MB per-`grep`-call budget, on top of the
existing line and match caps.

`tests/test_judgment.py::TestToolbox::test_read_file_refuses_a_file_above_the_read_limit`,
`::test_grep_skips_a_file_above_the_read_limit`

### 3. The GitHub token was persisted to `.git/config` — high

`CheckoutManager._clone_url` embedded the token in the clone URL. Git writes the remote
URL to `staging/.git/config`, and the staging directory is then renamed into place — so
every cached checkout held a live credential in plaintext, readable by anything that could
read the checkout directory, outliving the process that created it. The redaction applied
to error output matched only the literal `x-access-token:` prefix in `stderr`.

**Fixed by** giving git a credential-free remote URL and supplying authentication
per-invocation via `-c http.extraHeader=Authorization: Basic …`, which `-c` applies to one
command and writes nowhere. `_redact` now removes the token value itself from any message
before it is raised or logged, so it cannot matter which shape git echoed it in.

`tests/test_checkout.py::TestCredentialsNeverReachTheDisk`,
`::TestErrorMessagesAreRedacted`

### 4. Argument and path injection through `repo` and `ref` — high

`repo` and `commit_sha` became both a filesystem path component and an element of a git
`argv`. A ref of `--upload-pack=…` was parsed by git as an option, and `repo="../.."`
escaped the checkout root. A first attempt at validation used a charset check, which
`owner/..` passes — the audit's own test caught that, and the check now refuses `.` and
`..` segments specifically.

**Fixed by** `config.valid_repo()` (shared by the config loader, the checkout manager and
`scan-public --repo`) plus a ref pattern that rejects a leading `-` and any `..` segment.

`tests/test_config.py::test_a_repo_name_that_is_not_owner_slash_name_is_rejected`,
`tests/test_checkout.py::TestArgumentValidation`

### 5. Permanent provider errors were retried as transient — high

`ModelClient.complete` wrapped *every* exception from a provider call as
`ResponseClass.TRANSIENT`. An unset API key, a key rejected with 401, and an SDK that was
not installed were each retried three times with backoff and then reported as
`RetryExhausted` — which names nothing, and buries the one fact the operator needs. This
is the same confusion of "we could not tell" with a diagnosis that the rest of the system
refuses to make.

**Fixed by** `ResponseClass.CONFIG`, `is_permanent_provider_error()` (matching SDK error
types by name so neither vendor package must be installed), a `retry_if` predicate on
`retry_with_backoff`, and `build_provider()` failing fast with the environment variable
named. `harness run` now preflights credentials *before* the first stage and exits 3 with
an actionable message.

`tests/test_models.py::TestPermanentProviderErrorsAreNotRetried`,
`tests/test_cli.py::TestPreflight`

### 6. Every checkout walk followed directory symlinks — medium-high

Four walks used `Path.rglob`, which follows a symlinked directory. A repository
containing `loop -> .` makes the policy, evidence and recon stages walk forever; a link to
`/` makes them walk the host.

**Fixed by** consolidating all of them onto `fsutil.iter_repo_files()`, which prunes
skipped directories, refuses directory symlinks, confines every yielded file to the root,
bounds recursion depth, and yields in lexicographic order so context assembly stays
reproducible.

`tests/test_fsutil.py`

### 7. Unreadable and oversized manifests vanished silently — medium

`discover_dependencies` `continue`d on an `OSError` and on any manifest above the size
limit, and a deeply nested `package-lock.json` raised `RecursionError` straight out of
`json.loads` — an exception type no adapter caught. In each case the dependency count
stayed at zero and `coverage_complete` stayed `True`, so a lockfile nobody had read was
reported as a lockfile with nothing wrong in it. The size limit is not theoretical: a
multi-megabyte lockfile is normal in a large monorepo.

**Fixed by** recording every skip as a coverage gap, which forces `coverage_complete` to
`False` and therefore blocks every dismissal for that scan.

`tests/test_osv_scan.py::TestDiscovery::test_an_oversized_manifest_is_a_recorded_gap_not_a_silent_skip`,
`::test_a_deeply_nested_manifest_is_a_gap_not_a_crash`

### 8. Non-version references were counted as checked — medium

`Dependency.is_pinned` accepted anything without `^~><*=|`. That admitted `latest`,
`file:../pkg`, `git+https://…`, `npm:other@1.0.0` and `2.x`. Those were sent to OSV, which
returns no advisories for a version it cannot resolve; the dependency was then counted as
`queried`, keeping `coverage_complete` at `True`. An unanswerable query was being recorded
as a clean answer.

**Fixed by** requiring a version to look like a version.

`tests/test_ecosystems.py::TestIsPinned`

### 9. A hostile manifest could abort ingest for the whole fleet — medium

`IngestStage._resolve_scope` called `adapter.resolve_scope` unguarded on manifest text
from a repository the operator does not control. `tomllib` and `json` both raise
`RecursionError` on a deeply nested document, which would take down the stage for every
repository in the run.

**Fixed by** degrading to an unknown scope with a warning. Unknown scope is the safe
direction — it makes the `dev_only` rule decline.

`tests/test_ingest.py::TestHostileManifest`

### 10. `file_text` interpolated a caller-supplied path into a credentialed URL — low-medium

A `..` segment or a query character in `vulnerableManifestPath` retargeted the API request
made with the operator's token, and a space produced a malformed URL.

**Fixed by** refusing traversal and percent-encoding each segment.

`tests/test_github.py`

### 11. A corrupt cache entry crashed the run — low-medium

`JsonCache.get` indexed `entry["fetched_at"]` directly, so a truncated or hand-edited
cache file raised `KeyError` out of ingest.

**Fixed by** treating any malformed entry as a miss.

`tests/test_cache.py::TestMalformedEntriesAreMisses`

### 12. PURL parsing was duplicated and version-blind — low-medium, latent

`rules._package_name` and `python._package_from_purl` were two implementations of the same
thing, and neither stripped a version, qualifier or subpath. Today's `_purl` emits no
version, so nothing was broken — but a purl carrying `@1.2.3` would produce a coordinate
that matches no import, and `not_imported` reads "matches no import" as "never imported".
That path ends in a false `not_affected`. A leading `@` is an npm scope, not a version
separator, which is exactly the case a naive `split("@")` gets wrong.

**Fixed by** one `util.purl_package_name()` that strips version, qualifier and subpath,
preserves a scope, and returns empty for a malformed purl so the rule declines instead of
clearing.

`tests/test_util.py::TestPurlPackageName`

### 13. Resource and error-handling gaps — low

`harness run` constructed a `GithubClient` per invocation and never closed it, and
`main()` caught only `ConfigError`, so every other failure surfaced as a raw traceback.
`git` was the one subprocess with no timeout, so a hung `fetch` hung the run. Concurrent
runs cloning the same SHA shared one staging directory.

**Fixed by** closing the client in a `finally`, catching provider-configuration failures
with a non-zero exit, adding a timeout to `_git`, and giving each clone a unique staging
directory that is discarded if another run wins the race.

`tests/test_checkout.py::TestFailureSemantics`

## What the audit confirmed as already sound

Not every suspicion was a defect. These were checked and held:

- **SQL is parameterised throughout.** The only two f-string statements in `db.py` are
  `PRAGMA table_info` / `ALTER TABLE` in the forward-migration path, over a hardcoded
  table and column name.
- **No `shell=True`, `os.system`, `eval`, `exec`, `pickle` or `yaml.load`** anywhere in
  `harness/`. `yaml.safe_load` is used for config, `tomllib` and `json` for manifests.
  The single `__import__` in the tree is a string in a detection set, not a call.
- **`xml.etree` is not vulnerable to entity expansion here.** A billion-laughs document
  twelve levels deep parses in constant memory (the expansion would be 10¹² characters if
  it were expanded) and external entities are refused. Tested directly rather than
  assumed from the Python version.
- **Import-scanner regexes are free of nested quantifiers**, so there is no catastrophic
  backtracking on hostile source.
- **Cache keys are hashed**, never used as filenames, so an advisory id supplied by the
  model cannot choose where a write lands.
- **The dismissal gate fails closed.** Every clause is conjunctive, a missing
  `auto_dismiss_requires` key refuses rather than passing, and incomplete advisory
  coverage blocks every dismissal for the scan.
- **A failed toolchain is never a clearance.** `ReachabilityResult.failed` carries
  `confidence: 0.0` and `method: "failed"`, `EvidenceStage._reachability` converts any
  adapter exception into that, and `clamp` cannot raise confidence out of it.

## Single-model deployments

A deployment with one credential and one model is supported deliberately, and is the
config shipped in `config/deepseek.yaml`.

§7 requires that the stage confirming a verdict is not the stage that produced it. A
configuration that points judgment and validation at the same `(provider, model)` is
refused at startup — a reviewer sharing a base model with the author shares its blind
spots, and calling that independent review is worse than having none. The honest
alternative is to **omit** the validator slot rather than duplicate it, and
`assert_model_divergence` treats an absent validator as that case, not as a violation.

What changes when no validator is configured:

- The **mechanical checks still run in full.** Schema, CISA justification code,
  confidence ceiling, reachability contradiction and citation existence are pure code
  and do not depend on a second model.
- **Nothing is ever marked confirmed.** `validated` is written as `NULL`, which the
  dismissal gate treats as unconfirmed rather than as agreement.
- **Every dismissal is blocked.** `auto_dismiss_requires.validator_agreed: true` cannot
  be satisfied, so no alert is closed. Verdicts are advisory.
- The run is **reported as such**: the validation report counts the alerts under
  `validator_unavailable`, puts them in the human queue, and the stage logs why.

This is the safe direction. The failure this design guards against is a verdict nobody
checked being read as a verdict somebody checked, and an absent validator cannot be
mistaken for a passing one.

`harness models` exists for the same reason: a tier name is marketing and the identifier
is what the API accepts, so the provider is asked directly rather than guessed at.

## Round two — found by running it

Everything below surfaced from actually executing the pipeline against real repositories on a
real provider, not from reading it. Each was invisible to the test suite, and each is now
pinned by a test that would have caught it.

### 14. `--agents off` demanded a model credential — high

The documented free path. `DedupStage.__init__` built its `ModelClient` regardless of
`use_agent`, so with a config naming a provider that requires a key, even the fully
deterministic scan exited 3 asking for one it would never use. A stage that is switched off
must not construct the thing it is switched off from.
`tests/test_dedup.py::TestDisabledAgentStageNeedsNoCredential`

### 15. npm `lockfileVersion: 1` produced zero dependencies and complete coverage — high

`NpmAdapter.parse_dependencies` read only the modern flat `packages` map. Version 1
lockfiles — npm 6 and earlier, and plenty of repositories still — nest dependencies by
install path, so the parse silently returned nothing. The scan then reported **no
dependencies, no advisories, `coverage_complete: true`** over a lockfile holding a
known-vulnerable `lodash`. Found by scanning `dependabot/demo`, and the worst kind of
defect this audit turned up: a false all-clear, produced quietly.

Fixed by reading both shapes, deduplicating on `(name, version)` so multiple legitimate
versions of one package survive, and refusing a file that parses as JSON but matches
neither shape rather than calling it empty.
`tests/test_ecosystems.py::TestNpmLockfileShapes`,
`tests/test_osv_scan.py::TestDiscovery::test_a_v1_lockfile_now_yields_its_dependencies`

### 16. An unpriced model silently disarmed every budget cap — high

`price()` returns `0.0` for a model outside its table, so the ledger summed zeros and
`BudgetLedger.check` could never observe a threshold. `is_priced()` existed and was never
called. A run of 36 paid DeepSeek calls reported `spend_usd: $0.000000` — "unknown"
recorded as "free", which is the exact confusion the rest of the system refuses to make.

Fixed three ways: rates can be declared per role (`models.<role>.pricing`), a half-declared
price is refused at startup, and every call is ledgered with a `priced` flag so the run
reports `unpriced_calls` and `spend_is_complete: false` rather than a confident zero.
Startup warns by name when a configured model has no rates.
`tests/test_models.py::TestPricingIsNotOptional`

### 17. The OpenAI-compatible path could not carry tools, and mis-read truncation — high

Two independent defects, both found by pointing the harness at DeepSeek:

- `finish_reason` was passed through untranslated. OpenAI-shaped vendors report `length`
  for a truncated completion; `classify` reads `max_tokens`. The truncated-and-retried path
  therefore never fired on these providers and a clipped response was classified complete.
- `request.tools` was ignored entirely and history was forwarded in Anthropic content-block
  form, so the judgment agent received **no tool surface at all** and ran blind on every
  OpenAI-compatible provider.

Fixed by translating the stop-reason vocabulary at the provider boundary, translating tool
declarations and the tool round-trip into OpenAI's wire format, and parsing tool calls back
into the neutral block shape so the agent loop is unchanged. Verified live: the model drove
`grep` through the real toolbox, and the audit trail recorded each call.
`tests/test_models.py::TestOpenAiStopReasonVocabulary`, `::TestToolCallTranslation`

### 18. An empty `.env` value was refused as an unbalanced quote — low

`value[:1] in "\"'"` — an empty slice is a substring of every string, so `A=` raised.
Found by a test written for the feature itself.
`tests/test_env_file.py::TestParsing::test_values_are_unwrapped`

## Additions

**`scan-local`.** `scan-public` fetches from GitHub, which needs a credential and a network.
A private mirror, an air-gapped runner, a reviewer checking a colleague's branch, and the
harness's own end-to-end tests all have the code locally already. It reads the tree, derives
`structure_hash` with the same invalidation semantics as the API-backed version, refuses to
evict the operator's directory, and needs no GitHub credential. `tests/test_scan_local.py`

**`--env-file`.** The shell incantation for exporting a dotenv file is not portable; under
fish `set -a; . ./.env; set +a` is three separate errors. The file is now read directly,
explicitly, and never implicitly — existing environment variables win, and a missing
variable that a `./.env` defines produces a hint naming the flag. `tests/test_env_file.py`

**`harness models`.** A tier name is marketing and the identifier is what the API accepts.
This asks the provider's own listing endpoint (no SDK, no GitHub token) and reports a
rejected key as a rejected key rather than as an empty catalogue. It immediately resolved
`deepseek-flash`, which no amount of reading the source would have revealed.
`tests/test_catalogue.py`

## End-to-end runs against real repositories

All three at $0.00 model spend unless noted.

| Repository | Dependencies | Advisories | Cleared | Decided affected | Outcome |
|---|---:|---:|---:|---:|---|
| `dependabot/demo` (npm **v1** lockfile) | 6 | 6 | 100% | 0% | 6 statements, 6 dismissals blocked |
| `snyk-labs/nodejs-goof` (npm v2) | 980 | **294** | 74.8% | 16.3% | 18 evidence failures, repo `shallow`, 268 dismissals blocked |
| `apache/airflow` (Python, 306 MB tree) | 102 | 27 | 29.4% | 29.4% | 5 judged on `deepseek-flash`, 2 mechanically rejected, 17 dismissals blocked |

Airflow was also run with the agent stages **on** for 36 DeepSeek calls. Three things worth
recording:

- `validation` reported `mechanically_rejected: 2` — the deterministic checks rejected two of
  the model's verdicts before any reviewer saw them. That layer earning its keep on real
  output is the point of having it.
- Every verdict came back `validated: NULL`, and **all 13 dismissals were blocked** because no
  validator is configured. A single-model deployment cannot close an alert, by design.
- `snyk-labs/nodejs-goof` demonstrates the central invariant at scale: npm reachability is not
  implemented, so all 18 measurements are `method: failed, confidence: 0.0, level: 0` — a
  failure, never a low reachability — the repo is flagged `shallow`, and nothing is dismissed.
  "We could not tell" survived contact with 293 real advisories.

## Round three — the results were wrong

The two previous rounds were about the harness doing unsafe things. This one is about it
*reporting* things it had not done, which I only found by going back over the numbers I had
already published rather than by reading the code.

### 19. `superseded` removed alerts from every output while counting them as cleared — high

The `superseded` rule emitted `kind: dedup` with no verdict, reasoning that a dedup cluster
would carry a decision to the alert. No cluster ever held these alerts: clusters are keyed
on `(ghsa_id, purl, major, patched_version)` and this rule matches on a *different* advisory
for the same package, so there was no canonical member to inherit from.

Measured on real repositories:

| run | `superseded` alerts | verdict | VEX statement |
|---|---:|---:|---:|
| `snyk-labs/nodejs-goof` | 132 | 0 | 0 |
| `apache/airflow` (agents off) | 4 | 0 | 0 |
| `apache/airflow` (agents **on**) | 4 | 0 | 0 |

They were counted in the "cleared" percentage while producing no verdict, no OpenVEX
statement, no SARIF finding, no PR comment and no dismissal. In a real Dependabot workflow
those alerts stay open forever and the report says they were handled.

The engine's own validator already refused a non-`dedup` outcome with no verdict because it
"would bury the alert without deciding it" — `dedup` was the exemption, and this rule used
the exemption without honouring its precondition. **`dedup` is now refused outright for a
policy rule**, and `superseded` emits `affected` instead: the installed version is inside the
advisory's range, and a single upgrade remediates it. That is a real decision, a real VEX
statement, and no reachability claim that was never measured.

`tests/test_policy.py::TestSuperseded`,
`tests/test_policy_stage.py::TestStageWiring::test_superseded_alert_is_decided_and_written`,
`tests/test_policy.py::TestVerdictShapeValidation::test_dedup_outcome_is_refused`

### 20. Policy verdicts bypassed the ecosystem confidence ceiling — high

`policy._verdict_document` hardcoded `confidence: 1.0`, and the ceiling check lives in the
validation stage — which a policy-cleared alert never reaches, because validation requires
a completed judgment. So the ceiling was enforced on the expensive path and ignored on the
cheap, high-volume, deterministic one.

On `snyk-labs/nodejs-goof` that produced **135 `not_affected` verdicts at confidence 1.0
against a declared npm ceiling of 0.55** — nearly double, and comfortably over an
`auto_dismiss_requires.confidence_min` of 0.85. `CLAUDE.md` states the invariant directly:
*npm/TS (ceiling = 0.55) must never produce a high-confidence `not_affected`.* It did, 135
times.

Confidence for a policy verdict is now computed by `policy.policy_confidence()`, clamped to
the adapter's ceiling, with a deliberately low default for an ecosystem that has no adapter.
`tests/test_policy_stage.py::TestConfidenceIsHeldToTheEcosystemCeiling`

### 21. "Cleared by deterministic rules" counted decisions that clear nothing — medium

`ClearanceStats.cleared` was `sum(by_rule.values())` — every terminating rule, including
`trivial_patch` and `kev_direct_critical`, both of which emit `affected` and leave the
dependency needing an upgrade. The headline metric in the README ("68.75% cleared
deterministically") was therefore partly counting alerts that still require action.

Stats now separate `terminated`, `cleared` (a non-`affected` verdict) and `decided_affected`.
On the npm repository the honest figures are 74.8% cleared and 16.3% decided affected, not
the 91.1% previously reported.

### 22. Rule order let consolidation precede escalation — medium

`superseded` ran second, before `kev_direct_critical`, `dev_only` and `not_imported`. So a
known-exploited direct critical dependency with a newer sibling advisory was consolidated
instead of escalated, and a package nothing imports was given a per-advisory note instead of
the package-level clearance that is valid for every advisory on it at once.

The order is now: CVE-level facts needing no analysis, then escalations, then package-level
facts, then per-advisory consolidation, then remediation size. Reordering alone moved 85
alerts on the npm repository from `superseded` to the sounder `not_imported`.
`tests/test_policy_stage.py::TestRuleOrdering`

### 23. Nothing reconciled alerts against outputs — medium

No stage checked that every ingested alert ended up in an emitted artefact, which is why 19
could hide. `EmitStage` now separates the two states that look identical from the outside:
an alert still awaiting analysis (expected) and an alert a rule terminated without deciding
(impossible after this round). The second is counted as `unexplained`, logged at error
level, and surfaced in the report. An alert can no longer disappear silently.
`tests/test_emit.py::TestEveryAlertIsAccountedFor`

### 24. The eval set had no case for the rule that caused it — medium

`build_seed_set.py` never sets `superseded_by`, so no golden case ever triggered the rule.
The change that buried 132 real alerts was scored by the eval suite and passed without
comment. A coverage guard now runs every configured rule over the golden set and fails when
a rule is neither exercised nor explicitly listed as uncovered with a reason; `superseded`
is the one entry, because its output is a remediation decision and the set's
reachable/not-reachable labels do not describe it.
`tests/test_evaluation.py::TestEveryRuleIsExercised`

## Corrected end-to-end results

The numbers previously reported in this document for `snyk-labs/nodejs-goof` were wrong in
two directions at once: the clearance rate was inflated, and the emitted artefacts were much
smaller than they should have been. Measured on a clean database:

| | before | after |
|---|---:|---:|
| advisories | 293 | 294 |
| claimed cleared | 91.1% | **74.8%** |
| decided `affected` | not reported | 16.3% |
| terminated by a rule | 267 | 268 |
| VEX statements emitted | 135 | **268** |
| alerts that vanished | **132** | **0** |

`dependabot/demo` likewise went from 3 emitted statements to 6.

## Round four — what the labelled set then found

Round three ended with the admission that the eval set was synthetic and the gates were
comparing synthetic to synthetic. Building a real one immediately paid for itself.

### 25. Go standard-library advisories were invisible to discovery — high

Stdlib advisories are keyed to the toolchain version, and nothing in a `require` block
mentions the standard library — so a discovery pass that reads `go.mod`'s requires could
not see any of them. On prometheus, **7 of the 9 advisories govulncheck found a live call
path for were stdlib**, and every one was invisible.

`GoAdapter.parse_dependencies` now emits the toolchain's `stdlib` as a dependency, read
from `toolchain` or the `go` directive. Prometheus pins `go 1.25.8`, so the version is
exact; a bare `1.25` is used verbatim rather than padded, because OSV cannot match a
version it does not know and an unmatched version is indistinguishable from no advisories.

The same change would have created a *new* false negative: nothing "imports stdlib", so
`not_imported` would have cleared stdlib advisories as `vulnerable_code_not_present`.
`go_shipped` therefore always includes the standard library, because it is the one thing
unconditionally linked into the artifact.

Measured on prometheus:

| | before | after |
|---|---:|---:|
| dependencies | 537 | 542 |
| advisories | 87 | **217** |
| evidence toolchain failures | 10 | 4 |
| repo flagged `shallow` | True | **False** |

`tests/test_ecosystems.py::TestGoStdlibIsDiscovered`,
`tests/test_checkout.py::TestTheStandardLibraryAlwaysShips`

### 26. Evidence levels from govulncheck understated proven call paths — medium

The label pipeline recorded a function-bearing govulncheck finding as
`SYMBOL_REFERENCED` (3) when the adapter correctly calls it `PATH_FROM_ENTRY` (4).
govulncheck only reports call paths it can trace from a program entry point, so a function
frame *is* such a path. At level 3 the evaluator abstains, so every Go case abstained.
`tests/test_evaluation.py`, `eval/harvest.py`

### 27. Budget caps were inert on any unpriced model — high (closes round-three gap)

A dollar cap is only as good as the price list behind it, and an unpriced call contributes
zero to the ledger, so a threshold on the dollar total is never reached. Token caps are now
declared alongside the dollar caps and enforced at the same three scopes. Tokens are always
known, so they are the cap that holds when pricing cannot.

`tests/test_models.py::TestTokenCapsHoldWhenPricingCannot`

## Gating

The eval set gates the two rule changes in this audit (`is_pinned`, `purl_package_name`),
as it gates every rule change. Baseline and post-audit numbers are identical:

| Metric | Baseline | After |
|---|---:|---:|
| False-negative rate | 0.00% | **0.00%** |
| Abstention on reachable | 14.29% | **14.29%** |
| False-positive rate | 23.68% | 23.68% |
| Could-not-determine rate | 8.05% | 8.05% |
| Precision / recall | 0.82 / 0.86 | 0.82 / 0.86 |

`run_eval.py --baseline` reports `accepted: true`. The set is still synthetic; the M4
accept gate remains unsatisfied for that reason and no other.
