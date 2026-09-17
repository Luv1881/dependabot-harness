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

| Repository | Dependencies | Advisories | Cleared by rules | Outcome |
|---|---:|---:|---:|---|
| `dependabot/demo` (npm **v1** lockfile) | 6 | 6 | 100% | 3 statements, 3 dismissals blocked |
| `snyk-labs/nodejs-goof` (npm v2) | 980 | **293** | 91.1% | 18 evidence failures, repo `shallow`, 135 dismissals blocked |
| `apache/airflow` (Python, 306 MB tree) | 102 | 27 | 58.8% | 5 judged on `deepseek-flash`, 2 mechanically rejected, 13 dismissals blocked |

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
