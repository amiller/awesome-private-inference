# Reference change review workflow

Every job reviews one immutable event. The job decides what the evidence establishes and what remains unknown; it does not authorize new reference values.

## Run the instrument

Use Python 3.11+ with the locked environment (`uv sync --frozen --extra nearai --extra dev`). Keep one environment per active rehearsal. Heavy builds and image reproduction belong on zed. `NEARAI_VERIFIER_PATH` must point to the pinned verifier revision in `data/instrument.json`, not an arbitrary moving checkout.

Daily, run `python -m probes.collect`, then `python -m probes.references`, `python -m probes.quality --write`, and `python -m probes.render`. The run records exact adapter/collector source and lockfile hashes as its instrument revision; unchanged upstream NEAR code cannot hide local adapter changes. The collector refuses a NEAR checkout that does not match the pin. Weekly, add `python -m probes.references --catalogs`. Catalog discovery records model IDs and route metadata independently from the stable daily sentinel sample. A changed catalog must be reviewed before changing the sample; absence alone is not retirement.

Collection writes immutable runs and route attempts before probing. Results, publication bytes and change events are retained. `latest.json` is a derived view; a partial run retains the other routes with their original timestamps. The first daily snapshot is retained on same-day reruns. `python -m probes.collect --backfill` optionally imports historical snapshots as legacy evidence; this does not retroactively validate their claims.

Commit observation records, continuity events, publication captures and the generated view together. If collection terminates, retain its pending attempts and report that incompleteness. Never overwrite or silently delete an earlier observation to make a rerun look successful.

## Dispatch and completion

Run the watcher and the worker under the same account and filesystem. The default queue is `local-data/review-queue/`, ignored by git; it includes lease tokens. Never publish that directory. Existing `devproof-watch.state.json` acknowledgments belong to the retired detector and do not establish review completion.

```
python -m probes.review_queue ingest
python -m probes.review_worker --dry
python -m probes.review_worker
```

`--dry` ingests pending events and displays status but does not launch a worker. The watcher optionally fast-forwards a clean checkout and refuses to discard modifications. For a working branch use `DEVPROOF_PULL=0`. Set `DEVPROOF_PYTHON` only when reusing an existing environment. An explicit `DEVPROOF_PASEO_HOST` is supported; its worker must be able to access the checkout, Python executable and queue paths.

Jobs progress from queued to running under a lease, then draft_ready, reviewed and published. A worker crash expires its lease. The next dispatch retries it with a new token; the old worker cannot submit. A failed launch remains retryable, with a bounded three-attempt budget before supervisor intervention. A blocked job needs an explicit reason and requeue decision. The dispatch is one job per watcher invocation, limiting spend and parallel resource contention.

The packet names exact old/new observations and affected routes. The worker must produce the required draft schema and submit it using the lease in that packet. A prose response, shell exit or successful Paseo launch does not finish the job. A submitted draft must include:

- Summary, event ID and classification.
- Exact evidence paths or URLs and checks actually performed.
- Plaintext-boundary and client-acceptance-policy impact.
- Uncertainties and a concrete next action.

Classifications are continuity, substantive, regression, needs_evidence, coverage and policy_change. Dependency and build changes are not automatically continuity. Missing source-to-live-artifact mapping requires needs_evidence.

A distinct reviewer checks the strongest claim and the missing links:

```
python -m probes.review_queue review --event EVENT_ID --reviewer REVIEWER \
  --disposition needs_evidence --rationale 'State exactly what remains unresolved'
python -m probes.review_queue publish --event EVENT_ID
```

Publication writes an immutable review disposition under `data/reviews/decisions/`; it never updates accepted-reference ledgers. A rejected or needs_evidence conclusion can be published. Correct a publication with a new event/review, preserving history.

Reviewer names are audit labels, not authenticated identities. This local queue enforces ordering and prevents accidental same-name approval; it is not an authorization boundary against a worker with filesystem access. Draft validation checks structure, not whether cited artifacts support the claims. The supervisor must inspect the evidence before reviewing and committing a disposition. Workers use the normal Paseo permission mode. Unattended publication requires a separate account or approval service that workers cannot write to; it is not enabled here.

## Watch the watcher

The watcher writes a sanitized `status.json` in its queue directory after dispatch. Run the following under an independent scheduler, not only after successful collection:

```
python -m probes.health --queue-status local-data/review-queue/status.json
```

This checks collection age, per-route attempt age, reference-capture failures and age (daily policies, weekly catalogs), mirror disagreement, queue-heartbeat age and expired leases. GitHub's separate freshness workflow checks collection even when the probe workflow stops. It does not establish zed health; deploy a separate external check of zed's sanitized status to detect total host failure. No external chat/email notification is sent by these scripts.

## Acceptance and ownership

The supervisor owns priorities and independent dispositions. Sol owns one bounded evidence review at a time. Provider onboarding needs a route inventory, reference-policy source, plaintext graph, live proof where available and negative controls. Captured publication bytes alone remain publication-only evidence.

Prioritize binding failure, new plaintext access, unauthorized/retired accepted values, active unexplained builds, lost coverage, then historical unused identities. Shared-component changes affect every dependent route. Daily freshness and 30-day capture reliability must be measured after rollout; a green test suite is not that production evidence.

Candidate blockers are recorded in `data/candidates.json` and route cards. A missing account, reproducible build or compatible cryptographic verifier is an explicit unresolved gate. Do not purchase access, accept new trust roots, weaken checks or mark a route verified to bypass it.
