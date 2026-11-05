# GLM lane `rubric` (issue #9): site-quality rubric R1–R10 as build-failing checks

Date: 2026-11-05. Spec written before implementation; deviations are recorded in the
companion REPORT.

## Staleness audit of the issue's named cases (required by the brief)

The render code was rewritten on current main; each case the issue names was re-checked
against `data/latest.json` (generated 2026-11-04) and the current renderer
(`probes/render.py`):

- **Venice R3 (computed vs editorial disagreement): STALE.** Corrected 2026-08-10 in
  commit 7a14405. The current editorial layer (`data/assessments/routes.json`) claims no
  `established` axis for any route, so no provider's editorial verdict outranks its
  computed outcome today. R3 must still be implemented (it guards regressions).
- **tinfoil-router 0/5 (R2): STALE.** The rewritten renderer publishes every scorecard
  field per row (`checks` in `probes/render.py:_rows` renders `sorted(scorecard.items())`),
  and tinfoil's current scorecard contains all four layers required by
  `REQUIRED_LAYERS_BY_SHAPE["tinfoil-sev-snp-v2"]`. Measured R2 = 1.0 for every current
  row.
- **RedPill shape `redpill` absent from `REQUIRED_LAYERS_BY_SHAPE` (R4): STALE for the
  rendered snapshot** (redpill is retired; all five shapes emitted by `data/latest.json`
  have entries). The failure mode is real in history: `data/snapshots/*.json` contain
  `redpill`, `phala-simple`, `near-relay`, `chutes`, `error` shapes with no entry, so the
  check is still implemented against the rendered snapshot.
- **R6 `backend_attested` amber: STALE as a *current* failure** — no scorecard in
  `data/latest.json` carries an `audit_pending` value — but the encoding still exists
  (`probes/render.py:check_cell` renders `"audit_pending"` as amber "Review pending"
  inside provider columns), so the check is still implemented.
- **R1 and R9 still fail on current main** (re-measured below), and **R7 fails under the
  mechanical rule defined below**.

## Success criteria from the issue this spec commits to

1. R1, R2, R3, R4, R6, R7, R9 implemented as mechanical checks in a new module
   `probes/rubric.py`, each returning structured pass/fail with the violating rows/files.
   R5, R8, R10 are out of scope for this issue (not listed).
2. Each check has a synthetic failing fixture proving it fires, and a passing case
   (pytest, `tests/test_rubric.py`). Real retained evidence (`data/latest.json`,
   `data/assessments/routes.json`, `site/templates/*.j2`, `data/audits/*.json`) is used
   wherever the check currently has something to measure.
3. A CI job `site-quality` in `.github/workflows/ci.yml` runs `python -m probes.rubric`
   and fails the build on any failing check. `probe-daily.yml` is NOT touched: R4 would
   block snapshots during provider transport outages.
4. Current main's result against every check is measured and reported precisely; checks
   are not weakened to make them pass.

## Check definitions (mechanical, tied to the current renderer)

Inputs: the rendered row model is built with `probes.render._rows(snapshot)` so the
checks grade exactly what the page renders, plus `data/routes.json`,
`data/assessments/routes.json`, `site/templates/*.j2`, `probes.quality.compute`.

- **R1 information density** — over the rendered matrix (rows × `MATRIX_KEYS`, marks from
  `check_cell`): the modal cell state must not be the not-checked state (`—`, the current
  encoding of "N/A"), and no column may be 100% one mark when ≥2 rows are rendered.
  An empty matrix is a violation.
- **R2 verdict reconstructability** — per row, rendered columns = scorecard keys ∪
  `MATRIX_KEYS` (what `measurements.html`/`evidence.html` actually show); every layer in
  `REQUIRED_LAYERS_BY_SHAPE[shape]` must appear; site score is the minimum.
- **R3 same-page coherence** — per provider: computed signal from rendered outcomes
  (`verified` ⇒ positive; all rows `rejected`/`unavailable` ⇒ negative; else neutral);
  editorial signal from `data/assessments/routes.json` (any `established` axis cell ⇒
  positive; any `gap` and no `established` ⇒ negative; else neutral). A provider where
  the two signals rank oppositely is a violation unless the disagreeing editorial cells
  carry `issue_urls` (the linked explanation). The rubric's original Venice case is this
  shape.
- **R4 cause separation** — (a) no row whose `error` matches `probes.quality.TRANSPORT`
  may render in the failure encoding: outcome `rejected` or any × cell; (b) every
  `attestation_type` emitted by the rendered snapshot must be a key of
  `REQUIRED_LAYERS_BY_SHAPE`.
- **R6 subject separation** — no cell rendered inside a provider column (matrix cells or
  the per-row checks list) may carry the auditor-state value `audit_pending` (rendered
  amber "Review pending"; the `backend_attested` case in the issue).
- **R7 prose–data drift** — in `site/templates/*.j2` static text (tags and Jinja
  expressions stripped), every sentence naming a tracked provider (stems of
  `providers/*.md`) must carry a date: an ISO `YYYY-MM-DD` literal or a Jinja variable
  reference resolving to dated data (`as_of`, `reviewed_at`, `curated_at`,
  `evidence_date`, `generated_at`, `checked_at`, `last_new`, `at`). Sentences inside
  `{% for %}` bodies over dated data structures inherit the loop's dated variable.
- **R9 audit liveness** — from `probes.quality.compute(...)["audit_debt"]`:
  `backlog < 5` and `days_since_last_audit < 14` (thresholds from the rubric, derived
  from the measured ~4.2-day deploy cadence). Both must hold; a missing ledger date is a
  violation, not "unknown".

## Expected current-main results (pre-implementation measurements)

| Check | Result | Evidence |
|---|---|---|
| R1 | **fail** | modal mark `—` 63/119 cells (53%); no constant column |
| R2 | pass | minimum 1.0; all required layers rendered |
| R3 | pass | no `established` editorial cells; no opposite rankings |
| R4 | pass | 0 transport-cause failure cells; 0 unknown shapes |
| R6 | pass | 0 `audit_pending` cells |
| R7 | **fail** | `pricing.html.j2` "Venice Pro ($18/mo)…", "Z.AI GLM Coding Plan…" and `history.html.j2` "Maple publishes PCR0 measurements…" carry no as-of date |
| R9 | **fail** | backlog 93 ≥ 5; last audit 2026-09-02, 64 days old |

The CI job will therefore fail on main until R1, R7 and R9 are fixed. These fixes are
editorial/design decisions outside this lane's authorization: R1 requires redesigning the
rendered matrix (visual design — Astra's call per AGENTS.md), R7 requires as-of dates
only the observer of those rates can supply (inventing a date would fabricate evidence),
R9 requires real audit work. They are recorded as precise blockers in the REPORT, not
weakened.

## Negative controls

Each check's test suite mutates exactly one dimension of an otherwise-passing synthetic
input and asserts the check fires: a dash-majority matrix (R1), removal of one required
layer key from one row's scorecard (R2), an `established` editorial cell on a provider
whose rows are all `rejected` and the same without `issue_urls` (R3), a transport-error
row forced to `rejected` outcome and separately an unknown shape string (R4a/R4b), an
`audit_pending` value in one matrix column (R6), an undated provider-naming sentence
(R7), and backlog/age threshold crossings (R9). A pinned real-data test asserts the
current-main outcomes above so the reported state is itself tested.

## Out of scope / blockers

- R5, R8, R10 (not requested).
- Fixing R1/R7/R9 content (see above): outside this lane; documented, not weakened.
- Live collection: not needed; all checks run on retained repo evidence.
