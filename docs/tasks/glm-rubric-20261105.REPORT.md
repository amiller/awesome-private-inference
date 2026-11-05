# REPORT — GLM lane `rubric` (issue #9), epoch 1 (2026-11-05)

## What changed

- `probes/rubric.py` (new): R1, R2, R3, R4, R6, R7, R9 as mechanical checks over
  the *rendered* row model (`probes.render._rows`), `data/routes.json`,
  `data/assessments/routes.json`, `site/templates/*.j2` and
  `probes.quality.compute()["audit_debt"]`. CLI `python -m probes.rubric` prints a
  per-check report and exits 1 on any failure. Functions: `r1_density`,
  `r2_reconstructability`, `r3_coherence`, `r4_cause_separation`,
  `r6_subject_separation`, `r7_prose_dating` (+ `_template_sentences`,
  `_is_dated`, `_claim_subject`, `_computed_signal`, `_editorial_signal`),
  `r9_audit_liveness`, `run`, `main`.
- `tests/test_rubric.py` (new): 28 tests — per check a passing case and a
  synthetic negative control that mutates exactly one dimension, plus a pinned
  real-evidence test of current main's outcome per check and a CLI exit-code test.
- `.github/workflows/ci.yml`: new `site-quality` job running
  `python -m probes.rubric` (fails the build; no `continue-on-error`).
  `probe-daily.yml` is untouched, as required — R4 would block snapshot commits
  during provider transport outages.
- `docs/tasks/glm-rubric-20261105.md` (spec, written before implementation).

## Staleness audit (asked by the brief)

- **Venice R3: stale.** Fixed 2026-08-10 (commit 7a14405); no `established`
  editorial cells exist anywhere today, so nothing outranks a computed status.
- **tinfoil-router 0/5 (R2): stale.** The rewritten renderer publishes every
  scorecard field per row; all four `tinfoil-sev-snp-v2` required layers are
  rendered. Measured minimum = 1.0.
- **RedPill shape (R4): stale for the rendered snapshot** (all five current
  shapes have `REQUIRED_LAYERS_BY_SHAPE` entries) but the failure mode exists in
  history (`redpill`, `phala-simple`, `near-relay`, `chutes`, `error` shapes in
  `data/snapshots/`), so the check is implemented against the rendered snapshot.
  Sentinel shapes `""`/`skipped`/`error` (no architecture claim) are exempt and
  tested to be exempt.
- **R6 `backend_attested` amber: stale as a current failure** (no `audit_pending`
  values in `data/latest.json`), but the encoding exists in
  `render.check_cell`, so the check fires on it (tested).

## Issue success criteria status

| Criterion | Status | Proof |
|---|---|---|
| R1, R2, R3, R4, R6, R7, R9 implemented as checks | done | `probes/rubric.py`; `tests/test_rubric.py::test_current_main_state_against_every_check` asserts all seven IDs run |
| Each check has a synthetic failing fixture + passing case | done | `tests/test_rubric.py` (28 tests, all passing; see negative controls below) |
| R9 not silently dropped | done | `r9_audit_liveness` is mechanical: backlog/age thresholds from `quality.compute`; missing ledger date is a violation, not "unknown" |
| Wired into CI as a separate job that fails the build | done | `site-quality` job in `.github/workflows/ci.yml`; verified the module runs under `--extra dev` alone and exits 1 |
| probe-daily snapshot commit NOT gated | done | `probe-daily.yml` unmodified |
| Report current main's results against every check | below | pinned by `test_current_main_state_against_every_check` |

## Current main results (measured 2026-11-05 against data/latest.json 2026-11-04)

| Check | Result | Detail |
|---|---|---|
| R1 | **FAIL** | modal rendered cell state is the not-checked mark `—` (63/119 = 53%); no constant column (the rubric's `prod_os_image` 21/21 grey case no longer applies to the rewritten matrix) |
| R2 | pass | minimum 1.0 over 17 rows |
| R3 | pass | no `established` editorial cells; no opposite rankings |
| R4 | pass | 0 transport-cause failure cells; 0 shapes missing from `REQUIRED_LAYERS_BY_SHAPE` |
| R6 | pass | 0 review-pending cells in provider columns |
| R7 | **FAIL** | 9 undated claims: `pricing.html.j2` (Venice Pro $18/mo block, Z.AI GLM Coding Plan, three rate sentences), `history.html.j2` ("Maple publishes PCR0 measurements…", "reviewed Chutes design…"), `evidence.html.j2` ("Maple canonical ↔ legacy:" label) |
| R9 | **FAIL** | backlog 93 (not < 5); newest ledger record 2026-09-02, 64 days old (not < 14) |

The CI `site-quality` job therefore fails on this branch and will fail on main
until R1, R7 and R9 are fixed. These are genuine instrument findings, not check
bugs; per the brief they are listed, not weakened.

## Negative controls (all pass = each check fires on its tampered input)

- R1: not-checked-majority matrix → modal violation; all-✓ matrix → all 7 columns
  flagged constant; empty matrix → violation.
- R2: deleting exactly one required key (`serving_code_attested`, chosen because
  it is not in `MATRIX_KEYS`) from one row's scorecard → violation naming it;
  no characterized rows → violation.
- R3: editorial `gap` vs computed `verified` (and `established` vs all-`rejected`
  /`unavailable`) → violation; same input with `issue_urls` → passes (linked
  explanation honoured); neutral computed status → never contradicts.
- R4: transport error + `rejected` outcome → fires; transport error + one False
  cell → fires naming the cell; shape `redpill` → fires; sentinel shapes
  `error`/`skipped` → do not fire.
- R6: `backend_attested="audit_pending"` → fires naming the column.
- R7: undated provider sentence → fires; undated price sentence → fires even with
  no lexicon hit; ISO literal and dated Jinja variable (`{{ pricing.as_of }}`) →
  pass; nav fragments/scripts → ignored.
- R9: backlog 5 and 93 → fail (boundary at `< 5`); age 14 days → fail; no ledger
  record → fail as unmeasurable; backlog 4 / age 13 → pass.

## Validation status

- Full suite: `uv run --extra dev --extra nearai pytest -q` → 180 passed, 0 failed.
- `python -m probes.rubric` on current repo data exits 1 with the R1/R7/R9
  failures above (this is the CI job's expected red until fixed).
- No live collection; all checks run on retained repo evidence.
- R5, R8, R10 remain out of scope (not requested by the issue).

## Blockers (precise)

- **R1 fix** requires redesigning the rendered matrix (provider columns vs shape
  coverage) — a visual-design decision AGENTS.md reserves for Astra's framing
  and final review. Not attempted.
- **R7 fix** requires as-of dates for the pricing/Maple/Chutes sentences; only
  the observer of those rates can supply true dates. Inventing dates would
  fabricate evidence, so the failures stand.
- **R9 fix** requires real analyst-pair audit work (93 unreviewed builds); not a
  code change.
