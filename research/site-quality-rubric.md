# How to tell whether this site is any good

The registry grades providers. This grades the registry. It is meant to be re-run on every
build and to fail loudly, the same way the provider matrix is meant to.

Most of it is computed by `python -m probes.quality`. The dimensions that are not yet
automated are marked, and each has an open issue.

## The one-paragraph version

A dashboard like this fails in a specific way: it keeps producing output, so it looks alive,
while the output stops discriminating between anything. The guard against that is not more
columns. It is a small set of invariants that are false when the instrument has quietly
stopped measuring — a detector that never fires, a column that is always the same value,
prose that contradicts the data beside it, a bar that was moved without a reason being
recorded.

## The rubric

Thresholds are mostly zero rather than a tuned percentage, because each metric counts
violations of a contract the page itself states. A page that says "❌ rejected by verifier"
and renders ❌ for a DNS failure is not slightly wrong, it is making a false statement.

| # | Dimension | Metric | Threshold | Today | Why this threshold |
|---|---|---|---|---|---|
| R1 | Information density | Modal cell state across the rendered matrix; count of columns that are 100% one value | modal state must not be "N/A"; no constant column | **fail** — 74% grey, `prod_os_image` 21/21 grey | If "not applicable" is the *most common* thing on a grid, the grid is the wrong shape for the data. Grey conveys only shape membership, which the Shape column already carries. Structural, not tuned. |
| R2 | Verdict reconstructability | Per row, `\|required ∩ rendered\| / \|required\|`; site score is the minimum | 1.0 | **fail** — tinfoil/router scores 0/5 | If a verdict is a function of variables not on the page, "why" cannot be reconstructed. Definitional. |
| R3 | Same-page coherence | Count of providers whose computed status and editorial verdict disagree with no linked explanation | 0 | **now pass** — the Venice contradiction that motivated this row was corrected 2026-08-10 | Two signals ranking providers oppositely means a reader following either alone is wrong about someone. |
| R4 | Cause separation | Cells in the failure encoding whose cause was transport; plus emitted shape strings absent from `REQUIRED_LAYERS_BY_SHAPE` | 0 and 0 | **was fail** — 100% of historical red was transport; errored RedPill rows emit shape `redpill`, which has no entry | A cell contradicting its own legend is a false statement. Fixed by the reachable/verified/partial split. |
| R5 | Calibration honesty | Every check channel with zero firings must display "never fired (n=…)" and the rule-of-three 95% bound `3/n` | present on all silent channels | **now pass** | Rule of three is the standard zero-event bound. It converts silence into a quantified claim: 0 in 2,358 → daily failure rate < 0.13% (95%). A silent detector without its n is indistinguishable from a disconnected one. |
| R6 | Subject separation | Fields whose semantics are auditor state, rendered inside provider columns | 0 | **fail** — `backend_attested` amber is our review queue and sits in a provider column | 20 of 24 historical cell flips were this field. A provider grid whose only moving cell measures the auditor is mislabelled. |
| R7 | Prose–data drift | Template claims lacking an as-of date; anchored claims whose subject changed in data after that date | 0 and 0 | **now pass** | One contradicted sentence discounts every other sentence. The old page said RedPill's image switch "hasn't been done" while the column beside it tracked the fix. |
| R8 | Asset coverage | Collected scorecard fields neither rendered nor listed in an internal-fields manifest | 0 | **partial** — 6 of 15 unrendered, now listed per row | Prevents the tinfoil failure recurring silently. |
| R9 | Audit liveness | Observed builds with no review record; age of newest record | backlog < 5; newest < 14 days | **fail** — backlog 17, newest 53 days | A ledger that stops being appended to is indistinguishable from a ledger with nothing to say. Thresholds are set from the measured deploy cadence: NEAR ships every ~4.2 days, so a 14-day-old ledger means at least three unreviewed builds. |
| R10 | Measurability | Providers with no stable version identity, reported as unmeasured rather than scored | reported, never scored green | **now pass** — redpill and venice flagged | A provider that exposes nothing to track is not passing. It is unmeasured, and saying so is a stronger public statement than any green row. |

## The part that is not automatable

**Is the bar fair?** `REQUIRED_LAYERS_BY_SHAPE` decides what each provider is expected to
prove, and it is the most consequential judgment in the system. It is currently a
hand-edited dict with no changelog, and it was demonstrably uneven: Venice's set omitted the
layers it would fail, so Venice scored a full row while providers exposing more of their
stack scored less.

Worth recording how that one surfaced. This rubric flagged the Venice bar as *disputed* on
2026-08-10 and still left it scoring a full row; what actually forced the correction, the
same day, was an unrelated third-party audit naming the two excluded layers. A rubric that
labels a suspicion is not the same as a check that fails the build — which is the argument
for automating R1–R10 in CI rather than maintaining them as prose.

The defect has a diagnosable cause. The sets were derived from *what each provider's API
happens to expose* rather than *what each provider claims* — even though the onboarding
comment in `verifiers/common.py` states the claim-based rule correctly. That makes a vantage
limitation look like an architectural exemption.

The fix is structural, not editorial taste:

1. A per-provider claims inventory — quoted public claims with URL and date. Verifiable,
   because they are quotes.
2. One global entailment table mapping claim → required layers ("claims GPU inference →
   `gpu_attested`"). A single shared table cannot play per-provider favourites; bars may then
   differ only because claims differ, which is the correct kind of uneven.
3. A lint requiring every shape to classify all 15 fields as required, excluded-architectural,
   or excluded-claim-absent, each with a reason. Silent omission — the exact mechanism of the
   Venice full row — becomes impossible. Exclusions are the dangerous edit, so make them loud.

What stays editorial is small and global: which claims count, and what a claim entails. Govern
it the way provider code is governed — a dated changelog entry per edit, analyst-pair review,
and a public dispute path linked from each row. Until then, every disputed bar renders its
reasoning inline and sorts below sound ones, and cross-provider fractions are labelled unsound.

## Running it

```bash
python -m probes.quality          # the computed dimensions
python -m probes.trajectory       # deploy cadence and failure-mode census
```

`probes.quality --write` emits `data/quality.json`, which the dashboard renders as the four
tiles under "How much to trust this page". The intent is that the page cannot look healthy
while the instrument behind it is not.
