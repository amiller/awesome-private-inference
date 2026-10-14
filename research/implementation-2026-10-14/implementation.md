# Reference observatory implementation and rollout evidence

Implemented on `feat/reference-observatory`, based on upstream `cbf555f`, in [draft PR #20](https://github.com/amiller/awesome-private-inference/pull/20). The original dirty checkout was preserved. Astra supervised three Sol implementation tracks and reviewed their integration. The framing, detailed goals and provider research are in the [project review](../review-2026-10-13/review.md).

## Delivered

- Route-first explanations replace the entry-point Stage scoreboard. Nineteen cards distinguish client modes, plaintext holders, acceptance authority, observed evidence and missing proof, including NEAR gateway, relayed E2EE and direct paths.
- ACI quote/report-data and event/compose binding repairs, model-scoped NEAR policy and chain-block provenance, full-digest audit matching, and explicit incomplete states for unsupported proof. Tinfoil provenance is no longer independent reproduction or AMD signature verification. Archive downloads and extraction are bounded.
- Immutable runs, attempts, report/raw-evidence hashes and typed events; a partial run preserves other routes and timestamps. One legacy baseline is imported honestly; full historical backfill is optional.
- A locked observation environment, pinned upstream NEAR verifier and an instrument fingerprint covering actual local adapter/collector source and lock bytes. Daily capture, weekly catalog discovery and a separately scheduled freshness check have checked-in workflows.
- Public reference monitoring for Maple, Private Inference, Privatemode and Confidential AI, with exact archived bytes. Twenty-two sources were captured successfully. Maple's four canonical/mirror pairs agreed. Private Inference's main bundle imports a verifier whose bytes match the prior source review. No publication is labeled a live confidentiality proof.
- Durable review jobs with leases, retries, blocked states, exact evidence paths and supervisor dispositions. Worker launch does not finish a job. Reviewer identity remains an operational convention on a shared filesystem, not enforced authentication.

## Validation

The local integrated suite and the final frozen Python 3.11 environment on zed each passed **131 tests**. The remote run also tested the CI-only dependency selection and passed the freshness check; see [final test log](zed-final-tests.txt) and [live collection log](zed-validation.txt). The [deterministic replay](replay-results.json) passed **24/24** seeded cases; it tests detection, not blinded agent judgment. Lease-expiry and late-worker rejection are exercised with controlled clocks, not represented as a production worker-kill experiment. The temporary remote environment and upstream clone were removed after evidence capture; no new laptop install was created.

Two actual Sol runs reviewed an explicitly synthetic policy-expansion packet. The first draft was returned for imprecise evidence paths; the second was independently reviewed and exported with `needs_evidence`. [Rehearsal record](rehearsal-summary.md). Live dispatch exposed Paseo version differences and an invalid permission-mode choice; the worker now uses the common `-d` flag, explicit `gpt-6-sol`, and `auto` mode.

The frozen environment then ran a read-only public ACI collection on zed at 2026-10-14 01:42 UTC, against source commit `79fff1b17e371326a6b1d171b01b7cbcde1ed21c`. It made no inference request. Full retained evidence has verified content hashes. Both TEE-only hosts are `not_checked` because expected boot registers and the request path remain unverified; `api.redpill.ai` is `rejected` because its measured host policy does not require attested serving. All seventeen routes remain in the partial-run view. The old values for the other fourteen rows remain explicitly legacy.

This produced 26 typed events, including instrument changes and changes in declared verification scope. Sol reviewed the actual [tee.redpill.ai coverage event](../../data/continuity/events/chg-b69f2fb6d3774d63dbf5612b560ea77d.json), reconstructed its retained evidence, and recomputed available bindings offline. Astra independently reviewed the result and published a [needs-evidence decision](../../data/reviews/decisions/chg-b69f2fb6d3774d63dbf5612b560ea77d.json). The compose identity was unchanged; the legacy success did not establish the proof now required. A changed reported keyset has no demonstrated continuity endorsement. Neither result establishes provider compromise.

The watcher dry run ingested all 26 events without launching agents; its sanitized heartbeat and the independent freshness check passed. The generated site includes hash-checked raw publication downloads and separately displays reviewed dispositions. No accepted-reference ledger was expanded.

## Rollout and remaining gates

This branch is a reviewable implementation, not a claim that the production scheduler has switched. The existing zed cron was inspected but not replaced; it still uses the previous acknowledgment workflow. After main integration, deploy the watcher under the same account/filesystem as its workers, run a dry check, then enable dispatch. Check that the first scheduled collection commits all evidence and that a real worker reaches a reviewed disposition. Publish only sanitized queue health through an independently reachable endpoint if total zed failure must be detected; the GitHub freshness workflow cannot inspect the private zed queue.

Private Inference still needs authorized credentialed quote/request tests; Maple needs a live Nitro session, source-to-EIF reproduction and both upstream paths; Privatemode needs the pinned-client key exchange/worker chain; Confidential AI needs release/quote/TLS/request closure. Existing ACI boot, NEAR compose-manager/request, Tinfoil AMD signature and Chutes serving-code gaps remain explicit. New catalog entries are discovered, but rotating them into the daily sentinel sample still requires review.

The 30-day capture SLO, two-working-day triage goal, five-reader comprehension exercise, and blinded multi-case Sol evaluation remain unmeasured. Twenty-four deterministic tests and two synthetic Sol drafts do not satisfy those longitudinal or human-evaluation goals. Preserve that distinction when reporting progress.
