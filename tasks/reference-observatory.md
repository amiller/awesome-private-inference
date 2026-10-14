# Reference observatory implementation

Branch: feat/reference-observatory, based on upstream cbf555f. Original dirty checkout is preserved. Supervisor: Astra; bounded implementation/review jobs: Sol.

## Acceptance checklist

- [x] Correct ACI quote and event bindings with negative controls.
- [x] Scope NEAR anchors to requested model and record chain block provenance.
- [x] Mark incomplete hardware/model/request closure not_checked.
- [x] Preserve unique observations and partial-run freshness.
- [x] Persist typed change events and durable review leases.
- [x] Capture Maple and Privatemode reference publications; track two additional candidates.
- [x] Integrate route cards and observed identity timeline.
- [x] Pin instrument inputs and update daily/weekly/heartbeat workflows.
- [x] Run deterministic replay, live readonly capture, simulated lease/crash recovery and independent review.
- [x] Produce reviewed change packet and public sanitized decision.
- [x] Create reviewable [draft PR #20](https://github.com/amiller/awesome-private-inference/pull/20) and record rollout evidence.

## Evidence gates still requiring follow-through

- ACI MRTD/RTMR0-2 expected boot measurements, NEAR compose-manager/request closure, Tinfoil AMD chain/signature: explicit not_checked until verified.
- Private Inference credentialed attestation and request/reply binding.
- Maple live Nitro session, source-to-EIF reproduction, both upstream paths.
- Privatemode pinned client key exchange and worker proof.
- Confidential AI release/quote/TLS and request-bound worker proof.
- 30-day reliability and multi-reader comprehension goals require elapsed operation and independent readers.

A supported blocked/unknown disposition is acceptable onboarding output. It is not a completed confidentiality audit. No accepted reference policy is auto-expanded by review agents.

[Implementation evidence and rollout limits](../research/implementation-2026-10-14/implementation.md). Production cron replacement, a separately reachable zed heartbeat, blinded Sol evaluation and reader testing remain follow-through work.
