# Reference observatory implementation

Branch: feat/reference-observatory, based on upstream cbf555f. Original dirty checkout is preserved. Supervisor: Astra; bounded implementation/review jobs: Sol.

## Acceptance checklist

- [x] Correct ACI quote and event bindings with negative controls.
- [x] Scope NEAR anchors to requested model and record chain block provenance.
- [x] Mark incomplete hardware/model/request closure not_checked.
- [x] Preserve unique observations and partial-run freshness.
- [x] Persist typed change events and durable review leases.
- [x] Capture Maple and Privatemode reference publications; track two additional candidates.
- [ ] Integrate route cards and observed identity timeline.
- [ ] Pin instrument inputs and update daily/weekly/heartbeat workflows.
- [ ] Run deterministic replay, live readonly capture, queue crash recovery and independent review.
- [ ] Produce reviewed change packet and public sanitized decision.
- [ ] Create reviewable PR and record rollout evidence.

## Evidence gates still requiring follow-through

- ACI MRTD/RTMR0-2 expected boot measurements, NEAR compose-manager/request closure, Tinfoil AMD chain/signature: explicit not_checked until verified.
- Private Inference credentialed attestation and request/reply binding.
- Maple live Nitro session, source-to-EIF reproduction, both upstream paths.
- Privatemode pinned client key exchange and worker proof.
- Confidential AI release/quote/TLS and request-bound worker proof.
- 30-day reliability and multi-reader comprehension goals require elapsed operation and independent readers.

A supported blocked/unknown disposition is acceptable onboarding output. It is not a completed confidentiality audit. No accepted reference policy is auto-expanded by review agents.
