# GLM chutes lane — 2026-11-05 report

Epoch 1 (2026-11-05 ~20:45 UTC). Full suite
`~/.local/bin/uv run --extra dev --extra nearai pytest -q`: **201 passed**.

## What changed

- `verifiers/nvidia_nras.py` — rewritten against the **real** NRAS shapes
  (epoch 0 had assumed JWT-shaped gpu_evidence; the owner's keyed capture
  shows Chutes items are `{arch, certificate, evidence}` blobs). New:
  `evidence_nonce` (blob bytes [4:36]), `attest_gpu_evidence` /
  `attest_payload` (POST `v3/attest/gpu`), `appraise_jwt` (signature vs
  published JWKS, pinned intermediate SPKI, alg/key match, verdict,
  eat_nonce, per-GPU nonce-match), `appraise_gpu_attestation` (full policy,
  incl. new items/tokens count consistency and `allow_unknown_count` for
  Venice). Removed the unsafe `attest_gpu` wrapper (verdict read without
  signature); `common.decode_nvidia_jwt_verdict` stays, now with no callers.
- `verifiers/chutes.py` — GPU block now submits the real blobs to NRAS with
  expected nonce = **`report_data[0:32]`** (the TD-bound
  SHA256(nonce‖e2e_pubkey)); `fleet_size_semantics` recorded in details;
  **`gpu_attested` None (unverified) now makes the row `rejected`**
  ("gpu_layer_unverified: …") — `not_checked` requires every layer of every
  listed instance to actually pass.
- `verifiers/venice.py` — NRAS verdict no longer read without verification:
  payload nonce must equal our fresh request nonce; JWTs signature-verified
  against the published JWKS with eat_nonce binding; NRAS unreachable →
  gpu_attested None (unverified, recorded), never a pass.
- Fixtures (capture time + URL inside each): `chutes_capture_sample.json`
  (owner's keyed capture, trimmed to one evidence-backed instance per GPU
  class, full 5-instance listing retained), `nras_attest_response.json`
  (live NRAS appraisal of those instances), `venice_attestation_sample.json`
  (fresh unauthenticated Venice capture with our nonce) +
  `nras_venice_response.json` (its live NRAS appraisal), `nras_jwks.json`
  (epoch 0 capture of NVIDIA's public JWKS).
- Tests: `tests/test_nvidia_nras.py` (rewritten, real-shape),
  `tests/test_chutes_gpu_replay.py` (real capture end-to-end through
  `chutes.verify`), `tests/test_venice_gpu.py` (new), fleet/evidence tests
  updated for the GPU-verdict mock (their subject is census/registers/TCB;
  the real GPU path is covered by the replay files).

## CPU↔GPU association (new, established from real evidence)

The GPU evidence blob embeds a 32-byte nonce at bytes [4:36] which is
**exactly the TDX quote's `report_data[0:32]`** — i.e.
SHA256(url_nonce‖e2e_pubkey), hardware-bound by the TD. Submitting any other
nonce makes NRAS reject with `NONCE_NOT_MATCHING`. Chain: our fresh URL
nonce → TD report_data[0:32] → GPU blob nonce → NRAS `eat_nonce` echoed in
every platform/per-GPU JWT. This upgrades "nonce-bound to the TD" from a
docs claim to a checked binding.

## Success criteria status

- **#7/#19-1 census** — met. `verify()` fetches evidence for every listed
  instance; details retain instance_id, e2e_pubkey, MRTD, RTMR0-3, matched
  row identity + sha256, TCB status/advisories, GPU outcome and reasons;
  `fleet_size` exact daily count; `fleet_size_semantics` says the response
  has no pagination/total field so a cap can't be ruled out (every model
  listed exactly 5 instances on 2026-11-05 — not asserted a census).
  Tests: `test_chutes_fleet.py::test_fleet_census_retains_every_instance`,
  `test_chutes_gpu_replay.py` (real capture).
- **Row verdict semantics** — met and documented (spec §2, chutes.py
  docstring): `not_checked` only when every listed instance passes every
  crypto-core check; dissent preserved verbatim. Unverified layers reject.
  Tests: fleet unavailable/rogue-instance tests, replay transport-failure
  and absent-gpu tests.
- **#28 registers** — met. Exact full-row match (MRTD + boot RTMR0-2 +
  runtime RTMR3; ambiguous boot/runtime rows never match), matched row
  identity + `matched_row_sha256`, `golden_set_sha256` (continuity) and
  `golden_publication` digest with URL/time. All 150 retained quotes
  full-match their publications; each-register mutations independently
  destroy the match (`test_chutes_registers.py`, no mocks).
- **#18 Chutes TCB** — met. Per-instance `tcb_status`/`advisory_ids` from
  local dcap_qvl (`tcb_status_source: dcap_qvl`); errors recorded as
  `tcb_status_error`, never silent None. Phala root cause (no TCB field in
  its verify response) established live 2026-11-05 (epoch 0) and recorded.
- **#28 GPU** — met. Real appraisal against live NRAS with pinned JWKS;
  signature + verdict + nonce + association + count policy; unverified JWT
  or bare field can never pass. Pass path proven on the real capture
  (GLM-5.1-TEE, 8/8 GPUs); every negative control rejects.
- **Serving-code gap** — unchanged, explicit (`serving_code_attested`
  False by construction).

## Findings from the real capture (2026-11-05 19:34 UTC)

1. **gemma-4-31B-TEE: every one of its 5 listed instances returns exactly 1
   GPU evidence token while its matched published row (`8xpro_6000 …`,
   gpu_count 8) declares 8.** The GPU layer therefore rejects
   (gpu_count_mismatch) — 7 GPUs that the published configuration says can
   see the TD are not attested. Pinned as a regression test
   (`test_real_gemma_evidence_records_count_mismatch`). Worth asking Chutes
   whether gemma runs on a 1-of-8 GPU slice.
2. **Qwen3-32B-TEE `/e2e/instances` returned 404** — chute likely retired;
   recorded in the fixture and here, not silently dropped.
3. All other 20 instances (GLM-5.1/5.2, DeepSeek-V3.2, Kimi-K2.6) matched
   their published rows and their 8 GPU tokens all verified (live NRAS).

## Negative controls (each independently rejects; all tested)

Registers (real retained quotes, per-register byte flips), golden-set
mutation, bindings (report_data tamper, invalid signature, debug flag,
SPKI), NRAS: tampered platform/per-GPU payload (signature), unknown kid,
unpinned intermediate, bare JWK, coordinate/leaf mismatch, alg mismatch,
verdict false/FAIL, wrong/missing eat_nonce (platform and per-GPU),
per-GPU nonce-match false, duplicate ueid, dropped per-GPU token (item
count), gpu_count mismatch, evidence item nonce ≠ TD report_data[0:32]
(association break, on the real GLM instance), absent gpu_evidence (None,
never pass), NRAS unreachable (None + row rejected), forged-verdict JWT
(real token with verdict flipped fails signature). Pinned-production-JWKS
unknown-kid rejection covers cross-key substitution.

## Blockers / honest status

- No live keyed Chutes call from this lane (no credential, per
  instructions); the owner's keyed capture is the real evidence. The daily
  adapter path runs in CI with the key; unit tests mock Chutes transport
  only, and NRAS/JWKS fixtures are live captures.
- The pinned NRAS JWT fixtures are single captures (2026-11-05); NRAS
  rotates keys (~2-day kid window), so the pinned JWKS fixture will age —
  the live path fetches current JWKS and pins only the intermediates, so
  aging affects offline replay only, not CI.
- Venice `valid` aggregate semantics for an absent nvidia_payload were left
  as-is (pre-existing); the layer reads None and required-layer coverage
  stays False. Flagged for the owner rather than changed editorially.
- dcap_qvl TCB appraisal is replayed on retained quotes in tests via mocks
  at the `_tcb_appraisal` boundary (network collateral fetch in unit tests
  would be flaky); the function itself ran live in epoch 0 and in CI.
