# GLM chutes lane — 2026-11-05 spec

Lane: chutes. Entry point `verifiers/chutes.py`; also `verifiers/nvidia_nras.py`,
`verifiers/common.py`. Issues: #7 (fleet census), #28 (GPU appraisal + full
register comparison), Chutes part of #18 (TCB status retention), first two
checkboxes of #19 (per-instance daily check, full MRTD/RTMRs + matched row in
snapshot).

## Success criteria I commit to

1. **#7 / #19 checkbox 1 — census.** `verify()` retains the full
   `/e2e/instances/{chute_id}` array and fetches evidence for **every** listed
   instance. Per instance the row details record: instance_id, e2e_pubkey,
   MRTD, RTMR0-3, matched golden-row identity, TCB status + advisory IDs, and
   the evidence outcome (including the exact reason evidence was unavailable).
   `fleet_size = len(instances)` is an exact daily count in details and
   raw_evidence.
2. **Row verdict semantics (decided and documented).** The row's
   `verification_status` is `not_checked` (crypto core sound, serving-code gap
   remains) only if **every** listed instance passes every crypto-core check.
   Any instance that fails a check, runs an unpublished image, or yields no
   obtainable evidence makes the row `rejected`, with the dissenting instance
   and reason preserved verbatim — no aggregate erasure (#28 criterion 3).
3. **#28 registers — exact full-row match.** The authenticated MRTD **and**
   RTMR0-3 must match one exact row of the captured `/servers/tee/measurements`
   publication: quote MRTD+RTMR0-2 == row `boot_rtmrs.RTMR0-2`, quote RTMR3 ==
   row `runtime_rtmrs.RTMR3`. A row whose boot and runtime RTMR0-2 disagree is
   treated as ambiguous (no match, reason recorded) rather than silently
   choosing one. Recorded per instance: matched row (name, version,
   fingerprint, gpu_count, expected_gpus), canonical `matched_row_sha256`, the
   normalized-set digest (`golden_set_sha256`, continuity with retained
   evidence) and a new `golden_publication_sha256` over the raw response bytes
   with source URL and capture time.
4. **#18 (Chutes part) — TCB status.** Per instance, the TDX quote is appraised
   locally with `dcap_qvl` (as the NEAR verifier already does) to retain
   `tcb_status` (UpToDate/OutOfDate/…) and `advisory_ids`. The Phala verdict
   stays as the quote-signature check. Root cause of today's `null` (found
   live, 2026-11-05, by replaying retained quote
   `815ac144…` to Phala): Phala's verify response contains only
   `body/cert_data/header/verified` — no TCB field at all; `verified` alone
   conflates UpToDate and OutOfDate. Recorded in the report and in the row
   details (`tcb_status_source: dcap_qvl`).
5. **#28 GPU — real NRAS appraisal (confirmed against live NRAS 2026-11-05
   with the owner's keyed capture).** Chutes' `gpu_evidence` items are
   `{arch, certificate, evidence}` blobs, **not** JWTs: the NRAS
   `v3/attest/gpu` request payload is
   `{nonce, arch, evidence_list}` and the response is
   `[["JWT", platform_jwt], {"GPU-i": per_gpu_jwt, …}]`.
   The CPU↔GPU association is fully cryptographic and was established from
   the capture: the evidence blob embeds a 32-byte nonce at bytes [4:36]
   which is **exactly the TDX quote's `report_data[0:32]`** — i.e.
   SHA256(url_nonce || e2e_pubkey), hardware-bound by the TD. Policy
   (recorded in `verifiers/nvidia_nras.py`):
   (a) every item's embedded nonce must equal the quote's `report_data[0:32]`
   (an item minted for any other TD does not count); (b) the NRAS response's
   platform JWT must verify — `kid` selects a key from NVIDIA's published
   JWKS (pinned fixture `tests/fixtures/nras_jwks.json`, capture time + URL
   inside), the key's x5c leaf signature must verify under an intermediate
   whose SPKI digest is pinned, JWS signature valid — and carry
   `x-nvidia-overall-att-result` true/"PASS" and `eat_nonce` == the same
   report_data[0:32]; (c) every per-GPU JWT must verify the same way, carry
   the same `eat_nonce`, and `x-nvidia-gpu-attestation-report-nonce-match`
   true; (d) the count of per-GPU tokens (distinct `ueid`) must equal the
   matched golden row's `gpu_count`. Any failure → `gpu_attested` False with
   per-token reason; absent `gpu_evidence` → None with reason (never a
   pass); NRAS transport error → None with reason (unverified, not passed).
   `decode_nvidia_jwt_verdict` in common.py stays (documented legacy, no
   callers); Chutes and Venice never use it.
6. **Serving-code/model gap stays explicit.** `serving_code_attested` remains
   False by construction with the existing explanatory reason; no criterion
   here changes REQUIRED_LAYERS_BY_SHAPE or stage semantics (that is an
   editorial/coverage decision for the owner, recorded in the report).

## Criteria I cannot meet and precise blockers

- **Live keyed Chutes capture from this lane.** `CHUTES_API_KEY` (Bearer
  `cpk_…`) is required by `api.chutes.ai/e2e/instances/{chute_id}` and
  `/instances/{id}/evidence`; this lane must not seek one. The owner made a
  keyed capture on 2026-11-05 19:34 UTC and placed it at
  `/home/amiller/api-glm-run-20261105/captures/chutes-capture-20261105.json`
  (no credential inside). The parts tests use are committed trimmed under
  `tests/fixtures/chutes_capture_sample.json` with capture time/URL; NVIDIA
  NRAS (public) was called live from this lane to appraise them and the
  obtained response pinned as `tests/fixtures/nras_attest_response.json`.
  The live daily adapter path is exercised in CI with the key; unit tests
  mock transport only.
- **Qwen3-32B-TEE evidence.** `/e2e/instances/ac059e33-…` returned 404 on
  2026-11-05 19:34 UTC (chute likely retired); recorded in fixtures and
  report, not silently dropped.
- **October 12 unpublished-image replay (#28 criterion 5).** The `912aec3d` /
  MRTD `ddc6efcd…` quote is not in `data/observations/evidence/` (verified:
  150 Chutes evidence files, none with that MRTD); only its MRTD appears in
  `docs/reference-values.json` via the manual investigation. Evidence gap
  recorded. Substitute: a synthetic valid-signature, unpublished-measurement
  case (mocked transport) proves the mismatch path — rejected as a
  measurement-list mismatch, not a hardware-signature failure (tdx_verified
  stays True).

## Negative controls (each mutated independently must reject)

- Registers: for each retained-real quote, flip one byte in MRTD, RTMR0,
  RTMR1, RTMR2, RTMR3 independently → no golden-row match → row rejected.
- Golden-set policy: golden publication with no matching row (unpublished
  image, tdx_verified still True) → rejected as mismatch.
- Bindings (existing, kept): report_data tamper, invalid quote signature,
  debug flag, cert SPKI mismatch.
- NRAS (real shapes): tampered JWT payload (bad signature), unknown kid,
  verdict FAIL/false, wrong eat_nonce, missing eat_nonce, per-GPU
  `x-nvidia-gpu-attestation-report-nonce-match` false, one per-GPU token
  dropped/duplicated, gpu_evidence item whose embedded nonce ≠ the quote's
  report_data[0:32] (CPU↔GPU association break), token count != gpu_count —
  each independently rejects.
- Pinned-JWKS binding: a token signed by a test key rejected when verifying
  against the pinned production JWKS fixture; a forged JWKS entry without an
  x5c chain, an unpinned intermediate, or coordinates not matching the leaf
  cert each rejects.

## Real evidence used

- `data/observations/evidence/sha256/*.json`: 150 Chutes captures with quote,
  cert, nonce, golden measurements (56+ rows with boot/runtime RTMRs) —
  replayed through register matching and dcap_qvl TCB appraisal.
- `tests/fixtures/chutes_capture_sample.json` (from the owner's keyed capture,
  2026-11-05 19:34 UTC): real `/e2e/instances` + `/instances/<id>/evidence`
  responses incl. `gpu_evidence` (8-GPU and 1-GPU instances) and the real
  measurements publication.
- `tests/fixtures/nras_jwks.json` / `tests/fixtures/nras_attest_response.json`:
  captures from NVIDIA's public JWKS and attest endpoints (capture time + URL
  inside); the pinned GPU trust anchors and a real pass-path NRAS verdict.
- Phala public verifier: replayed one retained quote once, live, to establish
  why `tcb_status` is null (no TCB field in its response).

## Venice extension (owner update 2026-11-05 20:40 UTC)

After Chutes: `verifiers/venice.py` (~125-140) reads the NRAS verdict without
  checking the JWT signature or nonce. Extend the same appraisal: Venice's
  `nvidia_payload` `{nonce, arch, evidence_list}` is submitted to NRAS with
  the payload's nonce asserted equal to **our** fresh request nonce; the
  returned platform/per-GPU JWTs go through the same signature + eat_nonce +
  count appraisal (Venice has no golden gpu_count, so the count check records
  the observed count; pass requires platform + all per-GPU tokens good).
  `/tee/attestation` is unauthenticated: capture a fresh sample with a nonce,
  commit as fixture, negative controls as for Chutes.
