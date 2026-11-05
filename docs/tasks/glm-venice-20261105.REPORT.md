# Venice ACI/1 — milestone report (glm-venice-20261105, epoch 1)

## What changed

- `verifiers/venice.py` — `verify()` gained an optional `nonce` parameter
  (tests inject the capture nonce; the probe path is unchanged) and format
  dispatch: `api_version == "aci/1"` → new `_verify_aci1()`; any other
  non-null `api_version` → hard error (fail closed, no dstack fallback);
  absent → existing dstack path, byte-for-byte unchanged. `_verify_aci1`
  reuses `aci.py` helpers (`_jcs`, `_events_bind_payloads`, `_replayed_rtmr3`,
  `_unique_event`, `_event_payload`, `_event_precedes_boot_boundary`) and the
  existing `phala_tdx` appraisal path; `aci.py` itself was not modified.
  Bindings: quote appraisal (`tdx_verified`), nonce echo + quote reportdata
  second half (`nonce_bound`), reportdata address‖nonce layout + keyset digest
  recompute + signing-key-in-keyset + report_data echo ≡ quote
  (`report_data_binds_key`), keccak derivation (`key_derives_to_address`),
  MRConfigID + RTMR3 event-log replay + pre-boot compose-hash event
  (`compose_hash_committed`). Gateway/backend distinction scored, not assumed:
  `backend_attested` stays False, `attested_cvm: gateway`, the authenticated
  RTMR3 app-id event is recorded, and `unproven_reasons` names what the format
  cannot prove (backend, gpu when omitted, prod_os_image,
  serving_code_attested, code_measurement_reproducible).
- `tests/test_venice_aci1.py` — 21 tests over retained live evidence.
- `tests/fixtures/venice_*` — fresh captures (2026-11-05) from the public
  `https://api.venice.ai/api/v1/tee/attestation?model=<id>&nonce=<64 hex>`
  (no credential; endpoint ignores Authorization): 6 ACI/1 models, 1 dstack
  model (format boundary control), 1 HTTP 404, plus retained Phala appraisals
  for every captured quote — including a genuine `verified: false` appraisal
  for a one-nibble-tampered quote — so tests mock transport only.

## Issue success criteria status

1. **Recognise and verify ACI/1 with aci.py's bindings** — MET. Proven by
   `test_real_aci1_capture_verifies_gateway_bindings` and
   `test_all_retained_aci1_captures_share_one_gateway_cvm` (5 models ×
   retained appraisals; the 6th, `e2ee-qwen3-6-35b-a3b-uncensored-p`, carries
   an nvidia_payload whose NRAS verdict another lane owns — excluded from
   tests, fixture retained). Live end-to-end run against the real endpoint +
   real Phala appraisal also confirmed (valid: True, gateway identified).
2. **Honest row scoring** — MET. `backend_attested=False` always for this
   format; `gpu_attested` None with `gpu_evidence_omitted` reason when absent;
   `unproven_reasons` recorded per field; `compose_hash_committed` is now
   actually computed (was silently `null` before via the dstack path).
   Required-layer coverage for shape `venice` now reads 5/9 on ACI/1 rows
   instead of a specious full pass on echo fields.
3. **Fixtures captured with time and URL** — MET (all fixtures carry
   `captured_at`, full `url` incl. the nonce actually sent, `model`,
   `client_nonce`). `/models` needs a key we do not have; model ids worked
   from `providers/venice.md`, `data/latest.json` and teep docs (blocker
   recorded in the spec).
4. **Negative controls** — MET, all asserted to fail:
   wrong nonce (`test_wrong_nonce_is_rejected`); tampered quote paired with
   its genuine retained failing appraisal
   (`test_tampered_quote_is_rejected_by_real_appraisal`); ignored appraisal
   verdict (`test_appraisal_verdict_is_not_ignored`); bindings taken from the
   appraised body not response echoes
   (`test_bindings_read_the_appraised_quote_body_not_response_echoes`);
   altered event payload with unchanged digest
   (`test_altered_event_payload_with_unchanged_digest_is_rejected`); compose
   claim moved after boot boundary; edited compose manifest; keyset not
   recomputed; signing key outside keyset; report_data echo divergence;
   mismatched signing key (fresh secp256k1 pair) and swapped address; gateway
   quote presented as backend (`serving: "direct"`, `num_gpus: 8` tampered →
   `backend_attested` stays False); unknown/empty `api_version` fails closed;
   missing quote is an error; the 404 capture path; dstack path regression on
   a real dstack capture.

## Test-changes note

- New `tests/test_venice_aci1.py::test_dstack_capture_still_verifies_through_the_dstack_path`
  does not assert `valid` (unlike the old behaviour implied) because that
  dstack capture carries an `nvidia_payload` and its NRAS verdict
  (`gpu_error: "'hex'"`) is owned by the nvidia-nras lane; the four crypto
  bindings are asserted instead. No existing test was modified.

## Validation status

- Full suite: `~/.local/bin/uv run --extra dev --extra nearai pytest -q` →
  173 passed (includes the 21 new tests).
- Live collection: yes — the fixtures above, plus one live adapter run
  (2026-11-05) against `e2ee-glm-5-2-p` through the real Phala verifier.
- Not proved by this change (unchanged, stated in details): the inference
  host remains unattested (ACI/1 names no model host); no independent pin of
  the gateway app id / KMS root (teep pins them TOFU; we record the
  authenticated app-id event but do not treat first-seen as accepted); the
  receipt/paid path is untested (needs an API key).

## Follow-up outside this lane's scope

- `providers/venice.md` "Wire protocol" still says "This repo's verifier does
  not speak ACI and so does not see it" — now stale. Provider prose needs
  Astra framing/review per AGENTS.md, so it was left untouched here.
- The dashboard snapshot will pick the new scoring up on the next probe run;
  no snapshot data was modified by hand.

## Blockers

- `/api/v1/models` and `/chat/completions` require a Venice API key not held
  here (recorded in spec); everything else in the brief is done.
