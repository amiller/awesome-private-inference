# Venice ACI/1 gateway-format attestation — lane spec (glm-venice-20261105)

Issue: Venice's `/api/v1/tee/attestation` now answers some models with the
`api_version: "aci/1"` gateway format (the private-ai-gateway CVM described in
`providers/venice.md` and teep's `docs/attestation_gaps/venice_aci_gateway.md`).
`verifiers/venice.py` does not recognise the format: today it feeds those bodies
through the dstack path, which reads only the top-level echo fields
(`intel_quote`, `signing_address`, `signing_public_key`) and records
`valid: true / outcome: verified` while scoring the **gateway's** quote as if it
were the model's attestation (`compose_hash_committed: null`, no keyset check,
no gateway/backend distinction). Confirmed live 2026-11-05 and in
`data/latest.json` (`e2ee-gpt-oss-120b-p`, adapter_accepted 2026-11-04).

## Success criteria from the issue

1. Recognise the ACI/1 format in `verifiers/venice.py` and verify it with the
   same bindings `verifiers/aci.py` applies: quote appraisal via the existing
   `phala_tdx` path, report_data binding to our nonce and the signing key,
   gateway/backend distinction. Reuse aci.py's parsing/binding helpers
   (`_jcs`, `_events_bind_payloads`, `_replayed_rtmr3`, `_unique_event`,
   `_event_payload`, `_event_precedes_boot_boundary`) rather than duplicating
   them; aci.py itself changes only to expose an existing function if needed.
2. Score the Venice row honestly: anything the format does not prove stays
   unproven with its reason (`backend_attested` False, GPU/prod-OS/serving-code/
   reproducible-measurement reported missing/unproven, not green).
3. Capture fresh samples from the unauthenticated
   `GET https://api.venice.ai/api/v1/tee/attestation?model=<id>&nonce=<64 hex>`
   for the models that return ACI/1, committed as fixtures with capture time
   and URL. Model ids worked from known ids (providers/venice.md,
   data/latest.json, teep docs); `/models` needs a key we do not have.
4. Negative controls, each asserted to FAIL on its own: wrong nonce; altered
   signed field (event-log payload that must replay into the quote's RTMR3;
   quote/appraisal pairing; report_data echo divergence); mismatched signing
   key/address; gateway quote presented as backend (provider-asserted
   `serving`/`num_gpus` cannot flip `backend_attested`). Plus fail-closed
   format detection: an unknown `api_version` must error, never fall back to
   the dstack path.

## Evidence captured (public endpoint, no credential needed)

`tests/fixtures/venice_aci1_<model>.json` — wrapper
`{captured_at, url, model, client_nonce, response}`. Captured 2026-11-05,
sequential requests (Venice rate-limits parallel probes):

- ACI/1: `e2ee-gpt-oss-120b-p`, `e2ee-glm-5-2-p`, `e2ee-glm-5-1`, `e2ee-glm-5`,
  `e2ee-gpt-oss-20b-p`, `e2ee-qwen3-6-35b-a3b-uncensored-p`
- dstack (format boundary control): `e2ee-qwen3-6-35b-a3b`
- 404 (no attestation): `e2ee-gemma-4-31b`, `e2ee-venice-uncensored-24b-p`

Retained Phala appraisals (public verifier, captured 2026-11-05):
`tests/fixtures/venice_aci1_phala_appraisal_<model>.json` for
`e2ee-glm-5-2-p` and `e2ee-gpt-oss-120b-p`, so tests replay the real appraisal
instead of a synthetic `{"verified": true}` (mocks are transport-only).

## Bindings the ACI/1 path applies

- Format: `api_version == "aci/1"` → ACI/1 path; any other non-empty
  `api_version` → error (fail closed); absent → existing dstack path unchanged.
- `tdx_verified`: `phala_tdx.verify_tdx_quote(attestation.evidence.quote)`
  (existing path, same as aci.py). The quote sent for appraisal must be exactly
  the evidence bytes; a diverging top-level `intel_quote` is recorded and the
  nested field wins (teep's rule).
- `nonce_bound`: response echoes our client nonce (`nonce`, `nonce_source ==
  "client"`) AND the quote's 64-byte reportdata ends with our nonce bytes
  (Venice's gateway uses the dstack layout: address‖zero-pad‖nonce — teep
  `reportdata.go`).
- `report_data_binds_key`: quote reportdata[:32] binds the keccak-derived
  signing address and our nonce (`phala_report_data_binds_addr_nonce`), the
  response's `attestation.report_data` echo equals the quote's reportdata, the
  served `workload_keyset_digest` recomputes from the JCS keyset (aci `_jcs`),
  and the signing key is a member of the keyset's `e2ee_public_keys`.
- `key_derives_to_address`: `keccak_eth_address(signing_public_key) ==
  signing_address` (existing check).
- `compose_hash_committed`: the dstack MRConfigID rule on
  `evidence.app_compose` AND the event log replays into the quote's RTMR3 with
  per-event digest recomputation AND the unique `compose-hash` event precedes
  `boot-mr-done` and its payload equals sha256(app_compose) — aci.py helpers.
- Gateway/backend distinction: the attested CVM is the gateway — recorded
  `service_capabilities.serving`, `vm_config.num_gpus`,
  `downstream_tls_binding`, `source_provenance.repo_url`, and the
  hardware-bound RTMR3 `app-id` event. `backend_attested` stays False for this
  format regardless of provider-asserted fields (teep's `aci_backend_named`).
- GPU: ACI/1 captures carry `gpu_evidence_omitted: true` and no
  `nvidia_payload` → `gpu_attested` stays unproven with that reason. Existing
  NRAS handling for present payloads is untouched (another lane owns it).
- Unproven-with-reason: `prod_os_image`, `serving_code_attested`,
  `code_measurement_reproducible` (image_digest is null in this format),
  `gpu_attested` when omitted, `backend_attested`.

## What I cannot do (blockers)

- `/api/v1/models` and `/chat/completions` need an API key we do not hold, so
  the model list is worked from known ids and the receipt path is untested —
  same status as the existing dstack row.
- No independent pin of the gateway app id / KMS root: teep pins them TOFU; our
  row records the authenticated app-id event value in details but does not
  treat first-seen as an accepted value (registry rule: a newly observed hash
  is not an acceptance).

## Negative controls (tests/test_venice_aci1.py, real fixtures)

1. wrong nonce → nonce_bound/report_data_binds_key False, valid False
2. event-log payload altered (digests unchanged) → event/compose binding False
3. event appended after boot boundary → compose binding False
4. response `report_data` echo diverges from quote → report_data_binds_key False
5. keyset mutated (digest not recomputed) → report_data_binds_key False
6. signing key / address swapped → key_derives_to_address and binding False
7. appraisal says not-verified / tampered appraisal reportdata → tdx_verified
   or binding False
8. `serving: "direct"` + `num_gpus: 8` tampered → backend_attested stays False
9. `api_version: "aci/2"` → hard error, no dstack fallback
10. dstack-format fixture still parses through the dstack path (regression)
