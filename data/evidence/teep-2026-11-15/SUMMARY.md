# teep refresh 2026-11-15 (zed)

teep commit: `6548996bb53ffa74e05d2b2f52e71534d1650149 Merge pull request #235 from mikeperry-tor/google-ctfix`  
binary: `/data/amiller/teep-refresh-20261115/teep-bin` (go1.27.4)  
go test ./...: exit 0 — 27 packages ok, 0 FAIL lines (log: go-test.log)

teep `verify` has no JSON output; the evidence of record per run is `stdout.txt` (report), `capture/*/report.txt`, `capture/*/manifest.json` (teep-native JSON: nonce, E2EE probe outcome, errors) and `capture/*/responses/` (raw HTTP). Factor values below are parsed from stdout.txt by summarize.py. "absent" = factor line not in report. Cell = result [E]nforced/[A]llowed: detail.

## Notes (manual, 2026-11-15)

- venice: every run has `e2ee_usable` FAIL [ALLOWED] "HTTP 401"; the captured probe response body is `{"error":"Authentication failed"}`. A plain `curl` POST to `https://api.venice.ai/api/v1/chat/completions` with `$VENICE_API_KEY` from `~/.config/private-inference.env` also returned 401, so the 401 reproduces outside teep. Attestation fetches (`/api/v1/tee/attestation`) returned 200.
- phalacloud qwen/qwen3.8-27b: report shows 0 enforced failures, but teep exited 1 with `verification failed: capture self-check: reverify report differs from capture`.
- tinfoil_v3_cloud: no key on zed; teep refuses: `provider "tinfoil_v3_cloud" not configured (set TINFOIL_API_KEY ...)`.
- nearcloud z-ai/glm-5.3-flash has two runs (harness validation 165832Z, sweep 165950Z). No `Instances:` line was printed for nearcloud Qwen/Qwen3.8-27B.
- Key leak check: `grep -rlF` for the full key over each run dir found 0 files in all runs (run-20261115.log).


## chutes / Qwen/Qwen3.8-27B-TEE  (20261115T170040Z)

- dir: `captures/chutes/Qwen_Qwen3.8-27B-TEE/20261115T170040Z`
- exit code: 0
- score: Score: 20/25 passed, 1 skipped, 4 failed (0 enforced, 4 allowed), 14 n/a
- Hardware: intel-tdx
- Candidates: 13/68 evaluated
- enforced failures: none
- allowed failures: nonce_match, cpu_gpu_chain, measured_model_weights, cpu_id_registry

| factor | result | detail |
|---|---|---|
| nonce_match | FAIL [A] | no echoed nonce; freshness rests on tee_reportdata_binding |
| tls_key_binding | absent |  |
| e2ee_capable | pass [E] | ML-KEM-768 public key valid (1184 bytes); post-quantum E2EE key exchange possible |
| e2ee_usable | pass [E] | E2EE chutes ML-KEM-768: 30 encrypted chunks decrypted; non-standard response headers: Alt-Svc: clear; Via: 1.1 google; X-Chutes-Quota-Remaining: 0; X-Chutes-Quota-Total: 0; X-Chutes-Quota-Used: 0; X-Chutes-Rl-User: 60 |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [A] | SPDM: 1 GPU cert chains and ECDSA P-384 signatures verified (arch: BLACKWELL) |
| nvidia_nonce_client_bound | pass [E] | SPDM evidence of 1 GPUs answers the requester nonce derived from the client nonce and the instance key |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | n/a [-] | Chutes uses cosign image admission + IMA, not docker-compose |
| event_log_integrity | n/a [-] | Chutes RTMR verification is validator-side; event log not exposed |
| sigstore_verification | n/a [-] | Chutes cosign verification is validator-side only |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## chutes / zai-org/GLM-5.2-TEE  (20261115T170100Z)

- dir: `captures/chutes/zai-org_GLM-5.2-TEE/20261115T170100Z`
- exit code: 1
- score: Score: 19/25 passed, 1 skipped, 5 failed (1 enforced, 4 allowed), 14 n/a
- Hardware: intel-tdx
- Candidates: 1/6 evaluated
- enforced failures: tee_measurement
- allowed failures: nonce_match, cpu_gpu_chain, measured_model_weights, cpu_id_registry

| factor | result | detail |
|---|---|---|
| nonce_match | FAIL [A] | no echoed nonce; freshness rests on tee_reportdata_binding |
| tls_key_binding | absent |  |
| e2ee_capable | pass [E] | ML-KEM-768 public key valid (1184 bytes); post-quantum E2EE key exchange possible |
| e2ee_usable | pass [E] | E2EE chutes ML-KEM-768: 298 encrypted chunks decrypted; non-standard response headers: Alt-Svc: clear; Via: 1.1 google; X-Chutes-Quota-Remaining: 0; X-Chutes-Quota-Total: 0; X-Chutes-Quota-Used: 0; X-Chutes-Rl-User: 60 |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [A] | SPDM: 8 GPU cert chains and ECDSA P-384 signatures verified (arch: BLACKWELL) |
| nvidia_nonce_client_bound | pass [E] | SPDM evidence of 8 GPUs answers the requester nonce derived from the client nonce and the instance key |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | FAIL [E] | MRSEAM not in policy allowlist: f40772d82608da54... |
| compose_binding | n/a [-] | Chutes uses cosign image admission + IMA, not docker-compose |
| event_log_integrity | n/a [-] | Chutes RTMR verification is validator-side; event log not exposed |
| sigstore_verification | n/a [-] | Chutes cosign verification is validator-side only |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## nearcloud / Qwen/Qwen3.8-27B  (20261115T170019Z)

- dir: `captures/nearcloud/Qwen_Qwen3.8-27B/20261115T170019Z`
- exit code: 0
- score: Score: 36/46 passed, 0 skipped, 10 failed (0 enforced, 10 allowed), 8 n/a
- Hardware: intel-tdx
- App: dstack-nvidia-0.5.12
- enforced failures: none
- allowed failures: tee_boot_config, response_schema, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification, gateway_tee_measurement, gateway_tee_hardware_config, gateway_tee_boot_config, gateway_cpu_id_registry

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [E] | enclave ed25519 public key valid; E2EE key exchange possible (ed25519) |
| e2ee_usable | pass [E] | E2EE nearcloud: 35 encrypted fields decrypted across 38 chunks |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## nearcloud / z-ai/glm-5.3-flash  (20261115T165832Z)

- dir: `captures/nearcloud/z-ai_glm-5.3-flash/20261115T165832Z`
- exit code: 0
- score: Score: 36/46 passed, 0 skipped, 10 failed (0 enforced, 10 allowed), 8 n/a
- Hardware: intel-tdx
- App: dstack-nvidia-0.5.11
- Instances: 3 (19aea1693533dc2d529db03e3f725f20bde8d66d, a8a25faab3ef437d2da809382e05e59e3c55a0f5, cc796618bcd5a6b22907d8de7ac414a968d6a1aa)
- enforced failures: none
- allowed failures: tee_boot_config, response_schema, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification, gateway_tee_measurement, gateway_tee_hardware_config, gateway_tee_boot_config, gateway_cpu_id_registry

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [E] | enclave ed25519 public key valid; E2EE key exchange possible (ed25519) |
| e2ee_usable | pass [E] | E2EE nearcloud: 45 encrypted fields decrypted across 48 chunks |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | instance 19aea1693533dc2d529db03e3f725f20bde8d66d: Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | instance 19aea1693533dc2d529db03e3f725f20bde8d66d: CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | instance 19aea1693533dc2d529db03e3f725f20bde8d66d: no model weight hashes |

## nearcloud / z-ai/glm-5.3-flash  (20261115T165950Z)

- dir: `captures/nearcloud/z-ai_glm-5.3-flash/20261115T165950Z`
- exit code: 0
- score: Score: 36/46 passed, 0 skipped, 10 failed (0 enforced, 10 allowed), 8 n/a
- Hardware: intel-tdx
- App: dstack-nvidia-0.5.11
- Instances: 3 (19aea1693533dc2d529db03e3f725f20bde8d66d, a8a25faab3ef437d2da809382e05e59e3c55a0f5, cc796618bcd5a6b22907d8de7ac414a968d6a1aa)
- enforced failures: none
- allowed failures: tee_boot_config, response_schema, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification, gateway_tee_measurement, gateway_tee_hardware_config, gateway_tee_boot_config, gateway_cpu_id_registry

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [E] | enclave ed25519 public key valid; E2EE key exchange possible (ed25519) |
| e2ee_usable | pass [E] | E2EE nearcloud: 104 encrypted fields decrypted across 107 chunks |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | instance 19aea1693533dc2d529db03e3f725f20bde8d66d: Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | instance 19aea1693533dc2d529db03e3f725f20bde8d66d: CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | instance 19aea1693533dc2d529db03e3f725f20bde8d66d: no model weight hashes |

## neardirect / Qwen/Qwen3.8-27B  (20261115T165927Z)

- dir: `captures/neardirect/Qwen_Qwen3.8-27B/20261115T165927Z`
- exit code: 0
- score: Score: 28/33 passed, 0 skipped, 5 failed (0 enforced, 5 allowed), 6 n/a
- Hardware: intel-tdx
- App: dstack-nvidia-0.5.12
- enforced failures: none
- allowed failures: tee_boot_config, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [E] | enclave ed25519 public key valid; E2EE key exchange possible (ed25519) |
| e2ee_usable | pass [E] | E2EE neardirect: 46 encrypted fields decrypted across 49 chunks |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## neardirect / z-ai/glm-5.3-flash  (20261115T165919Z)

- dir: `captures/neardirect/z-ai_glm-5.3-flash/20261115T165919Z`
- exit code: 0
- score: Score: 28/33 passed, 0 skipped, 5 failed (0 enforced, 5 allowed), 6 n/a
- Hardware: intel-tdx
- App: dstack-nvidia-0.5.12
- enforced failures: none
- allowed failures: tee_boot_config, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [E] | enclave ed25519 public key valid; E2EE key exchange possible (ed25519) |
| e2ee_usable | pass [E] | E2EE neardirect: 30 encrypted fields decrypted across 33 chunks |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [E] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## phalacloud / qwen/qwen3.8-27b  (20261115T170151Z)

- dir: `captures/phalacloud/qwen_qwen3.8-27b/20261115T170151Z`
- exit code: 1
- score: Score: 17/47 passed, 14 skipped, 16 failed (0 enforced, 16 allowed), 7 n/a
- enforced failures: none
- allowed failures: nonce_match, tee_quote_present, tee_quote_structure, tee_cert_chain, tee_quote_signature, tee_debug_disabled, tee_reportdata_binding, nvidia_payload_present, aci_backend_named, cpu_gpu_chain, measured_model_weights, component_recognition, cpu_id_registry, compose_binding, gateway_nonce_match, gateway_tee_measurement
- stderr ERROR lines:
```
time=2026-11-15T11:02:03.065-06:00 level=ERROR msg="verification failed: capture self-check: reverify report differs from capture"
```

| factor | result | detail |
|---|---|---|
| nonce_match | FAIL [A] | no echoed nonce; freshness rests on gateway_tee_reportdata_binding |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [A] | enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible |
| e2ee_usable | pass [A] | E2EE v2 secp256k1: 17 encrypted fields decrypted across 20 chunks |
| aci_key_custody | pass [E] | keyset digest matches; signing key is a keyset e2ee key; e2ee key custody chain verified to accepted KMS root (02a335aea3df11d4...) for app 89c51ab856bee41e... |
| aci_session_verified | pass [E] | 8 attested sessions pinned: genuine TDX and GPU with allowed MRTD/MRSEAM, workload policy not checked (9 refused; first: not fetched: the session evidence limit of one verification is reached) |
| aci_receipt_verified | pass [E] | receipt verified, including the request hash |
| nvidia_signature | absent |  |
| nvidia_nonce_client_bound | absent |  |
| tee_tcb_current | absent |  |
| tee_debug_disabled | FAIL [A] | no TEE quote/report available; cannot check debug flag |
| tee_measurement | absent |  |
| compose_binding | FAIL [A] | ACI/1 publishes no compose manifest for the inference host; workload composition is not verifiable |
| event_log_integrity | absent |  |
| sigstore_verification | pass [A] | 3 component digest(s) found in Sigstore transparency log; 2 not Sigstore-signed (compose-pinned) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## phalacloud / z-ai/glm-5.3-flash  (20261115T170116Z)

- dir: `captures/phalacloud/z-ai_glm-5.3-flash/20261115T170116Z`
- exit code: 1
- score: Score: 14/47 passed, 16 skipped, 17 failed (1 enforced, 16 allowed), 7 n/a
- enforced failures: aci_session_verified
- allowed failures: nonce_match, tee_quote_present, tee_quote_structure, tee_cert_chain, tee_quote_signature, tee_debug_disabled, tee_reportdata_binding, nvidia_payload_present, aci_backend_named, cpu_gpu_chain, measured_model_weights, component_recognition, cpu_id_registry, compose_binding, gateway_nonce_match, gateway_tee_measurement

| factor | result | detail |
|---|---|---|
| nonce_match | FAIL [A] | no echoed nonce; freshness rests on gateway_tee_reportdata_binding |
| tls_key_binding | pass [E] | TLS transport SPKI bound to attestation |
| e2ee_capable | pass [A] | enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible |
| e2ee_usable | absent |  |
| aci_key_custody | pass [E] | keyset digest matches; signing key is a keyset e2ee key; e2ee key custody chain verified to accepted KMS root (02a335aea3df11d4...) for app 89c51ab856bee41e... |
| aci_session_verified | FAIL [E] | attested sessions: session list entry 2: channel_binding[0]: type "proxy_image_sha256" is not a channel binding of ACI/1 |
| aci_receipt_verified | absent |  |
| nvidia_signature | absent |  |
| nvidia_nonce_client_bound | absent |  |
| tee_tcb_current | absent |  |
| tee_debug_disabled | FAIL [A] | no TEE quote/report available; cannot check debug flag |
| tee_measurement | absent |  |
| compose_binding | FAIL [A] | ACI/1 publishes no compose manifest for the inference host; workload composition is not verifiable |
| event_log_integrity | absent |  |
| sigstore_verification | pass [A] | 3 component digest(s) found in Sigstore transparency log; 2 not Sigstore-signed (compose-pinned) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## tinfoil_v3_cloud / deepseek-v4-1-flash  (20261115T170203Z)

- dir: `captures/tinfoil_v3_cloud/deepseek-v4-1-flash/20261115T170203Z`
- exit code: 1
- score: no report
- enforced failures: none
- allowed failures: none
- stderr ERROR lines:
```
time=2026-11-15T11:02:03.090-06:00 level=ERROR msg="verification failed: load config: provider \"tinfoil_v3_cloud\" not configured (set TINFOIL_API_KEY or add [providers.tinfoil_v3_cloud] to config)"
```

## venice / e2ee-glm-5-3-flash  (20261115T165858Z)

- dir: `captures/venice/e2ee-glm-5-3-flash/20261115T165858Z`
- exit code: 0
- score: Score: 24/33 passed, 1 skipped, 8 failed (0 enforced, 8 allowed), 6 n/a
- Hardware: intel-tdx
- Upstream: z-ai/glm-5.3-flash
- App: dstack-nvidia-0.5.11
- Candidates: 1/3 evaluated
- enforced failures: none
- allowed failures: tee_hardware_config, tee_boot_config, response_schema, e2ee_usable, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) (client-supplied) |
| tls_key_binding | absent |  |
| e2ee_capable | pass [A] | enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible (ecdsa) |
| e2ee_usable | FAIL [A] | HTTP 401 |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [A] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## venice / e2ee-glm-5-3-p  (20261115T165902Z)

- dir: `captures/venice/e2ee-glm-5-3-p/20261115T165902Z`
- exit code: 0
- score: Score: 19/45 passed, 11 skipped, 15 failed (0 enforced, 15 allowed), 9 n/a
- Upstream: z-ai/glm-5.3
- Candidates: 1/1 evaluated
- enforced failures: none
- allowed failures: tee_quote_present, tee_quote_structure, tee_cert_chain, tee_quote_signature, tee_debug_disabled, response_schema, tee_reportdata_binding, e2ee_usable, aci_backend_named, cpu_gpu_chain, measured_model_weights, component_recognition, cpu_id_registry, compose_binding, gateway_tee_measurement

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) (client-supplied) |
| tls_key_binding | absent |  |
| e2ee_capable | pass [A] | enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible (ecdsa) |
| e2ee_usable | FAIL [A] | HTTP 401 |
| aci_key_custody | pass [E] | keyset digest matches; signing key is a keyset e2ee key; e2ee key custody chain verified to accepted KMS root (02a335aea3df11d4...) for app 89c51ab856bee41e... |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [A] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: BLACKWELL) |
| nvidia_nonce_client_bound | pass [A] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | absent |  |
| tee_debug_disabled | FAIL [A] | no TEE quote/report available; cannot check debug flag |
| tee_measurement | absent |  |
| compose_binding | FAIL [A] | ACI/1 publishes no compose manifest for the inference host; workload composition is not verifiable |
| event_log_integrity | absent |  |
| sigstore_verification | pass [A] | 3 component digest(s) found in Sigstore transparency log; 2 not Sigstore-signed (compose-pinned) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |

## venice / e2ee-qwen3-8-27b  (20261115T165916Z)

- dir: `captures/venice/e2ee-qwen3-8-27b/20261115T165916Z`
- exit code: 0
- score: Score: 24/33 passed, 1 skipped, 8 failed (0 enforced, 8 allowed), 6 n/a
- Hardware: intel-tdx
- Upstream: Qwen/Qwen3.8-27B
- App: dstack-nvidia-0.5.12
- Candidates: 1/1 evaluated
- enforced failures: none
- allowed failures: tee_hardware_config, tee_boot_config, response_schema, e2ee_usable, cpu_gpu_chain, measured_model_weights, cpu_id_registry, sigstore_verification

| factor | result | detail |
|---|---|---|
| nonce_match | pass [E] | nonce matches (64 hex chars) (client-supplied) |
| tls_key_binding | absent |  |
| e2ee_capable | pass [A] | enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible (ecdsa) |
| e2ee_usable | FAIL [A] | HTTP 401 |
| aci_key_custody | n/a [-] | not ACI/1 format |
| aci_session_verified | n/a [-] | not the canonical ACI/1 report |
| aci_receipt_verified | n/a [-] | not the canonical ACI/1 report |
| nvidia_signature | pass [E] | EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER) |
| nvidia_nonce_client_bound | pass [E] | EAT nonce matches client nonce (8 GPUs) |
| tee_tcb_current | pass [A] | TCB is UpToDate per Intel PCS |
| tee_debug_disabled | pass [E] | debug bit is 0 (production enclave) |
| tee_measurement | pass [E] | MRTD/MRSEAM policy matched |
| compose_binding | pass [E] | sha256(app_compose) matches MRConfigID |
| event_log_integrity | pass [E] | event log replayed (30 entries), all 4 RTMRs match quote |
| sigstore_verification | FAIL [A] | Sigstore check failed for sha256:079a14b41deb11e0 (HTTP 404) |
| cpu_gpu_chain | FAIL [A] | CPU-GPU attestation not bound |
| measured_model_weights | FAIL [A] | no model weight hashes |
