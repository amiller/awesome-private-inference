# ACI gateway -> Tinfoil upstream: what a verifying client gets (2026-11-15)

Sources: private-ai-gateway @ e9b6ae8a; confidential-model-router @ ef64384 (pins tinfoil-go v0.17.0-rc.4); tinfoil Python SDK 0.12.1 sdist (hash matches gateway uv.lock:1767). Live: tee.redpill.ai. Tags: [src] read in source, [obs] observed live, [inf] inferred.

## Verdict

**(a) No.** The gateway attests Tinfoil's router enclave (`inference.tinfoil.sh`, repo `tinfoilsh/confidential-model-router`), not the per-model enclave that runs the model. The client gets the router's code measurement and release digest. The per-model enclave's config repo, Sigstore release and weights never reach the client. The Tinfoil router checks them internally, and the router also sees the prompt in plaintext.

**(b) Router only.** The signed receipt's `upstream.verified` event cites a session that names the router host and its TLS SPKI. Nothing names the model enclave that served the request. The session is a cached SDK summary with no quote and no nonce.

## Gateway path [src]

- `TinfoilProviderVerifier` spawns the Python bridge `scripts/provider_verifier/tinfoil.py` (providers.rs:155-190, external.rs:1-6). The bridge uses Tinfoil's Python SDK, not tinfoil-go.
- The host defaults to `https://inference.tinfoil.sh` and the repo to `confidential-model-router`. The bridge calls `SecureClient(enclave, repo).verify()` (tinfoil.py:49-59). `Tinfoil` is `PerRouter` (upstream_config/mod.rs:204-209), so one session covers every Tinfoil model.
- The "fail closed unless router-scoped" check (tinfoil.py:106-124) accepts if `selected_router_endpoint` is non-empty. SDK 0.12.1 always sets it to the enclave host (client.py:390-394), so the check passes whatever host it is given. In practice the repo default is what enforces router scope.
- No nonce: SDK `fetch_attestation` is a plain GET of `/.well-known/tinfoil-attestation` (attestation/attestation.py:87-90). Sigstore matching (`verify_code`, `compare_measurements`) is done against the router repo.
- The gateway never contacts `*.containers.tinfoil.dev`, so the teep e732070 failure mode does not arise.
- The forward TLS connection is pinned to the attested router SPKI (tinfoil.py:125-137; upstream/openai.rs:328-345). The HPKE key is recorded but unused: plain TLS, no EHBP. The backend sets `served_instance_id: None` (openai.rs:322).
- The evidence is the SDK summary JSON (tinfoil.py:75-86). The code itself says "Tinfoil's SDK returns a summary without the authenticated quote" (external.rs:422-426).
- `serving_software_known_good` (claims.rs:232-250, 410-427) just formats the router's `config_repo` and `release_digest`. The label says serving software, but it names router code.
- The receipt event is `{result, required, model_id, session_id}` (receipt.rs:288-315).
- Inside the router: each model enclave is verified with tinfoil-go `NewHandle(host, model.Repo).Verify()` (manager.go:318, verification.go:21-27). That uses a fresh nonce (tinfoil-go v0.17.0-rc.4 enclave/verify.go:41-52) and pins TLS (verification.go:84-97). gpt-oss-120b maps to `tinfoilsh/confidential-gpt-oss-120b` (config.yml:29-30). The router sets `Tinfoil-Enclave: <host>` (manager.go:596). The gateway never reads it (grep finds no hits).

## Live [obs]

Everything is under `zed:/data/amiller/teep-refresh-20261115/captures/phalacloud-tinfoil/openai_gpt-oss-120b/20261115T182859Z/` (key-leak grep 0).

- `gateway-state/models.json`: 6 models list `tinfoil` as a provider. Three use only Tinfoil: voxtral-small-24b-2507, llama-3.3-70b-instruct and gpt-oss-120b. `gateway-state/sessions.json`: 81 sessions, one of them Tinfoil, `2ed1c71b…dd7d`. Its endpoint is `inference.tinfoil.sh`, its SPKI `e5db636a…`, and its repo confidential-model-router at release `cb88bff7…`, with all four SDK steps passing. `model_weights_provenance`, `os_known_good` and `gpu_attested` are `unknown`. The evidence in `gateway-state/session-tinfoil.json` matches its digest but holds no quote and no nonce.
- The live `inference.tinfoil.sh` leaf SPKI sha256 equals `e5db636a…`.
- teep (`capture/…/report.txt`, `stdout.txt`, exit 1): the capture's sessions response (`0034_…aci_sessions.body`) contains only `2ed1c71b…`. All gateway factors pass (quote, chain, signature, debug off, REPORTDATA binding keyset and client nonce, compose, event log, `aci_key_custody`, `tls_key_binding`) except the MRTD allowlist check, which is allowed to fail. `aci_session_verified` FAILS and is enforced: "teep does not verify the evidence of private-ai-verifier/tinfoil/v1" (teep phalacloud/sessions.go:106). `aci_backend_named` and `measured_model_weights` also fail. teep sent no inference.
- Manual request pinned with `aci_session_ids=[2ed1c71b…]` (`manual-receipt/`): receipt `rcpt-c8ac8ff85bb8519c726f427a` records `route.selected tinfoil:openai/gpt-oss-120b` and `upstream.verified {model_id: gpt-oss-120b, verified, required, session_id: 2ed1c71b…}`. The sha256 of `request.json` and `response.json` equal the `request.received` and `response.returned` hashes. `workload_keyset_digest` equals the digest teep bound to the gateway quote. No `Tinfoil-Enclave` header reached the client. The session was established 171 s before `served_at` and has a 1 h TTL, so no verification ran for this request.

## Verifiable vs the gateway's word

| Item | Client verifies | Taken on trust |
|---|---|---|
| Gateway quote, compose, keyset | yes [obs, teep] | |
| Receipt body hashes | yes [obs] | |
| Receipt signature, session-id recompute | possible per spec §9.2-9.3 [src]; not run by me | |
| Router TLS SPKI | matches the live cert [obs] | that it was attested when the session was made (no quote kept) |
| Router code / release | only by re-attesting the router yourself [inf] | the recorded SDK summary |
| Forwarding over the pinned channel | no | gateway code, attested via compose [inf] |
| Which model enclave decrypted the prompt | no | recorded nowhere |
| Model enclave repo, release, weights (dm-verity per spec/related-work.md:40) [inf] | no | Tinfoil router |
| Upstream freshness for this request | no | cached session, no nonce |

## Not established

- Whether the deployed gateway image is e9b6ae8a.
- How router release `cb88bff7…` maps to the router source I read (ef64384).
- Which model enclave served the receipt above.
- Whether the router exposes per-model verification status publicly (not queried).
