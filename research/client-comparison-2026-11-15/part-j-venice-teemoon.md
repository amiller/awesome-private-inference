# Verifying clients, part J: Venice E2EE library and proxies, teemoon (2026-11-15)

Source review only. Nothing was built or run, and no unit tests were run (no `node_modules` or cargo, and the brief ruled out network installs). Cells use part B's values: **E** enforced (the client refuses), **C** checked but only logged or shown, **N** not checked, n/a. teemoon adds **S** (soft): the send degrades to a confirm dialog and one tap sends anyway. M0dEx and teemoon were read by delegated reviewers; I re-read the load-bearing lines myself (M0dEx attestation.rs:8-16, 470-486, 600-614, 725-752, config/default.toml; teemoon AttestationService.kt:100-142, DcapVerification.kt:36-52, AttestationRecord.kt:130-170).

Commits:
- elkimek `venice-e2ee` `d8e37d15` (v0.5.5, 2026-11-03). This is the same commit as the older clone part B reviewed, so the library's behavior has not changed. jooray's fork `ac05b0d` has a byte-identical `attestation.ts`, `nvidia.ts` and `nras-jwks.ts`; its `aci.ts`, `session.ts`, `crypto.ts`, `receipt.ts` and `index.ts` differ.
- clawdbotatg `venice-e2ee-proxy` `4311d554` (2026-09-16)
- M0dEx `venice-e2ee-proxy` `0999259d` (2026-08-12)
- teemoon-android `63cef559` (2026-10-23)
- teemoon-ios `ab64f151` (2026-10-23). It is public.

Path keys:
- EL: elkimek `src/`.
- C: clawdbotatg `src/`.
- M: M0dEx `src/`.
- T: teemoon-android `confidential/src/main/kotlin/ai/teemoon/confidential/`. Paths starting `app/`, `inference/` or `providers/` are under their own module roots.

## 1. Venice: EL library, clawdbotatg (C), M0dEx (M)

Same axes as part B §4. EL is the library on its own with default options (`createVeniceE2EE`, EL index.ts:28-34). jooray (J) is the strict consumer reviewed in part B.

| Axis | EL (lib defaults) | C | M |
|---|---|---|---|
| Shape handled | Legacy `/api/v1/tee/attestation` only for E2EE (index.ts:48). ACI/1 is a separate API, `verifyAciAttestation` (aci.ts:216), used to anchor receipts, not E2EE. | Legacy only (attestation.ts:43) | Legacy URL only (venice.rs:172-176). ACI/1-shaped bodies are partly parsed: `evidence.quote` and `quote_report_data` are compared with the quote's REPORTDATA (attestation.rs:174-188, 376-393). Keysets, endorsement, sessions, receipts and `downstream_tls_binding` are N. |
| TDX quote | **N by default**: `requireDcap=false` and no `dcapVerifier` (index.ts:30-31). The quote is only parsed, and the README says these are "structural binding checks, not quote authentication" (README.md:5). Opt-in: `@phala/dcap-qvl` with Phala PCCS (dcap.ts:49-53). | **N**: the quote is never parsed. The proxy trusts Venice's `verified: true` (attestation.ts:66-68). The README claims "Intel TDX quote + NVIDIA GPU attestation" checks (README.md:35). | **N**: no QVL crate. `require_tdx=true` always fails with `ExternalVerifierUnavailable` (attestation.rs:602-613), and the default is false (default.toml:27). Venice's `verified` flag is the real gate (attestation.rs:470-477). |
| TCB | With DCAP: UpToDate, SWHardeningNeeded and ConfigurationNeeded* are accepted; OutOfDate is rejected (attestation.ts:434-444). ACI path: same set (aci.ts:436-446). | N | N |
| Debug | E on the unauthenticated quote (attestation.ts:367-370) | C: Venice's `tdx_debug_mode` is logged (attestation.ts:77, 83) | E on unsigned bytes (attestation.rs:571, 678) |
| GPU | **N by default** (`requireGpu=false`, index.ts:33). Opt-in: NRAS with `eat_nonce` = client nonce, plus per-GPU dbgstat/secboot/measres (attestation.ts:455-512). The JWT signature is checked only if a `tokenVerifier` from `createNrasTokenVerifier()` is passed: ES384 pinned, kid from JWKS, iss/exp (nvidia.ts:22-25; nras-jwks.ts:416-479). Otherwise only TLS to NRAS. | N. A Venice-reported NVIDIA failure is not read. | N. `require_nvidia` defaults to `never` (default.toml:28). `when_present`/`required` with a payload always fails, since no verifier is linked; `when_present` with no payload passes (attestation.rs:624-651). |
| Recipient | E (binding): keccak address = REPORTDATA[0:20], nonce = [32:64] raw or SHA-256 (attestation.ts:373-405). The quote is unauthenticated unless DCAP is on. | **N**: the key comes from the JSON `signing_key`, and the nonce check is the JSON echo (attestation.ts:62, 70) | Weak E: a prefix match on any of sha256(pubkey), sha256(address string) or raw address (attestation.rs:729-751). **The nonce is compared with the JSON field only** (:479-486), never with REPORTDATA[32:64]. Zero padding is not checked. |
| Channel | N | N | N (plain rustls webpki) |
| Reply | Plaintext refused (crypto.ts:93-96). A malformed stream or a missing `[DONE]` throws (CHANGELOG 0.5.4). No AAD: chunks can be dropped, reordered or replayed within a session (CHANGELOG 0.5.4). | **Plaintext passes**: content that is not hex is returned as is (e2ee.ts:122-125). Chunks that fail AES-GCM become `""` (e2ee.ts:127-137). Stream read errors and bad JSON lines are swallowed (proxy.ts:249-256). A whole-stream decrypt failure returns the raw ciphertext (proxy.ts:43-46). | Plaintext refused (e2ee.rs:286-289; http.rs:2101-2115). `[DONE]` required but plaintext (http.rs:606-618). No AAD (e2ee.rs:115). |
| Receipts | C: `fetchResponseSignature` and `verifyReceipt` exist (index.ts:183-195; receipt.ts:313), but the caller must invoke them | N | N |
| Code (compose, MRTD) | N by default. `expectedMeasurements` is opt-in and requires DCAP (attestation.ts:425-427, 529-531). There is no compose or event-log handling, so the payload-vs-digest bug class does not arise. | N | N, out of scope by design (attestation.rs:10-11) |
| Model binding | JSON `model` field, E (attestation.ts:314-316). The session is reused only for the same model (index.ts:58-62). | The model is fixed by the CLI flag (server.ts:57-60) | JSON `model` field (attestation.rs:488-497) |
| Fail mode | Any recorded error throws before the key is used (index.ts:97-101) | Fail-closed on the `verified` flag and the nonce echo; fail-open on replies | Fail-closed on what it checks. The server listens on 0.0.0.0:8080 with no client auth (default.toml:2-3), exposing the API key to the LAN. |
| Caching | One session for 30 min, with the client keypair reused (index.ts:22, 58-62) | Model key cached 10 min; fresh client key per request (attestation.ts:14; proxy.ts:62) | Per request by default; sessions last up to 30 min or 100 requests (default.toml:15-19) |
| Reuse | Original. The Python port is `elkimek/venice-e2ee-python` (README.md:23). | Ported from the author's `zkllmapi-v2` (e2ee.ts:4; PLAN.md:80). Does not use EL. | Independent Rust; no credits found |

**ACI/1 and `-p` models.** C and M both fetch only the legacy URL. C passes whatever Venice marks `verified`. M passes `-p` models under the default `require_nvidia=never`. EL's E2EE path behaves as in part B: with `requireGpu`, jooray refuses `-p` models (attestation.ts:514-518); with library defaults they pass. EL's ACI module requires DCAP by default (aci.ts:256), checks REPORTDATA = sha256(JCS statement over the keyset digest), the debug bit, freshness and `keyset_endorsement`, and returns a receipt anchor only when every check passes (aci.ts:216-482). No proxy in this part or part B calls it.

## 2. NEAR: teemoon-android (T); iOS has the same logic

| Axis | Value |
|---|---|
| Route | Gateway report `cloud-api.near.ai/v1/attestation/report` (AttestationService.kt:66-73, 207-222). The model key comes from a race between the direct host listed at `completions.near.ai/endpoints` (providers/EndpointDirectory.kt:116) and the gateway `?model=` (AttestationService.kt:237-243). Inference goes direct when the host is listed, otherwise through the gateway (providers/Provider.kt:97-104). |
| TDX quote | E: on-device `com.phala:dcap-qvl-android` 0.5.2 on the gateway, model and GPU-node quotes (DcapService.kt:24-34, 72-78). Collateral comes straight from Intel PCS (Collateral.kt:171), and the quote fails if collateral is unavailable (DcapService.kt:44-47). A second, hand-written parser must agree on MRCONFIGID and report_data (DcapService.kt:86-90). |
| TCB | **UpToDate and OutOfDate are accepted** with no degrade (DcapVerification.kt:38-50; ConfidentialSession.kt:820-823). SWHardeningNeeded, ConfigurationNeeded and Revoked fail. |
| Debug | N in teemoon code: `tdAttributes` is parsed (TdxQuote.kt:41) and never read. Whether dcap-qvl rejects debug TDs was not checked. |
| GPU | E: NRAS JWT ES384 against NVIDIA JWKS, plus iss, nbf/exp and eat_nonce = client nonce (NrasService.kt:115-173). An NRAS or JWKS outage is S (ConfidentialSession.kt:830, 963). **A missing `nvidia_payload` skips the check silently** (ConfidentialSession.kt:747). |
| Recipient | E: the Ed25519 key must equal model report_data[0:32], with the nonce in [32:64] (AttestationRecord.kt:134-141, 179-207). A key with no model quote is S, so "send anyway" encrypts to an unattested key (ConfidentialSession.kt:859-860, 975-977). |
| Channel | S: a side probe with `include_tls_fingerprint=true` checks live SPKI = `tls_cert_fingerprint` and report_data = sha256(addr‖fp)‖nonce under DCAP (TlsAttestationVerifier.kt:113-167). The inference connection itself is not pinned: no `CertificatePinner` was found. |
| E2EE version | **v2**: `X-Signing-Algo: ed25519`, `X-Encryption-Version: 2`, `X-Encrypt-All-Fields: true` (E2EE.kt:75-77). X25519 + HKDF + XChaCha20-Poly1305 with no AAD (E2EE.kt:183-206). Low-order points are rejected (E2EE.kt:245-261). Content, name, tool_calls and tools are sealed, and a sealing failure refuses before the request leaves the device (inference/OpenAiTransport.kt:391-397). |
| Reply | Plaintext or undecryptable fields fail the turn (inference/SseStreamParser.kt:116-121). Authenticity is C: v2 does not bind the reply key, so [#1061](https://github.com/nearai/cloud-api/issues/1061) is open. `/v1/signature/{id}` is verified against a quote-bound signer (TeeSignature.kt:104-219) but only feeds the UI, not the send policy (TrustVerdict.kt:83-86). |
| Code: gateway compose | E: sha256(app_compose) = compose_hash and MRCONFIGID = `01‖hash` (AttestationRecord.kt:160-169). A missing gateway leg yields null and passes (AttestationService.kt:174-180). |
| Code: model node | **N**: the model leg never reads `tcb_info` or `app_compose`. The GPU leg's compose_hash is only displayed (AttestationService.kt:110). MRTD, RTMR0-3 and the event log are only displayed, with no replay anywhere, so the payload-vs-digest bug class does not arise. There is no compose allowlist and no on-chain check. |
| Code: provenance | S: Sigstore/Fulcio bundles with the SAN pinned to the near.ai workflow, plus the Rekor SET, for `nearai/` and `nearaidev/` images pinned by @sha256 (ProvenanceVerifier.kt:9-25; ProvenanceTypes.kt:60-74). Third-party and tag-pinned images are shown but do not fail, and a 404 lets the send through. |
| compose-manager log | Partly E: the last `compose_up` action's `file_sha256` must match the YAML fetched from GitHub at the logged commit and path; a mismatch blocks (ConfidentialSession.kt:657-697, 812, 956). **The `actions` list is plain JSON**: neither the compose-manager quote nor `actions_hash` is verified (AttestationService.kt:109). A relay can substitute the list, the same gap as hermes (part B §1). |
| Instances | **Only the first entry** of `all_attestations` / `model_attestations` is appraised (AttestationService.kt:134-140). The key and the quote come from that same entry. |
| Model name | Compared with the served `model_name`, but null is accepted (AttestationService.kt:272-273). It is not in report_data. |
| Fail mode | One send policy, ALLOW / CONFIRM / BLOCK (ConfidentialSession.kt:986-998). Pending verdicts refuse, and there is no plaintext fallback for an attested provider (app/ChatViewModel.kt:327-337, 573-587). Verification cannot be switched off. **A failed re-attestation keeps the old record and key with no degrade** (ConfidentialSession.kt:556-560). The maximum age is 10 min (ConfidentialSession.kt:603-619). |
| Reuse | Phala's dcap-qvl Android binding. The TCB and NRAS policy cite NEAR's inference-sdk (DcapVerification.kt:58; NrasService.kt:13-15). `SelfVerifyScript` generates a Python script for the user; its `--full` mode clones nearai-cloud-verifier at an unpinned HEAD and pip-installs it (SelfVerifyScript.kt:549-580). No mention of teep. |
| iOS | Same TCB list (DCAPVerifier.swift:44), first-entry resolution (AttestationService+Reports.swift:225-232), v2 headers (E2EEPeer.swift:71-74) and 600 s max age (ConfidentialSession.swift:420). No material differences were found in the places checked. |

## Compared with teep on the same provider (part A §1)

- **Venice, EL defaults.** Weaker. teep authenticates the quote, pins MRTD and the compose, and verifies the GPU signature. EL with library defaults checks bindings on a quote it does not authenticate. EL with `requireDcap`, `requireGpu` and a `tokenVerifier` is about equal to teep on hardware and GPU (and enforces TCB, which teep leaves C), but still pins no code unless `expectedMeasurements` is supplied.
- **Venice, clawdbotatg.** Much weaker. It has no client-side attestation check, despite README.md:35, and it accepts plaintext replies.
- **Venice, M0dEx.** Weaker. It has no quote signature check, its nonce is never compared with the quote, and enabling the strict flags makes every request fail. It does refuse plaintext replies, as jooray does.
- **NEAR cloud, teemoon.** Weaker. teep appraises every instance, enforces TCB and pins the model-node MRTD and compose. teemoon appraises instance 0 only, accepts OutOfDate, and never binds the model node's code. teemoon is stronger on NRAS (JWT signature E, where teep has claims C) and on Sigstore image provenance (S vs C). Both send E2EE v2, so reply forgery is open for both.
