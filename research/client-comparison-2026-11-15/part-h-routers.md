# Client comparison, part H: AnonRouter SDK, Alien Fleet, Axiom web gateway

Source review only. Nothing was run: no installs, no unit tests (each suite needs an npm, Go-module or pip fetch). Pins: anonrouter-sdk `39e416b6` (2026-11-09), alien-compute `6a6be6f8` (2026-11-05), axiom-web-gateway `1b535ed8` (2026-11-14), plus axiom-desktop `b07e5dbc` (2026-11-14), which the gateway pins for its upstream client (`Cargo.toml:28-30`).

Cells use part A's legend: **E** enforced, **C** checked, not enforced, **N** not checked, **n/a**. `[i]` = inferred.

## 1. anonrouter-sdk (`@anonrouter/confidential` JS, `anonrouter-confidential` Python)

Path keys (JS, under `js/confidential/src/`): `C` = `client.ts`, `GV` = `gateway/verify.ts`, `EL` = `gateway/eventLog.ts`, `T` = `verify/tdx.ts`, `NA` = `verify/near-authority.ts`, `M` = `shared/measurements.json` (repo root). Python mirrors JS, and CI byte-compares shared pins and vectors (`M:4`, `python/src/anonrouter_confidential/tdx.py:1-8`).

The request takes two hops. Hop 1 is AnonRouter's own relay, `api.anonrouter.ai`: GCP TDX content nodes since 2026-10-14 (`README.md:31-43`), with the Phala dstack origin `api.private.anonrouter.ai` still pinned but deprecated. Hop 2 is the provider: `venice`, `chutes`, `other` (NEAR direct `*.completions.near.ai` via release authority), legacy `near-ai` (static NEAR pins), and `tinfoil` (`verify/index.ts:21,48-51`). There is no AnonRouter-run model TEE. Hop-2 evidence is fetched through AnonRouter's relay (`/v1/tee/attestation`, `C:1541-1551`).

**Hop 2 quotes are never signature-checked.** `T:1-6`: "deterministic byte-offset parsing, NOT signature verification". No file under `verify/` or `transport/` references a chain verifier or DCAP. The SDK says so and caps hop 2 at `provider-attested` (`README.md:193-197`). Every hop-2 binding below (nonce, key, measurement) therefore holds only if the bytes the relay returns came from a real TD. If hop 1 is skipped, a relay can mint a quote with any report_data and receive the prompt under its own key.

**Hop 1 is optional for chat.** `chat()` checks hop 1 only with per-call `requireGateway`, or when the client was built with `gatewayConnectionBinding: {mode:"required", chainVerifier}` (`C:674-687`, `C:1512-1520`). By default it gates on the relay's own verdict plus the local structural parse (`C:1602-1612`). `ACCEPTED_LEVELS` includes `provider-attested` (`C:529`).

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| hop 1 `api.anonrouter.ai` (GCP TDX) | DCAP via own Rust engine on dcap-qvl `=0.6.1`, no network, reproducible build (`native/dcap-verifier/Cargo.toml:27`); TCB `UpToDate` only, QE and platform status gated too (`native/.../main.rs:59,222-240`, `GV:853-881`, `shared/gateway-policies.json:68-70`); debug E (`GV:348`); RTMR3 must be unextended (`GV:391`) | TLS terminates in the TD; SPKI in report_data, observed on the retained socket that carries content, E (`GV:795-814`) | none from hop 1 | MRTD/RTMR0-2 tuples from an owner-signed release-v3 feed; 2-of-2 Ed25519 custodian keys pinned in the package (`gateway/release-v3.ts:1-13`, `shared/release-policy-v3-authority.json`) | n/a (relay sees plaintext on TEE routes, ciphertext on E2EE routes) | owner signs a new policy; no SDK release needed; feed policy has no expiry; last good policy served ≤1 h offline (`release-v3.ts:5-13,44`); rollback/fork refused | E when required: a missing engine fails `quote_signature_chain` for tuple policies (`GV:886-894`); off by default for `chat()` |
| hop 1 `api.private.anonrouter.ai` (Phala dstack, deprecated) | as above when an engine is supplied | in-TEE TLS E; SPKI binding only C if the caller cannot observe the cert (browser) (`GV:816-828`) | none | MRTD/RTMR0-2/compose/app-id/key-provider pinned in package (`GV:536,608,774-781`); RTMR3 digests **recomputed from payloads**; V2 preimages decoded and compared to the displayed fields (`EL:137-226`, `EL:259-268`) | n/a | static pins in package | as above |
| venice | quote parsed, **signature N** (`T:1-6`); debug E (`verify/venice.ts:70`); TCB N; GPU: presence only (`venice.ts:131-132`) | E2EE (secp256k1/AES-GCM) to the signing key; address in report_data[0:32] and key in the workload keyset, E structurally (`venice.ts:79-129`) | AEAD decrypt only; no signature or receipt (`transport/venice.ts:1-11`) | **no measurement pin**: `measurementPolicy: null` (`M:271-272`) | n/a | none to update | refuses on any required check (`verify/checks.ts:83-84`), but nothing is checked against a vendor root |
| other (NEAR direct) | quote parsed, sig N; debug E; GPU: nonce field compared in the JSON, **NRAS JWT signature N** (`NA:350-375`) | E2EE v2 to ed25519 `signing_public_key` (`transport/near.ts:1-10,263`); TLS SPKI binding to report_data E structurally (`verify/near.ts:99-110`) | v2: reply key not bound, content not authenticated [i] | release authority: os-image MRTD/RTMR0-2 from dstack's published images; compose on NEAR's on-chain KMS registry; compose-manager `actions` canonicalized and hashed against a second quote with the same nonce (`NA:302-306`, avoids hermes's bug); RTMR3 recomputed (`NA:109-147`) | model name from the evidence, E (`near.ts:147`) | GitHub and on-chain collateral delivered by AnonRouter's worker (`NA:19-21`, `README.md:92-96`) | refuses on failure (`transport/near.ts:146-147`) |
| near-ai (legacy) | as other, no GPU nonce check (`near.ts:152`) | E2EE v2 | as other | static MRTD+RTMR0-3+compose pins per model (`M:209`, `T:268-284`) | as other | SDK release | refuses |
| chutes | quote parsed, sig N; debug E; GPU: presence; RSA cert-possession signature over the attested body E in Node, advisory in browser (`verify/chutes.ts:1-11,128-143`) | ML-KEM-768 to instance key; report_data[0:32] = sha256(nonce‖key), E structurally (`chutes.ts:110`) | ML-KEM to client key, AEAD only | MRTD+RTMR0-3 allowlist, but the set is **Chutes's published list, auto-adopted** (`M:206`, `scripts/refresh-chutes-pins.mjs`) | n/a | maintainer reruns the refresh script | refuses |
| tinfoil (TEE route) | Node: official `tinfoil` npm verifier (SNP chain, Sigstore) plus SDK's own pinned-TLS observation (`tinfoil.ts:1-20`); Python checks the document and TLS observation that AnonRouter's gateway recorded (`README.md:261-263`); GPU N | prompt reaches AnonRouter's hop-1 relay in plaintext, which forwards it (`README.md:263-265`) | none | `confidential-model-router`, `releaseSelection: latest`; of the four policy fields only `configRepo` is enforced (`M:4,266`) | router→model N | auto-adopts the latest router release | Node verifier refuses on failure; the send doesn't depend on it [i] |

Freshness: client nonce of 32 bytes on every hop (`C:1538`); 5 min evidence age, 5 min verdict cache (`verify/checks.ts:19-20`).

Prior work: cites dcap-qvl (`native/README.md:42`), dstack-examples for the RTMR3 serialization (`EL:131`), the Tinfoil SDK. The NEAR authority is "an SDK port" of AnonRouter's private worker code (`NA:1-3`). No reference to teep, private-ai-gateway or nearai-cloud-verifier. Everything else is reimplemented with @noble.

Docs vs code:
- `README.md:89-91` says that on E2EE "AnonRouter's relay holds ciphertext whatever code it happens to be running." Hop-2 quotes are unsigned and fetched through that relay, so the claim holds only if hop 1 is verified and the measured relay doesn't forge evidence.
- Both quickstarts gate on `cryptographically_checked` (`README.md:315,368`). `VERIFYING.md:148` says that state does not prove "that any of it came from real silicon".
- Otherwise the docs are candid about the ceiling.

## 2. alien-compute (Alien Fleet Phase-0 testnet)

Path keys: `WP` = `alien-fleet-whitepaper-v1.0.md`, `P` = `internal/proxy/server.go`, `PE` = `internal/proxy/engine.go`, `R` = `internal/gateway/registry.go`.

No TEE code exists. A repo-wide search finds no quote, TDX, SNP or NVIDIA verification. The whitepaper's Class A attested path (§6, `WP:167-211`) is "not exercised": every testnet node is Class O on consumer GPUs (`WP:671-674`), and the operator sees plaintext (`WP:93`, `docs/PROVIDER.md:143`). Providers: three self-hosted GPU nodes running llama.cpp/vLLM, plus anyone who joins (`README.md:9-11,52-54`). No third-party provider.

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| fleet-proxy → gateway → node | N (no attestation) | HPKE (X25519/ChaCha20-Poly1305) to the node's NEK. NEK and NIK come from the gateway's `/v1/registry/nodes` over plain `http://` (`PE:380-386`, `PE:207-215`, `demo/aws/CLIENT.md:7`). The gateway checks the node's registration signature (`R:109-115`), but `NodeInfo` carries no signature for the proxy to re-check (`R:46-58`). A gateway or on-path attacker can substitute the key, N | node-signed receipt checked against the NIK from the same gateway (`P:262-267`); missing receipt only logs (`P:253-259`); failed check only withholds the countersign, and the reply was already streamed (`P:268-273`) | model = SHA-256 of the GGUF; alias→hash TOFU, client-side (`PE:349-370`); no code identity | n/a | TOFU | fail-open: plaintext always reaches an unattested node; the client gets no Class O caveat or opt-in (whitepaper requires one, `WP:99`) |

Docs vs code:
- Tagline "confidential, self-verifying market" and `README.md:109-112` "gateways … see ciphertext": a gateway that lies about NEK reads the prompt.
- Appendix A says deviations are "never of the trust model" (`WP:657-658`). Missing attestation and an unauthenticated key directory are trust-model gaps.

Prior work: none cited; no reuse.

## 3. axiom-web-gateway (Astrea)

Path keys:
- `V` = `verifier/gateway/verify.go`, the browser WASM and native verifier.
- `SDK` = `sdk/src/index.ts`.
- `F` = `sdk/src/frames.ts`.
- `SV` = `crates/axiom-web-gateway/src/service.rs`.
- `D/` = axiom-desktop `crates/axiom-secure-client/src/`.
- `PC/` = axiom-desktop `vendor/axiom-pool-client/src/`.
- `DV/` = axiom-desktop `vendor/axiom-direct-verifier/src/`.

The upstream rows (D/, PC/, DV/) come from a delegated read of axiom-desktop at `b07e5dbc`. I re-checked the NEAR MRCONFIGID-only finding myself (`D/providers/near/attestation.rs:606-626`).

There are two hops:
1. The browser attests the gateway, a CPU-only Tinfoil Container on SNP or TDX (`docs/architecture.md:3`).
2. Inside its TEE, the gateway runs axiom-desktop's upstream client against a provider and forwards that verdict to the browser as an `upstream_proof` frame (`SV:1137-1139`).

The browser does not re-verify the upstream proof. It treats the frame as provisional (`F:67`) and relies on the attested gateway. Upstream paths: `axiom-direct` (Astrea's own SEV-SNP + Blackwell worker at `worker.axiom.stream`, a Verda host, `deploy/astreaai-production.json:1-10`), NEAR, Tinfoil, and an off-by-default `axiom-pool`. Production uses the direct config: it is the only provider config baked into the image (`Dockerfile:28-43`). The README says "No production gateway has been deployed" (`README.md:11-12`).

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| browser → gateway | tinfoil-go `VerifyV3` (pinned rc, `verifier/go.mod`); offline, embedded roots (`V:131-141`). Axiom adds SNP debug, migration, VMPL0 and committed=current TCB (`V:172-185`), and the TDX debug bit (`V:163`). TCB "strict UpToDate" is a doc claim (`docs/architecture.md:23-25`); it's inside tinfoil-go, not re-read here. GPU n/a (CPU-only) | EHBP (HPKE) to an X25519 key from the attested `CryptoMaterialData`. The Ed25519 authorization key is bound the same way, and both must equal what the gateway advertises (`V:242-277`, `SDK:118-124`) | EHBP AEAD; frames checked for request_id and sequence, plus a transcript SHA-256 in the terminal frame. Deltas stay provisional until authenticated EOF (`F:57-77`) | code measurement must equal a publisher-signed manifest. The manifest maps source revision, lock hashes, image digest, config digest and origin. Tinfoil Sigstore release from the config repo (`V:219-240`) | upstream verified by the gateway, not the browser (`SV:1124-1139`) | publisher key pinned in the app (`SDK:50`). Policy is served by Axiom's backend, signed, ≤24 h validity (`V:220`). Min sequence defaults to 0 unless the app persists one (`SDK:55,64`), so rollback protection is opt-in. New signed manifests are auto-adopted | refuses on any failure (`V:189-198`); evidence ≤240 s (`V:278`); nonce = 32-byte browser challenge (`SDK:66`, `V:207,230`) |
| gateway → axiom-direct (production) | SNP report v5, AMD chain with ARK pinned by the signed policy, VCEK, CRL, min TCB from policy (`DV/snp.rs:51-175`); debug/migration/VMPL0 E (`snp.rs:28-36`). GPU: NRAS v4 JWT checked locally (JWKS, anchors, iss, nonce, exp) plus secboot/dbgstat/measres claims (`DV/nvidia.rs:15-158`). GPU evidence hash bound in SNP report_data (`DV/lib.rs:154-158`) | HPKE to the attested encryption key; TLS trusts only the attested cert (`PC/direct.rs:360-363,741`) | receipt signed by the attested identity key (`PC/direct.rs:820-823`) | SNP measurement must appear in a publisher-signed release list for the deployment digest (`DV/release.rs:156-169`). The measurement is not rebuilt from boot fields. `expires_at:null` is allowed (`release.rs:136`) | n/a (model runs in the same TEE) | publisher (Astrea) signs a new sequence; auto-adopted. Policy is served by the worker. Floor is `minimum_policy_sequence: 23` (`deploy/astreaai-production.json:9`) | E (`D/providers/direct.rs:786-812`); verifier binary sha256 checked before exec (`PC/attestation.rs:243-249`) |
| gateway → NEAR | dcap-qvl with Intel collateral E (`D/providers/near/attestation.rs:601-604`); only `UpToDate`, and the gateway also requires that policy (`SV:1124-1127`). **Debug bit N** (td_attributes never read). GPU: NRAS v3 JWT ES384 checked against JWKS with pinned x5c, `eat_nonce` E. exp/iat and per-GPU claims N (`attestation.rs:680-838`) | E2EE ("near-v3", encryption v2) to the attested Ed25519 key (`D/providers/near/mod.rs:22-23`, `crypto.rs:100-187`). Worker TLS SPKI is in report_data, but only Axiom's backend holds that socket | Ed25519 receipt from the attested key over `model:request_hash:response_hash`, E (`D/providers/near/inference.rs:990-1092`) | **only `mr_config_id == 01‖sha256(manifest)`** (`attestation.rs:610-618`). No MRTD/RTMR/compose/app-id allowlist, no event-log replay. The host chooses MRCONFIGID, so any image can claim any manifest. Overclaimed in `docs/protocols/near-v3.md:19,30` | gateway routes: gateway TD plus every worker replica verified (`attestation.rs:369-467`) | n/a: nothing to pin | E; relay "verified" flag ignored (`attestation.rs:381-382`) |
| gateway → Tinfoil | delegated to tinfoil-rs `SecureClient::verify()` (rev `91e8aef`, not reviewed) (`D/providers/tinfoil/mod.rs:221-228`) | EHBP to the router HPKE key (`mod.rs:229-232`) | EHBP AEAD; no receipt | router repo name only; latest Sigstore release [i] | router→model N | auto-adopt | E (`mod.rs:224-228`); no client nonce, cache ≤240 s (`mod.rs:237,252-268`) |

Prior work: tinfoil-go and tinfoil-rs (official SDKs), dcap-qvl, the `sev` crate. The NRAS checks and the direct verifier are custom. No citation of teep, private-ai-gateway, nearai-cloud-verifier or the dstack SDK.

Docs vs code:
- Architecture and README are accurate about what is unfinished. They say browser-delivered JS is a separate trust boundary (`docs/architecture.md:67-68`).
- The NEAR "measured workload manifest" claim overstates an MRCONFIGID self-consistency check.

## Differences from teep that matter

- **AnonRouter hop 2 vs teep.** On venice, NEAR and chutes, teep verifies the quote to Intel roots and pins MRTD.
  - AnonRouter parses the quote and never checks its signature.
  - Venice: no measurement pin at all.
  - Chutes: auto-adopts the provider's list.
  - NEAR `other`: richer release-authority logic than teep (compose-manager action log hashed, on-chain KMS), but over an unsigned quote and with collateral fetched by AnonRouter.
  - Confidentiality against AnonRouter rests on hop 1, which `chat()` skips by default.
- **AnonRouter hop 1** is strong when enabled:
  - Its own reproducible dcap-qvl engine, UpToDate-only.
  - Event digests recomputed from payloads, so it does not have the verifier-ts bug.
  - TLS observed on the content socket.
  - Pins come from AnonRouter's 2-of-2 owner key, which auto-adopts whatever the owner signs.
- **Axiom on NEAR is weaker than teep on code identity.** It has no MRTD/RTMR/compose allowlist and no debug check. It is stronger on replies: it verifies an Ed25519 completion receipt, which teep does not on NEAR.
- **Axiom direct** is a single-operator SNP+Blackwell path with publisher-signed measurements, GPU evidence bound in the CPU report, and signed receipts. teep has no equivalent route.
- **Alien Fleet** has no attestation. Its key directory is unauthenticated plain HTTP from the gateway.
