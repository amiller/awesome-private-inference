# Client comparison, part N: first-party clients (NEAR, Tinfoil)

Source review only; nothing was run, and no tests (no `node_modules`, no Go module cache for these deps). Pins: nearai/inference-sdk `9cc67f72` (2026-11-11, js v0.3.0), nearai/private-chat `5cf5b0d7` (2026-11-02), nearai/chat-api `1eb5d34c` (2026-11-13), nearai/private-chat-ios `04670853` (2026-06-23), tinfoilsh/tinfoil-webapp `bdfa6372` (2026-11-13), tinfoilsh/confidential-tinfoil-harness `c8fd64c1` (2026-11-13).

Cells as in part A: **E** enforced, **C** checked not enforced, **N** not checked. `[i]` = inferred.

## 1. nearai/inference-sdk (js; refs relative to `js/src/`)

| Axis | Value |
|---|---|
| attested scope | gateway quote first (`core/inference-client.ts:848-853`), then every returned model instance in parallel; any failure throws (`:1005-1014`). If gateway metadata says the model is not `vllm`/`attestationSupported`, gateway only ("Incognito"), allowed unless `e2ee`, `deploymentPolicy` or a model policy is set (`:979-996`) |
| quote | `@phala/dcap-qvl`; collateral from Intel in Node, from `cloud.near.ai/api/proxy/pccs` in browsers (`utils/intel.ts:61-78`, `utils/consts.ts:6-8`). Debug E (`core/dstack-attestation.ts:85-89`). TCB default accepts **UpToDate, OutOfDate, TDRelaunchAdvised** (`:20-24`); `policy.acceptedTcbStatuses` overrides |
| MRTD / RTMR0-2 | not extracted; verifier returns reportData, mrConfigId, rtMr3 only (`types/verification.ts:34-41`, `utils/intel.ts:104-113`) |
| recipient key / nonce | E: model report_data = signing address ‖ nonce (`core/attestation-common.ts:132-153`); E2EE key must derive to that address (`core/attestation-model.ts:433-461`) |
| gateway TLS | Node: SPKI in report data, connection pinned, E (`node/inference-client.ts:15-36`). Browser: unpinned fetch (`core/cloud-api.ts:417`) |
| NRAS | JWT ES384 sig against NVIDIA JWKS, issuer, `eat_nonce`, overall result (`utils/nvidia.ts:83-131`); payload nonce = client nonce (`core/attestation-model.ts:508-512`). Default `gpuEvidence: 'if-present'`: missing payload passes as `not_provided` (`:416, 497-504`). Browser NRAS POST goes through NEAR's proxy (`utils/consts.ts:10-12`) |
| event-log digests | **recomputed**: each runtime event rehashed, RTMR3 replayed (`core/event-log.ts:55-87, 132-170`); compose ↔ MRCONFIGID E (`core/attestation-common.ts:194-222`) |
| measurement pins | none by default ("does not check model measurements against an approved-deployment allowlist by default", `docs/verification-guide.md:135-137`; result `deploymentProvenance: 'not_checked'`, `core/deployment-verifier.ts:10`). On-chain: not found |
| compose-manager log | **new since v0.1.0.** When present: its quote under the same TCB/debug policy, `sha256(canonical actions)` = report_data[0:32], nonce in [32:64], same compose → MRCONFIGID, own RTMR3 replay (`core/compose-manager-attestation.ts:41-98`). **Absent → skipped silently** (`core/attestation-model.ts:98-107`). No same-machine check; comment says it binds "the same measured configuration, not a unique CVM instance" (`compose-manager-attestation.ts:30-32`) |
| deployed files | opt-in `verifyComposeManagerDeploymentImageProvenance` as a `deploymentPolicy`: requires the log (`core/compose-manager-provenance.ts:45`), checks **only the newest `compose_up`** (`:46-52`), fetches that file from `nearai/cvm-compose-files` at the logged commit, sha256 match (`:74-96`), then Sigstore/GitHub provenance of each image against a caller-given repo+workflow (`core/provenance.ts:220-340`; any image that workflow signs passes). Aging: not found |
| E2EE | **off by default** (`core/inference-client.ts:250`). When on: **v3** (`core/e2ee-request.ts:84`), AAD binds the reply key (`core/e2ee.ts:48-58`); model key required (`core/inference-client.ts:489-493, 900-907`) |
| reply | only if the caller calls `verifyResponse(id)` after the reply (README:65-70). A `gateway`-kind signature is accepted even in a model-attested session (`core/inference-client.ts:946-962`); the caller must check `signatureKind` |
| cache | per model, 60 min (README:107-110) |
| fail-closed | every check that runs throws before send; default config sends plaintext to the gateway with no pins |

Go/Rust parity: both verify compose-manager only when present (`go/verification.go:205-206`, `rs/src/model.rs:59-61`), both accept OutOfDate/TDRelaunchAdvised by default (`go/verification.go:412`, `rs/src/attestation.rs:13`), both send v3 (`go/e2ee.go:554`, `rs/src/e2ee.rs:796`). Rust `e2ee: false` by default (`rs/src/inference.rs:95`); Go default not found. Go rejects debug (`go/verification.go:407`).

Chain (verifiers note) with full opt-ins (`e2ee: true`, compose-manager `deploymentPolicy`, `acceptedTcbStatuses: ['UpToDate']`, `gpuEvidence: 'required'`): step 1 yes; 2 no (caller pin needed); 3 yes minus same-machine; 4 newest file only, no aging; 5 yes. Defaults: 1 with OutOfDate, 3 only if served, 5 no.

Grade: **partial**. vs teep: stronger on the deployment log (teep #166), weaker on defaults; overall similar.

## 2. NEAR Private Chat: web UI, iOS app, and the chat-api backend

Path keys. Web `W` = private-chat `src/`. iOS `I` = private-chat-ios `NEARPrivateChat/`. Backend `B` = chat-api `crates/`.

**Answer to the key question: the device verifies nothing and encrypts nothing beyond TLS.** Both apps send the prompt as plaintext JSON over ordinary HTTPS to chat-api at `private.near.ai`: web `POST {CHAT_API}/v1/responses` (`W api/chat/client.ts:85-101`, `W api/base-client.ts:108-109`, `W api/constants.ts:15-18`); iOS the same (`I Core/API/MessageAPI.swift:80`, `I Core/Routing/DeepLinkModels.swift:11-12`). iOS's "NEAR AI Cloud" route posts plaintext straight to `cloud-api.near.ai/v1/chat/completions` with the user's API key (`I Core/API/ModelAPI.swift:60`). chat-api parses the body, rewrites `instructions`, and forwards it with a stock `reqwest::Client` and a bearer key to cloud-api (`B api/src/routes/api.rs:155, 2524-2674`; `B services/src/response/service.rs:9-29, 97-133`). No `X-Encryption-Version` header, `signing_public_key`, or E2EE code exists in any of the three repos (grep: not found). The prompt is plaintext in chat-api (a dstack CVM, per its own quote, `B api/src/routes/attestation.rs:177-199`), then in NEAR's cloud-api gateway, then in the model CVM. chat-api never verifies the cloud-api or model attestations: it fetches cloud-api's `/attestation/report` and passes `gateway_attestation` and `model_attestations` through unchanged (`attestation.rs:104-236`).

| Axis | web (private-chat `5cf5b0d7`) | iOS (private-chat-ios `04670853`) | chat-api (`1eb5d34c`) as client of cloud-api |
|---|---|---|---|
| attested scope | displays model_attestations[0] + cloud-api gateway quote (`W components/chat/verifier/ModelVerifier.tsx:94-128`) | none parsed; extracts model-id-looking strings and two addresses (`I Core/API/AttestationAPI.swift:33-55, 82-106`) | own CVM quote with request nonce in report_data[32..] (`attestation.rs:163-199`); report_data[0..32] zero, no TLS key bound |
| quote verified locally | N: quote shown with a link to proof.t16z.com (`ModelVerifier.tsx:401-402`) | N | N for upstreams |
| TCB / debug | N | N | N |
| NRAS JWT sig + nonce | N: payload JSON-parsed and shown (`ModelVerifier.tsx:103, 269-283`) | N | N |
| client nonce | N: web sends none (`W api/nearai/client.ts:19-24`) | sent (`I Features/Security/SecurityStore.swift:71-75`), never compared with the report | forwards caller's nonce to cloud-api, reuses cloud-api's `request_nonce` for its own quote (`attestation.rs:157-165`) |
| measurements / compose / on-chain | N | N | N |
| event-log digests | N | N | N |
| compose-manager deployment log | N | N | N |
| E2EE | none | none | none (default `reqwest` TLS to cloud-api) |
| reply authenticity | C: per-message ECDSA sig over `request_sha256:response_sha256` checked, but hashes not recomputed from shown text (`W lib/signature.ts:5-48`; `MessageVerifier.tsx:79-95`; no sha256 of content in `W`), and signer compared with an unverified, optional `signing_address` (`MessageVerifier.tsx:85-86`) | N; offline verifier checks a device-local Ed25519 transcript signature, not the model's (`verifier/README.md`) | N |
| "verified" meaning | `isVerified = !loading && !error && attestationData !== null` (`ModelVerifier.tsx:222`) → "Verified models run in TEE" (`ChatVerifier.tsx:182-192`) | `.valid` = JSON fetched, contains the selected model id, <1 h old (`I Core/Security/AttestationStatus.swift:235-256`) → "Proof checked" (`Features/Chat/VerifiedFooterView.swift`) | n/a |
| fail-closed | N: sending does not consult attestation (`sentPrompt`, `client.ts:85-101`) | N: proof fetched on demand (`Features/Home/HomeScreenSetupActions.swift:265-273`) | N: forwards regardless; attestation is only an endpoint |

Other plaintext/custody points in chat-api: stored DB fields are encrypted under a key from dstack `get_key` or from a hex value or file in config (`B api/src/encryption_key_resolver.rs:79-90`, plus `KeySource::Hex`/`File`); request bodies are redacted in logs (`api.rs:2565`).

Grade: **weak**. Nothing on the user's device checks a quote, and the prompt passes through two first-party services (chat-api, cloud-api gateway) that do no verification of their own downstream. The green states are a fetch-success indicator.

## 3. Tinfoil Chat: tinfoil-webapp (W, `bdfa6372`) and confidential-tinfoil-harness (H, `c8fd64c1`)

**Answer to the key question: the browser verifies, but it verifies the harness, and the harness sees plaintext.** One open item: a safeguards sidecar inside the harness CVM gets the full messages of every first-party chat, and its config gives it `CONTROL_PLANE_URL: https://api.tinfoil.sh` on the `egress: open` network (`tinfoil-config.yml:22, 97, 108`). What it sends there was not reviewed (`confidential-safeguards`). The browser attests the harness enclave with tinfoil-js and talks to it over the SDK's `secure.fetch` (EHBP [i]). The harness is a measured enclave that builds prompts, runs tools, and seals storage. It attests the model router once at boot and talks to it over TLS pinned to the attested key. The router checks the model replica, according to a comment in H (`internal/inference/inference.go:31-32`); that code is in neither repo. Apart from that sidecar, these repos show no prompt plaintext leaving a TEE. Link-preview URLs go to context.dev, site hosts go to DuckDuckGo (`internal/pages/pages.go:2-3, 26`), and image hosts see the harness fetch.

The tinfoil-js 2.0.0-rc.1 and tinfoil-go internals were not read; SDK behaviour marked [i] follows part B §3.

| Axis | browser (W) → harness | harness (H) → router / helper enclaves |
|---|---|---|
| attested | harness enclave: `EnclaveHTTPClient.create(host, 'tinfoilsh/confidential-tinfoil-harness')` (`src/services/harness/client.ts:30, 153`), host `chat-api.tinfoil.sh` (`provider.tsx:110-111`) | router `tinfoilsh/confidential-model-router` (`internal/inference/inference.go:95-101`); embed/summary models via SDK default router (`embedder.go:40-47`, `account.go:78-85`); web search enclave `confidential-websearch` (`internal/engine/tools.go:243-256`) |
| quote verified locally | E in tinfoil-js `2.0.0-rc.1`, lockfile-pinned (`package.json:76`, `package-lock.json:19098-19101`); AMD chain, TCB, debug inside the SDK [i] | E in tinfoil-go `v0.16.3` (`go.mod:18`) [i]; `WithUserCacheSecret` option (`inference.go:46`), semantics not read |
| GPU / NRAS / event log | not found (SEV-SNP + Sigstore; no event-log replay) | not found |
| measurements | Sigstore release of the harness repo, no tag or digest: auto-adopt [i] (`client.ts:153`). Measured config `tinfoil-config.yml`: harness image digest set by release automation (`:1, 32`), sidecar digests hand-pinned (`:76, 95`), `upstream` network `egress: open` (`:22`) | router repo, no tag: auto-adopt [i] (`inference.go:99`) |
| channel / E2EE | SDK `secure.fetch` (EHBP [i]); a refusal without `RESPONSE_NONCE_HEADER` is rejected as unsealed (`client.ts:286-287`) | TLS pinned to attested key, explicit `WithTransport(TransportTLS)` (`inference.go:48-51, 56`) |
| router vs model enclave | the device reaches neither | router only; replica check delegated to the router (`inference.go:31-32`) |
| reply authenticity | attested channel only; no signatures or receipts | same |
| fail-closed | E: every request awaits `attested()` before `secure.fetch` (`client.ts:230-231`); 20 s timeout → `unverified` error with retry (`client.ts:33`, `protocol.ts:215-220`) | E at boot: router attestation failure is fatal (`inference.go:100-101`); search skipped if its attestation fails (`tools.go:243-256`); router attested once, not per turn |
| UI on failure | spinner → lock "Privacy verified", or red open lock "Error" (`components/chat/verification-status-button.tsx:70-110`, `chat-interface.tsx:1424-1426`). The sidebar document hardcodes every step to `VERIFIED` (`harness/attestation.ts:54-60`), but is built only after `verify()` resolves | n/a |

Storage: the content key lives in browser `localStorage`, with a passkey backup (`src/services/encryption/encryption-service.ts:163, 352-364`). The browser sends it to the harness, which seals rows with AES-GCM (`H internal/store/rows.go:180-188`). The control plane sees ciphertext plus project id, attachment refs and activity times (`rows.go:205-226`).

Safeguards: the harness POSTs `{credential, conversation_id, messages}` to the sidecar, fire-and-forget (`internal/engine/safeguards.go:30-38, 90-110`). The sidecar image is hand-pinned (`tinfoil-config.yml:95`), so it is measured, and it classifies with `gpt-oss-safeguard-120b` / `kimi-k3-1-pro` (`:100-101`). What it reports to the control plane is in `confidential-safeguards` and was not reviewed. The webapp has no chat-text path that bypasses `services/harness`: the other `fetch` callers are `safeguards.ts`, `reload-when-updated.ts`, `settings-modal.tsx`, `use-upgrade-to-pro.ts` [i from file names].

Grade: **partial**. The device checks a measured enclave and fails closed. That enclave is a first-party hop holding plaintext, it trusts the router after a single check at boot, and both hops adopt the latest release.

## Differences that matter most

- **Who reads the prompt.** No first-party chat app encrypts from the device to the model. NEAR Private Chat (web and iOS) sends plaintext to chat-api, which forwards plaintext to cloud-api; neither hop verifies the next one. Tinfoil Chat encrypts to an attested harness enclave that holds plaintext and relays to the router.
- **Device-side verification.** Tinfoil's browser verifies the harness (AMD chain, Sigstore) and blocks on failure. NEAR's apps verify nothing: "Verified" (web) means the report fetched, and "Proof checked" (iOS) means the JSON names the model and is under an hour old.
- **NEAR's own SDK vs NEAR's own app.** inference-sdk has every-instance quotes, event-log replay, NRAS JWT checks, the compose-manager log and v3 E2EE. private-chat uses none of it (no dependency in `package.json`).
- **Release adoption.** Both Tinfoil hops pass a repo with no tag [i]. inference-sdk pins nothing by default, and its provenance helper accepts any image the named workflow signs.

## Matrix cells

| Client | NEAR cell | Tinfoil cell | grade | event_log_hashed | fails_closed | vs teep |
|---|---|---|---|---|---|---|
| inference-sdk | Every instance quoted, event log replayed, deployment-log hash checked if served (absent passes). Defaults: E2EE off, no compose pin, OutOfDate and missing GPU accepted. | — | partial | true | true (checks it runs) | similar |
| NEAR Private Chat web + iOS (via chat-api) | Plaintext to chat-api, then cloud-api; no hop verifies. "Verified" means the report fetched; quotes only displayed. Reply signature not tied to shown text. | — | weak | false | false | weaker |
| Tinfoil Chat (webapp + harness) | — | Browser attests the harness enclave (latest release), which holds plaintext and attests the router once at boot; model replica checked by the router. Fail-closed. | partial | null | true | similar |
