# Verifying clients, part B (2026-11-15)

This note records what each client checks per request. Nothing was run live. **[src]** means read in source at the pinned commit; **[inf]** means inferred. Cells use four values: **E** enforced (the client refuses), **C** checked but only logged, **N** not checked, and n/a. Cells with no tag are [src].

Commits: hermes `amiller/hermes-agent` `feat/near-ai-attestation` `1f92ab10` (2026-05-19; [PR #12201](https://github.com/NousResearch/hermes-agent/pull/12201) closed, unmerged); nearai-cloud-verifier `94554726`; tinfoil-go `99112212` (v0.17.0-rc.9; latest release v0.16.4 predates the TLS-pin default `a8c8ab9`); tinfoil-python `bf161113`; jooray proxy `4b5602ef` + lib fork `jooray/venice-e2ee` `ac05b0d` (`attestation.ts` identical to elkimek `d8e37d15`); AxLabs `70ef39f6` + npm `@axlabs/venice-e2ee@0.3.0`; privatemode-public `3c98e0ab`; teep `6548996b`.

## 1. hermes-agent → NEAR gateway (E2EE), strict mode

In `hermes_cli/`: A `attestation.py`, T `e2ee_transport.py`, P `e2ee_proxy.py`, R `runtime_provider.py`. M is nearai-cloud-verifier `py/model_verifier.py`, imported from `NEARAI_VERIFIER_PATH` and not pinned (A:65-76).

| Axis | Value |
|---|---|
| TDX quote (gateway + each model) | E: A:271-275, 320-324 (`dcap_qvl`) |
| TCB | C: `OutOfDate` is accepted with a warning (M:245-251; A:306, 562) |
| Debug bit | N in hermes code. Whether `dcap_qvl` rejects debug TDs was not checked. |
| GPU | E: NRAS verdict plus the nonce, checked per instance (A:341-356) |
| Recipient key ↔ quote | E: report_data must hold address‖nonce, and the public key must derive to the address (A:336-339, 544-556) |
| Live channel | C: errors from `verify_domain_attestation` are swallowed (A:294-301), and the inference connection is not pinned |
| Reply | N: E2EE v1, no AAD (T:95-99, P:45), so [#1061](https://github.com/nearai/cloud-api/issues/1061) key swap is open; no v3, no receipts. Only string `content` is sealed (T:90-92). |
| Code: compose | E: sha256(app_compose) must equal mrconfig, and the compose must be in the static anchor (A:378-412) |
| Code: app_id, OS image, KMS key | E, but on unquoted input: the values are read from the `info` JSON, with no RTMR3 replay (A:395-429) |
| Code: post-boot workload | Partly E: it verifies the compose-manager quote, checks report_data = actions_hash‖nonce, and requires the latest action for the pinned file to match the pinned commit and sha (A:437-533). Gaps: (a) it never hashes `actions` to compare with `actions_hash`, so the list is unauthenticated (M:102-106 does this check); (b) compose-manager MRTD/RTMR3 is compared with the self-reported `tcb_info`, not the model quote (A:461-475); (c) other deployed files, `env`, and a compose-manager image replaced by the launcher are not checked. |
| Model / instances | E: `model_name` = requested unless empty (A:363-368); every instance checked, key from #1 (A:557-558) |
| Updates | A hand-edited JSON anchor (`anchors/nearai_mainnet.json:2-3`). No auto-adopt. |
| Fail-closed | Only when `attestation.enabled` and `strict` are set, and both default to false (config.py:4330-4331). In the default mode a failed verification only logs a warning and sends **without E2EE** (R:289-297). **Even in strict mode, a valid report whose instance #1 lacks `signing_public_key` produces no E2EE transport, so the request goes in plaintext** (A:546-558, R:293). |

The anchor dates from 2026-05-18. It has no `z-ai/glm-5.3-flash`, no compose `e8416a02` or `08d91c8e`, and no `pack-small-models.yaml`. For the models in our 2026-11-14 captures, strict mode therefore refuses (A:390-394, 408-412) [inf from anchor contents]. The loop would handle 3 instances/3 composes/one key if all were anchored.

## 2. nearai-cloud-verifier as a client

A demo CLI that prints booleans and never refuses (M `model_verifier.py`, X `encrypted_chat_verifier.py`, H `chat_verifier.py`). Quote, TCB (`OutOfDate` = verified, M:245-247), GPU, report_data and the TLS fingerprint (only with `--verify-tls`) are C; debug is N (M:129-266, 381-400). Code is C with no pins: it prints compose/mrconfig, HEAD-checks Sigstore links and recomputes `actions_hash` (M:67-126, 299-350). Replies are C after the fact via `/v1/signature` (H:70-108). **The E2EE example encrypts to a `signing_public_key` fetched with no nonce and no quote check** (X:28-41), using v1 headers (X:321-323).

## 3. Tinfoil: tinfoil-go (G, rc.9) and tinfoil-python (Y)

| Axis | G | Y |
|---|---|---|
| Default host | Router list from `atc.tinfoil.sh/routers` (unverified, errors ignored), falling back to `inference.tinfoil.sh`. Each candidate is verified against `tinfoilsh/confidential-model-router` with no tag (internal/router/router.go:19-21, 76-108). | Same (`_router.py:17-21, 81`) |
| Direct route | `NewEnclaveHTTPClient(host, repo@tag@sha256)` (enclave_client.go:89-105) | `_enclave.py` |
| Hardware chain | E: embedded AMD/Intel roots, CRLs, one clock read (verify/verifier.go:30-43, 244) | E (`_trust/*`) |
| TCB / debug / TD attributes | E against a **Tinfoil-signed platform policy**. The SDK has no floor of its own (verify/internal/policy/sev.go:14-57; quote/sev/expectations.go:117-121). | E, same design (`sev/lib/validate.py:196`) |
| Floor vs AMD-SB-3037/3038 | cvmimage `eaa503d` `platform/policies.json:9-13`: Genoa `snp_spl` 0x0E, ucode 0x48, below 0x1D/0x56; router served 0x17/0x1B (tinfoil.md F3). Signed artifact = this file is [inf]. | same |
| GPU | N: the evidence hash is bound into REPORT_DATA, but nothing appraises it (verify/document/document.go:26-31, 53) | N [inf] |
| Recipient | E: REPORT_DATA = H(nonce‖crypto_material‖device_evidence), and a TLS key is required (document.go:338-346; internal/enclave/enclave.go:189-202) | E (`_enclave.py:237-243`) |
| Channel | E: SPKI pin on every connection in the default TLS mode (internal/transport/tls.go:29-167). A proxy requires EHBP. | E (`_tls.py`, `_types.py:39`) |
| Reply | E inside the pin or EHBP. EHBP does not seal headers or bodiless requests (enclave_client.go:32-37). No receipts. | same (`_ehbp.py:1-11`) |
| Code | E: a Sigstore bundle from GitHub org `168487856` for the pinned repo (verify/internal/endorsement/provenance.go:39; verifier.go:277-317). On the router route this measures **the router, not the model enclave or weights**. | E (`_endorsement/provenance.py`) |
| Freshness | E: witnesses must be at most 7 days old, and the cached verification dies with them (verify/internal/endorsement/freshness.go:17; internal/transport/verification.go:25-27) | E (`_enclave.py:222-230`) |
| Downstream (router→model) | N: the client trusts the router | N |
| Updates | **Auto-adopt**: any router release Tinfoil signs, and any platform policy Tinfoil signs | same [inf from docstring `_verifier.py:231-236`] |
| Fail-closed | E: verifies before the constructor returns, re-verifies on expiry or key rejection, and offers a `VerificationCheck` hook (enclave_client.go:96-105) | E |

## 4. Venice E2EE proxies: jooray (J + lib EL) vs AxLabs (A + lib AL)

From a delegated review; the ACI/GPU branch spot-checked by hand.

| Axis | J | A |
|---|---|---|
| TDX quote | E: `@phala/dcap-qvl` with Phala PCCS (EL attestation.ts:430-447). **If DCAP fails to load, it warns and continues** with binding-only checks (J session-manager.ts:200-203). | E. A DCAP load failure stops startup (A e2ee.service.ts:105-111). |
| TCB | E: OutOfDate is rejected, SWHardeningNeeded and similar statuses are accepted (EL:434-444) | Only Revoked and OutOfDate* are rejected (AL attestation.js:168-174) |
| Debug | E (EL:367-370) | E (AL:115-118) |
| GPU | E: NRAS with `eat_nonce` equal to the client nonce. `requireGpu` refuses when evidence is absent (EL:455-521). | C: trusts Venice's `server_verification`, and absent evidence only logs a warning (A e2ee.service.ts:222-229) |
| Recipient | E: REPORTDATA = keccak(pubkey) addr‖nonce (EL:372-405) | E (AL:120-146) |
| Channel | N | N |
| Reply | E: plaintext content is refused, and a truncated stream fails (EL crypto.ts:93-96; J proxy.ts:746-779). The client key has no AAD, so reply chunks are forgeable by anyone who sees the header [inf]. | Short or non-hex content passes as plaintext, and plaintext `tool_calls` are forwarded (AL crypto.js:50-59, stream.js:87-90) |
| Receipts / downstream | C: off by default and log-only (J config.ts:98; proxy.ts:335-450) | N |
| Code (compose, OS, app_id) | N: `expectedMeasurements` is never passed (EL:425) | N |
| Model binding | A JSON `model` field, not bound to the quote (EL:314) | N. `_pendingSession` is not keyed by model (AL index.js:80). |
| Updates | No allowlist, so any genuine quote is accepted | same |

**ACI/1:** neither proxy parses it. Venice's ACI/1 body still carries `intel_quote` and `signing_public_key`, and its report_data uses address‖0‖nonce, so the binding checks pass. With no `nvidia_payload`, **J refuses `-p` models** (EL:517-518), while **A passes them with a warning** (e2ee.service.ts:225-229). `downstream_tls_binding`, `app_compose` and `key_custody` are ignored by both.

jooray `docs/SECURITY-AUDIT.md` (2026-08-06, proxy `3ac2725`): P3, P7, P8 fixed; P1, P2 (proxy.ts:291,655), P5, P6 open; gateway blind spots B1-B4 are not client-fixable.

## 5. Privatemode proxy

The client is public Go (`privatemode-proxy/`, `internal/oss/`). The quote check itself runs inside `edgelesssys/contrast` v1.26.2 (go.mod:23), which was not read. The served manifest and the gateway are not in the repo.

| Axis | Value |
|---|---|
| Hardware | E [inf]: the Coordinator attestation is verified with a fresh nonce via `ValidateAttestation` (internal/oss/attest/attest.go:49, 66). Workers are checked by the Coordinator. The generator script sets SNP `SNPVersion=30` (0x1E) and TDX `MinTCBEvaluationDataNumber=21` (scripts/adjust-manifest.sh:12-34), but the served values are unseen. |
| GPU | Server-side only; client OCSP defaults lax (cmd.go:117-121) |
| Recipient | E: hybrid HPKE to a leaf certificate chained to the attested mesh CA, with no SAN check (secretclient.go:50-113) |
| Reply | E: AES-GCM stream with AAD, and response keys derived from the request salt (oae.go:332-349). Error responses ≥400 and `/v1/models` are unencrypted (server.go:170, 310). |
| Code | E as byte-equality with the expected manifest (attest.go:70-75). **The default expected manifest is fetched from `cdn.confidential.cloud` over WebPKI, with no signature or log** (privatemode.go:235-261). `--manifest-path` pins a local file. |
| Updates | **Auto-adopt**: a new CDN manifest is accepted on a secret-exchange failure (updater.go:64, 74). The only record is a local append-only log. |
| Fail-closed | E on manifest mismatch. Secret refresh happens about every 45 min (secretmanager.go:20-21). |

## Differences between clients of the same provider

- **NEAR, post-boot workload.** Only hermes checks compose-manager's action log against pinned inner-YAML commits, and it never hashes the list against the quoted `actions_hash`. The NEAR verifier recomputes that hash but only prints it. teep parses the log (neardirect/parser.go:76-99) and nothing else in teep references it [inf, grep].
- **NEAR, reply key.** hermes sends v1 and teep sends v2 (internal/provider/inference.go:163). Neither binds the reply key, so #1061 stays open on the gateway route for both.
- **NEAR, downgrade.** hermes sends plaintext in its default config, and also in strict mode when instance #1 has no key.
- **NEAR, accepted code.** hermes pins composes statically and so refuses today's fleet. The NEAR verifier pins nothing. teep checks image provenance rather than compose hashes (attestation/report.go:2763-2964) [inf from function names], so a new `addComposeHash` by the owner EOA is not a client decision there.
- **Tinfoil, the SNP floor.** tinfoil-go and tinfoil-python take the floor from Tinfoil's signed policy, so it moves when Tinfoil re-signs it. teep hard-codes the same 0x0E (internal/attestation/sev.go:129-133, 261). Neither reaches 0x1D; both accept the router's 0x17 (teep's Tinfoil path calling this is [inf]).
- **Tinfoil, releases.** TLS pinning by default exists only in v0.17 RCs, not in release v0.16.4.
- **Venice, GPU and ACI.** jooray refuses Venice's `-p` (ACI/1) models because GPU evidence is missing. AxLabs serves them with only a warning. Neither reads the ACI/1 downstream fields, so neither can see a `required:false` hop.
- **Venice, reply integrity.** jooray rejects plaintext or truncated replies; AxLabs forwards plaintext content and tool_calls.
- **Auto-update.** Tinfoil (signed releases), Privatemode (an unsigned CDN manifest) and the Venice proxies (any genuine quote) adopt operator changes without a client decision. hermes's anchor and Privatemode's `--manifest-path` are the only pinned modes.
