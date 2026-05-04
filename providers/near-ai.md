# NEAR AI

## Claim

NEAR AI Cloud ([cloud-api.near.ai](https://cloud-api.near.ai)) exposes open-weight models
inside Intel TDX + NVIDIA confidential-compute enclaves, with per-model attestation at
`GET /v1/attestation/report`. Source-available gateway + verifier:
[nearai/cloud-api](https://github.com/nearai/cloud-api),
[nearai/nearai-cloud-verifier](https://github.com/nearai/nearai-cloud-verifier).

## Endpoint surface

- **Chat:** `https://cloud-api.near.ai/v1/chat/completions`
- **Attestation:** `https://cloud-api.near.ai/v1/attestation/report?model=<id>&nonce=<hex>&include_tls_fingerprint=true`
- **Models:** `https://cloud-api.near.ai/v1/models`
- **Auth:** NEAR-AI-issued bearer.

## Attestation bundle shape

Response contains:
- `gateway_attestation` — TDX quote of the cloud-api itself, plus its TLS cert fingerprint
  (so the key we encrypt to is bound to the TLS endpoint we're talking to).
- `model_attestations[]` — TDX + NVIDIA payload for each backend CVM serving the model.

Our re-verifier runs both layers through Phala's TDX verifier + NRAS, plus the canonical
address-derivation check.

## Scorecard

See [live matrix](https://amiller.github.io/awesome-private-inference).
- Gateway TDX: re-verifiable.
- Model-CVM TDX: re-verifiable.
- NVIDIA GPU: re-verifiable via NRAS.
- Signing-key-to-address derivation: re-verifiable.
- Backend-attested-by-gateway: ✅ since cloud-api PR [#552](https://github.com/nearai/cloud-api/pull/552) (Apr 2026) — gateway verifies each backend's TDX/RTMR3/NRAS inline before serving.
- **Server-side compose_hash anchoring**: ❌ (allowlist empty; see gaps below).
- **Client-side on-chain anchoring**: ❌ (PR open; see gaps below).
- **Client-side model→app_id / compose pin**: ❌ (see gaps below).

## Known gaps

- **Server-side compose_hash check is not enforced.** The gateway now verifies each
  backend cryptographically before serving (cloud-api PR
  [#552](https://github.com/nearai/cloud-api/pull/552), Apr 2026), but it does **not**
  check the backend's `compose_hash` against the on-chain
  `DstackApp.allowedComposeHashes` registry, and the `ALLOWED_IMAGE_HASHES`
  client-side allowlist is **empty** in production. Net: a CVM running an
  unauthorized compose still passes verification as long as its TDX quote and GPU
  attestation are individually valid. Full trace:
  [DEVPROOF-REPORT-revisit-2026-05-02.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/DEVPROOF-REPORT-revisit-2026-05-02.md).

- **Client-side on-chain anchoring missing.** The default verifier
  (`nearai/nearai-cloud-verifier`) does not check the deployer's on-chain registry
  (`DstackKms.registeredApps`, `DstackApp.allowedComposeHashes`,
  `DstackKms.allowedOsImages`). Anyone with TDX can produce a cryptographically valid
  quote of an unrelated CVM and the verifier accepts it. Fix open in
  [nearai-cloud-verifier#24](https://github.com/nearai/nearai-cloud-verifier/pull/24).

- **Client-side model→app_id / compose pin missing.** No client (verifier or
  hermes-agent) pins which `app_id` + `compose_hash` is canonical for each model. NEAR
  runs all models under a single `DstackApp` (`0x2c0a0c96…`); only `compose_hash`
  distinguishes one model's CVM from another. So a malicious gateway can return a
  different model's attestation for the requested model — every on-chain check passes
  (both composes are authorized for the same app), only the user's prompt got
  rerouted. A static client-side `(model → app_id, compose_hash_set)` pin is the
  natural floor for this; on-chain anchoring is the auto-update layer on top.

- **Operator-controlled routing (narrowed, not closed).** The original
  [`MODEL_DISCOVERY_SERVER_URL`](https://github.com/nearai/cloud-api/issues/224) gap
  (operator rewrites the discovery response) is **closed** by cloud-api PRs
  [#485](https://github.com/nearai/cloud-api/pull/485) /
  [#513](https://github.com/nearai/cloud-api/pull/513) /
  [#552](https://github.com/nearai/cloud-api/pull/552) /
  [#558](https://github.com/nearai/cloud-api/pull/558) (Mar–Apr 2026). Routing still
  flows through an `inference_url` DB column, but every backend now gets verified
  before serving — the surface narrowed from "redirect to anything" to "redirect to
  anything that produces a valid TDX/RTMR3/NRAS attestation," which combined with the
  on-chain-anchoring gaps above means redirect-to-another-NEAR-model-CVM is the
  residual.

- **Verifier TODOs.** Phala's `private-ai-verifier` that we (and NEAR) use still
  decodes NVIDIA and Intel Trust Authority JWTs with `verify_signature=False` —
  acknowledged but not yet fixed.

## Reproduce

```bash
export NEAR_API_KEY=...
git clone https://github.com/nearai/nearai-cloud-verifier _nearai-verifier
export NEARAI_VERIFIER_PATH="$(pwd)/_nearai-verifier/py"
python -c "from verifiers.near_ai import verify; \
           r = verify('$NEAR_API_KEY', 'https://cloud-api.near.ai', 'openai/gpt-oss-120b'); \
           import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
```

## History

Snapshots: [data/snapshots/](../data/snapshots/).

External case-study artifacts (devproof-audits-guide):
- [TRUST-CHAIN-ANALYSIS.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/TRUST-CHAIN-ANALYSIS.md) — full Links 1–9 walk from user E2EE encrypt down to TDX-protected KMS root, with source line numbers, May-2026 live observations, and a reference-values appendix (image digests, contract addresses, RPC endpoints, source pins).
- [DEVPROOF-REPORT-revisit-2026-05-02.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/DEVPROOF-REPORT-revisit-2026-05-02.md) — top-level revisit after the discovery-URL fix; identifies the new bottleneck.
- [VERIFIER-DESIGN.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/VERIFIER-DESIGN.md) — design for the on-chain-anchoring extension shipped as `nearai-cloud-verifier#24`.
- Earlier scope (closed): [near-private-chat ATTESTATION-GAP-ANALYSIS](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/near-private-chat/ATTESTATION-GAP-ANALYSIS.md).

Client integration:
- [hermes-agent `feat/near-ai-attestation`](https://github.com/amiller/hermes-agent/tree/feat/near-ai-attestation) — strict per-model attestation for near-ai inside hermes (PR upstream to NousResearch/hermes-agent #12201). Adds an `attestation_status` tool so the agent can introspect verified TEE state from the in-process cache. On-chain-anchoring wiring is the natural follow-up.
