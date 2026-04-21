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
- **Backend-attested-by-gateway**: ❌ (see gap below).

## Known gaps

- **Inner-boundary gap.** The cloud-api gateway fetches each model CVM's
  `/v1/attestation/report` but parses the JSON and discards the result —
  it does not cryptographically verify the backend TDX quote, check
  `compose_hash`, or validate the backend `signing_public_key`. The key we encrypt
  to is therefore trust-on-first-use inside the gateway. Canonical reference:
  [nearai/cloud-api#224](https://github.com/nearai/cloud-api/issues/224),
  open since 2025-12-03. Full trace in the
  [NEAR Private Chat attestation-gap analysis](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/near-private-chat/ATTESTATION-GAP-ANALYSIS.md).
- **Operator-controlled routing.** The gateway resolves a backend via `inference_url` in
  its database; an operator (or anyone with DB access) can point that at a logging relay
  that forwards to a real model and the attestation layer won't notice.
- **Verifier TODOs.** Phala's `private-ai-verifier` that we (and NEAR) use still decodes
  NVIDIA and Intel Trust Authority JWTs with `verify_signature=False` — acknowledged but
  not yet fixed.

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
