# Venice

## Claim

Venice ([venice.ai](https://venice.ai)) offers "private by default" inference: models
marked `e2ee-*` route through TDX-attested backends, and the attestation bundle is exposed
at an (undocumented) `GET /api/v1/tee/attestation` endpoint.

## Endpoint surface

- **Chat:** `https://api.venice.ai/api/v1/chat/completions`
- **Attestation:** `https://api.venice.ai/api/v1/tee/attestation?model=<id>&nonce=<hex>` — undocumented but functional
- **Models:** `https://api.venice.ai/api/v1/models`
- **Auth:** Bearer API key (also usable as sign-in for chat UI).

## Model naming conventions

- **`e2ee-<name>-p`** — Phala enclave (`tee_provider: "phala"`).
- **`e2ee-<name>`** (no suffix) — NEAR AI backend.

Non-`e2ee-*` models on Venice are *not* TEE-attested — treat them as any regular API.

## Wire protocol (confirmed 2026-04-24)

The E2EE wire is **ECIES on SECP256K1** (ECDH → HKDF-SHA256 → AES-GCM), identical to
NEAR AI upstream, differing only in header names: `X-Venice-TEE-Signing-Algo: ecdsa`,
`X-Venice-TEE-Client-Pub-Key` (uncompressed 04-prefix, 130-hex), `X-Venice-TEE-Model-Pub-Key`.
Live roundtrip against `e2ee-venice-uncensored-24b-p` confirmed the gateway is
transparent — ciphertext flows through and decrypts inside the enclave; Venice does
not see plaintext on the ECIES path.

## Scorecard

See the [live matrix](https://amiller.github.io/awesome-private-inference). The attestation
bundle contains everything needed for independent re-verification:
- TDX quote (hex) → forwarded to Phala's verifier
- NVIDIA payload → forwarded to NRAS
- `nonce_source: "client"` when a user-supplied nonce is echoed back correctly
- Signing pubkey + address for key-derivation check

## Known gaps

- **Skill-text backdoor.** [`veniceai/skills`](https://github.com/veniceai/skills)
  (the agent-facing catalog) misnames the protocol as "HPKE / Noise handshake",
  cites `docs.venice.ai/e2ee` which 404s, and teaches **zero of the six** standard
  TDX-verification steps (fetch quote, verify signature, check `report_data`
  binding, derive address from `signing_public_key`, pin TLS, check debug flag).
  An agent following the skill as written builds a TOFU connection — the crypto
  is correct but the anchor is never checked. Full analysis:
  [venice-private-inference case study](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/venice-private-inference/DEVPROOF-REPORT.md).
- **`supportsE2EE: true` flag is inconsistent.** `e2ee-gpt-oss-20b-p` attests
  successfully but returns no `signing_public_key` in the attestation body —
  the flag does not imply a usable ECIES path.
- **HPKE/OHTTP stub.** Attestation bundle publishes an `ohttp_key_config`
  (RFC 9458, DHKEM-X25519, AES-128-GCM / ChaCha20Poly1305), but no `/ohttp*`
  endpoint responds. Either unused infrastructure or a future plan. Agents
  following the skill's "HPKE" guidance hit nothing.
- **Attestation endpoint flaky.** `/tee/attestation` times out consistently on
  `e2ee-glm-5` and `e2ee-qwen3-5-122b-a10b` across retries; works quickly on
  `e2ee-venice-uncensored-24b-p` and others. Not transient.
- **Reseller markup.** Venice's Phala-backed models cost ~22% more than RedPill's equivalents
  on identical enclaves. The enclave is the same; Venice is paying per-token to a downstream
  Phala aggregator.
- **Inner boundary inherited.** Same gateway-to-backend gap as NEAR/RedPill.
- **Undocumented endpoint.** `/tee/attestation` isn't in Venice's public API docs; the
  schema could change without notice.
- **Subscription math.** Pro ($18/mo) is chat-UI only for API use — it provides only
  $1 of API credit. Pro+ ($68/mo → $75 credit) and Max ($200/mo → $225 credit) give
  10–12.5% bonus over pay-as-you-go.

## Reproduce

```bash
export VENICE_API_KEY=...
python -c "from verifiers.venice import verify; \
           r = verify('$VENICE_API_KEY', 'https://api.venice.ai/api/v1', 'e2ee-glm-5'); \
           import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
```

## History

Snapshots: [data/snapshots/](../data/snapshots/).
