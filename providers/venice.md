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

## Scorecard

See the [live matrix](https://amiller.github.io/awesome-private-inference). The attestation
bundle contains everything needed for independent re-verification:
- TDX quote (hex) → forwarded to Phala's verifier
- NVIDIA payload → forwarded to NRAS
- `nonce_source: "client"` when a user-supplied nonce is echoed back correctly
- Signing pubkey + address for key-derivation check

## Known gaps

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
