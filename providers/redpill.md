# RedPill

## Claim

RedPill ([red-pill.ai](https://red-pill.ai)) aggregates confidential-compute model backends
(Phala, NEAR AI, Chutes, Tinfoil) under an OpenAI-compatible gateway and advertises
per-model TEE attestation via `GET /v1/attestation/report`.

## Endpoint surface

- **Chat:** `https://api.red-pill.ai/v1/chat/completions`
- **Attestation:** `https://api.red-pill.ai/v1/attestation/report?model=<id>&nonce=<hex>`
- **Models:** `https://api.red-pill.ai/api/models`
- **Auth:** Bearer API key, or per-session cookie via web UI.

## Shapes observed

RedPill's attestation response is **not uniform** — it dispatches to one of four formats
depending on which backend actually runs the model:

| Shape | Trigger | Re-verifier coverage |
|---|---|---|
| `phala-simple` | `phala/*` models | TDX + NVIDIA + key derivation + compose-hash |
| `near-relay` | NEAR-hosted models surfaced through RedPill | TDX + partial (inner-boundary gap) |
| `chutes` | Chutes-routed models (`kimi-k2.5`, `mimo-v2-flash`, …) | TDX + SHA256(nonce‖pubkey) binding |
| `tinfoil` | Some catalog entries | **404 today** — catalog-only |

## Scorecard

See the [live matrix](https://amiller.github.io/awesome-private-inference). On 2026-04-21:
- `phala-simple` and `chutes` shapes re-verify end-to-end (the layers we can check).
- `near-relay` inherits NEAR's inner-boundary gap.
- Tinfoil-routed entries 404 on attestation.

## Known gaps

- **Inner-boundary for NEAR-relay shape.** RedPill inherits NEAR's gateway-to-model gap
  ([NEAR cloud-api #224](https://github.com/nearai/cloud-api/issues/224)).
- **Catalog ≠ served.** `qwen/qwen3-coder-480b-a35b-instruct`,
  `deepseek/deepseek-r1-0528`, `moonshotai/kimi-k2-thinking`, etc. appear in
  `/api/models` but return 404 on real calls.
- **No NVIDIA payload on Chutes shape.** Chutes publishes TDX-only attestation; GPU
  posture is not cryptographically attested.
- **Subscription arbitrage.** "RedPill Pro $50/mo" is effectively a pay-as-you-go credit
  pool (2026-04-21 sub/list ratio = 0.998).

## Reproduce

```bash
export REDPILL_API_KEY=...
python -c "from verifiers.redpill import verify; \
           r = verify('$REDPILL_API_KEY', 'https://api.red-pill.ai/v1', 'phala/gpt-oss-20b'); \
           import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
```

## History

Snapshots: [data/snapshots/](../data/snapshots/).
