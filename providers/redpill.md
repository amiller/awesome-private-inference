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
- `phala-simple` shape *re-verifies cryptographically*, but the verifier accepts a
  CVM running the `dstack-nvidia-dev` OS image with an operator-controlled host-SSH
  path (see Known gaps). Stage 0.
- `chutes` shape re-verifies the quote + key binding (the layers we can check), but the
  backend code/model are unmeasured — see Known gaps and [Chutes](./chutes.md).
- `near-relay` inherits NEAR's inner-boundary gap.
- Tinfoil-routed entries 404 on attestation.

## Known gaps

- **Phala-simple: dev OS image with operator host-SSH backdoor — RESOLVED as of
  2026-06-18; now auto-tracked.** Live probe 2026-06-18: both phala-simple models
  (`phala/qwen-2.5-7b-instruct`, `phala/gpt-oss-20b`) boot the **production** image
  `dstack-nvidia-0.5.9-806a352e` — no sshd, no `debug-tweaks`. The host-SSH path
  below is closed. This is now a checked layer: the verifier reads `vm_config.image`
  and the dashboard's **Prod OS image** column flips ✅/❌, so a regression to a
  `dstack-nvidia-dev-*` image would surface automatically. The historical finding,
  for the record:
  Every `phala/*` model on RedPill booted
  `dstack-nvidia-dev-0.5.{5,6,8}-*`. Live probe 2026-05-05:
  `phala/gpt-oss-20b` → `dstack-nvidia-dev-0.5.8-e3e677dd`,
  `phala/glm-4.7-flash` → `dstack-nvidia-dev-0.5.5-021bf66a`,
  `phala/qwen-2.5-7b-instruct` → `dstack-nvidia-dev-0.5.8-e3e677dd`,
  `phala/gemma-3-27b-it` → `dstack-nvidia-dev-0.5.8-e3e677dd`. Identical to the
  2026-04-28 audit — **not fixed**. The dev image ships
  `packagegroup-core-ssh-openssh`, `debug-tweaks`, `tools-profile`; the prod
  `dstack-nvidia-*` image installs *no* sshd and runs `disable_login()`.
  Combined with `DSTACK_AUTHORIZED_KEYS` in `allowed_envs` and a measured
  `pre_launch_script` that writes the host-supplied key to
  `/home/root/.ssh/authorized_keys` at boot, the operator gets host-network-namespace
  root SSH inside every phala-simple CVM. `/proc/<vllm-pid>/mem` is then reachable —
  prompts and responses in flight are exfiltratable, and the per-CVM ECDSA signing
  key can be lifted. **This is the single load-bearing finding for phala-simple
  Stage 1**: switching the OS image to the production variant neutralizes the path
  without any compose change. NEAR AI's model fleet runs the prod image
  (`dstack-nvidia-0.5.5`); Redpill's Phala-direct fleet does not. Full audit and
  recipe-level diff:
  [redpill-federated-inference DEVPROOF-REPORT](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/redpill-federated-inference/DEVPROOF-REPORT.md).
  Also: the same `pre_launch_script` evaluates `DSTACK_ROOT_PUBLIC_KEY` and
  `DSTACK_ROOT_PASSWORD` paths before `DSTACK_AUTHORIZED_KEYS` — multiple
  operator-controlled root-access knobs in the same script.

- **Inner-boundary for NEAR-relay shape.** RedPill inherits NEAR's gateway-to-model gap
  ([NEAR cloud-api #224](https://github.com/nearai/cloud-api/issues/224)).
- **Catalog ≠ served.** `qwen/qwen3-coder-480b-a35b-instruct`,
  `deepseek/deepseek-r1-0528`, `moonshotai/kimi-k2-thinking`, etc. appear in
  `/api/models` but return 404 on real calls.
- **No NVIDIA payload on Chutes shape.** Chutes publishes TDX-only attestation; GPU
  posture is not cryptographically attested.
- **Chutes shape re-verifies the quote but not the code or model.** The `chutes` rows show
  `valid` because TDX + the `SHA256(nonce‖pubkey)` key binding check out, but the Chutes
  backend's in-enclave `serve.py` and model are unmeasured — a verified quote proves a genuine
  TDX+GPU running *a* Chutes base image, not which model on which code. RedPill inherits this in
  full. See [Chutes](./chutes.md) and [chutesai/chutes#75](https://github.com/chutesai/chutes/issues/75).
- **Subscription arbitrage.** "RedPill Pro $50/mo" is effectively a pay-as-you-go credit
  pool (2026-04-21 sub/list ratio = 0.998).
- **Independent of the dev image, on phala-simple:** mutable tags
  (`vllm/vllm-openai:latest`, `lmsysorg/sglang:dev`) so compose-hash equality
  doesn't establish image identity; HuggingFace weights pulled at boot with no
  content digest pinning; `secure_time: false`; multi-model CVMs without per-query
  model binding (`c3f19eb2` serves both `gpt-oss-20b` and `gemma-3-27b-it` from
  one CVM — the attestation report is identical for both names). Switching to the
  prod OS image closes the SSH path but leaves these intact.

## Reproduce

```bash
export REDPILL_API_KEY=...
python -c "from verifiers.redpill import verify; \
           r = verify('$REDPILL_API_KEY', 'https://api.red-pill.ai/v1', 'phala/gpt-oss-20b'); \
           import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
```

## History

Snapshots: [data/snapshots/](../data/snapshots/).
