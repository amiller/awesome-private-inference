# Chutes

## Claim

Chutes ([chutes.ai](https://chutes.ai)) is serverless AI inference on Bittensor **subnet 64**
(Rayon Labs / chutesai). Its confidential (`-TEE`) chutes run on Intel TDX + NVIDIA
confidential-compute GPUs with ML-KEM-768 end-to-end encryption, and the docs advertise
"not even we can see your data" (`docs/tee-verification.md`). It is this cohort's first
**Bittensor-subnet** provider and first **non-dstack custom TDX stack** — its own attestation
sidecar, measurement registry, and LUKS key release rather than Phala's dstack.

## Endpoint surface

- **Chat (default):** `https://llm.chutes.ai/v1/chat/completions` (OpenAI-compatible)
- **Control plane:** `https://api.chutes.ai`
- **E2E invoke:** `https://api.chutes.ai/e2e/invoke`
- **Instance discovery:** `GET /e2e/instances/{chute_id}` → `{instance_id, e2e_pubkey, nonces}`
- **Attestation evidence:** `GET /instances/{id}/evidence`
- **Published measurements:** `GET /servers/tee/measurements`
- **Auth:** Bearer API key (`cpk_...`).

Chutes is reached two ways in this registry: **directly** (`chutes.ai`, documented here, not
yet in the daily probe) and **relayed through RedPill** as the `chutes` attestation shape —
see [RedPill](./redpill.md).

## What re-verifies (the crypto core is sound — confirmed live)

The hardware root is real, and a `~115`-line reproducer ([devproof case-study `verify/`](https://github.com/amiller/devproof-audits-guide/tree/main/case-studies/chutes-confidential-inference))
confirms it against the live API:

- Genuine **non-debug** Intel TDX enclave; DCAP signature valid; quote fresh.
- ML-KEM-768 E2E key **hardware-bound**: `report_data[0:32] == SHA256(nonce‖e2e_pubkey)`.
- Per-GPU **NVIDIA NRAS** evidence, nonce-bound to the TD.
- The miner (GPU host) is **contained**, not trusted: a measured OPA + cosign admission
  controller plus TEE-gated LUKS key release means a malicious host cannot swap code or read
  enclave memory. The residual trust is in **Chutes** (control plane + server-side build/sign)
  and the **chute operator** (whoever wrote the code on the plaintext path).

## Scorecard

Stage 0 for confidential inference. RedPill's `chutes` relay rows re-verify TDX + the
`SHA256(nonce‖pubkey)` binding and show `valid` on the [live matrix](https://amiller.github.io/awesome-private-inference)
— but that is exactly the "verified quote ≠ verified model or code" gap below: a passing quote
proves a genuine TDX+GPU running *a* Chutes base image, not *which* model on *which* code.

## Known gaps

The cryptographic core is sound, but the confidentiality claim collapses at the application
layer, where the code that touches plaintext is unmeasured. Full analysis:
[chutes-confidential-inference case study](https://github.com/amiller/devproof-audits-guide/tree/main/case-studies/chutes-confidential-inference).

- **Operator code & model are unmeasured (lead finding) — filed as
  [`chutesai/chutes#75`](https://github.com/chutesai/chutes/issues/75).** The decryption
  boundary is measured, but it hands plaintext to operator-authored `serve.py`/`/app/chute.py`,
  which CFSV explicitly excludes (`cfsv_wrapper.py:54`, `exclude_path="/app/chute.py"`) and which
  is in no RTMR. All published configs share one MRTD; `model_name`/`revision` are never placed
  in `report_data` or an RTMR, and weights are pulled at container start. So a verified quote
  cannot establish which model answered, and a verifying client cannot detect that the running
  code logs or ships the plaintext out. Cuts both ways: a third-party operator can exfiltrate
  prompts, and Chutes can substitute its own `serve.py` for a first-party model — the attestation
  is identical either way. **Demonstrated live** (2026-06-16/17): egress-free cross-user prompt
  exfiltration from a `verified=True` enclave.
- **Verify-then-encrypt is optional; no shipped client verifies — filed as
  [`chutesai/e2ee-proxy#3`](https://github.com/chutesai/e2ee-proxy/issues/3).** Discovery returns
  a miner-supplied `e2e_pubkey` with **no quote** (`e2e/router.py:144-151`); nothing cross-checks
  it against a quote. The only runnable example (`scripts/test_e2e_client.py:120-128`) encrypts
  straight to the discovered key — no `/evidence` fetch, no `report_data[0:32]==SHA256(nonce‖pubkey)`
  check — and the SDK ships no consumer-side verifier. A control plane can return its own key and
  read every prompt; TDX is bypassed silently. The docs warn about exactly this MITM
  (`docs/tee-verification.md:409-411`) but the demonstrated code contradicts it.
- **Default OpenAI path is plaintext at the control plane.** The standard `llm.chutes.ai` route
  reads the prompt in the clear before forwarding: `await request.json()`, `payload["model"]`
  alias rewrite (`invocation/router.py:902-930`), `payload["messages"]` iteration (`:933`), and
  `get_prompt_prefix_hashes(...)` for prefix-cache routing (`:605`). "Not even we can see your
  data" holds only on the opt-in `/e2e/invoke` path, not the path most users hit.
- **Reseller surface: tenant images are built and signed server-side by Chutes.** `forge` builds
  and `cosign`-signs the tenant image with Chutes' key (`api/image/forge.py:644-676`); the tenant
  holds no key and cannot compute "their" digest, and the image identity is in no
  verifier-readable measured register (RTMR3 = 0 in production). A Chutes customer cannot prove to
  *their* users which code ran.
- **Lower-tier.** NVIDIA's offline `LOCAL` GPU verifier isn't offered (NRAS network-only);
  a single fleet-wide static LUKS passphrase rather than per-TD sealed keys; the Jobs path
  (`@chute.job`, SSH-in-TEE) is unaudited.

## Reproduce

```bash
# API key (Bearer cpk_...) in /tmp/ck
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" \
     https://api.chutes.ai/servers/tee/measurements | jq 'length'   # 10 configs, 1 MRTD
# Standalone reproducer (crypto core [1]-[5] + model-substitution check [6]):
#   devproof-audits-guide/case-studies/chutes-confidential-inference/verify/verify_chutes.py
```

## History

Snapshots: [data/snapshots/](../data/snapshots/) (RedPill `chutes`-shape rows).
