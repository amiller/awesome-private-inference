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

Chutes is reached directly by the current daily probe. The RedPill ACI gateway
also represents Chutes channels as upstream-session records. Those records must
pass the ACI session-integrity checks described on the [RedPill page](./redpill.md).

## What re-verifies (the crypto core is sound — confirmed live)

The hardware root is real, and a `~115`-line reproducer ([devproof case-study `verify/`](https://github.com/amiller/devproof-audits-guide/tree/main/case-studies/chutes-confidential-inference))
confirms it against the live API:

- Genuine **non-debug** Intel TDX enclave; DCAP signature valid; quote fresh.
- ML-KEM-768 E2E key **hardware-bound**: `report_data[0:32] == SHA256(nonce‖e2e_pubkey)`.
  The chute computes this value itself and passes it to the in-VM attestation service, which
  forwards it unchanged (chutes `chutes/entrypoint/verify.py:330` at `1665c8b`; sek8s
  `src/sek8s/sek8s/services/attestation.py:63-73` at `3a74f23`). `report_data[32:64]` is
  `SHA256` of the attestation service's TLS public key (sek8s `providers/base.py:89-139`), so it
  identifies the VM, not the chute.
- Per-GPU **NVIDIA NRAS** evidence, nonce-bound to the TD.
- The miner (GPU host) is **contained**, not trusted: a measured OPA + cosign admission
  controller plus TEE-gated LUKS key release means a malicious host cannot swap code or read
  enclave memory. The residual trust is in **Chutes** (control plane + server-side build/sign)
  and the **chute operator** (whoever wrote the code on the plaintext path).

## Scorecard

Stage 0 for confidential inference. The direct rows re-verify TDX and the
`SHA256(nonce || pubkey)` binding. That is exactly the
"verified quote does not identify the model or serving code" gap below: a passing
quote proves a genuine TDX workload running a Chutes base image, not which model
or application code handled plaintext.

## Known gaps

The cryptographic core is sound, but the confidentiality claim collapses at the application
layer, where the code that touches plaintext is unmeasured. Full analysis:
[chutes-confidential-inference case study](https://github.com/amiller/devproof-audits-guide/tree/main/case-studies/chutes-confidential-inference).

Source revisions checked 2026-11-18: SDK `chutesai/chutes` main `08d7987` (2026-05-25) and
branch `official-llm-engines` `1665c8b` (2026-07-23, the PyPI 0.6.11rc2 code);
`chutesai/chutes-api` `3b5609f` (2026-09-03); `chutesai/sek8s` `3a74f23` (2026-10-15);
`chutesai/e2ee-proxy` `e213a09` (2026-08-07). `chutes-api` is archived on GitHub and has no
public commit after 2026-09-03, so the control-plane citations below are to its last public
source; whether production still matches it cannot be checked.

- **Operator code & model are unmeasured (lead finding) — filed as
  [`chutesai/chutes#75`](https://github.com/chutesai/chutes/issues/75).** The decryption
  boundary is measured, but it hands plaintext to operator-authored `serve.py`/`/app/chute.py`,
  which CFSV explicitly excludes (chutes `chutes/cfsv_wrapper.py:54`,
  `exclude_path="/app/chute.py"`, unchanged at `08d7987` and `1665c8b`; the validator passes
  `exclude_path=f"/app/{chute.filename}"` at chutes-api `api/instance/router.py:1177`) and which
  is in no RTMR. The control plane delivers the chute source at launch
  (`api/instance/router.py:2662`, `return_value["code"] = instance.chute.code`). All published
  configs share one MRTD, and RTMR1-3 take one value per base-VM version (see the measurement
  bullet below); `model_name`/`revision` are never placed in `report_data` or an RTMR, and
  weights are pulled at container start. So a verified quote
  cannot establish which model answered, and a verifying client cannot detect that the running
  code logs or ships the plaintext out. Cuts both ways: a third-party operator can exfiltrate
  prompts, and Chutes can substitute its own `serve.py` for a first-party model — the attestation
  is identical either way. **Demonstrated live** (2026-06-16/17): egress-free cross-user prompt
  exfiltration from a `verified=True` enclave. **Re-checked live 2026-11-17**
  ([#75 comment](https://github.com/chutesai/chutes/issues/75#issuecomment-6962921503)): 176 quotes from 19 chutes and
  5 accounts all verified `UpToDate` with one MRTD and three RTMR1-3 sets, each equal to the
  published runtime values of one base-VM version; a vLLM chute serving a Llama 3.3 70B finetune
  had the same RTMR1-3 as `Qwen/Qwen3.8-27B-TEE` on SGLang. On 2026-11-18 a chute of ours that
  loaded three encrypted LoRA adapters inside the instance passed the same checks; nothing in the
  quote identified the code or the adapters. #75 is open with no reply from Chutes on GitHub.
  Chutes said (call, 2026-11-18) that its roadmap includes fixes for these gaps, and that it
  favours the #75 approach of binding a workload hash (image digest, `sha256(chute.py)`, model
  revision) into `report_data` through the attestation service, because that avoids overloading
  RTMR3.
- **Confidential chutes from different accounts share one TDX VM (2026-11-17/18).** Grouping
  quotes by `report_data[32:64]` puts several chutes in one VM. Each of five snapshots of every
  public TEE chute (2026-11-17 20:24 to 2026-11-18 04:11 UTC) had 5 or 6 VMs holding chutes of
  two or more accounts. A private chute of ours landed on 2026-11-17 in a VM with four
  instances of Chutes' own models; a second one, on 2026-11-18, landed in a VM with six instances
  belonging to two other customer accounts. All quotes in both VMs verified `UpToDate` against
  Intel PCS (all 176 of the 2026-11-17 21:02 snapshot and all 146 of the 2026-11-18 04:11
  snapshot), and each matched a published row. The quotes show distinct instances sharing one
  attestation-service key. That this key identifies the VM comes from sek8s source
  (above). Which account owns each neighbour comes from Chutes' API, which is not signed. A
  tenant's chute is separated from co-tenant chutes by Kubernetes pod isolation and the in-VM
  admission policy, not by TDX; we have not tested that boundary. It also means a per-chute
  measurement cannot be a per-VM value: #75's fix has to identify the calling pod.
- **Verify-then-encrypt is optional; no shipped client verifies — filed as
  [`chutesai/e2ee-proxy#3`](https://github.com/chutesai/e2ee-proxy/issues/3).** Discovery returns
  a miner-supplied `e2e_pubkey` with **no quote** (chutes-api `api/e2e/router.py:142-149` at
  `3b5609f`; same shape live on 2026-11-17); nothing cross-checks
  it against a quote. The only runnable example (chutes-api `scripts/test_e2e_client.py:120-128`,
  unchanged since `77b6f35`) encrypts
  straight to the discovered key — no `/evidence` fetch, no `report_data[0:32]==SHA256(nonce‖pubkey)`
  check — and the SDK (0.6.11rc2) ships no consumer-side verifier. A control plane can return its own key and
  read every prompt; TDX is bypassed silently. The docs warn about exactly this MITM
  (chutes-api `docs/tee-verification.md:454-456` at `3b5609f`) but the demonstrated code
  contradicts it. Since `fdb03d3` (2026-08-04) the doc also describes `signature`/`attested_body` fields, an RSA
  signature over the evidence response by the attestation service's TLS key (`:406-408`); no
  shipped client checks them either. `e2ee-proxy` at `e213a09` still encrypts to the discovered
  key without fetching evidence. #3 is open with no reply from Chutes; `chutesai/e2ee-proxy#9`
  (2026-09-12, another reporter) describes the same gap.
- **Default OpenAI path is plaintext at the control plane.** The standard `llm.chutes.ai` route
  reads the prompt in the clear before forwarding: `await request.json()` (chutes-api
  `api/invocation/router.py:895` at `3b5609f`), `payload["model"]`
  alias rewrite (`:902-933`), `payload["messages"]` iteration (`:937`),
  `chat_template_kwargs` reasoning-effort rewrite (`:989-1000`, added `f6c817c`, 2026-06-18), and
  `get_prompt_prefix_hashes(...)` for prefix-cache routing (`:606`, per-chute path). "Not even we can see your
  data" holds only on the opt-in `/e2e/invoke` path, not the path most users hit.
- **Reseller surface: tenant images are built and signed server-side by Chutes.** `forge` builds
  and `cosign`-signs the tenant image with Chutes' key (chutes-api `api/image/forge.py:646-677`
  at `3b5609f`; a Depot-based `api/image/remote_forge.py:311-338` signs with the same key and is
  off by default in `charts/values.yaml:331-332`, so which builder production uses is unknown); the tenant
  holds no key and cannot compute "their" digest, and the image identity is in no
  verifier-readable measured register. RTMR3 is no longer 0: in the published runtime values
  and in the 2026-11-17 quotes it is non-zero but one fixed value per base-VM version, covering
  base-VM files only (sek8s `ansible/guest/roles/rootfs-measure/files/tee-measure-miner.conf`).
  The cosign keys are now published at `/servers/signing-keys` (chutes-api
  `api/server/router.py:778-794`, added `fdb03d3`, 2026-08-04), signed by a root key that RTMR3
  measures; the leaf keys are fetched at boot and not measured (`tee-measure-miner.conf:127-131`),
  so Chutes can rotate them with no measurement change. A Chutes customer cannot prove to
  *their* users which code ran.
- **Encrypted streaming has no integrity across chunks.** On `/e2e/invoke` with streaming, each
  SSE chunk is sealed separately with no sequence number or transcript MAC, so Chutes' API (or
  anything on that path) can drop, reorder or replay chunks and every chunk still decrypts. Only a
  missing inner `[DONE]` is detectable. NEAR's gateway, which streams from Chutes on this channel,
  documents the same limit (nearai/cloud-api `34fba04`,
  `crates/inference_providers/src/attested/chutes/e2ee_stream.rs:18-37`). An unstreamed
  `/e2e/invoke` reply is one AEAD-sealed blob and does not have this problem.
- **An instance running an unpublished TD image (2026-10-12).** All 55 rows of
  `/servers/tee/measurements` share one MRTD (`261CE538…`). Of the two listed `Qwen/Qwen3-32B-TEE`
  instances, `45130fc6` matched a published row; `912aec3d` returned a valid, `UpToDate` TDX quote
  bound to our nonce with MRTD `ddc6efcd…`, and its MRTD and RTMR0-3 appear in no published row.
  A client that checks the quote but not the measurement list would accept it. The quote was not
  retained, so the case cannot be replayed; the registry's ledger lists `ddc6efcd…` as a golden-set MRTD
  sampled from 2026-06-18 to 2026-09-02 ([research note](../research/chutes-912aec3d-evidence-gap-2026-11-15.md)).
- **Published measurements span four base-VM versions (2026-11-18).** `/servers/tee/measurements`
  had 61 rows on 2026-11-17 (`data/snapshots/2026-11-17.json`) and 62 on 2026-11-18, all with
  MRTD `261CE538…`, for base-VM versions 1.3.1 (19 rows), 1.4.0 (5), 1.4.1 (16) and 1.5.0 (22).
  Within a version, RTMR1-3 are identical across rows and only RTMR0 varies (41 distinct values
  across the host profiles). Boot RTMR3 is zero; runtime RTMR3 is one value per version. No row varies by
  chute, image or model.
- **`confidential_compute` models with no obtainable evidence (2026-10-12).** Of 14 models marked
  `confidential_compute` at `llm.chutes.ai/v1/models`, `/instances/<id>/evidence` failed for
  `Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` (HTTP 400, "Instances requires chutes_version >= 0.6.0
  to retrieve evidence") and `Nemotron-3-Nano-Omni-30B-TEE` (HTTP 502, "Attestation service
  unavailable"), and `unsloth/Mistral-Nemo-Instruct-2407-TEE` had no active instance. Ten verified
  `UpToDate` against the published list, with NRAS-signed GPU verdicts, and answered an E2EE request;
  `zai-org/GLM-5.2-TEE` verified but was at capacity (HTTP 429).
- **Lower-tier.** NVIDIA's offline `LOCAL` GPU verifier isn't offered (NRAS network-only;
  chutes-api `nv-attest/chutes_nvattest/verifier.py:10` at `3b5609f` still adds only
  `Environment.REMOTE`); a single fleet-wide static LUKS passphrase rather than per-TD sealed
  keys (changed in source, not observed live: chutes-api `api/server/util.py:1133-1207` at
  `3b5609f` uses a per-base-VM-version passphrase for first boot and rotates to a per-VM
  passphrase for VM >= 1.4.0, `api/constants.py:64`; the Chutes API still generates and holds
  every passphrase); the Jobs path
  (`@chute.job`, SSH-in-TEE) is unaudited. User secrets set with `chutes secrets` are decrypted by
  the Chutes API with its own keys and placed in the instance's launch config
  (`api/instance/router.py:2677-2688`), so Chutes can read them.

## Reproduce

```bash
# API key (Bearer cpk_...) in /tmp/ck
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" \
     https://api.chutes.ai/servers/tee/measurements | jq 'length'   # 62 configs, 1 MRTD, 4 VM versions (2026-11-18)
# RTMR1-3 sets per base-VM version (one each on 2026-11-18):
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://api.chutes.ai/servers/tee/measurements \
  | jq -r '.[] | [.version, .runtime_rtmrs.RTMR1[:8], .runtime_rtmrs.RTMR2[:8], .runtime_rtmrs.RTMR3[:8]] | @tsv' | sort | uniq -c
# Standalone reproducer (crypto core [1]-[5] + model-substitution check [6]):
#   devproof-audits-guide/case-studies/chutes-confidential-inference/verify/verify_chutes.py
```

## History

Snapshots: [data/snapshots/](../data/snapshots/).
