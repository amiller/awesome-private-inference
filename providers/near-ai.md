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
- **AppAuth Solidity verified**: ✅ as of 2026-05-09 — DstackKms impl `0x2e99ade1…` and DstackApp impl `0x7e5192c0…` (shared by every NEAR per-app proxy) have `exact_match` on Sourcify, Basescan, and Blockscout. Source = `Dstack-TEE/dstack@771f3c9e`, solc 0.8.22 / opt 200.
- **Server-side compose_hash anchoring**: ❌ (`ALLOWED_COMPOSE_HASHES` empty on cloud-api; see gaps below). N/A under closed-chain verification.
- **Client-side on-chain anchoring**: ✅ in [`verifiers/near_ai_lightclient.py`](../verifiers/near_ai_lightclient.py) (this repo) and [hermes-agent](https://github.com/amiller/hermes-agent/tree/feat/near-ai-attestation); upstream `nearai-cloud-verifier` PR [#24](https://github.com/nearai/nearai-cloud-verifier/pull/24) still open.
- **Client-side model→app_id / compose pin**: ✅ in hermes (static anchor) and in this repo's light client (per-model `(yaml, commit, file_sha256)` pin against `compose_manager_attestation.actions[]`); ❌ in upstream `nearai-cloud-verifier`.

## Known gaps

The verifier-design framing in
[VERIFIER-DESIGN.md §5](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/VERIFIER-DESIGN.md)
splits closed-chain checks across:
**Block A** (TDX/GPU, Intel-anchored) →
**Block B** (`os_image_hash`, `app_id`, `compose_hash`, KMS pubkey, Base-anchored) →
**Block C** (inner compose, Git-anchored) →
**Block D** (E2EE encrypt to verified pubkey).
A client that runs A+B+C+D end-to-end sidesteps most server-side gateway hygiene.
The remaining trust assumption shrinks to "the verifier release's anchor file
was reviewed responsibly."

### Moot under the closed-chain client

These are real on the cloud-api gateway today but do not block confidentiality
when the client runs the full chain (path B `*.completions.near.ai` or path C
E2EE). Full trace:
[DEVPROOF-REPORT-revisit-2026-05-02.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/DEVPROOF-REPORT-revisit-2026-05-02.md).

- **Server-side compose-hash check skipped + `ALLOWED_IMAGE_HASHES` empty.**
  cloud-api's `verification.rs` extracts `compose_hash` from RTMR3 but never
  compares it; `ALLOWED_IMAGE_HASHES` is unset in production. Block B5/B2
  on the *client* enforces this regardless.
- **`models.inference_url` admin-mutable, vestigial `MODEL_DISCOVERY_*`,
  `AUTH_ADMIN_DOMAINS` in `allowed_envs`.** Path B and path C bypass cloud-api
  routing — the prompt is ciphertext addressed to a TD-pinned key, so where
  the gateway thinks to route is irrelevant. The original
  [`MODEL_DISCOVERY_SERVER_URL`](https://github.com/nearai/cloud-api/issues/224)
  surface is also closed by cloud-api PRs
  [#485](https://github.com/nearai/cloud-api/pull/485) /
  [#513](https://github.com/nearai/cloud-api/pull/513) /
  [#552](https://github.com/nearai/cloud-api/pull/552) /
  [#558](https://github.com/nearai/cloud-api/pull/558).
- **compose-manager in-memory action log wipes on restart.** Block C2 refuses
  on `actions=[]`. A liveness regression for the operator, not a leak. Closed
  upstream by [compose-manager#11](https://github.com/nearai/compose-manager/pull/11)
  (merged 2026-05-08); awaiting NEAR's next outer-compose rotation to roll.
- **`/evidences/quote.json` 0 bytes after 2026-05-02 cert renewal.** Binds
  path A's dstack-ingress TLS cert; path B / C don't depend on it.

### Actively enforced by hermes' static pin

[hermes-agent #12201](https://github.com/NousResearch/hermes-agent/pull/12201)
ships
[`hermes_cli/anchors/nearai_mainnet.json`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/anchors/nearai_mainnet.json)
and refuses (in strict mode) if any pinned field mismatches. Static pin
substitutes for every Block B1–B5 read:

| Verifier-design block | On-chain authority | hermes static pin |
|---|---|---|
| B1: `kmsInfo.k256Pubkey` ↔ `info.key_provider_info.id` | `DstackKms.kmsInfo` (empty on NEAR; closed-chain clients pin `info.key_provider_info.id` directly — populating `kmsInfo` would be belt-and-suspenders) | direct pin of `info.key_provider_info.id` |
| B2: `allowedOsImages(os_image_hash)` | `DstackKms` (EOA-upgradeable) | `os_image_hashes[]` |
| B3: `registeredApps(app_id)` | `DstackKms` (EOA-upgradeable) | per-model `app_id` |
| B4: `model → app_id` map | (no on-chain map) | `models[M].app_id` |
| B5: `allowedComposeHashes(compose_hash)` | `DstackApp` (UUPS by EOA) | per-model `compose_hashes[]` |

This downgrades both "empty `kmsInfo`" and "EOA can UUPS-upgrade the AppAuth
impl" from runtime trust assumptions to **anchor-file refresh discipline**. A
hostile EOA upgrade or KMS rotation doesn't compromise existing hermes clients
at request time; the next anchor refresh is a reviewable GitHub PR with the
rotation visible in `git diff`. The on-chain Block B reader is the auto-update
layer on top — useful for ergonomics, not what's keeping the chain closed.

*Observed in the wild (2026-05-05):* `zai-org/GLM-5.1-FP8` rotated `compose_hash`
`0x700adbf5…` → `0x242a6272…` within ~30 min on the **same `signing_address`**
(`0xbb4d2e7f…`). The operator can swap deployed compose without rotating
signing keys (key bound to instance, not compose). Both composes were
authorized in our captures and nothing malicious was observed — but it's the
concrete substitution surface the static pin catches, and the upper bound on
legitimate refresh cadence: hermes-anchor staleness is bounded by operator
rotation rate.

### Residual (belt-and-suspenders / further upstream work)

Real but not blocking under closed-chain verification — closed-chain clients
sidestep these via static-anchor / on-chain reads / inner-compose closure
they perform themselves.

- **`DstackKms.kmsInfo` is empty on `0x8fa1593fac…`.** All four fields
  (`k256Pubkey`, `caPubkey`, `quote`, `eventlog`) return zero-length bytes;
  Phala's canonical KMS at `0x2f83172A…` populates them. Each per-CVM
  attestation already carries `info.key_provider_info.id` (the asserted KMS
  pubkey), so a closed-chain client can pin it across attestations and trust
  dstack's now-verified source for `OsRng`-inside-TD root generation. The
  on-chain `kmsInfo.quote` would be public TEE-attested proof of that fact
  rather than a transitive trust chain — useful but not load-bearing.
  Fix: NEAR populates `kmsInfo` once.
- **NEAR-published manifest is partial.** Per-proxy `app_id` IS in the
  attestation response (`info.app_id`, `gateway_attestation.info.app_id`).
  Missing: chain ID (it's Base 8453), KMS factory address, signed
  `model → app_id` map. We've stitched a complete one together as the hermes
  anchor + this repo's `MODEL_PINS`; an authoritative source-of-truth from
  NEAR would let other clients align without re-doing the capture.
- **AppAuth proxies have `_upgradesDisabled=false`, owner is a single EOA
  `0x21e6b7ef…`.** UUPS upgrades are retroactively logged
  (`Upgraded(address)` events) — auditable. Closed-chain clients can pin
  `expected_impl` at slot `0x360894…e103` and reject if the proxy ever
  delegates elsewhere; this repo's light client does NOT yet do this
  (deferred — see `near-lightclient-todo.md`). Impl source itself is now
  publicly verified, so the impl bytecode is auditable, not just the proxy
  shell.
- **`nearai-cloud-verifier` upstream doesn't yet enforce Block B / Block C.**
  Still runs only Block A + model_name check (PR #23). PR
  [#24](https://github.com/nearai/nearai-cloud-verifier/pull/24) for Block B
  is open; closed-chain reference impl shipped in this repo as
  `verifiers/near_ai_lightclient.py`.
- **Verifier JWT signatures unchecked.** Phala's `private-ai-verifier`
  decodes NRAS / Intel Trust Authority JWTs with `verify_signature=False`.
  Acknowledged TODO; affects every downstream that uses it as the TDX oracle.

## Reproduce

**Block-A only (dashboard verifier — TDX/GPU/report_data, no on-chain or inner-compose):**

```bash
export NEAR_API_KEY=...
git clone https://github.com/nearai/nearai-cloud-verifier _nearai-verifier
export NEARAI_VERIFIER_PATH="$(pwd)/_nearai-verifier/py"
python -c "from verifiers.near_ai import verify; \
           r = verify('$NEAR_API_KEY', 'https://cloud-api.near.ai', 'openai/gpt-oss-120b'); \
           import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
```

**Closed-chain (Block A + on-chain compose-hash anchor + inner-compose pin):**

```bash
# Same NEARAI_VERIFIER_PATH as above
python -m verifiers.near_ai_lightclient --model "zai-org/GLM-5.1-FP8" --onchain live
```

`--onchain live` queries Base via Blockscout for `addComposeHash` events and
checks the live `info.compose_hash` is in the authorized set; `--min-age-hours
24` adds an effective ERC-733 §5 upgrade-notice window. The inner-compose pin
in `MODEL_PINS` ties the running TD to a specific
`(yaml, commit, file_sha256)` in `nearai/cvm-compose-files`, which after
[#30](https://github.com/nearai/cvm-compose-files/pull/30) (HF revision
pinning, merged 2026-05-06) transitively commits the HuggingFace weight
checkpoint.

## History

Snapshots: [data/snapshots/](../data/snapshots/).

External case-study artifacts (devproof-audits-guide):
- [TRUST-CHAIN-ANALYSIS.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/TRUST-CHAIN-ANALYSIS.md) — full Links 1–9 walk from user E2EE encrypt down to TDX-protected KMS root, with source line numbers, May-2026 live observations, and a reference-values appendix (image digests, contract addresses, RPC endpoints, source pins).
- [DEVPROOF-REPORT-revisit-2026-05-02.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/DEVPROOF-REPORT-revisit-2026-05-02.md) — top-level revisit after the discovery-URL fix; identifies the new bottleneck.
- [VERIFIER-DESIGN.md](https://github.com/amiller/devproof-audits-guide/blob/near-ai-inference/case-studies/near-ai-private-inference/VERIFIER-DESIGN.md) — design for the on-chain-anchoring extension shipped as `nearai-cloud-verifier#24`.
- Earlier scope (closed): [near-private-chat ATTESTATION-GAP-ANALYSIS](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/near-private-chat/ATTESTATION-GAP-ANALYSIS.md).

Client integration:
- [hermes-agent `feat/near-ai-attestation`](https://github.com/amiller/hermes-agent/tree/feat/near-ai-attestation) — strict per-model attestation for near-ai inside hermes (PR upstream to NousResearch/hermes-agent #12201). Adds an `attestation_status` tool so the agent can introspect verified TEE state from the in-process cache. Strict-mode pins `(model → app_id, compose_hashes[], os_image_hash, kms_pubkey)` via a static anchor file plus per-model inner-compose closure (`compose_manager_attestation.actions[] → file, commit, file_sha256`).
- [`verifiers/near_ai_lightclient.py`](../verifiers/near_ai_lightclient.py) — closed-chain reference verifier in this repo. Block A primitives (TDX/GPU/report_data) + Block-B-via-on-chain (`addComposeHash` event log on Base, with optional age-filter) + Block-C inner-compose pin (`(yaml, commit, file_sha256)` per model, transitively committing HF revision after `cvm-compose-files#30`).
