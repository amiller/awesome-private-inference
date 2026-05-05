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
- **Client-side model→app_id / compose pin**: ✅ in [hermes-agent](https://github.com/amiller/hermes-agent/tree/feat/near-ai-attestation) via static anchor (`hermes_cli/anchors/nearai_mainnet.json`); ❌ in `nearai-cloud-verifier`.

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
  on `actions=[]`. A liveness regression for the operator, not a leak.
- **`/evidences/quote.json` 0 bytes after 2026-05-02 cert renewal.** Binds
  path A's dstack-ingress TLS cert; path B / C don't depend on it.
- **AppAuth contracts unverified on Basescan.** `eth_call` against the proxy
  ABI works regardless of source verification — only blocks human review.

### Actively enforced by hermes' static pin

[hermes-agent #12201](https://github.com/NousResearch/hermes-agent/pull/12201)
ships
[`hermes_cli/anchors/nearai_mainnet.json`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/anchors/nearai_mainnet.json)
and refuses (in strict mode) if any pinned field mismatches. Static pin
substitutes for every Block B1–B5 read:

| Verifier-design block | On-chain authority | hermes static pin |
|---|---|---|
| B1: `kmsInfo.k256Pubkey` ↔ `info.key_provider_info.id` | `DstackKms.kmsInfo` (empty on NEAR — see below) | direct pin of `info.key_provider_info.id` |
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

### Still requires NEAR action (or further client work)

Not blocked by the closed-chain client design, but limit how mechanically
auditable the chain is for clients that don't ship a static anchor:

- **`DstackKms.kmsInfo` is empty on `0x8fa1593fac…`.** All four fields
  (`k256Pubkey`, `caPubkey`, `quote`, `eventlog`) return zero-length bytes;
  Phala's canonical KMS at `0x2f83172A…` populates them. Without
  `setKmsInfo(...)`, an external verifier without a static pin has no on-chain
  anchor for the KMS root pubkey. Fix: NEAR populates `kmsInfo` once.
- **NEAR-published manifest missing.** No `cloud-api.near.ai/v1/apps/...`
  route, no signed JSON anchoring `(model → app_id, compose_hashes,
  os_image_hash, kms_pubkey)`. We've stitched one together as the hermes
  anchor; an authoritative source-of-truth from NEAR would let other clients
  align without re-doing the capture.
- **AppAuth proxies have `_upgradesDisabled=false`, owner is a single EOA
  `0x21e6b7ef…`** controlling all six DstackApps. UUPS upgrades are
  retroactively logged (`Upgraded(address)` events) — auditable but not
  active-refused unless clients pin the impl too.
- **Inner-compose closure (Block C) still missing.** `deepseek-ai/DeepSeek-V3.1`,
  `openai/gpt-oss-120b`, and the rotated GLM all share outer `compose_hash`
  `0x242a6272…` — the outer compose is one shell; per-model selection happens
  inside via env into vllm-proxy/sglang. Static anchor proves "an authorized
  NEAR-AI CVM"; closing on a per-model claim requires reaching the inner compose.
- **`nearai-cloud-verifier` doesn't yet enforce Block B / Block C.** Still
  runs only Block A + the model_name check from PR #23; PR
  [#24](https://github.com/nearai/nearai-cloud-verifier/pull/24) for Block B
  is the natural follow-up.
- **Verifier JWT signatures unchecked.** Phala's `private-ai-verifier`
  decodes NRAS / Intel Trust Authority JWTs with `verify_signature=False`.
  Acknowledged TODO; affects every downstream that uses it as the TDX oracle.

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
- [hermes-agent `feat/near-ai-attestation`](https://github.com/amiller/hermes-agent/tree/feat/near-ai-attestation) — strict per-model attestation for near-ai inside hermes (PR upstream to NousResearch/hermes-agent #12201). Adds an `attestation_status` tool so the agent can introspect verified TEE state from the in-process cache. As of May 2026 also strict-mode pins `(model → app_id, compose_hashes[], os_image_hash, kms_pubkey)` via a static anchor file (Block B-static); on-chain RPC reader (Block B) and inner-compose closure (Block C) are the natural follow-ups.
