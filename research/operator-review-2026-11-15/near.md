# NEAR AI: operator access review — 2026-11-15

Scope: routes `near-ai-gateway-plain`, `near-ai-gateway-e2ee`, `near-ai-direct`. Tags: **[src]** read in source; **[obs]** seen in captured attestation or on-chain; **[inf]** inferred, not read.

Versions:
- cloud-api `b26eb029` (2026-11-13) is the deployed gateway. Release `prod-20261114-b26eb02` has the digest `4cde8bc2…` observed 2026-11-14 [obs].
- compose-manager `2140f20c`, inference-proxy `3f7e9798`, cvm-compose-files `v0.0.585` (`b455cc09`).
- Model workload: teep's 2026-11-14 captures of a Qwen3.8-27B instance on app `2c0a0c96`, compose `e8416a02…`. Through the gateway (`nearcloud_gateway/…0001…body`) the last `compose_up` is `v0.0.585 prod/pack-small-models.yaml`, file_sha256 `a59dd69c…`, which matches the tagged file. Through the direct endpoint (`neardirect_near/…0020…body`) it is `v0.0.583` [obs].
- Attested composes: our evidence `08d91c8e…` (2026-11-14). The gateway runs compose `2643bc7a…` on app `f550fdfb` with no `pre_launch_script`; the GLM model instances run on app `2c0a0c96` [obs].

## Input → effect

| Operator input | Holder | Effect on prompt / reply | Tag |
|---|---|---|---|
| `models` table (`inference_url`, `provider_type`, aliases) in RDS outside the CVM | DB writer | Picks which backend or third-party provider reads a plain-route prompt | [src] [obs] |
| Gateway allowed_envs (93 entries, incl. `OPENAI/ANTHROPIC/GEMINI_API_KEY`, `CHUTES_*`, `TINFOIL_*`) | CVM deployer | Enables third-party providers. No measurement-policy variable is present | [obs] |
| compose-manager `/compose/up` (`tag`, `file`, `services`, `env`) | `BEARER_TOKEN` holder plus push access to `nearai/cvm-compose-files` (`GITHUB_REPO` is fixed in the measured compose) | Chooses the model workload after boot. `env` is not logged | [src] [obs] |
| `CM_MIN_TAG_AGE_HOURS` (allowed_env; measured default `0`, set value not visible) | CVM deployer | No required delay between a tag and its deploy | [obs] |
| `LAUNCHER_CHANNEL` + launcher override file read by `pre_launch_script` | CVM deployer | Swaps the compose-manager image to any cosign-signed build from `nearai/compose-manager` workflows | [obs] [src] |
| `addComposeHash` on DstackApp `2c0a0c96` / `f550fdfb` | `0x3ce4…dcdb`, an EOA | Authorizes composes that receive the same KMS keys | [obs] chain 2026-11-15 |
| DstackKms `0x8fa1…d637` (OS-image and KMS policy) | the same EOA | Can admit other OS images to key release, possibly a dev image | owner [obs]; powers [inf] |
| OS-image debug/SSH | — | The gateway rejects the TDX debug bit (`verification.rs:348`). Gateway `8db40cb2` and model `91fd5d69` image metadata say `is_dev: false` (research/dstack-mr-derivation-2026-11-05). SSH in those images not traced | [src] [obs] |
| `WEB_CONTEXT_SEARCH_URL` (request `env`) | token holder | Receives model-written search queries; its results enter the reply. Only on requests with the `web_context_search` tool | [src] |
| `REPLICA_STATE_REDIS_URL`, `FUSION_*` (request `env`) | token holder | Not read | missing |
| `CLOUDFLARE_API_TOKEN` in both CVMs' allowed_envs | DNS controller | A certificate can be issued outside the TEE. Matters only for clients that do not pin the attested TLS key | [inf] |

## F1. The gateway accepts any current TDX backend

**Problem.** The gateway checks a backend's quote, its report_data binding and its RTMR3 replay. It extracts the compose hash and stores it; nothing compares it. It uses app_id only to group signing keys, never against an allowlist. The OS-image allowlist and the TCB floor apply only when env vars set them, and the deployed compose sets neither.
**Impact.** Who: whoever can write the `models` table. What they do: point `inference_url` at a TDX VM running other code, or mark the model `external`. What they get: plain-route prompts and replies. What stops it today: nothing on the plain route. Attested models never fall back to non-attested providers (`inference_provider_pool/mod.rs:2813-2829`), but the table decides which providers a model has.
**Evidence.** @`b26eb029`: `services/src/attestation/verification.rs:282,326`; `measurement.rs:93-110`; `inference_provider_pool/mod.rs:796-811` (app_id used for grouping); `database/src/repositories/model.rs:1626-1645`. The deployed compose sets `DATABASE_HOST=cloudapi-postgres-prod…rds.amazonaws.com`. Neither allowlist variable appears in the compose, in allowed_envs or in the Dockerfile [obs]. Our 2026-11-14 probe asked for `zai-org/GLM-5.1-FP8` and got attestations for `z-ai/glm-5.3-flash` (data/latest.json). The mechanism is probably a DB alias [inf].
**Remediation.** Enforce an app_id and compose (or action-log) policy, fail-closed, with measured image and TCB pins. Move the model→backend map into measured config.

## F2. The model workload is chosen after boot, and env is unlogged

**Problem.** The measured model compose pins only compose-manager and its launcher. The serving code is whatever gets deployed from a cvm-compose-files tag. compose-manager writes tag, commit, file and file_sha256 into a quote-bound log, but not the per-request `env` that is interpolated into the file.
**Impact.** Who: a token holder with repo push access. What they do: tag and deploy at once, or redeploy a logged file with a different `WEB_CONTEXT_SEARCH_URL`/`FUSION_*`/`REPLICA_STATE_REDIS_URL`. What they get: arbitrary code beside the model, or egress the log does not show. What stops it today: clients can read the log. cloud-api never reads `compose_manager_attestation`/`actions_hash` outside tests [src]. Retention is 7 days plus the current-deploy entries.
**Evidence.** compose-manager @`2140f20c`: `src/main.rs:638-645` (`env` field), `:404-425` (`DeploymentAction` has no env), `:859` (tag age). Deployed: `MIN_TAG_AGE_HOURS=${CM_MIN_TAG_AGE_HOURS:-0}`. In `v0.0.585 pack-small-models.yaml`, `:36` mounts `dstack.sock`, `:847` is `WEB_CONTEXT_SEARCH_URL=${…}` and `:842` is `FUSION_ENABLED=${…}`, which inference-proxy main lacks. Engine request logging is off (`--log-requests-level 0`, `--no-enable-log-requests`) [obs]. inference-proxy `src/agent_loop.rs:1-19`.
**Remediation.** Hash the `env` map into each action, measure a nonzero tag age, and check the log at the gateway.

## F3. The E2EE key belongs to the app and model name, not to the code

**Problem.** inference-proxy derives its signing/E2EE key from dstack KMS at `{model_name}/ecdsa-signing-key` (and the ed25519 path). Any container with `dstack.sock` in any CVM of app `2c0a0c96` derives the same key, whatever its compose or workload.
**Impact.** Who: the EOA owning the DstackApp and DstackKms contracts, or a token holder with repo push access. What they do: `addComposeHash`, or deploy a workload that calls `get_key` on that path. What they get: the key that decrypts the model's E2EE prompts. What stops it today: a client that reviews every attested instance's compose and action log. There is no timelock: the owner address has no code.
**Evidence.** inference-proxy `src/signing.rs:149-167` @`3f7e9798` [src]. Base 2026-11-15: `owner()` of `2c0a0c96`, `f550fdfb` and `0x8fa1…d637` returns `0x3ce4142799a48b806118e9e09f3428f4f570dcdb`, and `eth_getCode` returns `0x`. Three observed compose hashes are chain-authorized on `2c0a0c96` (block 57457303) [obs].
**Remediation.** Bind the key path to the workload's code identity. Put the owner behind a multisig with a timelock.

## F4. Reply-key substitution (#1061) is closed for v3 only

**Problem.** [#1061](https://github.com/nearai/cloud-api/issues/1061) is open, with zero comments, last updated 2026-10-23. [inference-proxy #321](https://github.com/nearai/inference-proxy/pull/321) (merged 2026-10-28) binds the reply key into request AAD for v3 only. v1/v2 requests are still accepted unbound.
**Impact.** Who: the gateway or another intermediary. What they do: replace `X-Client-Pub-Key` on a v1/v2 request. What they get: the reply. What stops it today: the v3 check, if the deployed proxy includes #321 and the client sends v3 (SDK #127, merged 2026-11-06).
**Evidence.** inference-proxy `src/encryption.rs:63-75,161-167` [src]. The deployed proxy digest `60d08c20…` matches no `prod-2026111x` release digest [inf].
**Remediation.** Reject v1/v2 on encrypted routes and publish a digest→commit map.

## Changes since 2026-11-04

- No compose-hash enforcement at HEAD or in the deployed gateway [src].
- #1061 is fixed for v3 in the proxy. This corrects the 11-04 note's claim that v3 does not authenticate the reply key.
- [#1407](https://github.com/nearai/cloud-api/pull/1407) (2026-11-13) removed the admin catalog routes. The catalog is now written directly in RDS, which does not constrain the operator.

## Proposed operator-axis cells

**near-ai-gateway-plain**
- state: `gap`
- label: "Operator picks the backend"
- reason: An unmeasured RDS table maps models to backends or external providers, and the gateway enforces no compose, app or image policy (F1).
- evidence: `verification.rs:282,326`, `measurement.rs:93-110`, `model.rs:1626-1645` @b26eb029; gateway compose 2643bc7a (2026-11-14).
- missing: SSH in the non-dev OS images; gateway log and telemetry egress; a live substitution test.
- limitation: `reviewed_system`
- issue_urls: [#29](https://github.com/amiller/awesome-private-inference/issues/29)

**near-ai-gateway-e2ee**
- state: `gap`
- label: "App-wide key, unlogged env"
- reason: Protected fields decrypt only in model CVMs, but key access is set by an EOA without a timelock and by post-boot deploys whose env is unlogged (F2, F3). The reply key is bound only on v3 (F4).
- evidence: `signing.rs:149-167`, `encryption.rs:63-75`, compose-manager `main.rs:404-425,638-645`, the v0.0.585 action log, Base `owner()` 2026-11-15.
- missing: the commit behind proxy `60d08c20`; the fusion and redis code; DstackKms powers; the full authorized-compose set; `/compose/logs` as an unlogged read path.
- limitation: `reviewed_system`
- issue_urls: [#29](https://github.com/amiller/awesome-private-inference/issues/29), [#1061](https://github.com/nearai/cloud-api/issues/1061)

**near-ai-direct**
- state: `gap`
- label: "App-wide key, unlogged env"
- reason: Direct avoids the gateway's mapping (F1). The direct endpoint served the same app `2c0a0c96` and compose `e8416a02` (action log at v0.0.583), so F2 and F3 apply. F4 needs an intermediary, which direct with pinned attested TLS does not have.
- evidence: teep `neardirect_near` capture 2026-11-14; `signing.rs:149-167`; compose-manager `main.rs:404-425`.
- missing: an encrypted request through our lightclient; other models' direct hosts.
- limitation: `reviewed_system`
- issue_urls: [#29](https://github.com/amiller/awesome-private-inference/issues/29)
