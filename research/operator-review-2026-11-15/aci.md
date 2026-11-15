# ACI gateway: operator access review, 2026-11-15

Scope: the RedPill/Phala ACI gateway behind `tee.redpill.ai`, `inference.phala.com` and `api.redpill.ai`. At 2026-11-15T17:31:58Z all three hostnames returned compose `66e91ac6…` (release `gateway-prod-2026-11-05-2`), commit `e9b6ae8a`, OS hash `8db40cb2…` [read from the response body of `GET /v1/aci/attestation`; quote not verified in this pass]. `gateway-prod-2026-11-15` (compose `04d79a23…`, commit `8d0018f8`) is still a prerelease with a rollout window of 2026-11-16 03:00–07:00 UTC, so it has not shipped. Its compose differs only in `PRIVATE_AI_GATEWAY_REPO_COMMIT` (line 157). The `e9b6ae8a..8d0018f8` diff leaves the paths below unchanged. It adds an `x-api-key-hash` header on catalog calls to the control plane [read]. Source is cited at `e9b6ae8a`.

## 1. Routes and upstream acceptance policy are outside the measurement

**Problem.** The measured compose seeds no upstreams. They come from `PUT /v1/admin/upstreams` (admin token) and from a pull of `service.redpill.ai` every 300 s (pull token). Each entry sets `base_url`, `provider` and the appraisal pins. On the TEE-only hosts the measured code requires a verified upstream, but the policy it verifies against comes from the same mutable entry:
- `aci-service` takes its pins from the entry.
- `phala-direct` takes none. Its session check needs only debug off, a nonce match, a TLS SPKI and `app_compose` matching RTMR3. It parses `os_image_is_dev` and leaves it unused.
- No Intel TDX mapper asserts `serving_software_known_good`.

**Impact.**
- **Who:** a holder of the admin or pull token, or whoever controls `service.redpill.ai`.
- **What they do:** register a `phala-direct` upstream that is any non-debug dstack CVM with any compose. The code would also accept a dev OS image.
- **What they get:** prompts and replies routed there, on `tee.redpill.ai` and `inference.phala.com` too.
- **What stops it today:** sessions and receipts record each upstream's compose hash and OS image, so a client that pins audited sessions can refuse. A client that checks only the gateway cannot.

**Evidence.**
- Compose lines 256-262, 283-287 (<https://github.com/Dstack-TEE/private-ai-gateway/releases/download/gateway-prod-2026-11-05-2/app_compose.json>, sha256 `66e91ac6…`, fetched 2026-11-15) [read].
- `src/aggregator/upstream_config/mod.rs:47-100`; `builders.rs:288-324`; `src/aci/verifier/aci_service.rs:78-83` (refuses only an empty pin set) [read].
- `src/aci/verifier/session_material.rs:270-282, 373-382` [read].
- `scripts/provider_verifier/phala_direct.py:238-252`: dev images are "recorded metadata, not a gate … the deployed fleet currently runs dev images" [read].
- `src/http/app/handlers.rs:997-1023`; `src/aggregator/service/claims.rs:211-229` [read].
- Live `GET /v1/aci/sessions`, 2026-11-15T17:40Z: 77 sessions. The 13 `phala-direct` sessions all report `os_image_is_dev: false`, across 9 distinct compose hashes that no policy pins. All have `serving_software_known_good: unknown` [read].
- teep PR #175 gap 3 records the same mechanism on 2026-10-29 (open).

**Remediation.** Measure the routing table, or have each receipt cite a content-addressed copy. Move upstream pins into measured config. Gate `phala-direct` on a compose allowlist and `is_dev: false`.

## 2. The secrets in `allowed_envs` are unauthenticated

**Problem.** The admin token, control URL, control token and pull token are dstack encrypted envs. dstack says the host "may forge encrypted environment variables because the CVM encryption public key is known to everyone" and recommends `requirements.launch_token_hash`. The gateway compose sets no launch token.

**Impact.**
- **Who:** the operator of the host machine (Phala Cloud's VMM) [inferred from dstack docs].
- **What they do:** boot the CVM with their own admin token, control URL or pull token.
- **What they get:** the routing control in finding 1.
- **What stops it today:** nothing in the measurement. `main.rs:691` logs `control_url` at info, and `public_logs: true` [inferred visible; logs not fetched].

**Evidence.** `allowed_envs` (9 names) and `manifest_version: 2` [read]. dstack `docs/security/security-best-practices.md:39-43` at `8af10091` [read].

**Remediation.** Add a launch-token requirement, or authenticate the control and pull endpoints with keys derived from the dstack KMS.

## 3. Root SSH: the env path is removed; a user_config path remains and is inert

**Problem.** `gateway-prod-2026-11-03` dropped `DSTACK_ROOT_PUBLIC_KEY` and `PRIVATE_AI_GATEWAY_PREFIX_HASH_SECRET` from `allowed_envs`. The pre-launch script (v0.0.20) still appends `ssh_authorized_keys` from the unmeasured `/dstack/user_config`.

**Impact.**
- **Who:** the host operator.
- **What they do:** supply a key through user_config.
- **What they get:** nothing on this OS image.
- **What stops it today:** the image has no sshd. If the OS changes to a dev image, the path comes back.

**Evidence.**
- The earlier compose `aa767dbc` (teep `422be60`) vs `66e91ac6` [read].
- `pre_launch_script` lines 346-357 [read].
- `mr_8db40cb2….tar.gz` (download.dstack.org): `sha256(sha256sum.txt)` equals the attested hash. The file lists `metadata.json` (`0fb751b1…`), which says `is_dev: false`, 0.5.12, meta-dstack `7f7b2762` [read].
- At `7f7b2762`, openssh is installed only by `dstack-rootfs-dev.inc:3`. The prod rootfs adds `nologin` and strips getty [read].

**Remediation.** Delete the user_config SSH block.

## 4. Logging and control-plane egress: the registry finding is stale

`RUST_LOG=info` since `gateway-prod-2026-11-03` (line 148). `request_outcome` occurs only under `apps/desktop`, not in the gateway [read]. `PostReport.error_message` is an `ErrorClass`, "never free text" (`src/middleware/types.rs:460-462`). Request features sent to the control plane are counts, enums and an HMAC under a KMS key (`request_features.rs:1-30`) [read]. The control plane still picks the route candidates, the reasoning override and `hoist_system_messages` for each request (`types.rs:123-151, 197-221`) [read]. The "raw error-detail logging" item on `providers/redpill.md` needs revising. Not every log site was audited.

## Proposed operator-axis cells

**aci-gateway-tee-redpill** (also **aci-gateway-phala**: same deployment)
- **state:** gap
- **label:** Routes outside measurement
- **reason:** TEE-only routing is enforced, but upstreams and their acceptance pins come from admin- and pull-controlled config. `phala-direct` pins no compose.
- **evidence:** findings 1-2; source at `e9b6ae8a`; live compose and sessions 2026-11-15.
- **missing:** a measured or receipt-cited routing table with code pins; authenticated config secrets.
- **limitation:** reviewed_system

**aci-gateway-api-redpill**
- **state:** gap (unchanged, re-dated)
- **label:** Non-TEE backend allowed
- **reason:** The host is not TEE-only. Upstreams without a TEE serve unless the request sets `aci_verified`. Findings 1-2 also apply.
- **evidence:** compose line 273; `handlers.rs:1023`.
- **missing:** TEE-only enforcement here, plus the above.
- **limitation:** reviewed_system
