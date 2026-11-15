# Venice: operator access review, 2026-11-15

Venice resells two backends through `GET /api/v1/tee/attestation`:
- `e2ee-*-p` models go to the RedPill/Phala ACI gateway.
- Unsuffixed `e2ee-*` models go to a NEAR model CVM.

Live evidence is teep's captures of 2026-11-13 (`internal/integration/testdata/current/venice_{aci,aci_2,dstack}`, teep `6548996b`) [read]. I made no Venice request myself.

## 1. venice-phala uses the gateway's non-TEE-only hostname

**Problem.** Both `-p` captures route to the gateway's `api.redpill.ai` hostname, where TEE routing is opt-in per request ([aci.md](aci.md)). Whether Venice opts in cannot be observed. Findings 1-2 of aci.md apply as well: a mutable routing table, `phala-direct` pinning no compose, and forgeable config secrets.

**Impact.**
- **Who:** the gateway operator, a holder of a route-config token, or Venice through the flag it sets.
- **What they do:** route a `-p` request to an upstream without a TEE, or to an unpinned TDX CVM.
- **What they get:** prompt and reply plaintext.
- **What stops it today:** nothing that a Venice client can check. Since 2026-11-12 Venice also strips GPU evidence (`gpu_evidence_omitted: true`).

**Evidence.**
- Captures `e2ee-gpt-oss-120b-p` and `e2ee-glm-5-2-p`: compose `66e91ac6…`, commit `e9b6ae8a`, `downstream_tls_binding.domain: api.redpill.ai` [read].
- The JB receipt of 2026-08-06 showed `required: false` ([SECURITY-AUDIT.md §2.1 at `4307e9d2`](https://github.com/jooray/venice-e2ee-proxy/blob/4307e9d2/docs/SECURITY-AUDIT.md)) [read; not re-observed].

**Remediation.** Venice moves to `tee.redpill.ai` or sets `aci_verified`. It relays the ACI/1 report and receipts so clients see which upstream served them.

## 2. Status of JB's gateway findings

| JB item | Now | Basis |
|---|---|---|
| Dev OS image with SSH (§2.2) | Fixed: `dstack-0.5.12`, `is_dev: false` | read (aci.md §3) |
| B6 `DSTACK_ROOT_PUBLIC_KEY` | Removed 2026-11-03; user_config path inert without sshd | read |
| B5 `dstack-verifier:latest` | Pinned `0.6.3@sha256:22aeb680…` (compose line 198) | read |
| B3 error text to control plane | Fixed: `ErrorClass` token | read |
| B4 boot-time build, persistent unmeasured cache | Still: build at boot, `pal-cache` volume (line 120) | compose read; launcher not re-read |
| `required: false` on Venice's host | Still possible on `api.redpill.ai` | code read; Venice's flag unobserved |
| Unmeasured last hop | Still: every live `phala-direct` session has `serving_software_known_good: unknown`, 9 unpinned composes (17:40Z) | read |
| Third-hop report 401 to outsiders | Not re-checked | — |

## 3. venice-near: the code that reads plaintext is chosen at runtime

**Problem.** The NEAR CVM's measured compose holds only management services. The proxy and model containers that decrypt and serve prompts are started by `compose-manager` `POST /compose/up` from a tag of `nearai/cvm-compose-files`. The caller needs a bearer token, and the tag only needs to be older than an operator-set minimum age, default 0. The compose-manager image is itself replaced at runtime. The measured pre-launch script loads `COMPOSE_MANAGER_IMAGE` from `.env.launcher` on a persistent volume, so the measured digest is a fallback. The launcher follows `LAUNCHER_CHANNEL` (allowed env, default `latest`) under a cosign identity regex for `nearai/compose-manager` workflows. The tagged compose ships stdout of containers labelled with a model or deployment to NEAR's telemetry. The proxy carries such a label.

**Impact.**
- **Who:** NEAR, or anyone with tag push on `nearai/cvm-compose-files` plus the bearer token. Without a launch token the host can forge the token [inferred, dstack docs; aci.md §2].
- **What they do:** tag a compose that raises request logging or swaps the proxy, then call `/compose/up`.
- **What they get:** prompts in NEAR's telemetry, or read live in the swapped proxy. At today's sglang log level 0 this needs a config change [inferred].
- **What stops it today:** an action log that the CVM quotes as `actions_hash || client nonce`, naming tag, commit and file sha256 in a public repo. The log comes from the runtime-replaceable compose-manager, whose running image's source commit was not established.

**Evidence.**
- `app_compose` `e8416a02` (`dstack-nvidia-0.5.12`, `gpu13`, `manifest_version: 2`): lines 95, 127-130, 170, 179; `pre_launch_script` override block [read].
- `compose_manager_attestation`: 114 `compose_up` actions, 2026-10-21 to 2026-11-13, tags up to `v0.0.583`, four compose files [read].
- compose-manager `c7fbaaf` `src/main.rs:849-868` (`validate_tag`), `:2218` (`compose_up`), `:4361-4375` (routes, including `/compose/logs`) [read].
- cvm-compose-files `v0.0.583` (`c330ab4a`) `prod/small-models.yaml`: lines 90, 2162-2163, 2758-2815; proxy label `nearai.otel.model` [read].

**Remediation.** Extend RTMR3 with each served compose at `compose_up`, or require a client-checked allowlist of tag commits. Pin log levels in the measured compose.

## 4. Venice's own hop

Venice's E2EE encrypts message content to the attested key. Venice still reads model, tools and parameters, chooses the backend, and composes the attestation response, which is how GPU evidence disappeared on 2026-11-12 [read]. The `veniceai/skills` finding was not re-checked.

## Proposed operator-axis cells

**venice-phala**
- **state:** gap
- **label:** Non-TEE-only gateway host
- **reason:** Venice uses `api.redpill.ai`, where TEE routing is opt-in. Gateway routes are mutable and the last hop's code is unpinned.
- **evidence:** teep captures 2026-11-13; gateway `e9b6ae8a`; live sessions 2026-11-15.
- **missing:** proof that Venice sets `aci_verified` or uses a TEE-only host; relayed receipts.
- **limitation:** reviewed_system

**venice-near**
- **state:** gap
- **label:** Runtime-deployed serving code
- **reason:** Proxy and model containers come from git-tag deploys triggered by a bearer token, outside the measured compose. Their logs leave the CVM.
- **evidence:** NEAR `app_compose` `e8416a02` and the action log (teep capture 2026-11-13); compose-manager `c7fbaaf`; cvm-compose-files `c330ab4a`.
- **missing:** measurement of each deploy, or a client-checked tag allowlist; a pinned log policy.
- **limitation:** reviewed_system
