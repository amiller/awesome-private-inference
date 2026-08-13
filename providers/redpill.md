# RedPill

## Scope

RedPill's public inference surface is the Attested Confidential Inference (ACI)
gateway at `https://tee.redpill.ai`. The gateway attests its workload identity
and client-facing channel, then publishes receipts and upstream-session records
that identify the route used for each request.

`https://inference.phala.com` served the same ACI workload keyset as
`https://tee.redpill.ai` during the 2026-08-13 check. Each hostname had its own
TLS SPKI in the attested keyset.

## Endpoint surface

- **Chat:** `POST https://tee.redpill.ai/v1/chat/completions`
- **Models:** `GET https://tee.redpill.ai/v1/models`
- **Gateway attestation:** `GET https://tee.redpill.ai/v1/aci/attestation?nonce=<64-hex>`
- **Receipt:** `GET https://tee.redpill.ai/v1/aci/receipts/<receipt-id>`
- **Upstream sessions:** `GET https://tee.redpill.ai/v1/aci/sessions`

To determine which upstream served a request, verify the receipt's
`upstream.verified` event and the cited session record.

## Scorecard

**Verdict: ❌ Stage 0.** RedPill is not yet a row in the automated daily matrix,
because the ACI data model does not map faithfully onto the older per-model
Python verifier interface. The manual verdict is still clear. The official ACI
verifier passed five of six protocol checks, but only one of the seven
all-or-nothing Stage 1 requirements linked by this registry was demonstrated.

| Stage 1 requirement | Result | Reason |
|---|---|---|
| Immutable attestation and upgrade transparency | Fail | The live Compose is quote-bound, but no on-chain or equivalent immutable deployment history was demonstrated. |
| Auditable code | **Pass** | The report names a public repository and commit. |
| Reproducible code measurement | Fail | The current Compose pins every container image by digest, but the report's gateway image digest and image provenance are `null`, and this audit did not reproduce the source-to-image build. |
| Developer has no access to secrets | Fail | Custody policy is skipped, the subject is `null`, and the measured deployment permits an operator-supplied root SSH key. |
| Upgrade process and public history | Fail | No notice mechanism or publicly queryable deployment history was demonstrated. The withdrawal requirement is vacuous for ephemeral requests, but the history requirement is not. |
| No centralized integrity or privacy dependency | Fail | The control-plane URL and credentials are operator-injected, and active routes live in admin-mutable state outside the measured Compose. Session pinning limits substitution when clients use it. |
| No backdoor or debug path | Fail | The dev-OS root path is not ruled out, and public logs explicitly enable raw upstream error details that can echo request fragments. |

This is a deployment score, not a dismissal of ACI's verified properties. The
quote, keyset, measured Compose, TLS binding, session pins, and receipts all
reduce trust compared with an ordinary API. Stage 1 is simply an all-or-nothing
bar, and the current deployment does not meet it.

## Live ACI verification

The official [`aci` verifier](https://github.com/Dstack-TEE/private-ai-gateway/tree/main/src/bin/aci)
ran against `https://tee.redpill.ai` on 2026-08-13. A cross-check against
`https://inference.phala.com` returned the same workload keyset digest. The
RedPill endpoint produced the following results:

| ACI check | Result | What the evidence establishes |
|---|---|---|
| TDX quote and `report_data` | Pass | A genuine TDX workload with `UpToDate` TCB produced a nonce-bound quote. |
| Workload keyset binding | Pass | The quote binds the JCS digest of the receipt, E2EE, and TLS keys. |
| Keyset freshness | Pass | The keyset had not expired at verification time. |
| Measured Compose | Pass | RTMR3 binds Compose hash `0fcdf7fa2b9a40425871bc7c2978a14eda61386822ee30a622b7c00137ef6215`. |
| Key custody and subject policy | **Skipped** | The public CLI does not yet enforce dstack KMS custody policy. The keyset subject was `null`. |
| Live channel binding | Pass | The TLS SPKI observed for each hostname was present in the attested keyset. |

The command transcript and sampled claim fields are recorded in the
[2026-08-12 refresh audit](../research/redpill-phala-refresh-2026-08-12.md).

The report named
[`Dstack-TEE/private-ai-gateway@45a7666`](https://github.com/Dstack-TEE/private-ai-gateway/commit/45a7666275de3e2d877842513c2bd5c17676936d)
as source provenance. That repository and commit are a source declaration. The
measured Compose is attestation-bound, but this check did not independently
rebuild the source or prove that the published commit produced the running image.

The merged `--require-production-os` appraisal makes the OS policy explicit.
It rejected the live `de9c74f0...` dev-image hash. This check uses the
quote-verified RTMR3 event log; a production-OS conclusion must also use the
dstack verifier on the same quote, event log, and VM config to bind the OS hash
to MRTD and RTMR0-2.

A local run of the deployment's exact pinned dstack-verifier digest returned
`is_valid: true` and `os_image_hash_verified: true` for that evidence. Independent
validation of dstack's published image archive resolved the bound hash to
version 0.5.9 with `is_dev: true`.

The audit did not send a paid inference request, so it did not independently
exercise or verify a per-request receipt. Receipt support is established here by
the attested source and public endpoint, not by a sampled live receipt.

## Upstream evidence published by the gateway

The gateway publishes one content-addressed session record per verified upstream
channel. Two live examples on 2026-08-13 show why each record must be audited
claim by claim:

- A `private-ai-verifier/phala-direct/v1` session for
  `openai/gpt-oss-20b` reported a non-debug TDX workload, `UpToDate` TCB,
  production `dstack-nvidia-0.5.9`, a nonce-bound NVIDIA result, a
  report-data-bound TLS SPKI, and a canonical model ID. It left
  `serving_software_known_good` and `model_weights_provenance` unknown.
- An `aci-service/v2` session bound a Phala model endpoint's TLS SPKI and
  asserted the workload identity. Its typed GPU, TCB, OS, serving-software,
  and model-weight claims were unknown.

These are attestation-bound or verifier-derived claims recorded by the gateway.
They are not all equivalent to independently reviewed release provenance.

## Current gaps

- **The gateway deployment retains operator access paths.** The quote-bound VM
  config identifies `dstack-dev-0.5.9-de9c74f0`. Its allowed environment names
  include `DSTACK_ROOT_PUBLIC_KEY`, and its measured pre-launch script writes a
  supplied value to root's `authorized_keys`. dstack's published
  [dev-image recipe](https://github.com/Dstack-TEE/meta-dstack/blob/7cc276ff0ef82650c65b86ba000cfa35a604818a/meta-dstack/recipes-core/images/dstack-rootfs-dev.inc)
  includes OpenSSH and enables root public-key login. Attestation does not reveal
  whether a key was actually supplied, so it cannot rule out operator access to
  the TD. That is enough to fail the developer-access and backdoor requirements.
- **The measured logging policy can disclose request fragments.** The deployment
  sets `public_logs: true` and `RUST_LOG=info,request_outcome=debug`. The attested
  source says upstream error bodies can echo request content and, at that debug
  level, writes a sanitized snippet of up to 240 characters to the log. This is
  an error-path exposure, not a claim that successful prompts are logged.
- **Runtime routing is operator-mutable.** The measured upstream seed is empty;
  active routes are stored on a persistent volume and replaceable through the
  authenticated admin API. The `tee.redpill.ai` host forces ACI-verified routes,
  and clients can pin accepted session ids, so operator control is constrained
  and visible in receipts. It is not part of the measured routing policy itself.
- **Session integrity is adapter-specific.** At 2026-08-13T16:50:13Z,
  `aci sessions https://tee.redpill.ai --json` accepted 192 of 327 records.
  Every observed `aci-service/v2`, PhalaDirect, NEAR, SecretAI, and Tinfoil
  record passed. All 135 Chutes records failed. The Chutes records carried no
  ACI section 8.2 evidence digest and data. For a sampled Chutes record, the
  `session_id` also matched SHA-256 of the exact served bytes, while the current
  [ACI specification](https://github.com/Dstack-TEE/private-ai-gateway/blob/main/spec/aci.md#8-attested-sessions)
  requires `SHA256(JCS(document))`. A client can accept the passing sessions,
  but it must reject the Chutes sessions.
- **Key custody is not checked by the public client.** The attestation includes
  dstack KMS custody evidence, but the CLI explicitly skips the custody-policy
  check. Presence of the evidence is not a pass.
- **Release provenance is incomplete.** The gateway proves its measured Compose
  and publishes a source revision, but the public verification run did not
  reproduce the build or bind a reviewed image digest to that source revision.
  All four current Compose images are pinned by digest, including
  `dstacktee/dstack-verifier:0.5.11`; this closes the earlier mutable-verifier
  sub-gap but does not supply source-to-image provenance for the gateway.
- **Upstream quality varies by adapter.** ACI makes the route, channel binding,
  and provider claims auditable. It does not turn an unknown serving-software or
  model-weight claim into a proven one.
- **The vendored provider verifier still has JWT gaps.** The current gateway
  vendors `private-ai-verifier`. Its NVIDIA and Intel Trust Authority helpers
  still decode JWTs with `verify_signature=False`. This affects adapters that
  rely on those decoded results. It does not describe the gateway's native DCAP
  verification of its own ACI quote.

## What would change the verdict

- Move the gateway to the production dstack OS and remove every root-key input.
- Disable raw error-detail logging and keep any prompt-adjacent logs private.
- Publish a reproducible source-to-image record for the pinned gateway release.
- Put deployment and routing-policy changes in a public immutable history, or
  require clients to pin an independently audited Compose and session set.
- Implement custody and subject policy in the public client, then publish a live
  receipt test alongside the gateway and session checks.

## Reproduce

```bash
git clone https://github.com/Dstack-TEE/private-ai-gateway.git
cd private-ai-gateway
cargo run --bin aci -- verify https://tee.redpill.ai
cargo run --bin aci -- verify https://tee.redpill.ai --require-production-os
cargo run --bin aci -- sessions https://tee.redpill.ai
```

The production-OS option currently rejects this deployment. Use it together
with a dstack verifier that validates the same boot measurements.

## History

- **2026-08-13:** Confirmed the verifier digest pin, strict OS rejection, and
  refreshed session totals.
- **2026-08-12:** Recorded live gateway and session-verification results.
