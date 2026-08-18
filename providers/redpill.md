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
| Reproducible code measurement | Fail | The current Compose pins every container image by digest, but the report's gateway image digest and image provenance are `null`, and this audit did not reproduce the source-to-image build. The launcher clones and builds the gateway from `PRIVATE_AI_GATEWAY_REPO_COMMIT` at boot, so unlike the other three services the gateway binary is bound by a git commit rather than an image digest. |
| Developer has no access to secrets | Fail | Custody policy is unenforced by the public client and the subject is `null`; the measured deployment still permits an operator-supplied root SSH key (`DSTACK_ROOT_PUBLIC_KEY`), now on the production OS. The published custody chain is itself complete and appraisable — the only missing input is a dstack KMS root to pin. |
| Upgrade process and public history | Fail | No notice mechanism or publicly queryable deployment history was demonstrated. The withdrawal requirement is vacuous for ephemeral requests, but the history requirement is not. |
| No centralized integrity or privacy dependency | Fail | The control-plane URL and credentials are operator-injected, and active routes live in admin-mutable state outside the measured Compose. Session pinning limits substitution when clients use it. |
| No backdoor or debug path | Fail | Public logs explicitly enable raw upstream error details that can echo request fragments, and the legacy `/v1/attestation/report` returns a passing attestation for any model name. The dev-OS half of this row is **resolved** as of 2026-08-18. |

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

A live receipt was exercised on 2026-08-18 and passes every section 9.3 check
(see Current gaps).

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

- **The gateway moved to the production OS on or before 2026-08-18.** The
  quote-bound VM config now identifies `dstack-0.5.9-bd369a8c`, and
  `aci verify --require-production-os` passes on both TEE-only hostnames.
  Resolved independently of the client's allowlist: `mr_bd369a8c….tar.gz` from
  `download.dstack.org` satisfies `os_image_hash == sha256(sha256sum.txt)` with
  `metadata.json` listed in it, giving a cryptographically bound
  `is_dev: false`. The same procedure on the previously measured
  `de9c74f0…` returns `is_dev: true`, so the change is real.
  `DSTACK_ROOT_PUBLIC_KEY` remains in `allowed_envs` and the measured
  pre-launch script still writes it to root's `authorized_keys`, so attestation
  still cannot rule out a supplied key — but on the production image that path
  should be inert.

- **The legacy attestation endpoint attests any model name.**
  `GET /v1/attestation/report?model=<id>&nonce=<hex>` is still served for
  pre-ACI clients and still passes every pre-ACI check: genuine TDX quote,
  `report_data == addr.ljust(32) || nonce`, `keccak(pubkey)[-20:] == signing_address`.
  The `model` parameter is ignored — `anthropic/claude-opus-5` and
  `does/not-exist-xyz` both return 200 with the same gateway signing address
  `0x79a5061e…`. The companion `GET /v1/signature/{chat_id}` signs
  `sha256(request):sha256(response)`, dropping the `model:` prefix that
  upstream's own related-work note documents for this convention. Neither
  legacy surface binds the model actually served. This is why the retired
  `verifiers/redpill.py` must not simply be repointed at `tee.redpill.ai`: it
  would mint a green row for any model string.
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
  ACI section 8.2 evidence digest and data, so section 9.2 steps 2 and 4 cannot
  be performed on them. A client can accept the passing sessions, but it must
  reject the Chutes sessions.

  *Correction (2026-08-18):* an earlier draft of this page also reported that a
  sampled Chutes `session_id` matched SHA-256 of the exact served bytes rather
  than `SHA256(JCS(document))`. That does not reproduce. Fetching the full
  records through `/v1/aci/sessions/{id}`, every id recomputes correctly across
  all six adapters, Chutes included. Section 8.1 abbreviates *list* entries —
  they drop `evidence.data` and by design do not hash to their id — which is
  what the earlier check hashed. The missing evidence is the whole finding.
- **One attested identity spans two serving regimes.** The measured
  `gateway.config.json` sets `tee_only_domains` to `tee.redpill.ai` and
  `inference.phala.com` only. `api.redpill.ai` is served by the same CVM under
  the same workload keyset, with its own attested TLS SPKI, and is not
  TEE-only — so attested serving is not forced there: 67 models versus 25, the
  extra 42 including `anthropic/claude-opus-5`, `openai/o3` and
  `google/gemini-2.5-pro`. Verified with a live receipt: that model returns
  HTTP 200 under the same keyset digest with
  `upstream.verified: result=failed, required=false, session_id=None`. The
  receipt still verifies, so a client checking signatures but not `required`
  sees a green chain over an unattested hop. Sending
  `provider.aci_verified: true` is refused 503 with no `request.forwarded`
  event, so the guard works — it is opt-in, and invisible before you send.

- **Receipts verify end to end (2026-08-18).** A live completion on
  `tee.redpill.ai` produced a receipt whose ed25519 signature checks out under
  the attested `receipt_signing_keys` entry, whose `request.received` and
  `response.returned` hashes match the exact bytes on the wire, and whose cited
  session recomputes to its id with `served_at` inside the validity window —
  all seven section 9.3 checks. The earlier note that this audit had not
  exercised a receipt no longer applies.

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

- ~~Move the gateway to the production dstack OS~~ (done, 2026-08-18) and remove
  the `DSTACK_ROOT_PUBLIC_KEY` input.
- Stop accepting a `model` parameter on `/v1/attestation/report` that scopes
  nothing, or retire the legacy surface on a published date.
- Surface the per-host serving policy in the attestation report, so a client can
  see before sending whether attested serving is enforced on the host it is
  talking to.
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

- **2026-08-18:** Independent re-check. Production OS confirmed and bound;
  `--require-production-os` passes; receipts exercised end to end; legacy
  endpoint and `api.redpill.ai` findings recorded; the earlier JCS
  content-address claim withdrawn.
- **2026-08-13:** Confirmed the verifier digest pin, strict OS rejection, and
  refreshed session totals.
- **2026-08-12:** Recorded live gateway and session-verification results.
