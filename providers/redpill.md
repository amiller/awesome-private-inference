# RedPill

## Scope

RedPill's public inference surface is the Attested Confidential Inference (ACI)
gateway at `https://tee.redpill.ai`. The gateway attests its workload identity
and client-facing channel, then publishes receipts and upstream-session records
that identify the route used for each request.

`https://inference.phala.com` served the same ACI workload keyset as
`https://tee.redpill.ai` during the 2026-08-12 check. Each hostname had its own
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

RedPill is not yet scored in the automated daily matrix. The current ACI client
and data model do not map faithfully onto the registry's older per-model Python
verifier interface, so the live results below remain a separately reproduced
audit rather than a synthetic dashboard row.

## Live ACI verification

The official [`aci` verifier](https://github.com/Dstack-TEE/private-ai-gateway/tree/main/src/bin/aci)
ran against `https://tee.redpill.ai` on 2026-08-12. A cross-check against
`https://inference.phala.com` returned the same workload keyset digest. The
RedPill endpoint produced the following results:

| ACI check | Result | What the evidence establishes |
|---|---|---|
| TDX quote and `report_data` | Pass | A genuine TDX workload with `UpToDate` TCB produced a nonce-bound quote. |
| Workload keyset binding | Pass | The quote binds the JCS digest of the receipt, E2EE, and TLS keys. |
| Keyset freshness | Pass | The keyset had not expired at verification time. |
| Measured Compose | Pass | RTMR3 binds Compose hash `cbbc26ea26a5dbe807df5d9abdb22c0485fb40f7634b9a7cc719580959c51213`. |
| Key custody and subject policy | **Skipped** | The public CLI does not yet enforce dstack KMS custody policy. The keyset subject was `null`. |
| Live channel binding | Pass | The TLS SPKI observed for each hostname was present in the attested keyset. |

The command transcript and sampled claim fields are recorded in the
[2026-08-12 refresh audit](../research/redpill-phala-refresh-2026-08-12.md).

The report named
[`Dstack-TEE/private-ai-gateway@59882c2`](https://github.com/Dstack-TEE/private-ai-gateway/commit/59882c2970d931c0a12c6f05b86d835149b67dff)
as source provenance. That repository and commit are a source declaration. The
measured Compose is attestation-bound, but this check did not independently
rebuild the source or prove that the published commit produced the running image.

## Upstream evidence published by the gateway

The gateway publishes one content-addressed session record per verified upstream
channel. Two live examples on 2026-08-12 show why each record must be audited
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

- **Session integrity is adapter-specific.** At 2026-08-12T06:02:12Z,
  `aci sessions https://tee.redpill.ai --json` accepted 154 of 271 records.
  Every observed `aci-service/v2`, PhalaDirect, NEAR, SecretAI, and Tinfoil
  record passed. All 117 Chutes records failed. The Chutes records carried no
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
- **Upstream quality varies by adapter.** ACI makes the route, channel binding,
  and provider claims auditable. It does not turn an unknown serving-software or
  model-weight claim into a proven one.
- **The vendored provider verifier still has JWT gaps.** The current gateway
  vendors `private-ai-verifier`. Its NVIDIA and Intel Trust Authority helpers
  still decode JWTs with `verify_signature=False`. This affects adapters that
  rely on those decoded results. It does not describe the gateway's native DCAP
  verification of its own ACI quote.

## Reproduce

```bash
git clone https://github.com/Dstack-TEE/private-ai-gateway.git
cd private-ai-gateway
cargo run --bin aci -- verify https://tee.redpill.ai
cargo run --bin aci -- sessions https://tee.redpill.ai
```

## History

- **2026-08-12:** Recorded live gateway and session-verification results.
