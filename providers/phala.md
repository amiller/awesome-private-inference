# Phala Cloud

## Claim

Phala Cloud ([phala.network](https://phala.network)) operates dstack-based Intel
TDX and NVIDIA confidential-computing infrastructure. It also publishes several
verification components. These components have different security scopes:

- [`private-ai-verifier`](https://github.com/Phala-Network/private-ai-verifier)
  verifies provider-specific attestation responses. It is not an end-user
  encryption or receipt protocol.
- [`private-ai-gateway`](https://github.com/Dstack-TEE/private-ai-gateway)
  implements Attested Confidential Inference (ACI). It attests the gateway,
  binds client and upstream channels, enforces verified routing, and issues
  per-request receipts.
- `https://cloud-api.phala.network/api/v1/attestations/verify` is the public TDX
  appraisal service used by this registry's Python provider verifiers.

Treating `private-ai-verifier` as the whole Phala inference stack is no longer
accurate.

## Current endpoint surface

`https://inference.phala.com` served the same ACI workload keyset as
`https://tee.redpill.ai` on 2026-08-12. The current public endpoints include:

- `GET https://inference.phala.com/v1/aci/attestation?nonce=<64-hex>`
- `GET https://inference.phala.com/v1/aci/sessions`
- `GET https://inference.phala.com/v1/models`
- OpenAI-compatible inference endpoints under `/v1`

The ACI session records also expose direct model endpoints such as
`https://gpt-oss-20b.use1.phala.com`. Direct Phala inference is therefore
publicly observable, although this registry does not yet include the ACI surface
in its automated daily matrix.

## Scorecard

**Verdict for the current shared ACI gateway: ❌ Stage 0.** A manual live check on
2026-08-12 produced the same result documented on the [RedPill page](./redpill.md):
five of six ACI protocol checks passed, while the public key-custody policy check
was skipped. Against the registry's all-or-nothing Stage 1 checklist, only
auditable source was demonstrated. The dev-OS root-access path and public debug
logging are independently disqualifying; immutable upgrade history,
reproducible source-to-image provenance, custody policy, and measured routing
policy were also not demonstrated.

This verdict applies to the shared gateway deployment, not automatically to
every Phala-hosted model CVM. The upstream-session audit accepted every observed
PhalaDirect and `aci-service/v2` record. The gateway's Chutes records failed, so
each route still needs its own claim-level review. See the
[2026-08-12 refresh audit](../research/redpill-phala-refresh-2026-08-12.md)
for the commands and sampled claim fields.

## Corrected claim boundaries

### Client confidentiality

The statement that `private-ai-verifier` has no E2EE code remains true at
[`51c2b5a`](https://github.com/Phala-Network/private-ai-verifier/commit/51c2b5a83d6d753b9a29288e0ed522ab2d65bac4).
Its `VerificationResult` does not expose an encryption operation or make
`model_verified: true` sufficient for prompt confidentiality.

That limitation belongs to the library, not to every current Phala deployment.
ACI clients verify the gateway's TDX quote, bind the workload keyset to that
quote, pin the live TLS SPKI or use a key from the attested E2EE keyset, demand a
verified upstream route, and verify a signed receipt. Every observed
PhalaDirect and `aci-service/v2` session passed the ACI section 9.2 integrity
audit on 2026-08-12.

### TDX and JWT verification

The registry's Python verifiers send TDX quotes to Phala's public
appraisal endpoint. A green TDX cell on those rows means that service accepted
the quote. It is not the same as local verification to Intel roots.

The current ACI Rust client uses `dcap-qvl` and Phala PCCS collateral for the
gateway quote. Separately, `private-ai-verifier` still decodes NVIDIA NRAS and
Intel Trust Authority JWTs with `verify_signature=False`. That JWT limitation
affects the adapter results that depend on those helpers. It does not invalidate
the ACI client's native DCAP result.

### Compose and source provenance

The earlier `private-ai-verifier` critique identified a self-consistency check
that compared two server-supplied Compose values without reading the measured
register. That remains relevant to the affected `private-ai-verifier` helper.

The current ACI gateway verification follows a different path: it verifies the
TDX quote, replays the dstack event log to RTMR3, extracts the measured
`compose-hash` event, and checks it against `SHA256(app_compose)`. This proves the
Compose preimage is measurement-bound. It does not prove the source revision was
reproducibly built into an accepted image.

### TLS channel binding

The old blanket statement that Phala verification never checks a live TLS
fingerprint is no longer correct:

- The ACI client compares the live server certificate SPKI with the domain entry
  in the quote-bound workload keyset.
- The `phala-direct` version-2 adapter binds the direct model endpoint's TLS SPKI
  into TDX `report_data`, then enforces that SPKI on the forwarding connection.

### KMS custody

The current ACI report publishes dstack KMS custody evidence for its workload
keys. The first-party ACI upstream verifier can validate a custody chain against
configured KMS roots. The public `aci verify` client still marks its custody and
subject-policy check as skipped. The accurate status is "evidence published,
public policy check not implemented," rather than "no evidence exists."

## Remaining gaps

- The shared gateway uses a measured dstack dev OS, permits injection of a root
  SSH key, and publishes logs while enabling raw upstream error snippets. These
  facts make the gateway Stage 0 even when an upstream session passes.
- Active route state and control-plane coordinates are operator-mutable outside
  the measured Compose. ACI's verified-route requirement and optional session
  pins constrain this power, but clients must use the pins when route identity
  is load-bearing.
- All observed PhalaDirect and `aci-service/v2` session records passed the live
  ACI integrity audit. The same gateway's Chutes records did not, so this result
  is specific to the Phala paths.
- The gateway report's source repository and commit were not independently
  rebuilt during this audit, its image provenance fields were empty, and the
  measured `dstack-verifier` service used a mutable `latest` tag.
- A sampled PhalaDirect session proved a production OS, current TCB, TDX,
  nonce-bound GPU evidence, canonical model ID, and quote-bound TLS SPKI. It
  still reported serving-software and model-weight provenance as unknown.
- Some `aci-service/v2` sessions asserted the verified workload identity and
  channel while leaving typed GPU, TCB, OS, serving-software, and model-weight
  claims unknown.
- Provider adapters that rely on unsigned-decoded NRAS or Intel Trust Authority
  JWT claims retain that weakness.

## Relationship to this registry

The automated matrix still uses Phala's public appraisal service for TDX checks
on Venice, NEAR AI, and Chutes response shapes. That dependency must be named in
the scorecard. It should not be generalized into a claim that Phala's current
ACI endpoint lacks an independent client verifier.

## Reproduce

```bash
git clone https://github.com/Dstack-TEE/private-ai-gateway.git
cd private-ai-gateway
cargo run --bin aci -- verify https://inference.phala.com
cargo run --bin aci -- sessions https://inference.phala.com
```

Snapshots: [data/snapshots/](../data/snapshots/).
