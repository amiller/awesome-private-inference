# Phala Cloud

## Claim

Phala Cloud ([phala.network](https://phala.network)) operates Intel TDX + NVIDIA enclaves as
a direct inference provider and as the verifier backbone most other providers route through.
Phala is also the upstream for
[private-ai-verifier](https://github.com/Phala-Network/private-ai-verifier).

## Endpoint surface

Phala itself is most commonly reached through a reseller (RedPill, Venice, NEAR AI);
direct Phala Cloud endpoints are not yet included in this registry's daily probe.

## Scorecard

N/A (not directly probed) — see [RedPill](./redpill.md) or
[Venice](./venice.md) for live Phala-backed rows.

## Known gaps (affect every downstream)

- **KMS opacity.** Phala's own KMS (the service providing key material to the enclaves) is
  Stage 0 in the [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide)
  framework: mutable image tags, no published upgrade log, no third-party review.
- **Verifier is attestation-only, not private-inference.** `private-ai-verifier` has no
  E2EE code whatsoever — `signing_public_key` is never read anywhere in the repo, there is
  no `encrypt_prompt` or equivalent, and `VerificationResult` does not expose the
  enclave-bound encryption key. A user who sees `model_verified: true` and sends a
  prompt over plain HTTPS has the same confidentiality posture as any HTTPS endpoint.
  Full analysis:
  [phala-private-ai-verifier case study](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/phala-private-ai-verifier/DEVPROOF-REPORT.md).
- **Verifier JWT signatures unchecked.** The verifier library decodes Intel Trust Authority
  and NVIDIA NRAS JWTs with `verify_signature=False` (acknowledged TODOs). When a
  downstream scorecard shows ✅ on "TDX quote," that means *Phala's* verifier accepted the
  quote — we are trusting Phala as the root of truth for TDX.
- **Compose-hash check is self-consistency, not quote-binding.** On the NEAR AI path the
  verifier compares `info.compose_hash` against `sha256(app_compose)` — both server-supplied.
  The hardware-signed `mr_config` field in the quote is never consulted, so a lying server
  passes this check trivially.
- **No live TLS fingerprint probe.** The verifier reads whatever TLS fingerprint the
  attestation body contains — it never opens a live TLS connection to cross-check.
- **Local sidecar trust.** The verifier trusts an unauthenticated local `dstack-verifier`
  sidecar when one is present.

## Relationship to this registry

We use Phala's public verifier API as ground truth for TDX quote acceptance. If Phala's
verifier would reject a quote, so will we. Everything else (GPU, key derivation, report_data
binding) we re-verify independently.

## History

Snapshots: [data/snapshots/](../data/snapshots/).
