# Verifying clients compared — 2026-11-15

A provider row on the dashboard says what a route exposes. What a user actually gets depends on the client that checks it. This note compares the verifying clients that exist today, per provider, from source at pinned commits. Full tables with file:line citations: `research/client-comparison-2026-11-15/part-a.md` (teep, private-ai-gateway as a client of its upstreams, pap) and `part-b.md` (hermes, nearai-cloud-verifier, tinfoil-go and tinfoil-python, the Venice proxies, Privatemode). Nothing here was run live except where a capture is cited.

## Per provider, the best available client

| Provider | Strongest client | What it still can't establish |
|---|---|---|
| NEAR cloud | teep: every instance appraised, E2EE to the attested model key, enforced | Reply-key binding: teep sends E2EE v2 and hermes sends v1. Only v3 binds the reply key (inference-proxy #321). Neither client checks that the action log covers the serving code. |
| Tinfoil | tinfoil-go v0.17 RCs: local AMD chain, client nonce in REPORT_DATA, SPKI pin, ≤7-day freshness witness, refuses by default | On the router route, the model enclave's code and weights. Its TCB floor comes from Tinfoil's own signed policy (Genoa snp 0x0E, below AMD's 0x1D), and it adopts any router release or policy Tinfoil signs. |
| ACI canonical (Phala Cloud) | teep and pap: sessions pinned, receipts verified | Workload policy on the upstream: nobody checks it. The stream arrives before the receipt. pap checks key custody only when both `--accept-*` flags are given; otherwise the prompt is still sent. |
| Chutes | teep: MRTD/MRSEAM pinned to a static list | The serving code, which is excluded from measurement. |
| Venice | jooray proxy: refuses `-p` models without GPU evidence | The ACI/1 shape (neither proxy parses it), compose or OS identity, TLS binding. AxLabs serves `-p` models with only a warning. |
| Privatemode | its own proxy, with `--manifest-path` | The default manifest comes from a CDN over plain HTTPS, unsigned, and is auto-adopted. Any workload in the attested mesh can be the recipient. |

## Findings from the comparison

- **hermes (our NEAR closed-chain client, branch `feat/near-ai-attestation` at `1f92ab10`) has three gaps.**
  - It fails open by default: with attestation enabled but not strict, a failed check logs a warning and the request goes without E2EE (`runtime_provider.py:289-297`).
  - It binds the compose-manager `actions_hash` field to the quote, but never hashes the `actions` list it then checks against the anchor (`attestation.py:477-533`). A relay can keep the genuine hash and substitute the list.
  - It sends E2EE v1, so the reply key is not bound. Its anchor dates from 2026-05-18 and refuses every model NEAR serves today.
- **The private-ai-gateway is a weaker client than teep on NEAR.** Its NEAR adapter checks only NEAR's gateway quote and TLS key. It doesn't fetch `model_attestations` or pin a compose.
- **The private-ai-gateway attests only the router on Tinfoil**, without a nonce, and labels router code as serving software (`research/aci-tinfoil-upstream-2026-11-15.md`).
- **The gateway blocks only when asked.** It refuses a failed upstream only on TEE-only hosts or when the request sets `aci_verified` or session pins. Otherwise it forwards and records the failure in the receipt.
- **Every Tinfoil client accepts the router's current TCB.** tinfoil-go and teep share the 0x0E floor. Our probe is the only check here that uses AMD's bulletin minimum.
- **Reply authenticity is the weak point everywhere.** Only Phala Cloud receipts get verified (teep, pap), and only after delivery. No client authenticates NEAR, Chutes or Venice dstack replies.
- **Auto-adoption is the default.** teep and the gateway take the latest Sigstore router release for Tinfoil. tinfoil-go takes any Tinfoil-signed release or policy. Privatemode takes any CDN manifest. hermes and teep's static lists are the only pins a user controls.

## Corrections to earlier notes

- The 2026-11-04 note says the ACI CLI skips key custody. pap implements it (`cli/aci/verifier/policy.rs`, `appraisal.rs:447-500`) but applies it only with both `--accept-subject` and `--accept-dstack-kms-root-public-key` (`cli/args.rs:70-87`).
- The same note says NEAR E2EE v3 doesn't authenticate the reply key. It does, in source (inference-proxy #321). No client reviewed here sends v3.
