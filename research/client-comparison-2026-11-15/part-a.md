# Client comparison, part A: teep, private-ai-gateway as client, pap CLI

Source review only; nothing was run. Pins: teep `6548996`, private-ai-gateway `e9b6ae8a`.

Cells: **E** enforced (failure blocks the send or the reply), **C** checked, not enforced (computed and reported, or allowed to fail), **N** not checked, **n/a**. `[i]` = inferred. `.go`/`.rs`/`.py` refs were read in source; `.md` refs are the projects' own docs at the pin.

Path keys. teep: `R` = `internal/attestation/report.go`, `A` = `docs/attestation_gaps/aci_gateway.md`, `S` = `docs/api_support.md`, `P` = `internal/proxy/proxy.go`. Gateway: `F` = `src/aggregator/service/forward.rs`, `V/<kind>` = `docs/providers/<kind>/verification.md`. CLI: `cli/` = `apps/desktop/cli/`.

## 1. teep (per request, through an authorization cache)

teep blocks any enforced factor before it sends anything (`P:11`, `internal/proxy/authorization.go:44`). A factor on the provider's `allow_fail` list is C. Verified results are reused: the attestation cache lasts 1 h (`internal/attestation/attestation.go:64`), and NEAR authorizations last until they are invalidated (`S:282`). `--force` overrides all of this (`P:2503`).

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| venice (dstack) | quote/chain/debug E; TCB-current C (`R:434`); GPU sig E, claims/NRAS C (`R:436-437`) | E2EE to REPORTDATA-bound key, E (`P:3084`); TLS binding C (`R:441`) | nonce E; content only decrypted, anonymous-sender ECIES so no authenticity check [i] (`internal/e2ee/venice.go:111-124`); no receipt | MRTD E; RTMR0-2 C; compose→quote E; Sigstore C (`R:502`); weights C | n/a (attests host); Venice API is an unattested hop carrying ciphertext | static Go allowlists (`internal/provider/venice/policy.go:12`); teep release | refuses send; no plaintext fallback (`P:13`); decrypt failure aborts (`P:15`) |
| venice (ACI/1) | gateway quote E; host quote C (`R:721-737`); GPU C (`R:693-694`) | E2EE v2 to gateway key; `aci_key_custody` + gateway REPORTDATA E (`A:153-174`) | no auth: relay can forge fields (`A:386`); no receipt; keyset-digest header N (`A:210`) | gateway compose E, image pins static; gateway MRTD C (`R:777`); host N | gateway→host N (`aci_backend_named` C, `R:782`); downstream TLS self-asserted (`A:340`) | KMS root + app id pinned from live captures (TOFU, `A:312`) | send E; reply forgery undetected |
| neardirect | all core E incl. TCB, GPU (`R:508-526`) | E2EE to model key; TLS SPKI pinned E | nonce E; content N (anonymous-sender ECIES [i], `internal/e2ee/nearcloud.go:177-220`) | MRTD E; RTMR C; compose E; Sigstore C (`R:525`); weights C | n/a; model name is the provider's assertion (`docs/providers/near/near_attestation.md:55`) | static + Fulcio workflow identity (auto-adopts, but only C) | refuses send |
| nearcloud | model + gateway quotes E; gateway MRTD C (`R:482`) | E2EE to model key shared by ≤8 instances, every instance appraised (`near_attestation.md:14-40`); gateway TLS E; gateway REPORTDATA C (`R:485`) | nonce E; content N [i] | MRTD E; RTMR C; compose E; Sigstore C (`R:475`); weights C | gateway→model covered by E2EE to the attested model key, E; instance choice and model name are hints (`near_attestation.md:440`) | static + Fulcio identity | refuses send |
| chutes | core E incl. TCB; GPU sig C, client nonce E (`R:588-600`) | ML-KEM to instance key, REPORTDATA E; TLS C (`R:597`) | nonce via REPORTDATA E; content N (KEM to client key [i]) | MRTD/MRSEAM E (static, `internal/provider/chutes/policy.go:39-62`); RTMR C; weights C | n/a | static, from captures and NEAR's mirror | refuses send |
| nanogpt (dstack) | sig/chain/debug E; measurement, REPORTDATA, GPU C (`R:532-551`) | E2EE off by default (`internal/config/config.go:650`), so NanoGPT reads the prompt: N | N (`S:419`) | measurement, compose, Sigstore all C | NanoGPT hop N (`A:375`) | static | blocks only on quote failure |
| nanogpt (ACI/1) | gateway quote E; GPU sig + client nonce E (`R:808-811`, `A:196`) | with `e2ee=true`: E2EE v2 to gateway key, custody + gateway REPORTDATA E; default off: N | E2EE v2 forgeable, no receipt: N (`A:386`) | as venice ACI/1 | NanoGPT hop + gateway→host N (`A:375`) | TOFU pins (`A:312`) | send E (gateway tier) |
| phalacloud (ACI/1) | gateway quote E; GPU C (`R:795-801`) | E2EE v2 to gateway key + TLS pinned to keyset E (`A:201`) | receipt verified per response, E, but a stream reaches the client first (`A:405`); keyset digest E; nonce C, freshness via REPORTDATA | as venice ACI/1 | `aci_session_ids` pinned in each request; teep audits the cited sessions (`S:392`) | TOFU pins (`A:312`) | non-stream E; stream delivered before the receipt check |
| tinfoil_v3_cloud | router TCB/debug E [i] (`gateway_*` TCB/debug absent from `R:635-666`); router cert chain + signature C (KDS outages, `R:649-650`); backend C (`R:653-665`) | EHBP to router HPKE key; TLS SPKI from report_data E (`S:429`) | EHBP response tied to the request context [i]; no backend proof | router Sigstore code E; backend N; weights C | router→enclave N (`docs/attestation_gaps/tinfoil_cloud_integrity.md:9`) | auto-adopts the repo's latest release (`internal/provider/tinfoil/sigstore.go:79-102`) | refuses send |

## 2. private-ai-gateway as a client of its upstreams

The gateway fails closed only when a request is "required": a TEE-only hostname, `aci_verified`, or session pins (`F:689-717`, `docs/upstream-verification-lifecycle.md:30-36`). Otherwise a failed verification is recorded in the receipt and the prompt is forwarded anyway. Verifier results are cached (`verifier_cache_seconds` default 300 s, `docs/configuration-reference.md:306`) and refreshed in the background. Every forward checks the cached binding.

| Upstream | hardware | recipient | reply | code | downstream | updates | fail-closed (required) |
|---|---|---|---|---|---|---|---|
| tinfoil | SDK: SNP chain, debug, min TCB E (`V/tinfoil:19`) | router TLS SPKI E | N (TLS pin only) | router Sigstore release E; `release_digest` has no allowlist (`V/tinfoil:76`) | router→model N | SDK takes latest release; SDK version pinned in `uv.lock` | E |
| near-ai | dstack-verifier `is_valid` E; TCB C (`scripts/provider_verifier/nearai.py:87-93`); GPU C, JWT unsigned | gateway TLS SPKI E | N (TLS pin only) | no compose or app pin: any dstack CVM passes (`V/near-ai:63`) | gateway→model N; `model_attestations` not fetched (`V/near-ai:64`) | n/a (no pin) | E |
| phala-direct | quote E; debug E (`scripts/provider_verifier/phala_direct.py:143`); TCB C; GPU C | TLS SPKI in REPORTDATA E | N (TLS pin only) | compose measured E, no allowlist; dev OS C (`V/phala-direct:104-105`) | n/a (per model) | none | E |
| chutes | quote E; TCB C; GPU C (`V/chutes:73-78`) | ML-KEM to instance key E | N (decrypt only) | E against profiles fetched live and unauthenticated from Chutes (`scripts/provider_verifier/chutes.py:233-235`, `V/chutes:77`) | n/a | provider-served list; Chutes changes it | E |
| secret-ai | TDX UpToDate / SNP minimum E; GPU NRAS E (`V/secret-ai:73-86`) | TLS SPKI E | N (TLS pin only) | compose + registry match E; `accepted_subjects` optional | n/a | pinned verifier wheel; rollouts auto-accepted unless pinned | E |
| aci-service | DCAP E; TCB N (`V/aci-service:166`) | keyset TLS SPKI E; receipt-key custody E (attestation time) | N | app-id/image allowlist required E (`V/aci-service:28-32`) | n/a | operator config | E |
| armet-ai | quote E; TCB C except Revoked (`V/armet-ai:234`); NRAS E [i] (`V/armet-ai:164`) | channel E | N (TLS pin only) | operator measurement pin E | n/a | operator re-pins every release | E |
| 0g | quote E, no nonce (N) | provider E2EE key E | response signature vs on-chain signer E | compose recorded, C | broker plaintext destination N (`V/0g-private-computer:110-112`) | on-chain record | E |
| privatemode | delegated to the official proxy: N in gateway (`V/privatemode:13-19`) | proxy-image binding E (`V/privatemode:4`) | N in gateway | proxy image measured in compose, E | delegated to Contrast: N in gateway | dynamic manifest, auto-adopts (`V/privatemode:24-28`) | E (`V/privatemode:241-255`) |

## 3. `pap` CLI (`apps/desktop/cli`; `aci` is its legacy alias, `cli/main.rs:137-146`)

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| any ACI/1 service (`pap send`) | DCAP to Intel root E; TCB status printed, not gated (`cli/aci/verifier/quote.rs:39-76`) | no E2EE; the prompt goes over TLS pinned to the attested keyset SPKI, E (`cli/send.rs:73`); custody C, skipped unless `--accept-subject` + KMS root are given (`cli/aci/verifier/appraisal.rs:453`, `cli/args.rs:70-87`) | receipt and cited session verified after the reply is printed; exit 1 on failure (`cli/send.rs:132-200`) | compose measured E; `--accept-compose` optional, otherwise no allowlist (`appraisal.rs:424`) | sends `aci_verified:true` by default (`send.rs:238-246`); `--require-claim` optional | user-supplied flags only | refuses send if any check fails (`send.rs:55-59`); an unevaluated check is a skip (`cli/checks.rs:84`), and a skip does not block `verified()` (`cli/transcript.rs:175-193`) |

## Differences that matter most

- **NEAR cloud.** teep appraises every model instance and encrypts to the attested model key, so the gateway hop cannot read the prompt. The private-ai-gateway checks only NEAR's gateway quote and TLS key, with no workload pin. Any dstack CVM with matching REPORTDATA passes, and the gateway never fetches `model_attestations`.
- **Chutes.** teep pins MRTD/MRSEAM to a static list built from captures. The gateway accepts whatever profiles Chutes serves at `/servers/tee/measurements`.
- **TCB.** teep enforces TCB-current on NEAR, Chutes and the Tinfoil router, and allows it to fail on Venice dstack and NanoGPT. The gateway gates it only on tinfoil (SDK) and secret-ai; elsewhere it records a refuted claim or nothing. pap prints it.
- **Tinfoil.** Both teep and the gateway auto-adopt the latest Sigstore-signed router release, so neither pins a reviewed digest. teep allows the router's AMD cert-chain and signature factors to fail when KDS is unavailable (`R:649-650`). The gateway's SDK path appears to require them [i].
- **Reply authenticity.** On Phala Cloud, teep and pap both verify the ACI receipt, and both deliver a stream before the check. For Venice ACI/1 and NanoGPT, teep decrypts E2EE v2 fields that a relay could have forged (`A:386`). No client in this part authenticates replies on Venice dstack or NEAR [i].
- **Key custody.** teep enforces `aci_key_custody` against a TOFU-pinned KMS root and app id. pap skips custody unless the user supplies both flags, and the skip does not block the send. The gateway's aci-service path requires the policy before an entry will load.
- **When failure blocks.** teep blocks every request on an enforced factor. The gateway blocks only "required" requests; otherwise it forwards after a failed verification and records the failure in the receipt.

Not reviewed: `clients/verifier-ts`, `pap serve` and `pap curl`.
