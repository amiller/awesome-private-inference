# "Only Tinfoil adequately constrains the operator" — 2026-11-15

The claim has been attributed to teep and to Ritual. I could find neither in writing. teep's docs and threads favor Tinfoil's *direct* path and NEAR on specific points, and they never say "only Tinfoil". Mike Perry's position in [tinfoilsh/cvmimage#337](https://github.com/tinfoilsh/cvmimage/issues/337) (2026-08-10): "The detailed security reasons why we currently favor direct usage of tinfoil endpoints". teep's `docs/attestation_gaps/tinfoil_cloud_integrity.md:380` sends users who need per-request backend attribution to "use NEAR AI". `model_weights.md:175` calls Tinfoil's dm-verity weights "the strongest approach". I found no Ritual statement on any of these providers. Treat both attributions as secondhand. This note extends [the 2026-11-04 comparison](https://github.com/amiller/awesome-private-inference/pull/34).

## What "constrain" can mean

Start with a naive TEE inference service: an attested front door that decrypts your prompt and hands it to a model. The operator still has five ways to reach the prompt.

1. **Backend admission.** Route the prompt to code or weights nobody pinned.
2. **Serving-host attestation.** Run the model on a host the client never attests.
3. **Runtime inputs.** Change routing tables, env or secrets that the front door's measurement doesn't cover.
4. **Updates.** Ship new code the client didn't approve.
5. **Accountability.** Leave no signed per-request record of what served the request.

## How they compare

| | Tinfoil (router) | ACI/1 canonical (Phala Cloud, `tee.redpill.ai`) | ACI compat route (Venice, NanoGPT) | NEAR cloud (dstack) |
|---|---|---|---|---|
| 1. Admission | **Strong.** The router's measured config pins model → repo. A backend is admitted only if it matches that repo's Sigstore release, and weights are dm-verity-pinned in the measured config. | **Weak.** The spec says how upstreams are verified "is verifier-specific and out of scope" (`spec/aci.md:97`). The gateway's own claim mapper marks known-good software only for a Tinfoil upstream. | Weaker. It may forward to non-TEE upstreams (teep `aci_gateway.md` residual 1). | Compose is measured but not allowlisted unless the client pins it on-chain. Weights are unmeasured (teep today: `measured_model_weights` fail). |
| 2. Serving host | **None for the client.** The client attests only the router. Since router #502 the router checks backends, but the client never sees that evidence. teep disabled direct mode on 2026-11-12 because the enclave hosts stopped answering (e732070). | **Partial.** Session snapshots can be audited and pinned. teep today: "8 attested sessions pinned … workload policy not checked". | None. No GPU evidence since 2026-11-12 (residual 11). | **Yes, per instance.** Model quotes, compose and event log pass in teep and in our verifier today, but glm-5.3-flash runs on 3 instances with 3 different composes and one shared signing key, so a key-pinned client can't tell which served it. |
| 3. Runtime inputs | **The control plane can rewrite `model: "auto"` requests.** The router deep-merges an unvalidated fragment from the control plane's `/v1/models` into the request body (`autoroute/autoroute.go:271-359` at `ef64384`), and an unsigned runtime config assigns customers to replicas. Changing a model's repo still needs a router release. | The route table is admin-mutable outside the measurement (teep PR #175 gap 3). | Same as canonical. | No gateway compose enforcement shown. |
| 4. Updates | The router follows each repo's latest Sigstore release. Clients don't see upgrades. | Gateway compose measured; KMS and app id trust-on-first-use in teep. | Same as canonical. | On-chain app authorization a client can check. |
| 5. Accountability | No backend receipt. | Signed receipt per response; `aci_receipt_verified` passed today. The stream reaches the client before the receipt exists (residual 12). | The client can't fetch NanoGPT's receipts. | Model-TEE signature. |

ACI's own related-work file states the row 1 difference: "Tinfoil's enclave router chains attestation within one vendor; ACI's aggregator model verifies heterogeneous third-party providers" (`spec/related-work.md:84`). In today's glm-5.3-flash capture, the three sessions behind ACI canonical came from Armet AI, the NEAR AI gateway and a Privatemode proxy. On that route "the operator" is several companies.

## What admission is, and when it stops mattering

Admission is the rule a router or gateway applies before it hands your prompt to a backend: does this backend run approved code and weights? It matters most when your client can't see the backend. If you attest only the front door, its admission rule is the only thing between your prompt and whatever the operator plugs in behind it. On Tinfoil's router the rule is a Sigstore-pinned release per model. On the ACI gateway it is configurable, and for some upstream types it amounts to "any genuine TEE".

A verifying client that attests the backend itself does its own admission, and the router's rule drops out. What matters then is whether the measurement the client checks covers the code that reads the prompt, and whether that evidence belongs to this request.

- **Tinfoil direct.** The client attests the model enclave and checks its config against the repo's Sigstore release; the config commits to a dm-verity root for the weights. The measurement covers the serving code and the weights. teep disabled this path on 2026-11-12 because the enclave hosts stopped answering (e732070), so a verifying client today only gets the router route.
- **NEAR E2EE and direct.** The client encrypts to the model CVM's key and can pin the compose hash, as hermes's closed-chain client does. The compose doesn't contain the serving code: compose-manager deploys the proxy and model containers after boot from `nearai/cvm-compose-files` git tags, and the measured compose sets no minimum tag age (`research/operator-review-2026-11-15/near.md`). The signing key is also shared by 3 instances running 3 different composes, so pinning the key doesn't say which one served the request.
- **ACI canonical.** The client can apply its own policy to the gateway's session snapshots of upstream workloads. teep pins the sessions, but its report says "workload policy not checked", so nobody does that check today. The snapshots don't answer the client's nonce, and the receipt naming the serving session arrives after the stream is delivered (residual 12).
- **Chutes.** The serving code is excluded from measurement (`cfsv_wrapper.py:54`), so no client policy over the quote can cover it.

## Verdict

A narrower claim holds: Tinfoil is the only one whose attested measurement covers the code and weights that handle the prompt. Its router enforces that as admission, and on the direct path a client can check it itself. On ACI the admission rule is weak and the upstream evidence goes unchecked. On NEAR the measured compose leaves out the serving code.

"Only Tinfoil constrains the operator" is **wrong as a general claim**. On Tinfoil's router route, the only one reachable today, the client attests a router and not the model host, the same class of gap teep lists first for ACI. The router's control plane can also rewrite `model: "auto"` requests (row 3). ACI canonical and NEAR give the client more evidence about the serving host: sessions, receipts and per-model quotes. No deployed service gives a default client both a measurement that covers the serving code and evidence about the host that served the request.

## Found while checking

The Tinfoil router runs SEV-SNP firmware below AMD's published mitigation level. AMD-SB-3037 and AMD-SB-3038, first published 2026-11-10, list the Genoa fixes in firmware GenoaPI_1.0.0.J (dated 2026-06-26) at `TCB[SNP]=0x1D`; AMD-SB-3027 sets Genoa microcode at `>= 0x56`. The bulletins are five days old. On 2026-11-15, `inference.tinfoil.sh` reported `snp=0x17 ucode=0x54` (read 17:15Z) and `router-0.tinfoil.sh` reported `snp=0x1B ucode=0x58`. teep accepts both because its minimum is `snp=0x0e`. The ACI gateway's claim mapper asserts `tcb_up_to_date` for Tinfoil upstreams on the grounds that "Tinfoil's verifier requires an up-to-date TCB". Whether this TCB counts as up to date depends on whose minimum you use. Ours is now AMD's, in `verifiers/certs/amd_genoa_tcb_minimum.json`.

## Not verified

- Production contents of the control plane's `reasoning_params` and `router-config` (source review: `research/operator-review-2026-11-15/tinfoil.md`).
- Whether the deployed Tinfoil router matches source HEAD `ef64384f`.
- Whether Tinfoil's direct hosts are down globally.
- What teep's "reverify report differs from capture" error on the Phala qwen run means.
- No Tinfoil E2EE run today, because there is no Tinfoil key on zed.
