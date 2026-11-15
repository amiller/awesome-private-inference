# Client comparison, part D: BitRouter

I reviewed the source only. I built and ran nothing from BitRouter. The one exception is a Python re-implementation of two verifier functions, run on BitRouter's own test fixture (see finding 1).

Pins:
- `bitrouter/bitrouter` HEAD `79d46f4eb785` (2026-11-15).
- `f8763b1c75ba` is the parent of #701 and the last commit that contains the verifier. Every code cite below is at `f8763b1`.
- `bitrouter/bitrouter-docs` HEAD `7d256186e05f` (2026-11-11).

Path keys:
- `A/` = `crates/bitrouter-attestation/src/`
- `P/` = `plugins/bitrouter-attestation/src/`
- `M` = `apps/bitrouter/src/main.rs`
- `D/` = bitrouter-docs

## Status: removed, NEAR only, never on a request path

- **Timeline.**
  - Added 2026-06-14 in #563 (`9dc0a1d`).
  - Hardened by #573 (TCB floor, fixes amiller's #566) and #578 (base-MR pin, fixes amiller's #567).
  - Removed 2026-07-13 in #701 (`e9896fa`).
- **#701's commit message gives the reasons:**
  - "the route hook was never wired into the pipeline".
  - "the only surface was the NEAR-AI-only `bitrouter verify` subcommand".
  - "The /v1/aci/verify endpoint ... was planned but never implemented".
  - The published `bitrouter-attestation` alpha crates are left on crates.io.
- **#570 is unexplained.** It shows a merged 2026-06-15 "remove bitrouter-attestation crates from mainline". Its merge commit `22c4d84` is not an ancestor of main (`gh api compare` reports diverged), and the crate's path history doesn't include it.
- **HEAD has no verifier.** At HEAD, the "attest" matches in `apps crates docs skills` belong to other features:
  - offline-recovery evidence formats (`apps/bitrouter/src/offline/recovery/v2/run.rs:42-43,302`; `docs/RESOURCE_TENANCY_RECOVERY.md:23,29`);
  - harness run attestation (`crates/bitrouter-ai/src/core/protocol.rs:331-333`);
  - a pricing-profile flag (`skills/bitrouter/references/providers.md:101`).

  The "enclave"/"TEE" matches are model descriptions in `registry-dist/registry.json`. The non-PKCE "verifier" matches are an API-key hash (`crates/bitrouter-ai/src/gateway/operator.rs:108`) and task verifiers (`apps/bitrouter/src/main.rs:8104` at HEAD).
  - `tinfoil`, `phala`, `redpill` and `chutes` are plain bearer-auth OpenAI-compatible providers (`registry/providers/{tinfoil,phala,redpill,chutes}.yaml:2`).
  - HEAD has no `near-ai` or `venice` provider file.
- **Open PRs/issues about attestation: none.** The `gh` searches for attestation, TEE, confidential, verifier and enclave return the closed items above, release and registry PRs, and #1019 and #1047. Their matches are unrelated: "startup schema attestation", and "Tinfoil HTTP 402" metering.
- **Providers covered: NEAR AI Cloud only.**
  - `provider()` returns `"near-ai"` (`A/near/mod.rs:198`).
  - "NEAR is the only impl today" (`A/lib.rs:102-105`).
  - ACI appears only as an unimplemented enum variant, "future `AciGatewayVerifier`" (`A/types.rs:160`).
  - Tinfoil, Phala/RedPill, Chutes, Venice: not found.

## What the docs claim

- **No docs page describes the client verifier.** Only the changelog lists it (`D/content/changelog/v1-0-0-alpha-17.mdx:14,22-23`; removal at `v1-0-0-alpha-26.mdx:25`).
- **Platform claim.** The enterprise FAQ says "Every inference request on the BitRouter platform is verified against its declared model specification". It covers version, weights, precision and "end-to-end evidence", and says "TEEs provide hardware-backed execution evidence" (`D/components/landing/zed/enterprise-page.tsx:15-26`; also `D/lib/llms-shared.ts:20`).
- **The docs repo says these claims are unbacked by code there.** They are "user-confirmed product claims; the website does not implement or validate the verification service" (`D/docs/CONTRIBUTING.md:389-393`).
- **Tier pages.** "Verified" and "Secured" are described as "a market design preview" (`D/content/docs/(guide)/market/inference-tiers.mdx:6-18`).
- **No implementation in the open repos.** No verifier for these claims exists in either public repo at HEAD. #701 cites a private `bitrouter-cloud` repo, which I did not review.

## Verifier at `f8763b1` (NEAR, `bitrouter verify <model>`)

Cells:
- **E** gates the `verified` flag.
- **C** computed but does not gate it.
- **N** not checked.
- `[i]` inferred.

Nothing in this column blocks a request: the plugin is never installed, so no request path consults the verdict.
- The only `AttestationPlugin` reference outside `P/` is `Cargo.lock`.
- `verify_exchange` has no caller. The only caller of the verifier is `M:1745`, which calls `attestation_cached`.

| Factor | Finding |
|---|---|
| What is attested | Each NEAR `model_attestations[]` node, i.e. the serving host. The `gateway_attestation` is deliberately not parsed (`A/near/report.rs:10-18`), so the NEAR gateway at the default base `cloud-api.near.ai/v1` (`M:1698`) is unattested. Nodes are filtered by the report's own `model_name` (`A/near/mod.rs:233`). The verdict passes if any node passes (`:240-248`). |
| Quote | Verified locally with `dcap-qvl` 0.5.2 (`Cargo.toml`), using collateral from Phala's PCCS by default (`A/near/tdx.rs:101,111-129,171-174`), E. Whether the collateral's Intel signature chain is checked inside `dcap-qvl` is [i], not reviewed. |
| TCB | E. The floor is `UpToDate`. A non-current status passes only if every advisory is on the `NEAR_TCB_ALLOWED_ADVISORIES` list (`A/near/dcap.rs:140-152`, `M:1715`), and a missing status fails (`A/near/dcap.rs:150`; the parse-only path leaves it `None`, `A/near/tdx.rs:84`). |
| Debug | E: the TD attributes debug bit must be clear (`A/near/tdx.rs:57-59`, `A/types.rs:97-107`). |
| GPU | The NRAS EAT JWT signature is E. Keys come from NVIDIA's live JWKS and are resolved by `kid` (`A/near/nvidia.rs:84-105,214-234`). If the JWKS fetch fails, the key is unconfigured, so the GPU check fails (`M:1722-1733`). `x-nvidia-overall-att-result` E and `eat_nonce` E (`A/near/nvidia.rs:236-247`). `exp` N (`:227`). Only the platform token is read; per-GPU tokens are N (`:167-197`). The only link from the GPU to the CVM is the shared nonce [i]. |
| Measurements | Four pins come from the CLI environment, `NEAR_*` (`M:1701-1712`): base `MRTD‖RTMR0‖RTMR1‖RTMR2` E (`A/near/dcap.rs:180-189`); `app_id`, or either of `{os_image_hash, compose_hash}`, E (`:156-162`, `:243-254`); KMS root E (`:166-171`). The constructor refuses to build with no pins (`:99-107`). RTMR3 replay is E (`A/near/eventlog.rs:54-57`), but see finding 1. Compose is checked with `sha256(info.tcb_info.app_compose) == info.compose_hash`; both sides come from the report (`A/near/mod.rs:148-149`). |
| Who updates pins | The operator, by hand, through environment variables. The repo has no source or feed for the values, and the example ships none (`examples/verify_near.rs:44-52`). |
| Freshness | A client nonce is generated internally (`A/lib.rs:95-100`). It must be echoed by the report (`A/near/mod.rs:129`) and appear in REPORTDATA[32..64] (`A/near/binding.rs:46-49`), E. NRAS gets the same nonce. The only path used is `attestation_cached`, which caches a verdict per model name for 600 s (60 s if unverified) (`A/near/mod.rs:39,44,86-105`). |
| Recipient binding | N. REPORTDATA[0..20] binds the node's EIP-191 response-signing address (`A/near/binding.rs:22-44`). It binds no TLS SPKI or E2EE key, so the attestation says nothing about who receives the prompt. |
| Reply | L1.5 `verify_exchange` recovers NEAR's per-chat signature over `model:sha256(req):sha256(resp)` and requires it to be in the attested address set (`A/near/mod.rs:257-316`). It is implemented, but nothing calls it. The code notes that the NEAR gateway re-serializes bodies, so the hashes match only on direct completions (`A/types.rs:9-14`). |
| Fail-closed | The library fails closed: a failed report fetch returns an unverified verdict (`A/near/mod.rs:219-221`), and `all_pass` ANDs every gate (`A/types.rs:97-107`). The CLI prints UNVERIFIED but exits 0 (`apps/bitrouter/src/output/mod.rs:42-44`; a test asserts "verify keeps exit 0 even when UNVERIFIED", `output/reports/verify.rs:90-91`). The plugin defaults to `Record`, which tags the verdict and never drops a target (`P/lib.rs:27-35`), so it would have been fail-open if wired. `Enforce` drops unverified targets and treats verifier errors as unverified (`P/hooks.rs:57-71,95-104`). |
| Reuse | Reimplemented in Rust, with no dependency on teep, pap or private-ai-gateway. Its comments say it was ported from private-ai-gateway's `AciDcapVerifierPolicy`, `dstack.rs` and `verify_report_data` (`A/near/dcap.rs:3-4`, `A/near/eventlog.rs:2-4`, `A/near/binding.rs:2-4`), and it pins the same `dcap-qvl` version (`Cargo.toml`). The KMS-root pin was changed from secp256k1 to P-256 SPKI (`A/near/dcap.rs:10-16`). |

Same row in part A's columns:

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| near-ai (`bitrouter verify`) | node DCAP E; TCB E (UpToDate or allowlisted advisories); debug E; NRAS sig, result and nonce E | N (REPORTDATA binds only the response-signing address) | per-chat EIP-191 sig implemented, never called | base MRs E; app_id/compose/os/KMS pins E but forgeable by the report server (finding 1); compose circular | NEAR gateway not attested | operator `NEAR_*` env pins | verdict only; CLI exits 0; plugin never installed, default Record |

## Findings

1. **The event-log anchor does not bind payloads.**
   - `replay_rtmr` folds each event's `digest` field (`A/near/eventlog.rs:22-33`). The policy reads each event's `event_payload` (`:37-43,59-71`), and the verifier never recomputes digest from payload.
   - **Simulation.** I re-implemented `replay_rtmr` and `event_payload` in Python and ran them on BitRouter's fixture `tests/fixtures/near_report.json`. Rewriting the `app-id` payload left the replay equal to the quote's RTMR3. On the same fixture, `sha384(event_type_le32 ‖ ":" ‖ event ‖ ":" ‖ payload)` reproduces all 10 RTMR3 digests (1 node), so the check was available and was not made. The port could not have made it: `DstackEvent` has no `event_type` field (`A/near/report.rs:46-51`).
   - **Consequence [i].** Whoever serves the report can rewrite `app_id`, `compose_hash`, `os_image_hash` and `key_provider_info`, in `info` and in the payloads together, to the pinned values. That defeats the workload and KMS-root pins.
   - **What still binds:** the base-MR pin (MRTD/RTMR0-2), REPORTDATA (key and nonce), TCB, debug and NRAS.
   - **Net effect [i]:** any dstack app on a pinned base image passes.
   - **Comparison with the gateway.** private-ai-gateway at `e9b6ae8a` recomputes the digest, and its test is named `replay_recomputes_runtime_event_digest_from_semantic_fields` (`crates/aci-verify/src/dstack.rs:160-170,454`). I did not check whether the gateway version BitRouter ported from (June 2026) had this check.
2. **Pinning the OS image accepts any app.** `accepts` is an OR of `app_id` and the digests, and `os_image_hash` counts as an image digest (`A/near/dcap.rs:156-162,251`). So `NEAR_IMAGE_DIGESTS=<os_image_hash>` admits every compose on that OS, before any forgery.
3. **The compose check is circular.** `compose_matches_mr_config` compares two fields from the report and never reads the quote's MRCONFIG (`A/near/mod.rs:148-149`, `A/near/binding.rs:54-57`). `compose_hash` can be pinned via `NEAR_IMAGE_DIGESTS`, but its only link to the quote is the event log, which finding 1 breaks.
4. **The verdict does not constrain the recipient.** There is no TLS or E2EE binding, and the gateway attestation is ignored. A verified verdict says a pinned node exists; it does not say who reads the prompt. No send path exists, so where prompts would go is [i]; the report's default base URL is the NEAR gateway (`M:1698`).
5. **Pins are hand-edited environment lists** with no provenance. NEAR's image churn is about 4.7 days (`research/critical-review-2026-08-10.md:127-133`), so the pins go stale quickly.

## "Named verifier"

Not found. I searched with `grep -niE 'named.{0,3}verifier|verifier.{0,15}name'`:
- in bitrouter at `f8763b1` and HEAD;
- in bitrouter-docs;
- with `gh` `search/issues` and `search/code` (`org:bitrouter`) for "named verifier" (0 results each).

Candidates only:
- BitRouter's `VerifierRegistry`, which keys a `ConfidentialVerifier` by provider name and returns `UnknownProvider` for any name not registered (`A/lib.rs:102-135`).
- teep's `aci_backend_named` factor (part A, venice ACI/1 row).

## Compared with teep, per provider

| Provider | BitRouter (`f8763b1`) | teep (part A) |
|---|---|---|
| NEAR (direct or cloud) | Node quote, TCB, debug and NRAS signature all E. Base MRs pinned E. Workload and KMS pins are forgeable (finding 1). No E2EE or TLS binding. Gateway not attested. No request path; CLI exits 0. | neardirect/nearcloud: all core factors E, E2EE to the attested model key, every instance appraised, refuses to send. |
| ACI / Phala / RedPill | not found (`AciReceipt` placeholder only) | phalacloud ACI/1: receipts and sessions E, TOFU KMS/app pins |
| Tinfoil | not found; plain HTTPS provider at HEAD | router Sigstore E, EHBP |
| Chutes | not found; plain HTTPS at HEAD | static MRTD/MRSEAM, ML-KEM to the instance key |
| Venice | not found | dstack and ACI/1, E2EE |
