# Client comparison, part G: AntSeed buyer verifier

Source review only. Nothing was run, and the unit tests were skipped because there is no `node_modules` and installing would need network. Pin: Antseed/antseed `cda310ed` (2026-11-15).

Cells use part A's codes: **E** enforced, **C** checked, not enforced, **N** not checked, `[i]` inferred. `[nr]` marks dependency internals that were not read (`@phala/dcap-qvl`, `@phala/dstack-verifier-wasm`, `@sigstore/verify`).

Path keys: `V/` = `packages/antseed-verifier/src/`, `T` = `V/caps/tee-tdx.ts`, `BP` = `apps/cli/src/proxy/buyer-proxy.ts`, `PV` = `apps/cli/src/plugins/verifier.ts`, `TV` = `apps/cli/src/proxy/tee-verification.ts`, `SC` = `V/seller-config-rules.ts`.

## What is attested

A buyer's prompt travels over AntSeed's encrypted TCP (X25519, wallet-signed) to the **seller node**, the AntSeed CLI running a provider plugin. The seller node then forwards the prompt over HTTPS, using the operator's API key, to the upstream origin named in the seller config. A TEE seller runs Antseed's image `ghcr.io/antseed/tee-seller` in one of two ways:
- as a dstack app on Phala Cloud, checked against a local DCAP quote;
- on Google Confidential Space, checked against Google's signed token.

The allowed plugins are `openai` (any `baseUrl`), `anthropic` (fixed to api.anthropic.com), `typesafe`, `venice-video` and `alibaba-video` (`V/tee-provider-plugins.json`). The TEE therefore covers the relay. With the anthropic or openai defaults, Anthropic or OpenAI receives the plaintext. The docs say so: "does not guarantee that downstream inference runs inside a TEE" (`apps/website/docs/security/verify-tee.md`).

There is an optional second quote from the downstream provider. It comes from a generic HTTP route or from the `chutes` or `aci` adapters, and it is informational only (`V/verifier.ts:47`).

**Roles.** "Verifier" here means a buyer-side plugin from a pinned list (AIP-3). Each buyer's own node runs it per seller. It is not an auditor network. `antseed verifier …` is a separate system: KBF (Knowledge Boundary Fingerprinting) model audits by an on-chain approved auditor set (`apps/cli/src/verifier/auditor-set.ts:34-43`). It has no TEE or attestation code: a grep for `tee|attest` over `apps/cli/src/verifier` and `commands/verifier` finds nothing. `apps/ants/src/service/verification.ts` is a wash-trading proof registry (SP1), also unrelated to TEE.

## Per evidence path

| Path | hardware | recipient | reply | code | downstream | updates |
|---|---|---|---|---|---|---|
| seller node, dstack (required claim `seller-node-tee-genuine`) | DCAP via `@phala/dcap-qvl` E (`T:233-254`). Collateral comes from the seller if it sends any, else from a PCCS (`T:237-239`); default PCCS and collateral expiry [nr]. TCB: UpToDate, plus SWHardeningNeeded unless `ANTSEED_VERIFIER_STRICT_TCB=true` (`V/tcb-policy.ts:7-10`). TD10 and debug bit E (`T:451-453`) | report_data = SHA-512 TLV over nonce, peerId and the P2P **channel binding** (`V/report-data.ts:58-84`), all 64 bytes, E (`T:474-480`). The binding is a transcript hash over both peer ids, both nonces and both ephemeral X25519 keys (`packages/node/src/p2p/secure-channel.ts:72-92`). The seller sets it from its own connection and strips any buyer-supplied value (`packages/node/src/seller-request-handler.ts:371-374`). `seller-bound` signs the bundle with the identity key, which the operator supplies as `ANTSEED_IDENTITY_HEX` (`V/dstack-app-compose.ts:74`). It proves the payee and does not exclude the operator. Operator exclusion rests on the channel binding [i]. No E2EE beyond the node, and the node reads plaintext | N. No response signing; the P2P AEAD to the attested connection is the only binding [i] | MRTD and RTMR0-2 matched exactly against a static dstack 0.6.1 table for 7 Phala shapes (`V/approved-node-measurements.ts:45-65`), or recomputed by the dstack lite wasm from vm_config and the event log into an `os_image_hash` on a 0.6.1-0.6.4 list (`:68-73`, `T:336-354`; wasm [nr]). RTMR3 replay **recomputes every digest from name and payload** (`V/dstack-event-log.ts:86`), so it does not have the stored-digest bug. Kebab-case names prevent v1 preimage shifting (`:67`). init-script events are rejected (`:95`), and there must be exactly one compose-hash (`:97`). The app-compose hash must equal the measured hash (`V/dstack-app-compose.ts:143`), then whitelist rules apply: one service, image by digest, no cmd or entrypoint, inline config named by its own hash, env whitelist, no `$` substitution (`:85-132`). App-id and KMS fields are not checked (`:41-46`). Image: on the static list (one entry, `V/approved-seller-images.ts:14-16`) **or** accompanied by a Sigstore bundle verified offline. The bundle must have SAN `…/tee-seller-image.yml@refs/heads/main`, the GH Actions issuer, tlog and ctlog proofs, and a certificate issued after 2026-11-07 (`V/image-provenance.ts:15-21,29,60-74`), all E | upstream origins come from the measured config and are reported as the `seller-node-upstreams` claim (`T:380-385,492-493`). **No buyer allowlist**: any https `baseUrl` passes (`SC:129-131`), including one the operator controls. The claim feeds only the console badge (`apps/cli/src/gateway/console-api/handlers/network-mapping.ts:173,240`). `OPENAI_BODY_INJECT_JSON` is an allowed literal that merges arbitrary fields into upstream requests (`SC:39`, `plugins/provider-openai/src/index.ts:271`). Nested `provider.defaults`/`services` were not reviewed | Auto-adopts any image the workflow builds on main (`T:322-324`); the revoke list is empty. The image is assembled from npm tarballs pinned in `deploy/tee-seller/package-lock.json` (`deploy/tee-seller/Dockerfile:22-26`), so the provenance shows "lock on main" and not repo source; npm provenance N [i]. Buyer SDK pinned at `@antseed/antseed-verifier` 0.1.8 (`apps/cli/src/plugins/registry.ts:82-86`), loaded with `install:false` (`PV:151`) |
| seller node, Confidential Space | Google JWT checked against Google's JWKS, fetched live, with iss and aud checked (`V/confidential-space.ts:48-52`). `hwmodel`, `dbgstat`, `secboot` and `STABLE` are E. TCB is Google's `gcp_attester_tcb_status` under the same policy (`:73-85`). No local quote; trusts Google | same binding: `eat_nonce` = SHA-256 of the antseed-rd-v1 report_data (`T:403-410`) | N | image digest under the same approval as dstack; env_override whitelist, and the seller config passes the same rules (`V/confidential-space.ts:87-110`) | same as dstack | same |
| downstream provider (`seller-provider-tee-genuine`, informational) | same DCAP, TCB and debug checks (`T:451-453`). GPU via remote NRAS: JWT signature against NVIDIA's live JWKS (`V/nras.ts:200-201`), overall result and `eat_nonce` (`:208,214`); no issuer check, informational | binding uses a scheme the seller declares. A seller that declares none still passes, with only a detail note (`T:481-483`). Ingredients (`e2ePubkey`, ACI `keysetDigest`) are checked inside report_data, but nothing is encrypted to them. No TLS pin node→provider (`V/adapters/aci.ts:38-51`) | N | no pin by default; the measured-image allowlist exists only if the buyer sets an env var (`V/caps/measured-image.ts:57`) | counted only if the config has one upstream origin equal to the evidence origin (`T:394-400`). Even then it shows only that some TDX VM at that origin answered; nothing shows the inference endpoint is served by that VM [i] | buyer env only |

Freshness: a 32-byte random nonce each round (`V/verifier.ts:111`). Verdicts are cached for 5 minutes for routing and 24 hours for the badge (`packages/node/src/verification/tee-status.ts:2-3`, `TV:30-33,68`). Under `require`, a changed connection binding triggers re-attestation (`BP:5531`). Non-transient failures are also cached for 5 minutes (`TV:68`), although verify-tee.md says "Failures are not cached". This only matters in the fail-closed direction.

## When failure blocks

| Mode | Behaviour |
|---|---|
| default (`buyer start`, desktop, gateway) | Verifier on, `require:false` (`PV:57`). Every outcome is `ok: !policy.require \|\| verified` (`PV:140,154,182,189`; `TV:58`). The buyer routes anyway and logs "optional — routing anyway" (`BP:5450`). The request is not pinned to the attested connection (`BP:5541` needs `require`). **Fail-open** |
| `--require-verifier` / `buyer.verifier.require` | Requires `seller-node-tee-genuine` and `seller-bound` (`V/verifier.ts:47,168`). The buyer can override this set with `ANTSEED_VERIFIER_REQUIRED_CAPS` (`:53-57`). Automatic routing skips to the next seller (`BP:5143-5151`); a pinned seller returns 502 (`BP:5452-5456`). A request on any connection other than the attested one is refused before it is sent (`packages/buyer-core/src/buyer-request-handler.ts:166-170`). More than 8 concurrent checks return `ok:!require`, so this mode refuses (`TV:69-71`) |
| routing policy `requireTee` (console "TEE sellers only", or a request header, `apps/cli/src/gateway/request-shaping.ts:9-11`) | Forces `antseed-verifier` and `require` (`BP:1240`), and needs `sellerNodeVerified` (`BP:5537-5539`). With verification disabled, the request is refused (`BP:5520-5522`). Fail-closed |

## Reuse

Quotes go through `@phala/dcap-qvl`, OS measurements through `@phala/dstack-verifier-wasm` (`V/dstack-lite-os.ts:7`), image provenance through sigstore-js, and JWTs through jose. RTMR3 replay, the compose and config rules, the report_data schemes and the NRAS handling are AntSeed's own TypeScript. `aci-keyset-v1` copies the private-ai-gateway report_data statement (`V/report-data.ts:118`). No teep or dstack-verifier (full) code was found.

## Weaknesses

- **The attested relay does not constrain where the prompt goes.** `openai` accepts any https `baseUrl` (`SC:129-131`). An operator can point it at a server they run and still pass `seller-node-tee-genuine` and get the "TEE" badge. The only signal is the upstream host shown in the console. The operator also owns the upstream account, and `OPENAI_BODY_INJECT_JSON` lets the operator add request fields.
- **Fail-open by default.** Required mode and `requireTee` are opt-in. This is documented.
- **Image auto-adoption.** Any image the workflow builds on main is accepted (no review step, empty revoke list). Its contents are npm tarballs selected by a lock file.
- **SWHardeningNeeded is accepted by default.**
- **The provider "end-to-end" scope is weak.** It needs no measurement pin. A seller can declare no binding scheme, and the check then passes on genuineness alone. There is no key or TLS binding to the inference traffic.
- **Done well.** The event-log replay recomputes digests. The compose whitelist is tight. The quote is channel-bound to the P2P session, and under `require` the request is pinned to that connection, which works like RA-TLS.

## Compared with teep

teep attests the provider's model CVM and encrypts to the attested model key. It blocks by default. AntSeed attests its own relay CVM and binds the quote to the transport, so it is closer to RA-TLS. Its node policy is stricter than teep's on two points:
- Sigstore image provenance is enforced (teep only checks it).
- The compose rules are a whitelist.

The downstream hop, where the model runs, is out of scope by default. There, AntSeed's checks are weaker than teep's on every axis: no MRTD pin, no E2EE to a provider key, no TLS pin, and a verdict that is only informational.
