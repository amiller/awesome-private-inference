# Client comparison, part E: IronWire and Near AI Gateway (TraceCommons)

Source review only; nothing was built or run. Pins: nearai/ironwire `ac919ac` (2026-11-09), TraceCommons/trace-commons `df2e821` (2026-11-14). PRs read through `gh api`: #2070 (merged; brings in the ironwire crates as a squashed snapshot of `b234896`), #2073 (open, head `59b66d0179`, design doc only), #2075 (open, head `6b53cefcec`, org tenancy server side), #2086 (merged, renames the DMG). #2073, #2075 and #2086 change nothing about verification. In-tree `ironwire_proxy/src/proof.rs`, `ironwire_upstream/src/receipt.rs` and `ironwire_ledger/src/proof.rs` are byte-identical across the two repos. `openai_chat.rs` differs in one comment path.

Cells and legend as in part A: **E** enforced (failure blocks the send or the reply), **C** checked but not enforced, **N** not checked, **n/a**. `[i]` = inferred. **No cell in this part is E.** Every check runs after the response has been delivered and decides only a ledger label.

Path keys. IronWire: `P` = `crates/ironwire_proxy/src/proof.rs`, `RC` = `crates/ironwire_upstream/src/receipt.rs`, `OC` = `crates/ironwire_upstream/src/openai_chat.rs`, `L` = `crates/ironwire_ledger/src/proof.rs`. TraceCommons: `PA` = `crates/trace-commons-contributor/src/routing/proof_attestor.rs`, `AR` = `crates/trace-commons-attestation/src/receipt.rs`, `Q` = `.../attestation/src/quote.rs`, `M` = `.../attestation/src/measurements.rs`, `SR` = `.../attestation/src/staging_replay.rs`, `IPC` = `crates/trace-commons-contributor/src/daemon/ipc.rs`.

## What it is

IronWire is a loopback proxy for coding agents (Claude Code, Codex) that routes calls across subscriptions, API keys, local models and NEAR AI. The NEAR lane is ordinary OpenAI Chat Completions to `https://cloud-api.near.ai/v1` (`crates/trace-commons-contributor/src/channel.rs:116`) with a bearer key, over reqwest with rustls and the system roots (`Cargo.toml:81`, `OC:205-209`). TraceCommons embeds it as the "Private AI" destination in the "Near AI Gateway" desktop app (`daemon/private_inference.rs:1-10`). Here "gateway" names a local app; it is not NEAR's cloud gateway.

The verification is a provenance label. After an answer is delivered, a background task fetches NEAR's `GET /v1/signature/{id}` receipt, checks it against the digests of the bytes that crossed the wire, and asks a host-supplied `SignerAttestor` whether the signer is an attested model key (`P:1-32`). The results show up as an analytics label, "Through Private AI, verified" (`crates/trace-commons-contributor-insights/src/insights/service.rs:2100-2101`), and as evidence for trace submission (below). The app's copy rules forbid any sentence that claims privacy, with one owner-approved exception: the subtitle "Add a privacy layer to AI models you are already using" (`crates/trace-commons-contributor/src/private_inference_copy.rs:70-75,98-120`).

## Rows

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| ironwire standalone (`ac919ac`) | N. "IronWire itself carries no DCAP verifier" (`P:88-91`); the shipped attestor returns `Unsupported` (`P:103-117`), and the CLI installs none (no `signer_attestor` in `src/`) | N: HTTPS + API key, system roots, no SPKI pin, no E2EE (no `X-Encryption-Version` or client/model pub-key header anywhere in either repo) | receipt C, after delivery: ed25519 `verify_strict` over raw `text` (`P:197-208`); `provider_tee` kind (`P:145-149`); request and response SHA-256 equal to the wire bytes (`P:159-167`); model, when the 3-part form binds one (`P:150-155,171-173`). Best label reachable is `unattested` (`P:302-304`, test `P:667-676`) | N | `gateway` receipts settle `gateway_only`, never proof (`P:174-176`); a brokered model 404s and settles `unavailable` (`P:267-274`) | n/a | receipt checks are off by default (`crates/ironwire_core/src/config.rs:186-195`, test `:2172-2179`); when on, they never touch the response (`P:7-13`) |
| Near AI Gateway app, default build (`df2e821`) | per model entry: DCAP via `dcap-qvl` 0.6.6 (`Q:118-143`, `Cargo.lock:1718-1719`) against collateral relayed by TraceCommons ingest (`PA:264-270`); TCB must be `UpToDate` (`Q:100`, `PA:1226-1228`); debug bit not checked in repo code, left to dcap-qvl's defaults (not read) [i]; GPU/NRAS N (NVIDIA evidence is only mentioned in a comment, `AR:1808-1810`); **NEAR gateway quote N**: keys come from the model container only (`PA:22-25`, `AR:700-722`) | N, as above. `include_tls_fingerprint` is never requested (server-side note, `crates/trace-commons-server/src/near_attestation/client.rs:14-22`) | receipt as above, then signer must be in the key set (`P:288-301`). The set holds `report_data[0..32]` of every verified quote for the model, under our nonce at `[32..64]`, and must equal the keys the JSON claims (`AR:881-907`, `PA:1244-1252`). All of it runs after delivery | **operator-chosen register subset**, C. A set needs only one of `mrtd`/`mrconfigid`/`rtmr0-3` (`M:186-188,253-256`), and `Pinned` means only that the named fields match (`M:375-401`). No event-log replay, compose or app-id check in this build. Pins come from ingest's unsigned `GET /v1/contributors/me/near-ai-measurements`, trusted on TLS alone (`PA:47-60`), or from an env override (`PA:62-70`). The repo ships no values: the pilot template line is commented out (`deploy/pilot-gcp/ingest.env.template:64`), so deployed pins cannot be determined from source. With no pins, nothing verifies (`PA:103`, `M:410-420`) | gateway→model N; which model served is NEAR's JSON statement (`PA:27-31`). The server notes that "every NEAR AI model enclave presents the same mrtd/mrconfigid/rtmr0-3" (`crates/trace-commons-server/src/near_attestation/signer_resolver.rs:23-31`) | follows whatever ingest publishes: refresh every 10 min, valid 1 h (`PA:163-169`); a digest change drops cached verdicts (`PA:38-43`) | N for the user: a `failed` row is a label. Every failure resolves to "not proof" (`PA:33-43`, `P:30-32`) |
| Near AI Gateway app, `near-ai-staging` build | as default | N | as default | **adds** a signed pin set with rollback protection (`PA:72-83`); pins `mrtd`, `rtmr0-2`, `mrconfigid` (`SR:5-8`); replays RTMR3 with **each digest recomputed from `event_payload`**, refusing a non-empty recorded digest that differs (`SR:10-24,821-876`); fixed event list; the compose-hash event must equal MRCONFIGID (`SR:24-29`); allowlist for app id, KMS, OS image and key provider (`SR:30-33`); compose-manager quote, same TD, our nonce, `actions_hash` recomputed and every action allowlisted (`SR:36-54`, `PA:1260-1289`) | as default | signed staging set | as default |

The staging build cannot ship: `scripts/ci/check-release-staging-feature.sh:1-12` refuses any release or deploy build line that enables the feature. **The strong row is not what users get.**

## Freshness and caching

- The client nonce is 32 bytes from `ring::rand::SystemRandom` (`crates/trace-commons-contributor/src/routing/receipt.rs:475-478`). It is checked at `report_data[32..64]` (`AR:895-897`).
- The nonce is per model per refresh, not per request. An earned key set is served for 1 h (`PA:150`, `PA:1114-1131`), and a failed refresh does not extend it (`PA:38-39`). The report is fetched when a row is settled, not when the call was served, so the label means "this signer is in a set we attested at most an hour before the check". It does not mean the instance was attested when it answered.
- The settle loop runs every 30 s with up to 5 deferrals (`P:328-336`).

## "Receipt" and "proof"

- **Receipt**: NEAR's `/v1/signature/{chat_id}?model=..&signing_algo=ed25519` (`RC:3-10`, `OC:586-604`). It is fetched with the user's NEAR key, after delivery, only for the `Credits` backend kind (`OC:578-584`). It is a per-response signature by the model TEE (`provider_tee`) or by NEAR's gateway (`gateway`, which is what the Responses API, and so Codex, gets: `routing/receipt.rs:9-15`).
- **Proof**: the ledger label `verified`, written only by `P` (`L:3-21`). It is monotone: a settled row never changes (`L:19-21`). It needs body digests, so `capture.receipts` turns on digest-only hashing of the streamed bytes (`crates/ironwire_proxy/src/pipeline.rs:1268-1275`). An alias-rewritten NEAR body can never verify and settles `unavailable` (`P:245-250`).
- **Weaknesses in `judge`**: the 2-part receipt form, with no model, is accepted (`P:152`); the served model falls back to the requested model (`P:185-190`); and the per-model key set is looked up under that name, though the server itself says measurements don't distinguish models.
- **Trace submission**, a second consumer. The witness (gate enclave) verifies the receipt against raw bodies before redaction (`routing/receipt.rs:25-29`). The server's `signer_resolver` re-derives the signer set with its own nonce and DCAP check (`signer_resolver.rs:7-21`). The Windows `AttestationMark`/`RouteDisclosure` fields (`attested_bodies`, `measurement_label`, `verified_at_review`) describe this witness-certificate path, not the IronWire label (`windows/src/TraceCommons.Interop/AttestationMark.cs:5-8`, `RouteDisclosure.cs:9-28,112-123`). Not audited here.

## Fail-closed vs fail-open

The send is fail-open by construction, and that is intended. No check runs before or during a request (`P:7-13`). A `failed` receipt, wrong signer, unpinned image or non-UpToDate TCB changes only the row label (`P:283-308`, `PA:1209-1252`). Nothing found in either repo routes, refuses or alerts on `ProofStatus::Failed`: outside tests, the only reader is the lenient display parse in `crates/trace-commons-contributor-sources/src/routing/mod.rs:132-147`. The attestor side is fail-closed for the label: no pins, an unreachable report, or a mismatch never yields `verified` (`PA:33-37`, `P:289-307`).

## Privacy filter

Two different things carry the name, and neither touches the NEAR inference request.
- **IronWire `[privacy]`** substitutes on the request path. It is off by default (`docs/PRIVACY.md:7,36`), and `mode = "full"` restricts which destinations are eligible without encrypting anything (`docs/PRIVACY.md:132-142`). The contributor daemon does not turn it on (only a test writes `mode = 'off'`, `daemon/private_inference.rs:1631`).
- **TraceCommons' privacy filter** redacts traces before upload, LLM-backed, and its default base is NEAR's API (`channel.rs:261`; `daemon/uploader.rs:13-29`). It applies to contribution, not to inference.

## Other TEE providers

None verified. The picker's "Confidential TEE" and "3P Confidential TEE" tiers are read from `owned_by` in NEAR's `/models` response (`crates/trace-commons-contributor/src/managed/models.rs:49-76`), which is not attested. Third-party models have no `provider_tee` receipt and settle `unavailable`. #2073 says that org-run upstreams produce no receipt (`docs/superpowers/specs/2026-11-11-enterprise-gateway-design.md:949-953` at `59b66d0179`) and that "no client attestation exists today" (`:850-853`).

## Reuse

Reimplemented, no code reuse. No teep, ACI `aci-verify`, private-ai-gateway, dstack-verifier or nearai-cloud-verifier dependency or vendored code (word-bounded grep over `*.rs`/`*.toml` in both repos; the one hit is a doc reference). The receipt format follows `nearai/nearai-cloud-verifier` `py/chat_verifier.py` "with two departures, settled by captured triples" (`AR:11-30`). The DCAP check uses Phala's `dcap-qvl` crate (`crates/trace-commons-attestation/Cargo.toml`). The staging RTMR3 replay is their own.

## Compared with teep on NEAR (part A `nearcloud`/`neardirect`)

| | Better than teep | Worse than teep |
|---|---|---|
| Near AI Gateway (default build) | per-response `provider_tee` signature checked against attested keys and wire digests; part A records no NEAR reply check for teep | no E2EE: NEAR's gateway, and any TLS-terminating hop, reads the prompt (teep E2EE to the model key, E); NEAR gateway quote not checked (teep E); nothing blocks (teep refuses the send); pins are operator-published, unsigned, any register subset, with none in the repo (teep's static MRTD and compose, E); no GPU evidence; nonce per hour, not per request |
| staging build | recomputes RTMR3 event digests and checks the compose-manager `actions_hash` (part B's hermes gap) | same transport and fail-open gaps; not shippable |

Net: worse than teep on privacy. teep makes the prompt unreadable to everything except an attested model CVM before sending. The Gateway app sends plaintext to NEAR's gateway and later labels whether a pinned-image enclave signed the bytes. That is a data-provenance check for the trace commons, not a confidentiality check for the user.

Not reviewed: the server's `near_attestation/drill.rs`, the gate-enclave witness, `staging_pins.rs`, and the macOS and GTK shells.
