# Client comparison, part K: crow-004/attestation-verifier, AdverserialAI/confidential-policy, tee-proof-demo

Source review; nothing was built or run except the policy repo's Python validator and its tests (both pass, no network), plus read-only fetches of `verify.adverserial.ai` and the GitHub API on 2026-11-15. Pins: attestation-verifier `2ab27487` (2026-10-06), confidential-policy `26fb9a5d` (2026-10-17), tee-proof-demo `5226ef12` (2026-09-02). For the policy consumer, AdverserialAI/confidential-sdk `bdf24fda` was also read, but not in full.

Cells use part A's notation: **E** enforced, **C** checked, not enforced, **N** not checked, `[i]` inferred.

Path keys. `AV/` = attestation-verifier, `CP/` = confidential-policy, `SDK/` = confidential-sdk, `TP/` = tee-proof-demo.

## 1. crow-004/attestation-verifier: not an inference verifier

**Who Tachpawl is.** Tachpawl is a proprietary MPC signing system. Its `HSM_AUTHORITY` role runs as a networked threshold signer, `NetworkedThresholdSigner`, apparently on `cggmp21` [i] (`AV/README.md:12-17`, `AV/Cargo.toml:16`). The nodes it checks are `tee-service` and `authority-service`, which are closed source (`AV/README.md:337-352`). No public site turned up: web search and GitHub code search for "tachpawl" both return nothing. The repo owner, crow-004, describes himself as the creator of the Musical Chairs on-chain game. The repo was created 2026-09-29 and its only commit says "Sync from the main tachpawl repository". It verifies no inference service, so it has no matrix row.

It is a CLI that checks one TEE document against hex values passed on the command line.

| Path | hardware | recipient | code | freshness | fail-closed |
|---|---|---|---|---|---|
| Nitro | COSE_Sign1 + chain to the AWS root, delegated to Evervault's `attestation-doc-validation` (`AV/src/nitro.rs:167`; root and expiry handling are that crate's, not inspected here); debug = all-zero PCR0, E unless `--allow-debug` (`nitro.rs:206`, `main.rs:357`) | N: NSM `public_key` and `user_data` are always `None` (`nitro.rs:139-143`) | PCR0 and PCR8 only (`main.rs:175-176`); PCR1/PCR2 cannot be checked | nonce round trip E when live (`main.rs:367-374`); offline only with `--expect-nonce` | exit 1 on any FAIL |
| dstack/TDX | `dcap-qvl` 0.6 against Phala's PCCS by default (`dstack.rs:251-273`); TCB `UpToDate` E by default, `--allow-tcb-status` widens it (`main.rs:434`); debug bit E (`dstack.rs:300`) | N: REPORTDATA is a nonce or the constant `tachpawl-attestation-verifier-v1` (`main.rs:405`) | MRTD, MRCONFIGID and RTMR0-3 compared as raw values, only when passed; the event log is fetched but never read (`dstack.rs:234`, no use in `main.rs`), so the payload-swap bug class does not arise; no app-id or compose check | report_data round trip E when live (`main.rs:461-470`) | exit 1 |

No NVIDIA evidence, Sigstore or on-chain anchor. Measurements come from whatever Tachpawl publishes, since the production source is closed (`README.md:341-346`).

**Weakness.** "At least one `--expect-*`" (`main.rs:194`) is satisfied by `--expect-nonce` or `--expect-report-data` alone. Such a run checks only signature, TCB, debug and nonce, so any genuine non-debug enclave or TD passes. Third-party use means the operator relays a `--dump-raw` file (`README.md:107-147`). The tool has no network transport and no key binding, so a quote proves hardware state only. It says nothing about the channel to the node.

**"Reuses already-tested logic".** The logic was moved verbatim from Tachpawl's private `tee-adapter` crate (`AV/src/lib.rs:1-14`). The underlying checks are third-party: Evervault `attestation-doc-validation` 0.10.1 and Phala `dcap-qvl` 0.6.5, both from crates.io (`AV/Cargo.lock:851-853, 1643-1645`), plus `dstack-sdk`. The owner's account also holds forks of both crates; the lockfile does not use them. The README cites two unnamed external reviews (`README.md:151-158`) and `Lanetus/TTKServer#17` as prior art for the TDX debug bit (`dstack.rs:184-191`). It cites no teep, ACI, or NEAR/Phala verifier. The README publishes a reproducible-build hash for the verifier binary (`README.md:299-302`).

## 2. AdverserialAI/confidential-policy: a repo, not a log

**Who AdverserialAI is.** Adverserial AI LLC sells confidential inference of its own fine-tuned "cyber" models (`lordx64/cyberglm`; live: `adverserial/cyberseek`, "DeepSeek-V4.1-Flash with category-selective cyber abliteration"). Its site claims Intel TDX with NVIDIA H200/B300. The live policy's `measurement_approval` says the measurements are "corroborated against the authenticated Phala control plane", so it runs on Phala Cloud/dstack [i]. The serving code is `AdverserialAI/attest-proxy`. The policy repo's license is "source-available proprietary" (`CP/README.md:23-25`).

**Format.**
- **Runtime policy** (`CP/schema/runtime-policy.schema.json`): model id; allowed TEE and GPU types with a minimum GPU count; a `required_bindings` name list; digests for runtime image, model artifact and deployment config; TLS SPKI hash; receipt JWKs; source repo; status `template-not-production|active|retired`.
- **Release manifest:** tag, commit, image digests, a GitHub Actions run URL, `provenance: "github-attestation"` and an SPDX flag. `activation_missing` lists what is not done yet (`CP/releases/attest-proxy-v0.1.0-rc.28.json:34-42`).

**Signing.** Nothing in the repo is signed. `tools/validate_registry.py` checks shape only, in CI: regexes, required fields, and that an active policy points at an active manifest (`:85-145`). It checks no GitHub attestation and no signature. One spot check: the rc.28 attest-proxy image has 1 GitHub attestation via the API. The live policy says so itself: `"trust": {"policy_distribution": "https-origin", "detached_policy_signature": false}`.

**Where the active policy lives.** It is not in this repo.
- At HEAD every policy is a template. The README says the repo "deliberately contains no active policy" (`CP/README.md:5`).
- The repo mirrored an active policy on 2026-10-08 (commit `068a4810`) and demoted it on 2026-10-15 (`9de320e9`, "fail closed on unverified policy releases").
- The live `https://verify.adverserial.ai/policies/production.json` is `status: active`, `published_at: 2026-11-15T20:33:27Z`. It pins rc.29, plus MRTD, RTMR0-2, app_id, compose_hash and os_image_hash. Neither rc.29 nor these TDX pins are in the repo.
- The policy's `runtime_image_digest` (`sha256:c1633485…`) is not any image in the rc.29 manifest. It has no GitHub attestation under `AdverserialAI/attest-proxy` (404); other repos were not checked.
- The registry model (`lordx64/cyberglm`) differs from the live one (`adverserial/cyberseek`). The registered template asks for `minimum_gpu_count: 1` (`CP/policies/lordx64-cyberglm.json:13`), `production.json` asks for 8.

**Consumers.** All consumers found are the vendor's own code: confidential-sdk, plus adverserial-confidential-kit, which was not read.
- The TS SDK, the Python SDK and `adverserial-hardware-verify` fetch `production.json` from the origin with no cache. They require `status == "active"` and a matching model, then compare digests, SPKI and receipt keys (`SDK/python/adverserial/verify.py:231-251`, `SDK/typescript/src/verify.ts:256-260`, `SDK/typescript/src/runtime-policy.ts:14-33`).
- The fetch happens only when the endpoint is `api.adverserial.ai`. Otherwise the policy is optional (`verify.ts:256`).
- The digest, compose and proxy comparisons read `evidence.workload.*`, which is unmeasured JSON (`runtime-policy.ts:34-43`). The quote-bound pins are the `tdx` block.
- A separate hardware verifier is required in both SDKs (`verify.ts:321-330`, `verify.py:385-387`). It receives the `tdx` pins only when a policy was loaded.
- The SDK's bundled TDX verifier recomputes each RTMR3 event digest from its payload before reading app-id and compose-hash (`SDK/typescript/src/tdx-workload.ts:22-35`, called from `phala.ts:91`). The known bug class is absent there.
- Found by GitHub code search for `verify.adverserial.ai` and `template-not-production`; only AdverserialAI repos match.

**Against "publish everything that may run, accept after N hours, observatory watches".**
- It publishes one current policy, not the set of everything that may run.
- Distribution is mutable HTTPS from the operator's origin, with no signature.
- Clients adopt a new policy immediately: today's was published the same day.
- There is no inclusion proof, no delay and no monitor.
- Git history was the only append-only record, and the live policy left it on 2026-10-15.

What it gets right: it pins measurements as well as images, and clients refuse to dispatch without an active policy.

## 3. ethanolivertroy/tee-proof-demo: browser verifier behind a Cloudflare Worker

The demo serves a React app and a relay from one Worker. The relay forwards to three fixed origins (`TP/README.md:35-41`, `worker/index.ts:170-172, 389`), and each route serves one fixed model. Policies are compiled into `src/lib/policy.ts`. They were captured live and are updated by editing source and redeploying (`policy.ts:85-108`). The Phala code is adapted from `Dstack-TEE/private-ai-gateway` `clients/verifier-ts` at `898f19f3` (`TP/NOTICE`, `src/lib/phala-aci/index.ts:5-11`). The NEAR code comes from the author's earlier "Attested E2EE Chat".

| Route | hardware | recipient | reply | code | downstream | updates | fail-closed |
|---|---|---|---|---|---|---|---|
| NEAR direct (`dsv4-flash.completions.near.ai`, model host [i], not the cloud gateway) | `@phala/dcap-qvl` in a browser worker; TCB `UpToDate` E, debug E (`cpu-verifier-core.ts:72-80`); 8 Hopper NRAS JWTs: signature by NVIDIA JWKS fetched directly by the browser, nonce, secboot, dbgstat, measres, overall↔device digest binding, all E (`attestation.ts:72-119`) | E2EE v2 to the Ed25519 model key in REPORTDATA = key‖nonce, E (`cpu-verifier-core.ts:82-83`); reply key in the `x-client-pub-key` header, not covered by the quote or the signature: N | Ed25519 signature by the attested key over `model:sha256(req body):sha256(resp body)`, E before decryption (`api.ts:220-228, 264-266`) | MRTD, RTMR0-3 and os_image exact, E; app_compose hashed and checked against MRCONFIGID, E (`cpu-verifier-core.ts:20-57`); no event-log use; no Sigstore | n/a | static compiled profile; the exact RTMR3 pin fails closed on any redeploy or new instance [i] | no send before verification; 5-min local TTL (`api.ts:19, 44-49`) |
| Phala Cloud ACI/1 (`inference.phala.com`, private-ai-gateway) | gateway quote: TCB `UpToDate` E, debug E (`phala-verifier-core.ts:98-102`); GPU of the upstream: the session's `gpu_attested` claim is required, but its evidence is not appraised (`phala-completion.ts:81-83`) | E2EE v2 to the keyset X25519 key, with keyset digest → REPORTDATA → nonce E (`phala-verifier-core.ts:86-104`); KMS custody chain for the E2EE and receipt keys to a pinned root, E (`phala-dstack.ts:157-227`); TLS SPKI from the keyset (`:131-134`) | non-stream; receipt signature, request and response hashes, and one `required` verified upstream, all E before display (`api.ts:300-317`, `phala-completion.ts:101-134`) | RTMR3 replayed with digests recomputed from payloads (`phala-dstack.ts:52-57`); app-id, compose-hash, source repo and commit from the measured Compose E (`:199-213`); MRTD, RTMR0-3 and MRCONFIGID exact E | session content address, verifier id `phala-direct/v1`, TLS pin shape and "asserted" claims checked; the upstream evidence itself is not appraised (`phala-completion.ts:62-88`, `docs/THREAT_MODEL.md:59`) | static compiled profile | as above |

**What the relay can do.**
- **Evidence.** It cannot substitute evidence. Quotes, NRAS JWTs, NEAR signatures and Phala receipts are all checked in the browser against Intel, NVIDIA or pinned keys, and against a browser nonce. NRAS verdicts pass through the Worker (`attestation.ts:82`), but the JWKS comes direct (`:94`, CSP `public/_headers:2`).
- **Replies, both routes.** The relay can read them [i]. The client's reply key travels only in the `X-Client-Pub-Key` header: NEAR forwards it at `worker/index.ts:296`; on Phala it is set at `phala-aci/e2ee-channel.ts:96`, and the request AAD covers purpose, algo, model, field, nonce and ts, not the key (`phala-aci/e2ee.ts:25-33`). A relay that swaps in its own key gets the reply encrypted to it. The browser then rejects the reply because the signed or receipted response hash, or decryption, fails. So it detects the read but cannot prevent it. `docs/THREAT_MODEL.md:38` overclaims ("cannot read the prompt or completion").
- **Prompts.** These stay safe on both routes.
- **The code itself.** The Worker also serves the verifier code (`worker/index.ts:421`). Every browser check assumes the deployer and Cloudflare serve honest JS. That holds for the deployer's own use, but it is no assurance to anyone else.

**Against teep.**
- **NEAR direct.** The demo is stronger than teep on reply authenticity (signature E vs content N) and on RTMR pinning (E vs C). Both leave the reply key unbound (v2). The demo has no Sigstore.
- **Phala ACI.** The demo is stronger on delivery: the receipt is checked before display, with no streaming. It also pins the source commit in the measured compose. It is weaker on the upstream. teep pins `aci_session_ids` it has audited before sending (part A). The demo sends `aci_verified: true` (`api.ts:287`) and checks the cited session only after the completion. One fixed model per route, a demo.

## Matrix-ready cells

- **Tachpawl (Nitro / dstack):** out of scope: an MPC signer, not inference; the CLI pins operator-supplied PCR0/MRTD/RTMRs with no key binding, and `--expect-nonce` alone passes.
- **Adverserial (Phala TDX, own models):** live policy pins MRTD/RTMR0-2/compose; served unsigned over HTTPS, not in Git, adopted immediately; the bundled SDK verifier recomputes event digests.
- **tee-proof-demo, NEAR direct:** quote, TCB, 8-GPU NRAS and exact RTMRs E. Reply signature over the exact bytes E; reply key unbound (v2); the relay serves the verifier JS.
- **tee-proof-demo, Phala ACI:** quote, RTMR3 replay, measured source commit and KMS custody E. Receipt checked before display; the upstream session is audited only after sending.
