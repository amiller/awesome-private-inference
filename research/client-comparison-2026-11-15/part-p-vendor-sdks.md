# Client comparison, part P: vendor SDKs (Nillion nilAI, Secret AI / SecretVM, Maple / OpenSecret)

Source review only. No unit tests were run: each suite needs dependencies installed from the network (`uv`/pip for nilai-py and secretvm-verify, npm for the TS packages, cargo for Maple).

Pins (default branch, shallow clones):
- Nillion: nilai-py `e49b528` (2026-04-17), nilai-ts `c3fcd88` (2026-04-17), n8n-nodes-nilai `f5dac94` (2026-07-22), server nilAI `dc2e9b8` (2026-04-16).
- Secret: secretvm-verify `a5d0d7c` (2026-09-17; Python 0.12.0, Node 0.13.0), verifiers `3f55845` (2025-12-10), secretai-chatbot-2026 `e2da664` (2026-09-03; locks `secretvm-verify` 0.12.0, `package-lock.json:983-985`), antseed-verification `c7adc08` (2026-08-20).
- Maple: MaplePrivacyLabs/Maple `0944a86` (2026-11-15), sparse: `sdk/`, `proxy/`, `services/opensecret/`. Rust SDK `maple-sdk` 4.2.0; maple-proxy 0.5.0 builds against the in-tree SDK (`proxy/Cargo.toml:69`).

Cells use part A's codes: **E** enforced, **C** checked, not enforced, **N** not checked, `[i]` inferred, `[nr]` not read.

Path keys. Nillion: `AT` = n8n `nodes/NilAi/attestation.ts`, `ND` = n8n `nodes/NilAi/NilAi.node.ts`, `NS/` = nilAI `nilai-api/src/nilai_api/`. Secret: `SV/` = secretvm-verify `python/src/secretvm/verify/`, `SN/` = secretvm-verify `node/src/`, `CB` = chatbot `server.js`. Maple: `RS/` = `sdk/rust/src/`, `TS/` = `sdk/src/lib/`, `PX/` = `proxy/src/`, `OS/` = `services/opensecret/src/`.

## 1. Nillion nilAI

**What the server exposes.** nilAI runs as a docker-compose app (API, vLLM, attester) in a nilCC AMD SEV-SNP CVM with an NVIDIA CC GPU (`scripts/nilcc/README.md`). `GET /v1/attestation/report?nonce=` proxies `http://nilcc-attester/v2/report` (`NS/attestation/__init__.py:5`). The nonce is echoed in the JSON and never sent to the attester (`:8-20`), so it gives no freshness. The fields are swapped: `gpu_attestation` holds the SNP `report`, `cpu_attestation` holds the `gpu_token` (`:17-18`). `verifying_key` is filled in afterwards from app state (`NS/routers/private.py:95`). It is not in REPORT_DATA. The signing key is a secp256k1 key the API container generates or loads from `private_key.key` (`NS/crypto.py:7-48`), and it is also served unauthenticated at `/v1/public_key` (`NS/routers/public.py:11-16`). Non-stream chat and responses bodies are signed over the response JSON only (`NS/routers/endpoints/chat.py:405-408`, `responses.py:381-384`). Neither the request nor a nonce is covered. The stream branch (`chat.py:235-300`) signs nothing. Model backends register through Redis discovery (`packages/nilai-common/src/nilai_common/discovery.py:19-47`). Per the n8n node's comment, nilCC puts `0x00‖sha256(TLS SPKI)` in REPORT_DATA (`AT:125-131`). The `/nilcc/api/v2/report` route is served by nilCC, outside this repo (not found in nilAI).

**nilai-py / nilai-ts** verify no attestation; a grep for attest/quote/verify finds none in `src/`. Both fetch `/public_key` only as the NUC token audience. nilai-py fetches it with TLS verification disabled (`nilai_py/client.py:104`, also `nildb/__init__.py:77`); nilai-ts uses plain `fetch` (`src/client.ts:112`). The prompt goes over ordinary WebPKI TLS through the OpenAI client.

| Axis | n8n-nodes-nilai (`verifyAttestation` default on, `ND:142-149`) |
|---|---|
| What is attested | the nilCC CVM at `${baseUrl}/nilcc/api/v2/report` (`AT:163-167`); GPU N |
| Hardware chain | ARK→ASK→VCEK and report ECDSA-P384, computed with Node crypto (`AT:242-264`). The ARK is any self-signed cert in the KDS response (`AT:109-123`); no pinned AMD root, so trust rests on WebPKI to `kdsintf.amd.com`. CRL N |
| TCB / debug | VCEK TCB extensions must equal the reported TCB (`AT:96-104`); no minimum. Debug bit from raw report (`AT:189-190`). Both feed `attestation_verified` |
| Measurement | one pin: `0.3.0` → launch digest (`AT:10-12`). The lookup key `nilcc_version` comes from the unsigned JSON (`AT:175,268`). An unknown version gives `null`, and null passes (`AT:269,288`) |
| Freshness | N: no nonce sent; report cached nowhere but fetched once per execution (`ND:181-182`) |
| Recipient | N: REPORT_DATA is surfaced, not compared to the serving TLS key (`AT:270-273`); `checkReportDataBinding` exists only for tests (`AT:133-146`) |
| Reply | `verify` (default on, `ND:133-140`): secp256k1 signature over the body, checked against the key from `/v1/public_key` (`ND:215-223`). That key is not bound to the attestation. The signature doesn't cover the prompt or a nonce, so a signed reply can be replayed [i] |
| Fail-closed | **No.** The prompt is posted (`ND:198-205`) whatever `attestation_verified` says; the result and `tee_verified` are attached to the output (`ND:234-249`) |

## 2. Secret AI / SecretVM

**secretvm-verify `check_secret_vm`** (Python `SV/vm.py:215-463`; Node `SN/vm.ts:224-497` has the same required set). It is a library. It does not send prompts.

| Axis | secretvm-verify |
|---|---|
| What is attested | the SecretVM at host:29343 or :21434 (`SV/vm.py:20-25,169-188`): CPU quote `/cpu`, GPU `/gpu`, `/docker-compose`, `/info`. The model runs in that CVM on the attested GPU, so this is the host, not a gateway [i] |
| TDX quote | `dcap-qvl` with collateral from `pccs.scrtlabs.com` by default (`SV/tdx.py:23,149-174`); `dcap-qvl>=0.3` unpinned in Python, `0.3.9` in Node. TCB status recorded, not gated (`SV/tdx.py:225-229`); whether dcap-qvl rejects Revoked [nr]. Debug bit E (`:238`) |
| SEV-SNP | ARK SPKI pinned per product (`SV/amd.py:317,440`); CRL signature + revocation E; TCB ordering E, no floor (`:576,584-594`). Without `strict` (default off), a stale cached VCEK/chain/CRL is used when KDS fails (`:125-129`). `strict` reaches only this path |
| GPU | NRAS v4 (`SV/nvidia.py:14`); JWT ES384 against NVIDIA's JWKS fetched live, leaf `x5c[0]` key taken without chain check (`:46-58`); `x-nvidia-overall-att-result` E (`:186-187`); `exp`/`iss` N; `eat_nonce` recorded only (`:155`). The evidence nonce must equal REPORT_DATA[32:64] (`SV/vm.py:342-355`). **GPU is optional**: a VM with no `/gpu` passes unless `enforce_gpu` (default False, `:318-364,452-456`) |
| Code | MRTD+RTMR0-2 must match a row of the bundled `tdx.csv` (`SV/workload.py:189-197`). The registry includes `dev` rows; `env` is reported, not gated (`SV/vm.py:416-421`). On a miss it downloads the registry from GitHub `main` and overwrites the package copy (`SV/workload.py:317-322,558-590`): auto-adopt. SEV: launch digest recomputed from registry artifacts plus a cmdline carrying `docker_compose_hash`/`rootfs_hash`, same registry refresh on a miss (`SV/workload.py:616-756`) |
| Event log | **RTMR3 recomputed from payloads**: sha256(compose bytes), rootfs, app-id, optional docker-files hash, each as a dstack event digest (`SV/workload.py:102-164`). The compose is whatever the VM serves; any compose that replays is `authentic_match` (`:333-345`). No compose or app-id allowlist unless the caller compares `report.docker_compose` itself |
| Freshness | N: REPORT_DATA is `sha256(TLS SPKI)‖GPU nonce`, both VM-chosen; no client nonce |
| Recipient | TLS SPKI (or legacy full-cert hash) in REPORT_DATA[0:32] vs a separate TLS handshake to the same host:port, WebPKI enforced (`SV/vm.py:38-71,299-316`; `SN/url.ts:225`). Using that key for the prompt is left to the caller |
| Reply | N |
| Fail-closed | `valid=False` on any required check (`SV/vm.py:443-458`); the library never sends, so blocking is the caller's job |

**secretai-chatbot-2026** (Secret's reference chat app) never consults the verdict before sending.
- Process-wide `NODE_TLS_REJECT_UNAUTHORIZED=0` (`CB:2`). Chat goes to raw IPs such as `https://67.215.13.123:21434` (`CB:17-19`), or to any `serverUrl` in the request body (`CB:289-295`), with no SPKI pin (`CB:296-304`).
- Attestation runs against a different name, `attestHost` (`CB:130`), only to render a badge.
- The badge's `valid` counts a missing check as a pass (`CB:150-158`). When the verifier returns early (TLS-cert or `/cpu` fetch failure, `SN/vm.ts:299-315` at HEAD 0.13.0; the app locks 0.12.0, so [i]), every core check is undefined, so the badge says valid. Nothing after it in the handler (`CB:160-211`) overrides `valid`.

**scrtlabs/verifiers** is the proofofcloud.org backend, not an inference client. DCAP is delegated to `cloud-api.phala.network` (`src/verifiers.ts:7-24`). SEV is sent to `nilcc-verifier.nillion.network`, and any 2xx returns `success:true, proof_of_cloud:true` regardless of the body (`:30-60`). Nitro is unimplemented (`:67-71`).

**antseed-verification** holds only `antseed.json`: `{type: antseed-github-verification, peerId: dd80a361…, username: scrtlabs}`. It is a GitHub ownership proof for an AntSeed peer id. Nothing ties that peer to a SecretVM quote.

## 3. Maple / OpenSecret (AWS Nitro)

Both SDKs speak transport v2. One HTTPS request to `/v2/session` carries a 32-byte client challenge and an X25519 client key (`RS/transport_v2/client.rs:153-174`). The Nitro document must carry nonce = challenge, `user_data` = domain‖client key, and `public_key` = the server's X25519 key (`:361-374`; `TS/transportV2/client.ts:129-140`). Records are ChaCha20-Poly1305 under keys derived from the attested transcript (`RS/transport_v2/crypto.rs:336-357`). maple-proxy creates one shared client and attests once, lazily (`PX/proxy.rs:64-90,128-151`); the client re-handshakes when the 1 h session expires (`RS/transport_v2/client.rs:38,96-97`; `RS/client.rs:1069-1085`).

| Axis | Rust SDK + maple-proxy | TS SDK (`@mapleai/sdk`, `sdk/package.json:2`) |
|---|---|---|
| What is attested | OpenSecret's Nitro enclave (`enclave.trymaple.ai`, `PX/config.rs:35`), which decrypts the prompt | same |
| Nitro document | COSE_Sign1 signature; `cabundle[0]` must equal the embedded AWS root (`RS/attestation.rs:9,336-347`); chain issuer/signature E (`:375-420`); cert validity vs device clock (`:173,431-470`) | root from `assets/aws_root.der` (`TS/attestation.ts:6,204-233`); same checks [i] from `authenticateBytes` |
| Debug | all-zero PCR0 rejected (`RS/pcr.rs:176-179`) | via PCR0 trust [i] |
| Measurements | PCR0 only. Static list (`RS/pcr.rs:30-40`), else any PCR0 in the history at `raw.githubusercontent.com/MaplePrivacyLabs/Maple/master/services/opensecret/pcr{Prod,Dev}History.json` signed by OpenSecret's embedded P-384 key (`:17-28,184-205`). The signature covers only the PCR0 hex (`:258-262`); timestamp is unsigned and unused, so every PCR0 ever signed stays valid. One key signs both histories (`:22`), so prod vs dev rests on which URL is fetched. PCR1/2 N. A history fetch error skips to the next URL and ends in reject (`:193,203`) | same scheme (`TS/pcr.ts:24,188-215,253-266`); `remoteAttestation` defaults on, and history URLs can be overridden, signature still required |
| Reproducible build | Nix build documented (`services/opensecret/docs/nitro-deploy.md:325,397`); not checked by the client | same |
| Freshness | client challenge = document nonce, E | same |
| Recipient | E2EE to the attested X25519 key, bound to the client key in `user_data`, E | same |
| Reply | AEAD under attested session keys, E | same |
| Downstream | enclave → model host is the enclave's own job: in-process `tinfoil-rs` pinned at `f0fef79` (`services/opensecret/Cargo.toml:78`) [nr]; Maple's own `i0{1,2}.tfinf.maple.ai` with release digests pinned in code (`OS/maple_inference.rs:1-40,119-145`); a Continuum (Privatemode) proxy binary inside the image (`docs/local-linux-x86_64-proxy.md:1-7`). `OPENAI_API_BASE` defaults to `https://api.openai.com` when unset (`OS/main.rs:4219-4220`, `OS/proxy_config.rs:30-48`); the production value is not found in `main.rs` or `docs/` | same |
| Updates | auto-adopts any PCR0 OpenSecret signs | same |
| Fail-closed | E: verification failure → `AttestationRejected`, no request sent (`RS/transport_v2/client.rs:188-199`); the proxy returns the handshake error (`PX/proxy.rs:145-149`). Mock attestation only for exact `http://` loopback (`RS/transport_v2/client.rs:432-469`) | E; local-dev bypass only for exact HTTP loopback (`TS/transportV2/client.ts:124-127`) |

The legacy `TS/getAttestation.ts` (nonce + NaCl key exchange, session cached in storage) is not imported by `encryptedApi.ts`, which uses transport v2 only [i].

## Differences that matter most

- **Only Maple blocks.** It is the only vendor client here that binds the prompt key to the attestation, uses a client nonce, authenticates the reply and refuses on failure. Nillion's n8n node and Secret's chatbot send the prompt whatever the result. nilai-py and nilai-ts check nothing.
- **Maple stops at its gateway.** The client attests the Nitro enclave that decrypts the prompt. The GPU host is attested by that enclave, through code the client trusts only as far as OpenSecret's PCR0 signing key. Every PCR0 ever signed stays accepted.
- **Secret recomputes RTMR3 from payloads.** It is the only one of the three with a dstack-style event log, and it replays the compose, rootfs and app-id from their bytes. It pins none of them. It accepts dev images, auto-downloads the registry, treats the GPU as optional, and has no client nonce.
- **Nillion's measurement pin is keyed by a field the server controls.** An unknown `nilcc_version` makes the comparison null, and null passes. The response-signing key is served separately and is not in the report. The attestation endpoint ignores its nonce.
- **Reuse.** secretvm-verify uses dcap-qvl and cites dstack's event digest. The n8n node ports Nillion's `attestation-verification` crate (`AT:149-156`). Maple embeds a fork of tinfoil-rs and the Privatemode proxy. A grep of these clones (Maple: sparse paths only) finds no mention of teep or private-ai-gateway.

Not reviewed: `tinfoil-rs` internals; nilCC's attester and `nilcc-verifier`; Secret's Python `secret-ai-sdk`; `secretvm-verify` `agent.py` (ERC-8004) and `proof_of_cloud.py`; Maple apps (`apps/`), the enclave entrypoint and the EIF build.
