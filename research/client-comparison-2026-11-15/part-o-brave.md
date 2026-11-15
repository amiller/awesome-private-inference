# Client comparison, part O: Brave Leo on NEAR AI Cloud

Source review only; nothing was run. Pins:
- brave-core `94668fc8` (master, 2026-11-15), sparse checkout of `components/ai_chat`. UI strings: `components/resources/ai_chat_ui_strings.grdp` at master the same day.
- brave/ai-gateway `087f9306` (2026-11-13). This is Brave's Leo server, the OHTTP relay.
- brave/near-verifier `72a1a994` (master, 2026-10-28). This is the offline verifier.
- nearai/cloud-api `b26eb029` (OHTTP gateway only).
- dcap-qvl: the verifier's `poetry.lock` locks Python package 0.3.13. Rust source was read at tag `v0.3.12`.

Cells use part A's codes: **E** enforced, **C** checked, not enforced, **N** not checked, `[i]` inferred, `[nr]` not read, `[blog]` taken from a blog post and not confirmed in code. Path keys:
- `BC/` = brave-core `components/ai_chat/core/browser/`
- `AG/` = ai-gateway `aichat/serve/`
- `NV/` = near-verifier
- `CA/` = cloud-api `crates/api/src/`

Blog posts: "Verifiable Privacy and Transparency" (brave.com/blog/browser-ai-tee, 2025-11-20) and "Leo adds End-to-end Encryption, Oblivious HTTP, and Verifiable Confidential Computing" (brave.com/blog/browser-ai-e2ee, 2026-10-15). NEAR's post, "NEAR AI Cloud Brings Private Inference to Brave Leo" (near.ai/blog, 2026-10-15), says "Before Leo's browser receives the enclave's key" Brave's verifier checks the TDX quote and the GPUs: "No pass, no key." It says prompts decrypt "only inside" the enclave [blog]. It does not mention a gateway separate from the model, web search, or a roadmap. `.md` refs are the projects' own docs at the pin, not source I read; `NV/` rows citing `README.md` rest on those docs.

## Who verifies

**Brave's servers verify, and the browser trusts Brave.** No browser code verifies any quote. A grep of `components/ai_chat` for `quote|dcap|mrtd|rtmr|nras|attest` finds only the verdict struct (`core/common/mojom/common.mojom:609-611,672-673`) and unrelated `Capabilities` hits. The browser issue says so: "Client-side attestation/Intel SGX quote verification is currently out of scope" (brave-browser #55247). The 2026-10 post says the same: "Today, your browser relies on the gateway for this check" [blog].

Verification happens in two stages:
1. **near-verifier** (`NV/`) runs on a schedule in Brave's AWS CodeBuild (`NV/README.md:206`; the schedule is not in the repo). It does the full appraisal against a fresh nonce. Only when every check passes does it write approval markers to S3: image digests, signing keys, serving composes and serving-log heads (`NV/README.md:281-283,344-355`).
2. **ai-gateway relay** (`AG/services/near.py`) runs before it hands out a key config and before it relays each message. It does no quote verification of its own. It checks the live attestation JSON against those S3 markers and caches a pass in Redis for 1 h (`near.py:112-113,418-445`).

## Data path

1. The browser fetches `GET /v1/models/{m}/ohttp_config` from Brave's server (`BC/engine/oblivious_http_config_manager.cc:30,181-189`). It keeps `key_config`, `endpoint_url` and `upstream_model_name`, and caches them for 3 days (`:31,105-138`). The server also sends `signing_key` and `signature` (`AG/services/near.py:84-89`), and the browser **ignores both** (`config_manager.cc:105-108`).
2. The browser OHTTP-encapsulates the OpenAI-format request to that key. It POSTs to Brave's relay with its Leo SKU credential in outer headers (`BC/engine/oblivious_http_api_client.cc:297-320`).
3. The relay re-runs `verify_and_get_ohttp_config` and returns 500 on failure (`AG/ohttp.py:85-86`). Otherwise it forwards the ciphertext to `https://<cloud-api>/ohttp` with Brave's NEAR API key (`:93-107`). It uses httpx's default TLS, with no SPKI pin.
4. cloud-api, in NEAR's gateway CVM, decapsulates the request and replays it over loopback to its own `/v1/chat/completions` (`CA/routes/ohttp.rs:109-110,364-369`). **The prompt is in plaintext inside NEAR's attested cloud-api CVM.** The forward to the model CVM uses cloud-api's normal path [nr]. The browser sends no NEAR E2EE (`X-Encryption-Version`) headers, so the model-key E2EE that teep's nearcloud route uses is not involved.
5. cloud-api derives the HPKE key from its Ed25519 signing-key seed, which comes from dstack KMS. The key is shared by every cloud-api instance (`CA/ohttp_gateway.rs:9-26`). It stays fixed while the KMS seed does [i].

Brave sees the user's IP, the credential and the model name, but not the content, **provided the key config it serves is honest**.

## Matrix

| Axis | Brave Leo (browser + Brave relay + near-verifier) |
|---|---|
| Hardware chain | Browser N. Verifier: dcap-qvl `get_collateral_and_verify` against Intel PCS, E (`NV/verifier/verifications/tdx.py:216-218`). The relay checks no quote live; it relies on S3 markers. |
| TCB / debug | Verifier E. Accepts `UpToDate` and `SWHardeningNeeded`, and `OutOfDate` only when every advisory is one of INTEL-SA-01192/01245/01312/01313 (`tdx.py:34-46`, `NV/verifier/config.py:49-51`). Debug: dcap-qvl rejects a TD whose debug bit is set (`dcap-qvl v0.3.12 src/verify.rs:670-671,691-697`); near-verifier has no check of its own. |
| GPU | Verifier E. NRAS JWT checked against NVIDIA's JWKS with asymmetric algorithms only and `exp` required (`NV/verifier/verifications/gpu.py:21-50`). The nonce is read from the signed claim (`:54-75`). The GPU evidence is not bound into the TDX quote, which the README admits (`NV/README.md:58`). |
| Measurements | Verifier E. MRTD/RTMR0-2 must be one of the tuples in `EXPECTED_OS_MEASUREMENTS` (`config.py:253`, `tdx.py:134-141`). MR_CONFIG_ID must equal `0x01‖sha256(app_compose)` (`tdx.py:110`). No RTMR3 event-log replay; RTMR3 is used only for the same-CVM check. |
| Code | Verifier E, for both gateway and inference CVMs. Each NEAR image's SLSA provenance is checked through cosign, and the image is **reproducibly rebuilt** from a pinned commit (`NV/README.md:295-301,323-325`). Third-party runtimes such as vLLM/SGLang are not checked. compose-manager-launcher gets provenance only, with no rebuild (`config.py:235`). |
| compose-manager log | Verifier E. The canonical actions hash is recomputed and compared to `report_data[0:32]`, with a nonce in `[32:64]` (`NV/verifier/verifications/compose_manager.py:566-606`). It checks that the log and the proxy come from the same CVM. Every logged file is fetched at its commit and its sha256 checked (`:628-650`), and the log is replayed. Weights must be in `APPROVED_MODEL_WEIGHTS` (`config.py:154`). Minimum tag age: not found. The relay recomputes the log chain from live JSON and looks for a `serving-log` marker, but only when `verify_near_compose_sequence` is set (`AG/services/near.py:303-307`). That setting **defaults to False** (`AG/external_service_settings.py:9`); the production value was not found. |
| Recipient | Browser: OHTTP (RFC 9458) to whatever key Brave serves, N. Relay: the key config must carry a valid Ed25519 signature (`near.py:229-245`). The signing key must be the gateway's or model's `signing_address` (`:258-261`) and must have an S3 `signing-keys/` marker (`:287-291`). The verifier writes that marker only when the key is bound in a verified quote: for the gateway, report_data = `sha256(addr‖tls_fp)‖nonce` (`tdx.py:149-205`, `NV/README.md:340-342`). The recipient is the NEAR **gateway** (cloud-api), not the model instances. |
| Freshness | Verifier: fresh nonce per run (`NV/verifier/main.py:385-403`). Relay: **no nonce** (`near.py:379`), so a pass depends on markers that live up to 120 days in S3 (`NV/README.md:348`). The relay caches a pass for 1 h and the browser caches the key for 3 days. |
| Reply | The OHTTP response is AEAD-sealed under the request's HPKE context, so a relay can't forge it if the key is honest [i]. There is no receipt. |
| Updates | Pins are in `NV/verifier/config.py`. `make review-pins` diffs live attestations against the pins, offers an optional Claude "privacy scan", and opens a PR that a human approves (`NV/README.md:231-262`). Nothing is on-chain, and NEAR's Base authorization is not used (not found). |
| Fail-closed | At the relay, E: verification failure means no key config and no relay (`AG/ohttp.py:54-56,85-86`). The browser has no check to fail. |
| UI | A green "Verified" label with the NEAR logo (`resources/page/components/near_label/near_label.tsx:21-38`, grdp `IDS_AI_CHAT_VERIFIED_LABEL`). The browser sets it to `true` for **every** 2xx OHTTP reply and every chunk (`BC/engine/oblivious_http_api_client.cc:389-392,429-438`). It means only that Brave's relay passed this model within the last hour. The model subtitle reads "Verifiably Private With NEAR AI TEE". |

## Second path: Conversation API with a header verdict

`BC/engine/conversation_api_client.cc:479-484` sets the per-turn verdict from a server header, `brave-near-verified: true`. The server computes that header **after** `backend.converse` has already sent the plaintext prompt to NEAR through litellm, using Brave's key (`AG/open_ai_api.py:375-380,407-410`). So this path fails open, and Brave's server holds the plaintext. It would serve a remote-config model with `is_near_model` set [i]: `remote_models_serialization.cc:180` reads that field but not `supports_private_inference`, and only `supports_private_inference` routes a model to OHTTP (`BC/model_service.cc:1238-1243`). The built-in NEAR model, "GLM 5.3 Flash" (`near-glm-5-1`), sets `supports_private_inference` (`model_service.cc:442-466`), so it goes through OHTTP. NEAR models are behind `AIChatNEARModels`, disabled by default and enabled by variations (`components/ai_chat/core/common/features.cc:173-175`).

## Weaknesses

1. **The browser trusts Brave for the key.** It discards the signature and signing key (`config_manager.cc:105-108`), so a compromised or compelled Brave server could serve its own HPKE key and read prompts. The badge would still show (`oblivious_http_api_client.cc:391`). This is the main gap; Brave's roadmap says it will fix it [blog].
2. **The relay checks against S3, not live hardware.** There is no nonce and no live quote. The live `gateway_app_compose`, `compose_actions` and `model_name` it reads are not bound to any quote it verifies. Only the signing-key marker ties the OHTTP key to a verified quote. Whoever can write to the bucket can approve keys, which the README admits (`NV/README.md:50`).
3. **The prompt is plaintext in NEAR's gateway CVM, not only the model CVM.** The cloud-api→model hop was not reviewed here.
4. **The serving-compose check is off by default** (`verify_near_compose_sequence=False`). If it is off in production, the relay doesn't notice weight changes between verifier runs.
5. **Web search leaves the TEE.** For streaming requests the browser always adds a `web_context_search` tool (`BC/engine/oblivious_http_api_client.cc:228-235`; `kAIChatSSE` defaults to true, `core/common/features.cc:34`). cloud-api runs that tool server-side against Brave's LLM Context search (`cloud-api crates/services/src/responses/tools/web_context_search.rs:1-3`). Its result comes back as `nearai_tool_result` (`oblivious_http_api_client.cc:408-431`). So model-written queries derived from the prompt leave the enclave for Brave Search. The credential used and the logging policy were not traced.
6. Known limits the verifier itself documents: GPU evidence not bound to the quote, compose-manager-launcher not rebuilt, runtime images unverified, and env values missing from the actions log (`NV/README.md:41-60`).

## vs teep (nearcloud)

teep verifies per request on the user's machine, encrypts to every attested model instance's key, and refuses to send otherwise. Brave's browser verifies nothing. Brave's server-side chain is deeper than teep's on NEAR. It does steps 1-3 of the NEAR chain, and half of step 4: files must be public at their commit, but no archive or minimum age is checked. Its checks include reproducible rebuilds, compose-manager log recomputed and replayed, weights pinned, same-CVM check. The OHTTP reply is authenticated, which NEAR's E2EE replies are not. But the user can't check any of it, and the recipient is NEAR's gateway, not the model. Grade: **partial**. The verification is strong but run by Brave's server, so the browser user has to trust Brave.

Matrix cell: `partial` — "Brave's server verifies (reproducible builds, compose-manager log, pinned OS); the browser verifies nothing and encrypts with OHTTP to whatever gateway key Brave serves." `event_log_hashed: true` (verifier recomputes the actions-log hash; the compose is bound by MR_CONFIG_ID). `fails_closed: true` (the relay refuses).
