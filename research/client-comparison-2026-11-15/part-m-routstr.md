# Client comparison, part M: Routstr (Tinfoil EHBP, TLSNotary, confidential mode v3)

Source review only. No unit tests were run: routstr-core needs a `uv` environment and the SDK needs `node_modules`, and installing either needs the network. The Tinfoil JS packages were read from tarballs fetched with `npm pack --ignore-scripts`.

Pins (main unless noted):
- routstr-core `aafe361` (2026-11-14). Branches `feat/tlsn-verified-mode` `93a08f4`, `fix/venice-tee-metadata` `52ba4e7` (PR #807, open). Fork PR #855 `410e6b4` (open).
- routstr-sdk `f847f91` (v0.5.1). Branches `feat/tlsn-verifier` `d5543a5`, `feat/venice-only` `d0f03bb` (PR #16, open), `fix/e2ee-attest-before-spend-v2` `a2a99ad` (PR #14, open). Fork PR #112 `f4a0257` (open).
- routstrd `52e1115` (pins `@routstr/sdk` 0.5.1, `package.json:51`). PR #132 `03a6ee8` (open); fork PR #155 `f7d4543` (open).
- proverd `b3e69cf`.
- jooray/routstr-confidential `430604a`.
- npm, as locked in the SDK's `pnpm-lock.yaml`: `tinfoil` 1.2.1, `@tinfoilsh/verifier` 1.2.1, `ehbp` 0.3.2.

No branch named `confidential*` exists in the Routstr org. The confidential work is on jooray forks, as PRs core #855, sdk #112 and routstrd #155, all open and last updated 2026-11-13.

Cells use part A's codes: **E** enforced, **C** checked, not enforced, **N** not checked, `[i]` inferred, `[nr]` dependency internals not read. Path keys:
- `TS` = sdk `client/TinfoilSecure.ts`, `RC` = sdk `client/RoutstrClient.ts`
- `TV/` = `@tinfoilsh/verifier@1.2.1/dist/`, `TJ/` = `tinfoil@1.2.1/dist/`
- `EH` = core `routstr/upstream/ehbp.py`, `TF` = core `routstr/upstream/tinfoil.py`
- `CF/` = routstr-confidential

## 1. Tinfoil (main, shipped)

**Who verifies.** The client does: `@routstr/sdk` and routstrd through it (`routeRequests` → `RoutstrClient`, routstrd `src/daemon/http/index.ts:2679`). The node verifies nothing. It is a blind relay for requests that carry `Ehbp-Encapsulated-Key` (`proxy.py:748`, `TF:162-171`). The node routes those only to `supports_ehbp` upstreams (`proxy.py:945-955`), and Tinfoil is the only one: PPQ's enclave is off (`ppqai.py:146-149`). The node also proxies `GET /attestation` to `atc.tinfoil.sh` (`TF:290-339`; this is what `tests/unit/test_proxy_tinfoil_attestation_routing.py` covers). The SDK doesn't use that route: it leaves `attestationBundleURL` unset and fetches from ATC directly (`TS:118-120`, `TJ/atc.js:16`).

**Trigger.** The client's own model id must start with `tinfoil-` (`TS:57,64`). Then `RC:1031-1039` attests before any token is spent, and failover attests the next node too (`RC:2733`). For a model without that prefix the request is plain JSON to the node. A node-side rule refusing a plaintext request to Tinfoil: not found. The node presumably forwards it with its own key through the inherited `forward_request` [i].

| Axis | Routstr SDK (tinfoil JS 1.2.1) |
|---|---|
| Hardware chain | SEV-SNP report and VCEK chain E (`TV/attestation.js:75-82`); roots/CRL [nr] |
| TCB / debug | E against a hard-coded floor: snp 0x0E, ucode 0x48, bl 0x7, build ≥21 (`TV/sev/validation.js:22-36`). The floor is the same as tinfoil-go's and below AMD's bulletin (part B §3). Debug E (`:71-72`) |
| Freshness | **N.** The bundle comes pre-built from ATC (`TJ/secure-client.js:181-188`). REPORT_DATA is `tls_fp‖hpke_key` with no client nonce (`TV/attestation.js:39-41`). A grep of both packages finds no freshness witness. The SDK caches the attested client for the life of the process (`TS:61,136-162`) and re-attests only on an EHBP key-config 422 (`TS:368-377`) |
| Code | Sigstore bundle for `tinfoilsh/confidential-model-router` (`TJ/config.js:12`), any `refs/tags/*` release (`TV/sigstore.js:52`); digest = measurement E (`TV/client.js:53-66`). **Router only**: the model enclave and the weights are N |
| Recipient | E: request body HPKE-sealed to the `hpkePublicKey` from REPORT_DATA (`TS:297-310`). The request may go only to the node's or the router's origin (`TS:263-267`). The node may forward it only to `https://*.tinfoil.sh` (`EH:348-381`), so wrong routing fails decryption and is not a leak |
| Channel to node | ordinary TLS to the node's URL. The SPKI pin doesn't apply because the node is not the enclave. EHBP does not seal headers, so `X-Routstr-Model`, the Cashu token and the usage header are visible to the node |
| Reply | **N for authenticity.** A response without `Ehbp-Response-Nonce` is returned as is, whatever its status (`TS:323-325`). The stock `ehbp` client throws on a 2xx without the nonce (`ehbp@0.3.2 esm/client.js:92-100`). The node therefore never sees the prompt, but it can return a fabricated plaintext 200. Billing comes from the unsealed `X-Tinfoil-Usage-Metrics` header (`TF:166-170`), which the node relays and could alter [i] |
| Downstream router→model | N (as every Tinfoil client) |
| Updates | auto-adopts any router release Tinfoil tags; `tinfoil` is a caret range (`^1.2.1`, sdk `package.json:79`), but the lockfile pins 1.2.1 |
| Fail-closed | E for the send: if `prepareTinfoilClient` throws, the request aborts before the spend (`RC:1039`), and there is no plaintext fallback for a `tinfoil-` id. For the reply, see the Reply row |

Can the client check it without trusting the node? Yes, for confidentiality: the attestation comes from ATC, the key is bound in REPORT_DATA, and the node only relays ciphertext. The reply's integrity still rests on the node.

## 2. Other TEE upstreams

- **Venice.** On main the node sees plaintext: `venice.py` has no TEE or E2EE code (it only drops Venice's encrypted-reasoning item, `:65-104`). The SDK's Venice E2EE was removed from main in `2eb14ab` (2026-06-24, "remove Venice E2EE, keep Tinfoil EHBP only").
  - Open PR #16 (`feat/venice-only`) adds it back. The client fetches `/tee/attestation?model&nonce` **from the node** and accepts the key when the JSON says `verified === true` and echoes the nonce (`client/VeniceE2EE.ts:128-161` at `d0f03bb`). It parses no quote, so the node can supply its own key.
  - Open core PR #807 (`fix/venice-tee-metadata`) has the node proxy Venice's `tee/attestation` and `tee/signature` routes per model (`tests/unit/test_proxy_venice_attestation.py:15`). The node relays the evidence but doesn't verify it [i].
  - Open routstrd PR #132 (`feat/venice-e2ee-transport` `03a6ee8`) adds a smoke test whose `--trust-server-attestation` flag "does not independently verify hardware quotes, workload measurements or response signatures" (`scripts/smoke/venice-e2ee.md:16`).
  - Open sdk PR #86 preserves the Venice encryption headers; its diff was not read.
- **NEAR, Phala/RedPill, Chutes, NanoGPT, Privatemode:** no attestation code found. Chutes appears only as a litellm host prefix (`litellm_routing.py:68`).
- **Node identity.** The client gets nodes from Nostr kind 38421 announcements. It checks event signatures (`discovery/ModelManager.ts:798`) and gates nodes on kind-38425 reviews from Routstr's key (`:65-76,170`). There is no attestation of the node.

## 3. proverd / TLSNotary (branches only; no PRs)

**What is proven, and to whom.** The node runs `proverd` as the TLSN prover in **proxy-TLS** mode; the client is both verifier and notary.
- The client dials the upstream itself and relays ciphertext (`src/testverifier.rs:125-142`). It sets Mozilla roots for the server certificate check (`:104-108`; the check runs inside vendored tlsn alpha.16 [nr]) and requires the server identity to be revealed (`:159-165`).
- The prover then proves in ZK the plaintext of the transcript, with the `authorization` value redacted (`docs/TLSN-routstr.md:326-347`).
- The SDK compares the proven request (method, path, `messages` and `tools` deep-equal, model under the declared mapping) and the proven response (byte-equal, or the same SSE event sequence) with what it got from the node (sdk `client/tlsn/TlsnVerifier.ts:137-161` at `d5543a5`).
- Result: an upstream with a valid cert for host H returned exactly these bytes, and the node didn't edit or fabricate them. The proof convinces only this client and is not transferable (`TLSN-routstr.md:164-180`).

**Not proven.**
- Confidentiality: the node is the prover and sees everything.
- Which weights ran: a stated non-goal (`TLSN-routstr.md:50-52`).
- That H is the right host. The allowlist is "node-advertised" (`TlsnVerifier.ts:44-46`), and an empty list accepts any host (`client/tlsn/backends/native.ts:119-121`).
- Soundness assumes the node can't sit on the network path between the client and H [i].

**In the request path?** Only as a post-hoc label. A mismatch returns `{status:"mismatch"}` after the stream has been delivered (`TlsnVerifier.ts:150-157`, `TLSN-routstr.md:471-476`), and the client opts in per request with `verify:"tlsn"`.

**Status.** Core `feat/tlsn-verified-mode` and sdk `feat/tlsn-verifier` exist. The routstrd branch `feat/tlsn-verify` named in the proverd README (`README.md:34-42`) was not found in Routstr/routstrd. The README says no PRs exist (`:44-45`); a `gh` search agrees.

## 4. routstr-confidential (protocol v3; open fork PRs)

**Threat model.**
- **Client (C):** the TLS 1.3 client of the provider (U), connected through the node (N). C and N run a 2PC of the handshake key schedule. C gets `c_hs`, `s_hs`, `s_ap_0` and `c_ap_1`; N gets only `K_0`/`IV_0`, the epoch-0 write key that seals the record carrying its API key (`CF/PROTOCOL-V3.md:157-163`).
- **Node:** sees ciphertext and metadata: provider, model, timing, body length, chunk sizes, and which requests share a connection (`CF/docs/ONE-PAGER.md:49-53`). It can't read or change the prompt or the reply. It can write extra epoch-0 records, such as another account or a retention header, which change how U handles the request (`ONE-PAGER.md:36-38`; `PROTOCOL-V3.md:771`, risk 7). A cheating node can learn up to 3 bits per connection (`ONE-PAGER.md:78-79`).
- **Provider:** sees the full plaintext and the node's IP, and can link requests on one HTTP/2 connection (`README.md:23`, `ONE-PAGER.md:75-76`).
- **Hardware:** none trusted. TEE is a stated non-goal (`PROTOCOL-V3-DRAFT.md:308`).

**What the client verifies about the provider.**
- **TLS:** the cert chain, hostname and CertificateVerify, verified by C's own TLS stack: `verifyServerCertificate: true` (sdk PR #112 `client/confidential/connection.ts:1380`, `tls-fork/lib/make-tls-client.js:271-272`). The host must be on the user's `trustedHosts`, and the client refuses when the list is missing (`client/confidential/offer.ts:750-761`). The node's request route is pinned to the API base the user trusts (`:764-767`).
- **Reply:** E, because only C and U hold the application keys [i from the key split].
- **Model and `max_tokens`:** pinned by a suffix that C writes, and C proves it to N (π_WIN) so the node can price the request (`ONE-PAGER.md:40-47`). Against the provider, this is the provider's word, not a check.
- **Billing:** the provider's usage event, which C proves to N (π_C3S) and checks against N's signed receipt.

**What it does not protect.**
- The provider sees the plaintext.
- No attestation of what the provider runs.
- Only Venice has been tested (`README.md:23`).
- No external review of π_WIN, the HTTP/2 rules or the key schedule (`README.md:23`).

**Composability with TEE upstreams.** The paper claims it composes: C could verify a provider's attestation-bound TLS or E2EE key through N (`paper/paper.md:1850-1854`). It isn't implemented:
- The Venice offer's `head_template` is a fixed `POST /api/v1/chat/completions` with no `X-Venice-TEE-*` headers (`crypto/relay/offer.venice.json:7`), and C's header blocks are pinned in full (`PROTOCOL-V3.md:529`).
- No code in the repo fetches or verifies an attestation.
- Tinfoil EHBP would already hide the body from the node without it.

**Status.**
- Open fork PRs: core #855, sdk #112, routstrd #155.
- The node side is inert unless `CONFIDENTIAL_SIDECAR_URL` is set (core PR #855 `routstr/confidential.py:58`).
- The README says one node (routstr.cypherpunk.today) has run v3 since 2026-11-12 (`README.md:53-54`).

## 5. Fail-closed defaults (client)

| Path | Default |
|---|---|
| Tinfoil `tinfoil-*` | attestation failure aborts before the spend, E (`RC:1039`). A plaintext reply, 200 included, is accepted (`TS:323-325`) |
| Tinfoil, model without the prefix | no EHBP; the node reads the prompt |
| Venice (main) | no E2EE; the node reads the prompt |
| Venice E2EE (PR #16) | throws on `verified!==true` or a nonce mismatch, but the evidence comes from the node |
| TLSN (branch) | opt-in, post-hoc label; the stream is delivered before the verdict |
| Confidential v3 (PR) | opt-in per request through a header that routstrd parses (routstrd PR #155 `src/daemon/http/index.ts:2604`). It refuses non-chat/image endpoints before spending (sdk PR #112 `RC:1049-1055`), fails over only to nodes that advertise confidential sessions (`:2324-2330`), and refuses an offer without trusted hosts (`offer.ts:750-752`) |

## Versus teep

- **Tinfoil.** Both encrypt to the router's attested HPKE key, both appraise only the router, and both auto-adopt router releases. Routstr differs from teep (part A, `tinfoil_v3_cloud` row) in four ways:
  - an extra hop, the node;
  - no TLS SPKI pin, because the client's TLS ends at the node;
  - the attestation is cached for the life of the process;
  - plaintext replies pass through, so the node can forge the reply, although the prompt stays sealed.

  Against tinfoil-go (part B §3), it also lacks the client nonce and the ≤7-day freshness witness. The TCB floor is the same 0x0E.
- **Venice.** teep enforces dstack E2EE to a REPORTDATA-bound key. Routstr main has no Venice privacy at all. The open PRs trust a `verified` flag relayed by the node. Confidential v3 hides the prompt from the node, not from Venice, and doesn't attest Venice.
