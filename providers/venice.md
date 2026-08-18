# Venice

## Claim

Venice ([venice.ai](https://venice.ai)) offers "private by default" inference: models
marked `e2ee-*` route through TDX-attested backends, and the attestation bundle is exposed
at an (undocumented) `GET /api/v1/tee/attestation` endpoint.

## Verdict (revised 2026-08-10)

Two answers, because two different things are being asked about.

- **Client side — Stage 1 if you use a verifying proxy.** Third-party clients now do the
  full attestation chain and refuse to send when it fails. This closes the TOFU gap that
  earlier versions of this page flagged as Venice's headline problem.
- **Infrastructure — Stage 0.** Two defects on the prompt path are unresolved: the enclave
  may carry an operator root-SSH key that attestation cannot rule in or out, and the GPU
  node that ends up holding your plaintext runs software nobody has measured.

Both infrastructure defects are the same classes this registry already tracks as
`prod_os_image` and `serving_code_attested` (found on Chutes). **This
page did not apply either of them to Venice until 2026-08-10**, because Venice's required
layer set in `verifiers/common.py` excluded them — see [Scoring correction](#scoring-correction).

## Endpoint surface

- **Chat:** `https://api.venice.ai/api/v1/chat/completions`
- **Attestation:** `https://api.venice.ai/api/v1/tee/attestation?model=<id>&nonce=<hex>` — undocumented but functional
- **Models:** `https://api.venice.ai/api/v1/models`
- **Auth:** Bearer API key (also usable as sign-in for chat UI).

## Model naming conventions

- **`e2ee-<name>-p`** — Phala enclave (`tee_provider: "phala"`).
- **`e2ee-<name>`** (no suffix) — NEAR AI backend.

Non-`e2ee-*` models on Venice are *not* TEE-attested — treat them as any regular API.

## Wire protocol

> **Partly superseded.** The ECIES description below was confirmed 2026-04-24 and still
> describes the `/tee/attestation` path this repo probes. It is no longer the whole
> picture: the same enclave also answers a native **ACI** protocol whose quote commits to
> `sha256(JCS({purpose, workload_id, workload_keyset_digest, nonce}))`. That matters — it
> is what lets a client bind the workload keyset to a DCAP-verified quote instead of
> pinning it on first use. This repo's verifier does not speak ACI and so does not see it.

The E2EE wire is **ECIES on SECP256K1** (ECDH → HKDF-SHA256 → AES-GCM), identical to
NEAR AI upstream, differing only in header names: `X-Venice-TEE-Signing-Algo: ecdsa`,
`X-Venice-TEE-Client-Pub-Key` (uncompressed 04-prefix, 130-hex), `X-Venice-TEE-Model-Pub-Key`.
Live roundtrip against `e2ee-venice-uncensored-24b-p` confirmed the gateway is
transparent — ciphertext flows through and decrypts inside the enclave; Venice does
not see plaintext on the ECIES path.

Note the scope of that last sentence: it holds **on the ECIES path**. Venice's default
API path is not end-to-end encrypted, and `supportsE2EE` does not reliably indicate a
usable path (see gaps below). "Venice cannot read your prompts" is a statement about
clients that encrypt, not about Venice users generally — the same shape as Chutes, where
the E2E path is opt-in and the default handles plaintext at the control plane.

## Client implementations

Not Venice's software. Independent third-party work, and the reason the client-side
verdict moved.

| Project | What it is |
|---|---|
| [`elkimek/venice-e2ee`](https://github.com/elkimek/venice-e2ee) | The underlying library both proxies build on. |
| [`jooray/venice-e2ee-proxy`](https://github.com/jooray/venice-e2ee-proxy) | Local OpenAI-compatible proxy by Juraj Bednár. Adds the quote-bound receipt anchor, upstreamed as [venice-e2ee#13](https://github.com/elkimek/venice-e2ee/pull/13). |
| [`AxLabs/venice-e2ee-proxy`](https://github.com/AxLabs/venice-e2ee-proxy) | A second, more packaged proxy over the same protocol. |

What the jooray proxy checks before sending anything, per its
[security audit](https://github.com/jooray/venice-e2ee-proxy/blob/main/docs/SECURITY-AUDIT.md)
(2026-08-06, automated review by Qwen with live experiments — self-published in the repo it
audits, not an external assurance): DCAP quote against Intel PCK roots and CRLs, `report_data`
binding, keyset endorsement, KMS custody chain to a measured root, EIP-191 recovery to the
quote-bound address, debug-bit clear, freshness window, and TLS SPKI channel binding for
upstream hops. It fails closed.

Its `src/receipt-anchors.ts` is worth reading directly: it refuses to take workload identity
from the response being verified ("a provider serving both sides just makes them agree"),
reports `first-seen` distinctly from `pinned` and never as a match, and lets a quote-bound
value outrank a stored pin. That is the design this repo proposes in
[`research/observation-log.md`](../research/observation-log.md) as TOFU-and-complain,
arrived at independently.

## Scorecard

See the [live matrix](https://amiller.github.io/awesome-private-inference). The attestation
bundle contains everything needed for independent re-verification:
- TDX quote (hex) → forwarded to Phala's verifier
- NVIDIA payload → forwarded to NRAS
- `nonce_source: "client"` when a user-supplied nonce is echoed back correctly
- Signing pubkey + address for key-derivation check

## Known gaps

Findings marked **[JB]** come from Juraj Bednár's
[audit of the Venice stack](https://github.com/jooray/venice-e2ee-proxy/blob/main/docs/SECURITY-AUDIT.md)
(2026-08-06) and its accompanying [write-up](https://x.com/jurbed/status/2085364598111191380).
They were reached independently — that work does not cite this registry, and this registry
had not applied them to Venice.

- **[JB] Operator root SSH cannot be ruled out.** The enclave's boot script can install an
  SSH key for root; whether one was installed is an encrypted secret and the attestation
  cannot tell you either way. Compounded by a dev OS image with SSH and serial console
  enabled and not published, so you cannot reproduce it and check what actually boots.
  If a key is set, the holder has a shell inside the sealed box and can read every prompt
  passing through it. This `allowed_envs` + dev-image pattern is tracked by the
  **Prod OS image** column — which was never required of Venice.
- **[JB] The last hop's serving software is unmeasured.** Plaintext ends up on a GPU node
  whose serving software nobody has measured; nothing cryptographically prevents it from
  logging prompts. This registry's **Serving code attested** column exists for exactly this
  (found on Chutes) and was never required of Venice. The GPU node's attestation endpoint
  returns 401 without the router's bearer token, so the third hop cannot be inspected
  independently.
- **[JB] Attested recipe, not attested binary.** The gateway is built from source at boot
  against a persistent, unmeasured cargo cache and `image_digest` is null — the measurement
  says "I compiled this source commit", not "I am running this binary". Maps to the
  `code_measurement_reproducible` field, which this repo collects and never renders.
- **[JB] Upstream verification is advisory, not enforced.** The gateway supports refusing to
  forward when the next hop fails verification, but on the domain Venice's traffic uses that
  enforcement is off (`required: false`): a failed check is recorded in the receipt and the
  prompt goes anyway. Same class as NEAR's unset `ALLOWED_COMPOSE_HASHES` — extracted but
  unenforced. This registry has no column for it.
- **[JB] Replay is not excluded on the second hop.** The gateway does not publish the random
  challenge it sent the next machine, so a client cannot prove that passport is current
  rather than captured earlier. This registry binds a client nonce on the first hop only.
- **Model substitution is a confidentiality issue on an E2EE path, not only a correctness
  one.** The JB write-up sets model-weight provenance aside as correctness ("a swapped model
  gives you worse answers, it does not leak what you typed"). That holds for a plaintext
  path. On an E2EE path a silent substitution means you encrypt to the substituted TD's key
  — you have encrypted to a machine you did not choose. This registry caught exactly that on
  NEAR on 2026-05-05 (`deepseek-ai/DeepSeek-V3.1` → `Qwen/Qwen3.5-122B-A10B`).
- **Skill-text backdoor.** [`veniceai/skills`](https://github.com/veniceai/skills)
  (the agent-facing catalog) misnames the protocol as "HPKE / Noise handshake",
  cites `docs.venice.ai/e2ee` which 404s, and teaches **zero of the six** standard
  TDX-verification steps (fetch quote, verify signature, check `report_data`
  binding, derive address from `signing_public_key`, pin TLS, check debug flag).
  An agent following the skill as written builds a TOFU connection — the crypto
  is correct but the anchor is never checked. Full analysis:
  [venice-private-inference case study](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/venice-private-inference/DEVPROOF-REPORT.md).
  **Re-checked 2026-08-10 and unchanged:** `veniceai/skills` last shipped 2026-07-29 with
  commits covering crypto-rpc, image, audio and x402 — nothing touching E2EE verification —
  and `docs.venice.ai/e2ee` still returns 404. The third-party proxies above fix this for
  their own users; they do not fix Venice's agent-facing catalog, which is what an agent
  loads by default.
- **`supportsE2EE: true` flag is inconsistent.** `e2ee-gpt-oss-20b-p` attests
  successfully but returns no `signing_public_key` in the attestation body —
  the flag does not imply a usable ECIES path.
- **HPKE/OHTTP stub.** Attestation bundle publishes an `ohttp_key_config`
  (RFC 9458, DHKEM-X25519, AES-128-GCM / ChaCha20Poly1305), but no `/ohttp*`
  endpoint responds. Either unused infrastructure or a future plan. Agents
  following the skill's "HPKE" guidance hit nothing.
- **Attestation endpoint flaky.** `/tee/attestation` times out consistently on
  `e2ee-glm-5` and `e2ee-qwen3-5-122b-a10b` across retries; works quickly on
  `e2ee-venice-uncensored-24b-p` and others. Not transient.
- **Inner boundary depends on the serving path.** The NEAR response shape had
  the gateway-to-backend limitations documented by this
  audit. The current RedPill ACI gateway publishes an upstream session and
  enforces its channel binding. Its PhalaDirect and `aci-service/v2` records
  passed the live integrity audit, while its Chutes records failed. Do not
  transfer either result to Venice without verifying Venice's own route.
- **Undocumented endpoint.** `/tee/attestation` isn't in Venice's public API docs; the
  schema could change without notice.
- **Subscription math.** Pro ($18/mo) is chat-UI only for API use — it provides only
  $1 of API credit. Pro+ ($68/mo → $75 credit) and Max ($200/mo → $225 credit) give
  10–12.5% bonus over pay-as-you-go.

## Reproduce

```bash
export VENICE_API_KEY=...
python -c "from verifiers.venice import verify; \
           r = verify('$VENICE_API_KEY', 'https://api.venice.ai/api/v1', 'e2ee-glm-5'); \
           import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
```

## Scoring correction

Venice was the only provider scoring a full row on the dashboard. That was an artefact of
its own required-layer set, not a finding about Venice.

`REQUIRED_LAYERS_BY_SHAPE["venice"]` requires six of fifteen scorecard fields and excludes
nine, among them `prod_os_image`, `serving_code_attested` and `code_measurement_reproducible`
— the three the JB audit shows are load-bearing here. The stated reason was that Venice
"sits downstream of Phala/NEAR (no own gateway→backend hop to attest from this side)".

That reasoning asks *whose responsibility a gap is* rather than *whether the user is
exposed*. Reseller is a commercial relationship, not a security boundary: a prompt sent to
Venice is decrypted in a Phala enclave, and if that enclave boots a dev image with root SSH
the prompt is exposed regardless of whose invoice it appears on.

Mechanically the bug is narrower than the reasoning. The renderer already distinguishes
two kinds of missing value:

- required and not exposed → red dash, **counts as a failure**
- not required → grey dash, benign, "not applicable to this architecture"

All three fields are `None` for Venice because the `/tee/attestation` endpoint never
reports them. They were filed as benign N/A when the truthful reading is "this question
matters and Venice does not let you answer it". The machinery was right; the classification
was wrong.

Reclassifying the three as required moves Venice from `6/6 verified` to `6/9 partial` with
`code_measurement_reproducible, prod_os_image, serving_code_attested` named as unproven.
Tracked in [#6](https://github.com/amiller/awesome-private-inference/issues/6) (derive each
bar from provider claims rather than from what the API happens to expose) and
[#11](https://github.com/amiller/awesome-private-inference/issues/11).

## History

- **2026-08-10** — Verdict split into client-side and infrastructure. Three infrastructure
  gaps added from Juraj Bednár's independent audit; scoring correction recorded above;
  skill-text finding re-checked and unchanged; wire-protocol section marked partly
  superseded by ACI.
- **2026-04-24** — Initial live-probe findings: ECIES wire protocol confirmed, skill-text
  backdoor, HPKE/OHTTP stub, flaky attestation endpoint.

Snapshots: [data/snapshots/](../data/snapshots/).
