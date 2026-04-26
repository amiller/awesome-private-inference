# Tinfoil

## Claim

Tinfoil ([tinfoil.sh](https://tinfoil.sh)) offers a confidential-compute inference
service backed by AMD SEV-SNP CVMs (with TDX support landing). Their attestation
shape is unique in this registry: code measurement is published via Sigstore on
each release, the SEV report's `report_data` carries `sha256(TLS pubkey) ‖ HPKE
pubkey`, and the enclave's TLS certificate's SANs encode the HPKE pubkey and a
hash of the attestation document.

## Endpoint surface

- **Catalog:** `https://api.tinfoil.sh/v1/models` (bearer auth required)
- **Inference:** `https://inference.tinfoil.sh/v1/chat/completions` (OpenAI-compatible)
- **Per-host attestation:** `https://<enclave>/.well-known/tinfoil-attestation`
- **Bundled attestation (ATC):** `https://atc.tinfoil.sh/attestation`
  — single-request bundle containing the SEV report, VCEK, Sigstore bundle,
  and the enclave's TLS certificate.

## Status in this registry

**Live.** The verifier in [`verifiers/tinfoil.py`](../verifiers/tinfoil.py)
re-runs the trust chain end-to-end with no provider-supplied trust roots:

1. Fetch the ATC bundle.
2. Decompress + parse the 1184-byte SEV-SNP report
   ([`tinfoil_sev.py`](../verifiers/tinfoil_sev.py)).
3. Verify the Sigstore in-toto DSSE for the bundle's digest against
   `tinfoilsh/confidential-model-router`'s GitHub Actions release workflow
   identity (cert SAN regex pinned to `^https://github.com/tinfoilsh/confidential-model-router/.github/workflows/.*@refs/tags/.*$`,
   issuer `https://token.actions.githubusercontent.com`).
4. Cross-check Sigstore-published `snp_measurement` == SEV report measurement.
5. Decode the bundle's TLS cert SANs (`NN<base32>.{hpke,hatt}.tinfoil.sh`)
   and confirm:
   - `hpke` SAN bytes == `report_data[32:64]`
   - `hatt` SAN string == `sha256(format ‖ body)` of the attestation doc
6. Open a live TLS connection to `bundle.domain` and check
   `sha256(SubjectPublicKeyInfo) == report_data[:32]`.

The model-router at `inference.tinfoil.sh` is **one of multiple enclaves** in
the path. The router is itself a CVM whose attested config lists per-model
upstream enclaves; user prompts are forwarded to those enclaves where the
actual model serving happens. Each model enclave is its own CVM with its own
Sigstore-signed deployment under a per-model repo (e.g.
`tinfoilsh/confidential-gpt-oss-120b`). The verifier audits each enclave
separately. As of 2026-04-26:

| Model | Host | Repo | Containers | Image digest-pinned | External env | External secrets |
|---|---|---|---:|:---:|---:|---:|
| `router` | `inference.tinfoil.sh` | `confidential-model-router` | 1 (proxy) | ✅ | **1** (`DOMAIN`) | **1** (`USAGE_REPORTER_SECRET`) |
| `gpt-oss-120b` | `gpt-oss-120b-0.inf6.tinfoil.sh` | `confidential-gpt-oss-120b` | 1 (vllm 0.17.0) | ✅ | 0 | 0 |
| `llama3-3-70b` | `llama3-3-70b.tinfoil.containers.tinfoil.dev` | `confidential-llama3-3-70b` | 1 (vllm 0.17.1) | ✅ | 0 | 0 |
| `gemma4-31b` | `gemma4-31b-inf6.tinfoil.containers.tinfoil.dev` | `confidential-gemma4-31b` | 1 (custom image) | ✅ | 0 | 0 |
| `deepseek-v4-pro` | `deepseek-v4-pro.tinfoil.containers.tinfoil.dev` | `confidential-deepseek-v4-pro` | — | — | — | — *(TLS EOF — unreachable from our probe at audit time)* |
| `kimi-k2-6` | `kimi-k2-6.tinfoil.containers.tinfoil.dev` | `confidential-kimi-k2-6` | — | — | — | — *(TLS EOF — unreachable from our probe at audit time)* |

The model enclaves where the prompts are actually processed are **fully
attested**. The runtime-config gap exists only at the router layer, where it
controls subdomain routing (`DOMAIN`) and billing telemetry HMAC
(`USAGE_REPORTER_SECRET`) — both off the prompt path on this deployment. See
the [tinfoil-confidential-inference case study](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/tinfoil-confidential-inference/DEVPROOF-REPORT.md)
for the trace through the router's source code that establishes "off the
prompt path."

## What it covers (and doesn't)

| Capability | Status |
|---|---|
| Code measurement reproducible (Sigstore-signed) | ✅ |
| `report_data` binds the live TLS pubkey | ✅ |
| HPKE pubkey attested in `report_data` | ✅ |
| Debug-mode (SNP guest policy bit 19) enforced | ✅ |
| Container image pinned by digest in attested config | ✅ |
| Model weights pinned by dm-verity rootHash in attested config | ✅ |
| Runtime config fully attested | ⚠️ *partial* — see audit below |
| Client-supplied nonce in `report_data` | ❌ (no nonce slot — freshness is via live TLS pin) |
| Live GPU attestation (NRAS) | ❌ (Tinfoil checks GPU at boot inside the CVM, not per-request) |
| VCEK chain → AMD Genoa root | ⚠️ skipped in v1 — VCEK is in the bundle but not chained to AMD's root yet |

## Runtime-config audit

Tinfoil's container schema lets the attested `/config.yml` declare env vars in
two forms:
- `KEY: value` (map) — value is in the attested config, ✅ measured
- `KEY` (string) — value is read at runtime from a *separate, unattested*
  external-config disk

`secrets:` entries are always read from the unattested disk.

The verifier now decodes the attested config (sigstore predicate carries it
as `config: <base64>`, with `cmdline` carrying its sha256), parses it, and
counts these slots. `runtime_config_fully_attested` is true only if every
container has zero string-form env entries and zero secrets.

On the live router (2026-04-26):

| Container | Image pinned by digest | Attested env | External env | External secrets |
|---|---|---|---|---|
| `proxy` | ✅ | `REFRESH_INTERVAL`, `USAGE_REPORTER_ID`, `CONTROL_PLANE_URL` | `DOMAIN` | `USAGE_REPORTER_SECRET` |

`DOMAIN` and `USAGE_REPORTER_SECRET` are populated by the operator at
runtime. They affect the public hostname and billing-telemetry HMAC; neither
is on the prompt path, so the practical exposure on this specific deployment
is small. But the schema is general — a future deployment could declare a
prompt-path env var (e.g. `LOG_PROMPTS_TO=...`) the same way and the
attestation alone would not surface it. The audit makes this visible.

## Source code we depend on

All open-source under [github.com/tinfoilsh](https://github.com/tinfoilsh):
[`tinfoil-go/verifier`](https://github.com/tinfoilsh/tinfoil-go/tree/main/verifier)
(reference Go re-verifier),
[`measure-image-action`](https://github.com/tinfoilsh/measure-image-action)
(publishes the Sigstore measurement on release),
[`confidential-model-router`](https://github.com/tinfoilsh/confidential-model-router)
(the orchestrator whose digest the bundle pins),
[`cvmimage`](https://github.com/tinfoilsh/cvmimage) (the measured CVM image),
[`encrypted-http-body-protocol`](https://github.com/tinfoilsh/encrypted-http-body-protocol)
(EHBP / HPKE wire format).

## Reproduce

```bash
python -c "from verifiers.tinfoil import fetch_bundle, verify_bundle; \
           import json; r = verify_bundle(fetch_bundle(), model='router'); \
           print(json.dumps(r.as_dict(), indent=2, default=str))"
```

No API key needed — the bundle is public. The catalog and inference probes do
need `TINFOIL_API_KEY`.

## History

Snapshots: [data/snapshots/](../data/snapshots/).
