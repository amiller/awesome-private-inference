# RedPill and Phala claim refresh, 2026-08-12

This audit records the fields needed to reproduce conclusions about the current
RedPill and Phala ACI deployment. No API keys, raw quotes, JWTs, or full evidence
bundles are included.

## Follow-up, 2026-08-13

A fresh nonce-bound check found three changes worth recording:

- The live report now declares
  [`private-ai-gateway@45a7666`](https://github.com/Dstack-TEE/private-ai-gateway/commit/45a7666275de3e2d877842513c2bd5c17676936d)
  and Compose hash
  `0fcdf7fa2b9a40425871bc7c2978a14eda61386822ee30a622b7c00137ef6215`.
- All four Compose images are now digest-pinned. In particular, the earlier
  `dstacktee/dstack-verifier:latest` is now
  `dstacktee/dstack-verifier:0.5.11@sha256:06a20b77...`.
- The session audit accepted 192 of 327 records: 92/92 `aci-service/v2`, 81/81
  PhalaDirect, 16/16 NEAR, 2/2 SecretAI, and 1/1 Tinfoil. All 135 Chutes
  records still failed.

The public CLI still reports five passes and one custody-policy skip. Its new
`--require-production-os` appraisal rejects the live
`de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`
dev-image hash. The same fresh quote, event log, and VM config passed a local run
of the deployment's exact pinned dstack-verifier digest with `is_valid: true`
and `os_image_hash_verified: true`, binding that hash through MRTD and RTMR0-2.
Re-verifying dstack's published archive resolved version 0.5.9 with
`is_dev: true`.

The Stage verdict remains 0. The dev OS, operator root-key input, public
error-detail logging, mutable route state, missing immutable upgrade history,
unreproduced source-to-image provenance, and unenforced custody/subject policy
remain. The digest pin closes one sub-gap; it does not close the verdict.

## Targets

| Target | Role | Observation on 2026-08-12 |
|---|---|---|
| `https://tee.redpill.ai` | Current RedPill ACI gateway | ACI attestation and models returned HTTP 200. |
| `https://inference.phala.com` | Current Phala-branded ACI hostname | ACI attestation and models returned HTTP 200. |

The ACI verifier observed the same workload keyset digest on both current
hostnames. The keyset listed a separate TLS SPKI for each hostname.

Reviewed source revisions:

- `amiller/awesome-private-inference@152ad397d96868805106a5170dbf24dc6f29f15c`
- `Dstack-TEE/private-ai-gateway@70556f5b1ee464eea846c9b2cb060896acecb01a`
- Live report source declaration:
  `Dstack-TEE/private-ai-gateway@59882c2970d931c0a12c6f05b86d835149b67dff`
- `Phala-Network/private-ai-verifier@51c2b5a83d6d753b9a29288e0ed522ab2d65bac4`
- `Dstack-TEE/meta-dstack@7cc276ff0ef82650c65b86ba000cfa35a604818a`
- Stage rubric: `amiller/devproof-audits-guide@7edaafd65b894d1a357521d38b397add2ba97f80`

## Gateway verification

Command:

```bash
cargo run --bin aci -- verify https://tee.redpill.ai --json
```

The verifier produced five passes and one skip:

| Check | Result | Evidence level |
|---|---|---|
| TDX quote, current TCB, nonce-bound `report_data` | Pass | Directly attested |
| Workload keyset JCS digest bound to the quote | Pass | Directly attested |
| Keyset validity window | Pass | Attestation-bound artifact |
| Compose hash measured into RTMR3 | Pass | Attestation-bound artifact |
| dstack KMS key custody and subject policy | Skip | Evidence present, policy not implemented in this client |
| Observed TLS SPKI present in the attested keyset | Pass | Directly attested channel binding |

The measured Compose hash was
`cbbc26ea26a5dbe807df5d9abdb22c0485fb40f7634b9a7cc719580959c51213`.
The report declared public source commit `59882c2`. The verification did not
rebuild that commit, so the source label remains a source declaration rather
than reproduced release provenance.

The same command passed the same five checks and skipped custody at
`https://inference.phala.com`. The channel check observed and matched the
distinct SPKI for each hostname.

The live receipt path was not exercised because this audit did not send an
authenticated inference request. Receipt support is source- and
attestation-grounded in this report, but not confirmed with a sampled request.

## Deployment posture and Stage verdict

The ACI verifier's 5/6 result is a protocol score, not an ERC-733 Stage score.
The fresh report also exposed the measured deployment configuration:

| Field | Live value | Security consequence |
|---|---|---|
| VM image | `dstack-dev-0.5.9-de9c74f0` | The deployment uses the development OS rather than the production flavor. |
| Operator SSH input | `DSTACK_ROOT_PUBLIC_KEY` is allowed; the pre-launch script writes it to root's `authorized_keys` | Attestation cannot rule out operator root access inside the TD. |
| Logs | `public_logs: true`; `RUST_LOG=info,request_outcome=debug` | The attested source can write up to 240 characters of upstream error detail, which may echo request content, to publicly visible logs. |
| Source provenance | Public commit declared; `image_digest` and `image_provenance` are `null` | The source label was not reproducibly connected to the running image. |
| Verifier image | `dstacktee/dstack-verifier:latest` | This integrity-path component is not pinned by digest. |
| Active routes | Empty measured seed; persistent `upstreams.json` replaced by authenticated admin API | Effective routing policy can change without a new Compose measurement. |
| Control plane | URL and token supplied through allowed environment variables | Authorization, catalog, and route selection depend on operator-selected infrastructure. The code sends model, provider constraints, API-key hash, and usage—not prompt content—to this service. |

The root key is a capability, not proof that an operator key was present during
the check. dstack's published
[dev-image recipe](https://github.com/Dstack-TEE/meta-dstack/blob/7cc276ff0ef82650c65b86ba000cfa35a604818a/meta-dstack/recipes-core/images/dstack-rootfs-dev.inc)
includes OpenSSH and permits root public-key login. The measured pre-launch
script deliberately configures that path. The logging exposure is active in the
measured configuration, but applies to error snippets rather than every request.

Against this registry's linked Stage 1 checklist, the result is **Stage 0 (one
of seven requirements demonstrated)**:

| Stage 1 requirement | Result | Evidence |
|---|---|---|
| Immutable attestation and upgrade transparency | Fail | Current attestation exists; immutable deployment history was not demonstrated. |
| Auditable code | **Pass** | Public source and an exact commit are declared. |
| Reproducible code measurement | Fail | No reproduced build or source-to-image proof; one verifier image uses `latest`. |
| Developer has no access to secrets | Fail | Custody policy is skipped and operator root access is not ruled out. |
| Upgrade process and public history | Fail | No notice mechanism or queryable deployment history was demonstrated. |
| No centralized integrity or privacy dependency | Fail | Operator-selected control infrastructure and mutable route state remain. Session pins mitigate route substitution when used. |
| No backdoor or debug path | Fail | The dev-OS SSH path and public error-detail logging remain enabled. |

Stage 1 fails if any requirement fails. The result does not erase the five
cryptographic checks that passed; it says the current trust chain still leaves
operator-controlled paths that the client cannot exclude.

## Upstream-session verification

Command:

```bash
target/debug/aci sessions https://tee.redpill.ai --json
```

The session set is dynamic. At 2026-08-12T06:02:12Z, the service listed 271
current or retained records. The client accepted 154:

| Verifier | Total | Passed ACI integrity audit |
|---|---:|---:|
| `aci-service/v2` | 70 | 70 |
| `private-ai-verifier/phala-direct/v1` | 65 | 65 |
| `private-ai-verifier/near-ai-gateway/v1` | 16 | 16 |
| `private-ai-verifier/secret-ai/v1` | 2 | 2 |
| `tinfoil-verifier/v1` | 1 | 1 |
| `private-ai-verifier/chutes/v1` | 117 | 0 |

The Chutes records omitted the ACI section 8.2 evidence digest and data. A
sampled Chutes record also showed a content-address mismatch:

```text
session_id          29897616ec315f09ed739168cf33b92055f8da0cb867f8d57f2f4684e1247c43
sha256(served bytes) 29897616ec315f09ed739168cf33b92055f8da0cb867f8d57f2f4684e1247c43
sha256(sorted compact JSON) 13073765983846e9bb338e4c8271ffad8ce387e7cb9951df3f0acc83a45592f3
```

The sorted compact JSON check is a diagnostic approximation. The authoritative
failure is the official client's RFC 8785 JCS computation. ACI section 8 defines
`session_id = hex(sha256(JCS(document)))`; the sampled Chutes id instead matched
the exact response bytes. The missing evidence and id mismatch block section 9.2
acceptance for those Chutes sessions. They do not invalidate the 154 passing
records from the other adapters.

## Provider-session claim samples

The records below were sampled from the public ACI session list. They are
gateway-published verifier results. Each field keeps its original assurance
level.

### PhalaDirect v1

`private-ai-verifier/phala-direct/v1` for `openai/gpt-oss-20b` reported:

- TDX attested from hardware evidence;
- non-debug TDX and `UpToDate` TCB;
- production `dstack-nvidia-0.5.9`, resolved from the attested OS image hash;
- nonce-bound NVIDIA evidence with Hopper architecture;
- version-2 `report_data` binding for the direct endpoint TLS SPKI;
- canonical model ID `openai/gpt-oss-20b`;
- unknown serving-software and model-weight provenance.

All 65 observed PhalaDirect records passed the session integrity audit.

### ACI service v2

An `aci-service/v2` session for a Phala model endpoint reported:

- a verified workload identity and enforced TLS SPKI binding;
- unknown typed GPU, TCB, OS, serving-software, and model-weight claims.

All 70 observed `aci-service/v2` records passed the session integrity audit.

The differing claim sets show why a gateway-level ACI pass cannot be copied into
every upstream row.

## `private-ai-verifier` scope

At `51c2b5a`, `private-ai-verifier` remains an attestation SDK. Its
`VerificationResult` exposes verification status and claims, not a client E2EE
or receipt flow. The NVIDIA and Intel Trust Authority helpers still call
`jwt.decode(..., options={"verify_signature": False})`.

The current ACI client is a separate layer. It adds native DCAP verification of
the gateway quote, a quote-bound workload keyset, live TLS or attested E2EE
channel binding, verified-route constraints, sessions, and receipts. The adapter
JWT issue still applies wherever an upstream claim depends on those decoded
tokens.

## Corrections applied to this registry

- Document the current ACI gateway per route without assigning it a synthetic
  score in the Python matrix, while giving the deployment an explicit manual
  Stage 0 verdict.
- Replace blanket statements about Phala E2EE, TLS binding, Compose binding,
  KMS evidence, and local sidecar trust with component-specific statements.
- Preserve current limitations: custody-policy skip, unreproduced source label,
  unknown serving software and weights, unsigned adapter JWTs, and the failed
  Chutes session records.
