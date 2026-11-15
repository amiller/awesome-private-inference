# Tinfoil router: operator access review (2026-11-15)

Route: client → `inference.tinfoil.sh` router enclave → model enclaves.
Code reviewed: confidential-model-router v0.0.176 (released 2026-11-12), commit `29f5e0b` (`R`). HEAD `ef64384` (2026-11-13) changes only `tinfoil-config.yml`: a placeholder digest and `drain_connections`. Also reviewed: tinfoil-go `6325a16` (v0.17.0-rc.4, `G`) and cvmimage `eaa503d` (v0.14.15, `C`). Links take the form `https://github.com/tinfoilsh/<repo>/blob/<sha>/<path>#L<n>`. **[read]** means traced in source. **[inferred]** means not read directly.

## F1. Control plane can rewrite `model: "auto"` request bodies

**Problem.** The router stores `reasoning_params` from `api.tinfoil.sh/v1/models` without checking it; only the intelligence scores are range-checked. For `model: "auto"`, `ApplyEffort` deep-merges the published `enable`/`disable` fragment into the request body. There is no key allow-list, and the merged body is what goes upstream. **[read]**

**Impact.** *Who:* Tinfoil's control plane, or anyone who can answer for `api.tinfoil.sh` under WebPKI. *What they do:* publish a fragment such as `{"messages": [...]}`, `{"instructions": "..."}`, `{"max_tokens": 1}` or `{"tools": [{"type": "web_search"}]}`. *What they get:* the attested model answers a prompt the client did not send. On `/v1/responses`, an injected `web_search` tool selects the router's web-search profile, because `DetectProfiles` runs after the merge, and the request then goes to `toolruntime.Handle` **[read]**. Queries derived from the prompt would then go to an outside search provider **[inferred]**. *What stops it today:* only `auto` requests are affected. `priority` and `cache_salt` are removed or re-derived after the merge. `auto` can only pick models that are in the measured `config.yml`. The client cannot see that its body was changed.

**Evidence.** R `manager/model_metadata.go:125-135, 147-189`; `autoroute/autoroute.go:271-304, 343-359`; `main.go:447-448, 836-850, 854, 893, 905-915, 917-939`; `toolruntime/profile.go:74-77`.

**Remediation.** Make the reasoning fragments part of the measured config, or allow-list the reasoning keys each fragment may set.

## F2. Unsigned runtime config assigns customers to attested replicas

**Problem.** `sync` fetches `UPDATE_CONFIG_URL` every minute over plain WebPKI with `sha256_required=false`. That config sets hostnames, overload limits, the `cache_route` mode and per-org/per-user `reservations`. For each request, `/api/shim/route-context` returns the caller's `org_id`/`user_id`, which select the reservation pool. Each host must pass `verifyEnclave(host, model.Repo)` against the repo pinned in the embedded config. Runtime repo changes and unknown model names are ignored. **[read]**

**Impact.** *Who:* the control plane. *What they do:* reserve a chosen host for a target org or user. *What they get:* that customer's prompts go to a machine the operator chose, for example one where it holds a hypervisor exploit (F3) **[inferred composition]**. A backend is accepted if it runs any release of the pinned repo whose freshness witness is under seven days old. The witnesses come from `tinfoilsh/freshness-witness` **[read: constants]**, and who signs them is **[inferred]** to be Tinfoil. Six model names share `confidential-small-models`, and nothing ties a backend to its model name beyond the repo, so a host could be listed under a sibling name **[inferred]**. *What stops it today:* hardware attestation of each backend.

**Evidence.** R `manager/manager.go:318, 743, 746-768`; `config/config.go:36-56, 186-235`; `route_context.go:54-58`; `config.yml`. G `verify/README.md:43-45`; `verify/internal/endorsement/provenance.go:35-36`.

**Remediation.** Sign the runtime config or log it in a transparency log. Publish reservation assignments so customers can audit them.

## F3. Router platform TCB is below AMD's Genoa minimum

**Problem.** A live fetch from `inference.tinfoil.sh` on 2026-11-15 reported SNP SPL 0x17 and microcode 0x54. `router-0` reported SNP 0x1B (2026-11-04, unchanged on 2026-11-15). Our pinned minimum is SNP 0x1D, citing AMD-SB-3037/3038 (GenoaPI_1.0.0.J), and microcode 0x56, citing AMD-SB-3027. **[read, our capture]**

**Impact.** *Who:* the platform operator (host or hypervisor). *What they do:* exploit the hypervisor-attacker SEV firmware CVEs that the newer firmware fixes. *What they get:* possible loss of integrity on the router, which holds every plaintext prompt **[inferred]**. *What stops it today:* nothing visible. Clients and the router take the TCB floor from Tinfoil-published platform endorsements in `tinfoilsh/cvmimage` **[read]**. That floor is an operator update channel. Because the router serves with these reports, the current floor presumably accepts them **[inferred]**.

**Evidence.** `verifiers/certs/amd_genoa_tcb_minimum.json` (fetched 2026-11-15); `tests/test_tinfoil_amd_chain.py:422-428`. G `endorsement/freshness/statement.go:24-25`; `verify/internal/policy/sev.go:20`.

**Remediation.** Update the firmware to SNP ≥ 0x1D and microcode ≥ 0x56, and raise the published `minimum_tcb`.

## F4. Secrets and metadata on the control-plane path

**Problem.** The values of all four secrets are supplied by the operator, either from the host's external config or from Tinfoil's keyserver, and they are not part of the measurement. The router sends the raw API key and model name to the control plane on every request. Billing events carry user ID, model, token counts, enclave, path and API key, but no content. **[read]**

| Secret | Effect traced |
|---|---|
| `USAGE_REPORTER_SECRET` | HMAC on billing reports; billing only **[read]** |
| `USAGE_CONTEXT_SECRET` | Verifies harness usage-context headers and signs tool-service headers. A holder can make requests bill zero; it does not touch content **[read]** |
| `CACHE_ROUTE_SECRET` | Key = Sum(secret, salt, cache key, tools, system, first user message, ≤1 KiB), and the key picks the replica **[read]**. In tenant mode the salt comes from the API key or JWT subject, so the operator can compute it. In `enforced` mode, an operator watching which backend the router dials can test prefix guesses, about log2(replicas) bits per request **[inferred]**. A client-supplied `user_cache_secret` blocks this |
| `METRICS_API_KEY` | Bearer token for backend `/metrics` polling; affects admission only **[read]** |

**Evidence.** C `tinfoil/internal/secretstore/handoff.go:83-93`; `tinfoil/cmd/boot/main.go:181-191`. R `route_context.go:45-47`; `billing/events.go:21-33`; `billing/usage_context.go:28-50`; `toolruntime/runtime.go:130-134`; `cacheroute/cacheroute.go:216-224`; `cache_salt.go:43-59`; `main.go:200, 493-498`.

**Remediation.** Keep `cache_route` out of `enforced` mode until placement is unobservable. Document what each request sends to the control plane.

## Inputs with no traced prompt-path effect

| Input | Finding |
|---|---|
| Measured env (`REFRESH_INTERVAL`, `CACHE_SALT_ENABLED=true`, `CONTROL_PLANE_URL`, `UPDATE_CONFIG_URL`, `USAGE_REPORTER_ID`) | Hardcoded map entries in `tinfoil-config.yml` **[read]** |
| `DEBUG`, `LOCAL_MCP_ENDPOINT_*`, `INIT_CONFIG_URL`, `VERBOSE` | Container env is limited to the measured entries plus declared secrets. Host external-config `env` fills only names the config lists, and the router lists none (C `containers.go:445, 761-796`) **[read]**. `DEBUG` would bypass MCP pinning (R `manager/http_client.go:243-247`) |
| Admin SSH / debug boot | cvmimage gates config-declared admin SSH off in debug mode (C `runtimeconfig/types.go:23-28`). The router config declares no SSH section **[read]**. The implementation lives in the `tinfoil-config` module, which I did not read |
| Route-context `priority`, rate decision | Sets vLLM `priority` or rejects; scheduling only (R `route_context.go:390-402`) **[read]** |
| `overload`, `cache_route` shadow | Admission and metrics only **[read]** |
| Release channel | Release notes publish the measurement and a Sigstore digest; Tinfoil controls the repo **[read]** |
| Egress `open` | Bounded by the measured code **[read]** |

## Proposed cell: operator access

**state:** gap. **label:** Control-plane prompt rewriting. **reason:** In v0.0.176 the router merges an unvalidated fragment from the control plane's `/v1/models` into `model: "auto"` request bodies, which can replace messages or select web search. An unsigned runtime config assigns customers to attested replicas, and those replicas run at SNP TCB 0x17/0x1B, below AMD's 0x1D Genoa minimum. **evidence:** R `autoroute/autoroute.go:271-359`, `main.go:836-939`, `manager/manager.go:743`, live attestation 2026-11-15. **missing:** the production `reasoning_params` and `router-config` contents; the live `minimum_tcb` value; the admin-SSH implementation in `tinfoil-config`. **limitation:** reviewed_system.
