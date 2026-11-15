# teep parity

A living table. It compares the checks in our daily probe with the factors in [teep](https://github.com/13rac1/teep) (`internal/attestation/report.go`). Last full rebuild: 2026-11-15, against teep `6548996` and branch `refresh/2026-11-15`. The previous rebuild was 2026-11-05.

teep checks each request it proxies. Our probe checks one sample per route per day. A daily pass says nothing about other requests.

V = Venice, N = NEAR cloud, C = Chutes, T = Tinfoil router, A = ACI gateway. ✓ = we check it, ~ = partial, ✗ = we don't, n/a = doesn't apply.

| teep factor | V | N | C | T | A | Notes |
|---|---|---|---|---|---|---|
| nonce_match | ~ | ✓ | ✓ | ✗ | ✓ | V: trusted only when `nonce_source=="client"`. C: freshness rests on REPORTDATA, since the evidence echoes no nonce (teep 6967376). T: no client nonce on the router path. |
| quote_signature / cert_chain | ✓ | ✓ | ✓ | ✓ | ✓ | T: ARK/ASK/VCEK chain and report signature (#26, merged 2026-11-15). |
| tee_debug_disabled | ✓ | ✓ | ✓ | ✓ | ✓ | Read from the parsed quote alone. |
| tee_measurement / boot_config (MRTD, RTMR1-2) | ✓ | ✓ | ✓ | n/a | ✓ | Compared with dstack-mr derivations (N, V, A) or with Chutes' published rows (C). |
| tee_hardware_config (RTMR0) | ✓ | ✗ | ✓ | n/a | ✓ | N exposes no vm_config, so RTMR0 is reported unproven. teep pins it from captures. |
| tee_tcb_current | ✓ | ✓ | ✓ | ✓ | ✓ | Intel: UpToDate only. AMD: the AMD-SB-3037/3038 minimum (snp 0x1D), stricter than teep's 0x0e. The Tinfoil router fails ours. |
| reportdata_binding | ✓ | ✓ | ✓ | ✓ | ✓ | |
| nvidia_signature / claims / nonce | ✓ | ~ | ✓ | ✗ | n/a | Signed NRAS JWT with JWKS chain, iss and exp (chutes lane). V: GPU count unpinned. N: vendored `check_gpu`. V ACI/1 carries no GPU evidence since 2026-11-12. |
| compose_binding | ✓ | ✓ | n/a | n/a | ✓ | |
| event_log_integrity | ~ | ✓ | n/a | n/a | ✓ | All four RTMRs must equal the replay. V: ACI/1-shaped responses only; the legacy shape has no event log. |
| sigstore / build provenance | ✗ | ✗ | n/a | ✓ | ✗ | |
| gateway_* | n/a | ~ | n/a | n/a | ✓ | N: gateway quote and compose, chain authorization via live `eth_call`. |
| NEAR cloud every instance | n/a | pending | n/a | n/a | n/a | Branch `pass/near-instances` (teep c1f253a, da6cbcf). |
| tls_key_binding | n/a | ✗ | n/a | ✓ | ✓ | N: #29. |
| e2ee_usable, aci_session / receipt | ✗ | ✗ | ✗ | ✗ | ✗ | Not in the daily probe. teep captures from zed are retained instead (`data/evidence/teep-2026-11-15/`, `/data/amiller/teep-refresh-20261115/run.sh`). |
| measured_model_weights | ✗ | ✗ | ✗ | ✗ | ✗ | teep passes this only on Tinfoil direct (dm-verity), which teep disabled on 2026-11-12. |
| cpu_gpu_chain, cpu_id_registry | ✗ | ✗ | ✗ | ✗ | ✗ | |

## Where we check something teep doesn't

- On-chain compose authorization for NEAR, checked at a recorded Base block.
- The AMD-bulletin TCB minimum for Tinfoil.
- Tinfoil's model → repo pin sweep.
- The Chutes golden set, fetched live (teep pins a static copy).
- A human audit ledger.
- Observed reference values, exported daily as `docs/reference-values.json`. teep could diff these against its allowlists, for example NEAR's 2026-11-04 OS measurements (teep #233).

## Pending

The daily beat appends a dated line here whenever teep changes a factor or a gap doc. Each line names the factor and our matching check, if we have one. Pending lines are folded into the table at the next rebuild.
