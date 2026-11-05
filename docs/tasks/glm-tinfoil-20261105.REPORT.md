# GLM tinfoil lane — REPORT (epoch 1, 2026-11-05)

Issue #26 (authenticate the AMD report and certificate chain) + Tinfoil part
of #18 (retain `reported_tcb`/`current_tcb` in row details).
Spec: `docs/tasks/glm-tinfoil-20261105.md`.

## What changed

| File | Change |
|---|---|
| `verifiers/tinfoil_sev.py` | Full ABI-layout parser for report versions 2/3/5 (1184 bytes): all fields at spec offsets, structural MBZ checks per version, policy/signer_info reserved-bit checks, product (FMS→Genoa/Milan/Turin), signature halves (LE R,S at 0x2A0/0x2E8), `signed_data` = bytes [0x000,0x2A0). |
| `verifiers/tinfoil_amd.py` (new) | ARK→ASK→VCEK chain verification: pinned ARK-Genoa/ASK-Genoa anchors (`verifiers/certs/`, DER SHA-256 pin, fail-closed load), ARK self-signature, ARK→ASK, ASK→VCEK (RSA-PSS with cert-declared parameters), issuer DN + validity + X.509 v3 + CN/product/CSP_ID checks, hwID==chip_id, bl/tee/snp/ucode SPL==reported_tcb bindings, ECDSA P-384/SHA-384 report signature over the exact signed bytes. `InvalidSignature` is mapped to `ChainError` (a `ValueError`), so tampered input yields a *rejected report*, never a crash. |
| `verifiers/tinfoil.py` | Hardware chain verification runs **before** every use of parsed report fields (sigstore measurement match, report_data→TLS/HPKE/hatt bindings). `hardware_signature_verified=True` only on full chain success; per-host bundles (`vcek_b64=""`) stay `not_checked` with "no VCEK" recorded in details and error. `details["sev"]` retains `reported_tcb`/`current_tcb` (hex + decomposed parts) — #18. |
| `verifiers/certs/` (new) | Pinned ARK-Genoa/ASK-Genoa PEMs + provenance (KDS URL, capture time, PyPI cross-check, fingerprints). |
| `tests/fixtures/` (new) | `amd_kds_genoa_cert_chain.pem`, `amd_kds_milan_cert_chain.pem` (wrong-product negative control), `amd_kds_provenance.json`, `tinfoil_router0_v5_bundle.json` (v5 replay packet from retained daily-probe evidence, hash + capture date recorded in `_provenance`). |
| `tests/test_tinfoil_amd_chain.py` (new) | 32 tests: positives on both retained reports + all negative controls below. |
| `tests/test_tinfoil.py` | Assertions updated: error strings changed because the hardware chain now *verifies* (the fixture's VCEK is genuine), so the remaining reason names encrypted-request binding/session freshness; `hardware_signature_verified` now `True` for VCEK-carrying fixtures and stays `None` with "no VCEK" for the per-host bundle. Parser test gains product/chip_id assertions. |
| `data/verifiers.json` | Tinfoil entry: `tinfoil_amd.py` implementation, AMD-chain checks, KDS trust-anchor delegation; AMD chain removed from `unchecked`. |
| `providers/tinfoil.md` | Verification-steps list and capability table updated to the performed AMD-chain checks (was "skipped in v1"). |

## Success criteria status (issue #26 + #18)

1. **Authenticate the chain** — MET.
   - ARK/ASK for Genoa captured from `https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain` (2026-11-05, provenance in `verifiers/certs/amd_genoa_provenance.json` + `tests/fixtures/amd_kds_provenance.json`), byte-identical to the chain in published `tinfoil==0.15.0` (two independent publications). Product determined from the reports themselves: FMS bytes at 0x188 (v3) → Genoa for both retained reports; VCEK product extension agrees.
   - ARK self-signature, ARK→ASK, ASK→VCEK RSA-PSS: `tests/test_tinfoil_amd_chain.py::test_hardware_chain_and_report_signature_verify` (both v3 and v5 retained reports).
   - ECDSA P-384 over exact signed bytes: same tests.
   - hwID/chip_id + SPL/reported_tcb bindings + debug-off: positive tests plus the binding-specific negative controls below.
2. **Report body matched to measurement and keys actually used** — MET: hardware verification precedes `_verify_sigstore`, the measurement cross-check, and report_data→(TLS SPKI, HPKE SAN, hatt) bindings. Swapped-key control proves the bindings reject.
3. **Replay packets retained with versions** — MET: `tests/fixtures/tinfoil_atc_bundle.json` (v3) and `tests/fixtures/tinfoil_router0_v5_bundle.json` (v5, evidence sha256 + observer run recorded in `_provenance`).
4. **Per-host `vcek_b64=""` stays unverified** — MET: `tests/test_tinfoil.py::test_per_host_bundle_fully_attested` asserts `hardware_signature_verified is None`, details+error record "no VCEK"; never passes.
5. **Checks published, remaining obligations named** — MET: `details["hardware_signature_verification"]` is the structured record (checks list, anchor/VCEK fingerprints, provenance); `valid` stays `False` with the reason naming encrypted request binding and session freshness.
6. **#18: `reported_tcb` retained** — MET: `details["sev"]["reported_tcb"|"reported_tcb_parts"|"current_tcb"|"current_tcb_parts"]`; consistency with the VCEK-bound SPLs asserted in `test_v5_bundle_full_pipeline_hardware_verified`.

## Negative controls (each independent, all rejecting)

| Control | Test |
|---|---|
| Flipped report byte (policy/report_data/measurement/reported_tcb/chip_id, v3+v5) | `test_flipped_report_byte_in_signed_area_rejected[...]` — report signature + full pipeline reject |
| Flipped signature byte (R start, S start, last byte) | `test_flipped_signature_byte_rejected[...]` |
| Wrong ASK/ARK: real Milan chain vs Genoa VCEK | `test_milan_anchors_reject_genoa_vcek` |
| Wrong ARK key with genuine ARK identity (self-sig passes) | `test_wrong_ark_key_rejects_at_signature_layer` |
| Corrupted ARK file | `test_corrupted_ark_file_fails_closed` |
| Different valid cert substituted for pinned ARK | `test_swapped_valid_anchor_rejected_by_pin` (fingerprint pin) |
| Milan ARK substituted *with re-pinned provenance* | `test_substituted_ark_rejected` (identity check) |
| VCEK for another chip (router-0 VCEK vs router.inf6 report) | `test_vcek_for_another_chip_rejected` (unit + full pipeline) |
| Mismatched TCB: each SPL part flipped independently | `test_mismatched_tcb_rejected_by_spl_binding` |
| Tampered VCEK SPL extension bytes | `test_tampered_vcek_spl_extension_rejected` (ASK→VCEK signature fails) |
| Debug bit set | `test_debug_bit_set_rejected_before_any_trust`, `test_debug_bit_parse_level` |
| report_data not bound to key in use (swapped genuine enclaveCert) | `test_report_data_not_bound_to_key_in_use_rejected` |
| VCEK product ≠ report product | `test_wrong_vcek_product_rejected` |
| Parser structural checks: nonzero reserved byte (v3 FMS pad, v3 reserved, v5 MBZ, v5 ECDSA tail, reserved u32) | `test_nonzero_reserved_byte_rejected[...]` |
| Parser policy checks: reserved bit 63 set / mandatory bit 17 cleared | `test_policy_reserved_bits_enforced` |
| Non-VCEK signer discriminator | `test_non_vcek_signer_rejected` |
| Unsupported report version (4) | `test_unsupported_report_version_rejected` |
| Milan chain fixture genuineness (so the control is meaningful) | `test_milan_chain_fixture_is_genuine` |

## Validation status

- Full suite: `uv run --extra dev --extra nearai pytest -q` → **184 passed** (was 4 failures at epoch start: `tbs_certificatebytes` typo; fixed).
- All verification runs against retained real evidence (two real VCEK-signed reports, two real KDS chains). The only stub is the live-TLS transport in full-pipeline tests (offline CI), matching existing repo practice; no check substitutes a default for a failure.
- Expected values (anchor fingerprints) come from a source independent of the observations: the KDS capture cross-checked against Tinfoil's published PyPI client; hwID/SPL expectations come from the VCEK itself (AMD-issued), not from the report.

## Blockers / honest gaps

- AMD's ABI spec PDF is not downloadable from this host (TLS completes, body never arrives). Layout is established from Tinfoil's published client parser plus intrinsic cryptographic confirmation (signature verifies over [0x000,0x2A0); hwID/SPL extensions match parsed offsets) — recorded in the module docstring. Not a correctness blocker for the checks performed.
- No GitHub access (run rule): go-sev-guest mirrors not consulted; the PyPI publication is the independent second source.
- `valid` remains `False` by design: no encrypted request/session-freshness evidence exists in this lane; the reason is recorded in every row.
- Epoch-0 note carried forward: epoch 0 left the work uncommitted with no report; this epoch fixed the `tbs_certificate_bytes` crash, added the `InvalidSignature`→`ChainError` mapping (tampered input previously crashed the adapter instead of yielding a rejected report), and added all negative controls above.
