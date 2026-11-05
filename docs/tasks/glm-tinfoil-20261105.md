# GLM tinfoil lane — 2026-11-05

Issue: #26 (Tinfoil adapter: authenticate the AMD report and certificate chain)
plus the Tinfoil part of #18 (retain `reported_tcb`/`current_tcb` in row details).

Entry points: `verifiers/tinfoil.py`, `verifiers/tinfoil_sev.py`.
Retained real evidence: `tests/fixtures/tinfoil_atc_bundle.json` (SEV report v3,
DER VCEK ~1347 bytes, router.inf6.tinfoil.sh) and v5 reports + VCEKs retained
under `data/observations/evidence/sha256/` (router-0.tinfoil.sh, captured by the
daily probe through 2026-11-05).

## Layout determination (before trusting any parsed field)

The repo parser assumed a v3-only layout with no signature verification. Live
daily-probe evidence is report **version 5** (SEV SNP ABI rev 1.58). Offsets
were determined from Tinfoil's published reference client (`tinfoil==0.15.0`
from PyPI, `attestation/abi_sev.py`, which encodes the ABI spec layout) and
confirmed against the retained reports cryptographically:

- chip_id at 0x1A0–0x1E0 (64 bytes) — independently corroborated: it equals the
  VCEK `hwID` extension (1.3.6.1.4.1.3704.1.4) of the ASK-signed VCEK.
- reported_tcb at 0x180–0x188 — corroborated by VCEK SPL extensions
  (…1.3.1 bl, …1.3.2 tee, …1.3.3 snp, …1.3.8 ucode).
- signature: ECDSA P-384/SHA-384 over bytes [0x000, 0x2A0); R = LE integer in
  0x2A0–0x2E8, S = LE integer in 0x2E8–0x318 (72-byte halves). Confirmed by
  successful verification under the VCEK public key for every retained report;
  all other candidate extents/offsets fail.
- v3: family/model/stepping at 0x188; 0x1F8–0x2A0 MBZ. v5: 0x1F8 launch_mit_vector
  and 0x200 current_mit_vector are valid; 0x208–0x2A0 MBZ. 0x318–0x4A0 MBZ for
  ECDSA. Structural MBZ checks are enforced per version as in the reference.

## Success criteria from issue #26 and how this lane meets them

1. **Authenticate the signed report under the AMD chain, including report
   format, signature coverage and applicable TCB/debug policy.**
   - Pin ARK-Genoa/ASK-Genoa (DER SHA-256 fingerprints) captured from
     https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain on 2026-11-05,
     cross-checked byte-identical against the chain embedded in Tinfoil's
     published `tinfoil==0.15.0` client (two independent publications).
   - Verify ARK self-signature (RSA-PSS), ARK→ASK (RSA-PSS), ASK→VCEK
     (RSA-PSS, parameters from the certificate), issuer DN linkage, validity
     window, VCEK format (v3, ECDSA P-384 key, CN=SEV-VCEK, product ext,
     no CSP_ID).
   - Verify ECDSA P-384/SHA-384 report signature over the exact signed bytes.
   - Enforce debug policy off (existing check kept; policy structural checks
     added: reserved bit 17 set, bits 63–26 zero).
   - Bind VCEK hwID == report.chip_id and VCEK SPLs == report.reported_tcb
     parts.
2. **Match the authenticated report body to the measurement and TLS/HPKE keys
   the adapter actually uses.** Hardware verification now runs *before* the
   sigstore-measurement match and the report_data→(TLS SPKI, HPKE SAN, hatt)
   bindings, so those bindings consume authenticated fields only.
3. **Retain a sanitized known-good replay packet with exact versions.**
   Fixture `tests/fixtures/tinfoil_atc_bundle.json` (v3) plus a new v5 replay
   fixture extracted from retained daily-probe evidence with evidence hash and
   capture date. `data/verifiers.json` records instrument identity and external
   appraisal trust (KDS fetch + PyPI cross-check).
4. **Negative controls (each independent, asserted to fail/reject):** flipped
   report byte, flipped signature byte, wrong ASK/ARK (Milan chain against a
   Genoa report; tampered ARK file), VCEK for another chip (router-0 VCEK vs
   router.inf6 report), mismatched TCB (tampered VCEK SPL extension; VCEK whose
   SPLs ≠ report), debug bit set, report_data not bound to the key in use
   (swapped enclaveCert). Missing chain (per-host `vcek_b64=""`) stays
   `not_checked` with reason, never passes.
5. **Publish performed checks, remaining obligations.** `details` carries the
   structured hardware verification record; scorecard gains
   `hardware_signature_verified=True` only on full success. `valid` stays False
   (encrypted request binding / session freshness remain unproven); the
   recorded reason names exactly what remains.

## #18 part

`details["sev"]` now retains `reported_tcb` and `current_tcb` (hex + decomposed
SPL parts). These are VCEK-bound (authenticated) whenever the hardware chain
verified, and labeled unauthenticated otherwise.

## Negative controls to test

See criterion 4. Each mutation is applied to the real retained fixtures
individually; every check that can pass has a test proving it rejects the
tampered input.

## Blockers / cannot-do

- AMD's ABI spec PDF cannot be downloaded from amd.com (TLS completes, document
  body never arrives from this host). Layout is instead established from
  Tinfoil's published client parser + intrinsic cryptographic confirmation
  (signature verification success, hwID/SPL binding). Recorded in the report.
- No GitHub access (run rule), so go-sev-guest &c. mirrors were not consulted.
  The PyPI cross-check stands in as the independent second source.
