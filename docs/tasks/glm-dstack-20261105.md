# GLM dstack lane spec — 2026-11-05

Lane: dstack (NEAR AI + Venice on dstack/Phala TDX CVMs). Issue #18 (NEAR part,
first box) + teep parity (github.com/13rac1/teep, read-only clone at
/home/amiller/installing/teep; factors in internal/attestation/report.go,
internal/attestation/eventlog.go, internal/attestation/dstack_defaults.go,
known gaps in docs/attestation_gaps/dstack_integrity.md).

Entry points: verifiers/near_ai.py, verifiers/venice.py, verifiers/phala_tdx.py,
verifiers/common.py (REQUIRED_LAYERS_BY_SHAPE). Forbidden: verifiers/nvidia_nras.py
and Venice's GPU/NRAS path (owned by another lane).

## Teep parity items (from the brief, checked against the teep source)

1. TCB status (#18 NEAR part): near_ai.py must retain dcap status + advisory IDs
   per quote in row details (retention landed upstream in 9266390; keep it), and
   the OutOfDate policy must be explicit — teep's `tee_tcb_current` factor
   (report.go evalTDXTCBCurrent) passes only UpToDate and fails
   OutOfDate/Revoked/SWHardeningNeeded/ConfigurationAndSWHardeningNeeded/
   OutOfDateConfigurationNeeded. Venice goes through the Phala-hosted verifier:
   retain whatever TCB status it returns, or record that it returns none.
2. tee_debug_disabled: TD_ATTRIBUTES byte0 bit0 (teep tdx.go tdxDebugBit = 0x01)
   for every NEAR and Venice quote.
3. MRTD/RTMR0-2 vs independently derived values: dstack OS image version comes
   from the quote/event log; reproduce expected registers with dstack-mr for
   that image (aci lane's harness + built binary reused read-only; my own
   derivation record committed). Copying observed registers into the expected
   set is not verification.
4. Event-log integrity: replay the event log to RTMR3 and to RTMR0-2 where the
   log covers them; require equality with the quote registers; compose_hash /
   app_id must come from the replayed log, not detached JSON.

## Success criteria I commit to

- SC1 (item 1, NEAR): every probe retains per quote (gateway + each model CVM)
  `tcb_status`, `advisory_ids`, `intel_quote`, plus an explicit policy layer
  `tcb_current` (True only for UpToDate; False for every non-UpToDate Intel
  PCS verdict; None recorded as None with reason, never silently True). An
  OutOfDate gateway or model CVM turns `tcb_current` False and is visible in
  row details with its advisory IDs.
- SC2 (item 1, Venice): the Phala-hosted verifier response is retained in
  details; if it carries no TCB verdict that is recorded as
  `phala_tcb_status: null`; Venice quotes additionally get a local dcap-qvl
  appraisal with real status/advisories retained like NEAR.
- SC3 (item 2): `tee_debug_disabled` scorecard layer for NEAR (gateway + every
  model quote) and Venice; TD_ATTRIBUTES retained in details.
- SC4 (item 3): pinned expected boot registers in
  `verifiers/dstack_boot_registers.json`, keyed by os_image_hash (+ vm shape
  where RTMR0-2 are derivable), derived with dstack-mr from the published
  image archive. MRTD checked for NEAR and Venice. RTMR0-2 checked where the
  provider exposes vm_config (Venice's aci/1 evidence does). NEAR does not
  expose vm_config: recorded as a precise blocker, layer False with reason
  (required-and-unexposed, mirroring the Venice prod_os_image precedent), never
  silently passed. New layer `boot_registers_derived`.
- SC5 (item 4): `event_log_replayed` layer — replay to RTMR0-3 where the log
  covers those IMRs, equality with the authenticated quote registers required;
  runtime events recomputed from (event_type, event, payload) per dstack
  cc-eventlog (stored digest must match or the check fails); compose-hash,
  app-id, os-image-hash read from the replayed log and cross-checked against
  the detached JSON info fields — mismatch is a rejection.
- SC6: REQUIRED_LAYERS_BY_SHAPE gains the new layers for "tdx+gpu" and
  "venice" shapes (inclusions only; BAR_NOTES updated where the note must say
  what each layer's failure means).

## Negative controls (each must FAIL the new check when tampered)

- N1 debug bit: set TD_ATTRIBUTES byte0 bit0 in a retained quote →
  tee_debug_disabled False.
- N2 each register: flip MRTD, RTMR0, RTMR1, RTMR2, RTMR3 in the quote (and in
  the pinned policy) → replay/pin check fails on that register only.
- N3 event log: alter an event-log entry (digest, payload, event name, imr
  index), drop an entry, add an entry → replay equality or payload binding
  fails.
- N4 detached-JSON binding: swap the detached app_id/compose_hash/os_image_hash
  so it disagrees with the replayed log → rejection even though the log itself
  still replays to the quote.
- N5 TCB: an OutOfDate verdict (and each other non-UpToDate verdict) makes
  tcb_current False; UpToDate makes it True; missing status stays None.
- N6 policy tamper: a quote whose (os_image_hash, vm shape) has no pinned entry
  is rejected, not skipped; a tampered policy digest/register is rejected.

## Evidence sources

- Retained real evidence: data/observations/evidence/sha256/*.json (27 NEAR
  captures: gateway os images da9a3d5c… (0.5.5) and 8db40cb2…, model CVMs
  a6eafc5f… (0.5.11/12) and 91fd5d69…; full quotes + event logs retained).
- Venice: fresh unauthenticated capture from
  https://api.venice.ai/api/v1/tee/attestation (2026-11-05), now serving the
  aci/1 format with quote, event_log and vm_config (os image bd369a8c…,
  dstack-0.5.9). Sanitized capture committed under tests/fixtures/ with capture
  time and URL. No credential involved.
- dstack-mr 0.6.3 (dstack-TEE/dstack d7e15dc), harness binary built by the aci
  lane (reused read-only at /data/amiller/api-lanes/cache/dstack-target/release/
  glm-mr-harness); image archives from https://download.dstack.org/os-images/.
  My own derivation record committed under research/.

## What I cannot do (precise blockers, recorded as found)

- NEAR RTMR0-2 dstack-mr derivation: NEAR's /v1/attestation/report exposes no
  vm_config (whitelist in _public_attestation_fields would keep it; 27
  retained captures have none), and RTMR0-2 depend on the VM shape
  (cpu/memory/gpus/qemu version; teep dstack_integrity.md). Only MRTD is
  image-derived; RTMR0-2 stay replay-bound (item 4) and un-pinned, layer False
  with reason.
- No NEAR or Venice API key: NEAR checks run against retained evidence only;
  Venice attestation is unauthenticated so live capture works. Venice GPU/NRAS
  path untouched (other lane).
- Dashboard TCB display (issue box 2) is not this lane's box; the data lands in
  row details/scorecard for whichever lane owns the view.

## Milestones

- M1: verifiers/dstack_tdx.py (offline quote parse, debug bit, full RTMR0-3
  replay, runtime-event extraction) + unit tests against retained NEAR
  evidence with N1-N4 controls. Suite green.
- M2: near_ai.py wiring: SC1, SC3, SC5; TCB policy; details; tests (N1-N5).
- M3: venice.py: aci/1 format support, SC2/SC3/SC5, fixture capture, tests.
- M4: dstack-mr derivation records + dstack_boot_registers.json + SC4 policy
  enforcement + tests (N2, N6). RTMR0-2 for Venice.
- M5: REQUIRED_LAYERS_BY_SHAPE/BAR_NOTES (SC6), full suite, report polish.
