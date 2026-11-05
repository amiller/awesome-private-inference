# GLM dstack lane report — 2026-11-05, epoch 1

Issue #18 (NEAR part, first box) + teep parity for NEAR AI and Venice
(dstack/Phala TDX CVMs). Spec: docs/tasks/glm-dstack-20261105.md.
Branch glm/dstack-20261105; commits b7a088e, d7000cb, 89c78b4, 823e56f.

## What changed

- verifiers/dstack_tdx.py (new): offline dcap-qvl quote parse (MRTD,
  RTMR0-3, MRCONFIGID, REPORTDATA, TD_ATTRIBUTES, MRSEAM); TD debug-bit
  check; event-log replay to all four RTMRs with dstack cc-eventlog runtime
  digest recomputation (stored digest must match payload or replay raises);
  attestation_measurements() binds one quote to its log and returns the
  log-authenticated app-id/compose-hash/os-image-hash.
- verifiers/dstack_boot_registers.py + verifiers/dstack_boot_registers.json
  (new): boot-register policy. MRTD (both QEMU page-add variants), RTMR1,
  RTMR2 pinned per published OS image; RTMR0 pinned per VM shape where the
  provider exposes vm_config. Malformed policy raises; unknown image /
  unpinned shape are rejections with reasons, never skips.
- verifiers/near_ai.py: _check_tdx docstring now states the split (verified =
  signature appraisal for UpToDate/OutOfDate; currency policy separate).
  _measurement_checks() per attestation (gateway + every model CVM): replay
  equality, debug bit, detached-JSON agreement, boot pins. Model compose
  authorization consumes the log-authenticated compose hash and app-id.
  New scorecard layers tcb_current / tee_debug_disabled / event_log_replayed
  / boot_registers_derived wired into checked_ok; details.tdx entries carry
  tcb_status, advisory_ids, intel_quote, registers, td_attributes and
  per-register pin results; details.tcb_policy records the explicit policy.
- verifiers/venice.py: aci/1 evidence support (quote/event_log/vm_config/
  app_compose under attestation.evidence; top-level quote duplicate must
  agree), same measurement layers, tcb_current from local dcap-qvl appraisal,
  phala_tcb_status retained (null, confirmed live). Legacy shape reports the
  new layers unproven (None) except the debug bit. GPU/NRAS path untouched;
  nvidia_nras.py untouched.
- verifiers/common.py: 4 new ScoreCard fields; tdx+gpu and venice required
  sets extended; BAR_NOTES updated. probes/render.py: labels.
- research/dstack-mr-derivation-2026-11-05/: my derivation record (harness
  source reused read-only from the aci lane's build, per-image derivation,
  shape-sensitivity experiment, Venice vm_config).
- tests: test_dstack_tdx.py (13), test_near_measurements.py (9),
  test_venice_measurements.py (10), test_dstack_boot_registers.py (8).
  tests/fixtures/venice_tee_attestation_e2ee-glm-5-1.json: verbatim live
  capture 2026-11-05T20:30:09Z, unauthenticated, no credential involved.

## Success criteria status (spec SC1-SC6)

- SC1 NEAR TCB retention + explicit OutOfDate policy: MET. Retention was
  already in 9266390 and is preserved per quote; tcb_current added with
  TCB_CURRENT_STATUSES = {"UpToDate"} (teep tee_tcb_current parity). Proof:
  test_outofdate_gateway_flips_tcb_current_and_keeps_advisories (Out OfDate
  gateway → tcb_current False, tdx_verified still True, advisories retained);
  test_verdicts_that_fail_appraisal_reject_the_row (SWHardeningNeeded /
  Revoked / ConfigurationAndSWHardeningNeeded reject the quote outright).
- SC2 Venice TCB: MET. Phala's hosted verifier returns no TCB verdict —
  recorded as phala_tcb_status: null, confirmed on a live run 2026-11-05;
  the real status comes from a local dcap-qvl appraisal (live run:
  UpToDate, advisories []). Proof: test_live_capture_passes_measurement_layers,
  test_outofdate_dcap_verdict_fails_tcb_current, live run in this report.
- SC3 tee_debug_disabled: MET for NEAR (gateway + every model quote) and
  Venice (aci/1 and legacy shapes). Negative controls:
  test_debug_bit_clear_on_real_quotes_and_set_when_flipped,
  test_debug_bit_flip_fails_only_debug_layer (NEAR),
  test_debug_bit_flip_fails_debug_layer (Venice).
- SC4 boot registers vs independent derivation: MET with two recorded
  blockers. Pins derived with dstack-mr 0.6.3 (d7e15dc) from published
  archives (hash chain + manifest digests re-verified); all 45 retained
  NEAR attestations on published images matched (MRTD one of the two
  page-add variants, RTMR1/RTMR2 equal); Venice bd369a8c + exposed vm shape
  matches all four registers (test_venice_shape_pins_all_four_registers;
  also equals the aci lane's independent derivation of the same shape).
  Blockers: (a) NEAR exposes no vm_config → RTMR0 un-derivable → layer False
  with reason per quote (required-and-unexposed, Venice-prod_os_image
  precedent); (b) os image a6eafc5f… (18/27 attestations) is no longer
  served at download.dstack.org (404, 2026-11-05) → no derivation possible
  → rejected with that reason. Negative controls:
  test_tampering_each_register_is_rejected, test_unknown_os_image_is_rejected_not_skipped,
  test_venice_unpinned_shape_is_rejected, test_vm_shape_without_vm_config_cannot_pass_rtmr0,
  test_malformed_policy_is_a_policy_error.
- SC5 event-log integrity: MET for NEAR and Venice (aci/1). Replay to
  RTMR0-3 with equality required for covered IMRs; runtime-event digests
  recomputed from (type, event, payload) — stored-digest disagreement
  raises; compose-hash/app-id/os-image-hash are read from the replayed log
  and the detached JSON must agree. Negative controls:
  test_replay_rejects_* / test_runtime_event_digest_rejects_* (NEAR unit),
  test_event_log_tamper_* (NEAR + Venice wiring),
  test_detached_json_disagreement_with_log_fails_replay,
  test_os_image_hash_disagreement_between_log_and_vm_config.
- SC6 required layers + BAR_NOTES: MET for tdx+gpu and venice shapes
  (inclusions only). test_every_required_layer_has_a_display_name passes
  with the four new labels.

## Independent-value sourcing

- Expected boot registers: computed from published OS image archives with
  dstack-mr before any comparison; cross-checked against teep's
  capture-derived MRTD pins (b24d3b24/f06dfda6/df4d77c8 = three of the
  build-derived variants) and the aci lane's derivation. No observed quote
  value was copied into the policy.
- Anchor/chain checks for NEAR remain the pinned hermes-agent anchor and
  Base contract queries (unchanged).
- Tests run against retained real evidence (data/observations/evidence,
  27 NEAR captures) and the committed Venice live capture. Mocks are
  transport only (attestation HTTP, Base RPC replayed from the captured
  block, dcap collateral verdict stubbed parameterizably in unit tests).

## Live evidence collected

- Venice /api/v1/tee/attestation, 2026-11-05T20:30:09Z, unauthenticated
  (no credential), committed verbatim as
  tests/fixtures/venice_tee_attestation_e2ee-glm-5-1.json. Shows the aci/1
  migration (event_log + vm_config now exposed).
- Live full-verify run of venice.verify against the real endpoint with the
  real Phala verifier and real Intel PCS collateral: all layers True, dcap
  UpToDate, phala_tcb_status null.
- Four OS image archives downloaded from download.dstack.org and
  re-verified (kept under gitignored local-data/, not committed).

## Blockers (precise)

1. NEAR RTMR0 (and per-shape RTMR0 confirmation): NEAR's
   /v1/attestation/report does not expose vm_config (would be retained by
   the whitelist; absent from all 27 captures). RTMR0 depends on the VM
   shape. boot_registers_derived therefore honestly fails for NEAR rows
   with the reason recorded per quote.
2. os_image_hash a6eafc5f007f642d…: archive 404 at download.dstack.org on
   2026-11-05, so no dstack-mr derivation exists; 18/27 retained NEAR
   attestations (model CVMs) fail boot_registers_derived with that reason.
   Observed MRTD df4d77c8… is consistent with the 0.5.12 firmware's
   single-pass variant but that observation is not verification.
3. No NEAR API key: NEAR checks validated against retained evidence only;
   no fresh NEAR capture was possible. dcap-qvl collateral appraisal of the
   retained NEAR quotes re-runs on every unit test run only as the stubbed
   verdict (collateral fetch is transport).
4. Issue box 2 (dashboard TCB display) and the other boxes of #18 are not
   this lane's scope; the data they need (tcb_status/advisories per quote)
   now lands in row details and the scorecard.

## Validation status

- Full suite: ~/.local/bin/uv run --extra dev --extra nearai pytest -q →
  193 passed after each milestone (165 → 174 → 183 → 193).
- Honest limits: unit tests stub the dcap verdict (transport) so TCB-status
  handling is proven at the policy layer, not against live Intel PCS for
  NEAR; the Venice live run covers that path end to end. Snapshot/dashboard
  regeneration not run (CI owns it); coverage classification for existing
  rows will show the new required layers as unmet until the next daily run,
  which is the intended visibility change.
