# Chutes 912aec3d: the October 12 unpublished-image case cannot be replayed

Issue #28 asks us to replay the 2026-10-12 unpublished-image case from retained
evidence, or record why we can't. We can't. This note records what was kept,
what is missing, and what the tests do instead.

## What was observed

On 2026-10-12, two instances were listed for `Qwen/Qwen3-32B-TEE`
(`providers/chutes.md`, commit `4b0b843`). Instance `45130fc6` matched a
published row. Instance `912aec3d-1231-421d-97d7-f5c81fc7988a` returned a TDX
quote that verified as `UpToDate` and was bound to our nonce. Its MRTD was
`ddc6efcd…`, and its MRTD and RTMR0-3 matched no row of
`/servers/tee/measurements`. All 55 rows of that publication carried MRTD
`261CE538…`.

## What was retained

`data/snapshots/2026-10-12.json` holds the daily adapter's row for
`Qwen3-32B-TEE` at 22:43:50Z. That row is for instance `912aec3d` and records
the instance ID, the E2E pubkey, the full MRTD `ddc6efcd…8455`,
`gpu_evidence_count: 1`, `mrtd_in_golden_set: false`, and the scorecard flags
(`tdx_verified`, `report_data_binds_key`, `nonce_bound` all true).

## What is missing

- The quote. The adapter at that revision did not store `quote_b64`. All 200
  Chutes quotes stored under `data/observations/evidence/` decode to MRTD
  `261ce538` (checked 2026-11-15 by parsing each stored quote, not by grepping
  for hex).
- RTMR0-3. The finding that the RTMRs matched no row comes from the manual
  session. Neither that session nor the snapshot kept the register values.
- The nonce, the evidence certificate and the GPU evidence blobs.
- The `/servers/tee/measurements` publication as it stood on that day. Neither
  its content nor its digest was kept.

Without the quote, the TDX signature, the nonce binding and the register
comparison cannot be re-run. The only thing that can be checked is that the
recorded MRTD differs from `261ce538`.

One more detail: `ddc6efcd…` is not a never-published value. It is the second
row of `data/audits/chutes_tee.json`. That ledger records it as a golden-set
member that was sampled from 2026-06-18 to 2026-09-02. So on October 12 it was
an image that had been withdrawn from the publication, not one that had never
appeared in it. Whether the RTMRs had also been published before can't be
determined from what we kept.

## What the tests do instead

`tests/test_chutes_fleet.py::test_unpublished_image_instance_rejects_row_not_signature`
uses a synthetic quote that verifies but whose measurements are not published.
It checks that the row is rejected as a measurement-list mismatch while
`tdx_verified` stays true. That covers the behaviour #28 asks for. It is not a
replay of 912aec3d.

Every instance the adapter now appraises keeps its quote, registers, matched
row and publication digest (`raw_evidence.fleet_census`,
`golden_publication`). A later case like this one can therefore be replayed.
