# Independent derivation of dstack expected boot registers (2026-11-05)

Reproduction of the pins in `verifiers/dstack_boot_registers.json`: expected
MRTD/RTMR1/RTMR2 for every dstack OS image observed in NEAR AI retained
evidence, plus (MRTD, RTMR0) tuples for the VM shapes Venice and the redpill
ACI gateway expose. Issue #18/#27, teep parity: expected registers must be
derived independently of the observed quotes (teep
docs/attestation_gaps/dstack_integrity.md).

## Tool

dstack-mr 0.6.3, built from dstack-TEE/dstack commit `d7e15dc` (branch `next`,
cached on zed at /data/amiller/api-lanes/cache/dstack). `Machine::measure()` is
the full-image TDX path the upstream dstack verifier uses
(`dstack/verifier/src/verification.rs::compute_measurements`). The harness
(`glm-mr-harness`, source `main.rs` + `Cargo.toml` here, path-deps on dstack-mr)
parses the image's TDVF out of `ovmf.fd`, regenerates the QEMU ACPI blobs from
the VM shape and replays the RTMR0-2 measurement sequence. No VM is started.

## Inputs

OS image archives downloaded 2026-11-05 from
`https://download.dstack.org/os-images/mr_<sha256(sha256sum.txt)>.tar.gz`.
For each archive: `sha256(sha256sum.txt) == <os_image_hash>` verified and every
manifest member digest (ovmf.fd, bzImage, initramfs.cpio.gz, metadata.json)
re-verified on extraction. `is_dev: false` for all four.

| os_image_hash | version | git_revision | observed in (retained evidence) |
|---|---|---|---|
| da9a3d5cc196a1a76d953fb27069be428ddf60a1ce10b0534c3cf968d3053fde | 0.5.4 | f7c795b7… | NEAR gateway (20/27 captures; teep labels the same os_image_hash "0.5.5") |
| 8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd | 0.5.12 | 7f7b2762… | NEAR gateway (7/27 captures); redpill ACI gateway (evidence 2d27859e…) |
| 91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829 | 0.5.12 | 7f7b2762… | NEAR model CVMs (9/27 captures) |
| bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033 | 0.5.9 | e3655d13… | Venice aci/1 attestation (2026-11-05 capture, tests/fixtures/); redpill ACI gateway (evidence 01680c7c…) |

VM shapes (served vm_config, treated as untrusted derivation input; the quote's
hardware registers are what authenticate it):

- `vm_config-venice-bd369a8c.json` and `vm_config-01680c7c.json`: Venice's and
  the redpill gateway's served configs, identical values (32 vCPU, 32 GiB,
  qemu 8.2.2, 0 GPU, 9p).
- 8db40cb2, 16 vCPU, 32 GiB, qemu 8.2.2, 0 GPU, 9p, `ovmf_variant: pre202505`:
  the redpill gateway's vm_config in evidence 2d27859e….

## Procedure

```
glm-mr-harness <extracted_image_dir> <vm_config.json>   # per image, qemu 8.2.2 and 9.1.0
```

- MRTD depends on the QEMU page-add order (`two_pass_add_pages`): qemu 8.x
  measures two-pass, qemu 9.x single-pass. Both variants are recorded per
  image; NEAR does not expose vm_config, so either may legitimately appear.
- shape-sensitivity-bd369a8c.json: RTMR1 and RTMR2 are identical across every
  modeled shape (cpu 4/32/64, memory 8/32/64 GiB, 0/8 GPUs + hotplug_off,
  NVSwitches, hugepages, hotplug_off, pic, qemu 8.0/8.2.2/9.1.0), so they are
  image-level constants. RTMR0 moves with every shape knob, so it is pinned as
  (MRTD, RTMR0) tuples per derived shape.
- derived-registers-per-image.json: the per-image MRTD variants and RTMR1/RTMR2.
- derived-registers.json: the ACI lane's harness output for bd369a8c with
  vm_config-01680c7c.json (MRTD/RTMR0-2).
- 2026-11-15 re-derivation on zed (fix review): bd369a8c/32 vCPU/qemu 8.2.2
  reproduced f06dfda6…, 46a83f6b…, 07e6f51a…, df67e467…; 91fd5d69/qemu 9
  reproduced MRTD df4d77c8…, RTMR1 4ae60980…, RTMR2 bd67ab75…; 8db40cb2/16 vCPU/
  ovmf pre202505 gave MRTD 7fe60787…, RTMR0 d6118f0e…, RTMR1 4ae60980…, RTMR2
  764489f2…. That run's output was recorded by 8-hex prefix only; the full
  RTMR0 for the 16 vCPU tuple was taken from the matching quote in evidence
  2d27859e…, and the other three registers equal the per-image derivation.

## Output validation (after derivation was recorded)

- Every retained NEAR quote whose image is published matched MRTD (one of the
  two derived variants), RTMR1 and RTMR2. Gateway deployments on
  da9a3d5c/8db40cb2 ran two-pass (qemu 8.x); model CVMs on 91fd5d69 ran
  single-pass (qemu 9.x). NEAR exposes no vm_config, so RTMR0 is not derived
  for its shapes and tee_hardware_config reads as unproven.
- Venice capture 2026-11-05 and redpill evidence 01680c7c… (bd369a8c, 32 vCPU):
  derived MRTD/RTMR0/RTMR1/RTMR2 all equal the quote registers.
- Redpill evidence 2d27859e… (8db40cb2, 16 vCPU): all four equal the quote.
- dstack-mr's own integration test (`dstack/dstack-mr/tests/tdvf_parse.rs`)
  pins the same MRTD `f06dfda6…` as the baseline for dstack v0.5.5 firmware,
  the firmware shipped in the 0.5.9 image.
- teep's pinned MRTD set {b24d3b24…, f06dfda6…, df4d77c8…} (capture-derived) is
  exactly {single-pass 0.5.4/0.5.9 firmware, two-pass 0.5.4/0.5.9 firmware,
  single-pass 0.5.12 firmware} from this build-derived set.

## Blocker

os_image_hash a6eafc5f007f642d8ea90c7fa8881f1e6715720ccb531941a28218f4f26d7b02
(dstack 0.5.11/0.5.12-family, NEAR model CVMs in 18/27 captures) is no longer
served at download.dstack.org (404 on 2026-11-05), so no independent
derivation exists for it; its quotes carry MRTD df4d77c8… (consistent with the
0.5.12 firmware's single-pass variant) but RTMR1/RTMR2 differ from every
published image. It has no entry in verifiers/dstack_boot_registers.json, so
such quotes fail tee_boot_config with the archival reason recorded.
