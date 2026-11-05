# Independent derivation of dstack expected boot registers (2026-11-05, dstack lane)

Reproduction of expected MRTD/RTMR1/RTMR2 for every dstack OS image observed in
NEAR AI retained evidence, plus the full MRTD/RTMR0-2 set for the VM shape
Venice's attestation exposes. Issue #18/teep parity: expected registers must be
derived independently of the observed quotes (teep
docs/attestation_gaps/dstack_integrity.md).

## Tool

dstack-mr 0.6.3, built from dstack-TEE/dstack commit `d7e15dc` (branch `next`,
cached at /data/amiller/api-lanes/cache/dstack). `Machine::measure()` is the
full-image TDX path the upstream dstack verifier uses
(`dstack/verifier/src/verification.rs::compute_measurements`). The harness
binary was built by the aci lane (`glm-mr-harness`,
/data/amiller/api-lanes/cache/dstack-target/release/) and is reused read-only;
its source (`main.rs`, `Cargo.toml`) is copied here unchanged. No VM is
started; the tool parses the image's TDVF, regenerates QEMU ACPI blobs and
replays the measurement sequence.

## Inputs

OS image archives downloaded 2026-11-05 from
`https://download.dstack.org/os-images/mr_<sha256(sha256sum.txt)>.tar.gz`.
For each archive: `sha256(sha256sum.txt) == <os_image_hash>` verified and every
manifest member digest (ovmf.fd, bzImage, initramfs.cpio.gz, metadata.json)
re-verified on extraction. `is_dev: false` for all four.

| os_image_hash | version | git_revision | observed in (retained evidence) |
|---|---|---|---|
| da9a3d5cc196a1a76d953fb27069be428ddf60a1ce10b0534c3cf968d3053fde | 0.5.4 | f7c795b7… | NEAR gateway (20/27 captures; teep labels the same os_image_hash "0.5.5") |
| 8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd | 0.5.12 | 7f7b2762… | NEAR gateway (7/27 captures) |
| 91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829 | 0.5.12 | 7f7b2762… | NEAR model CVMs (9/27 captures) |
| bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033 | 0.5.9 | e3655d13… | Venice aci/1 attestation (2026-11-05 capture, tests/fixtures/) |

`vm_config-venice-bd369a8c.json` is Venice's served vm_config (32 vCPU,
32 GiB, qemu 8.2.2, 0 GPU, 9p) from the capture; hardware registers compare
against the quote, so an untruthful vm_config fails rather than passes.

## Procedure (2026-11-05)

```
glm-mr-harness <extracted_image_dir> <vm_config.json>   # per image, qemu 8.2.2 and 9.1.0
```

- MRTD depends on the QEMU page-add order (`two_pass_add_pages`): qemu 8.x
  measures two-pass, qemu 9.x single-pass. Both variants are recorded per
  image; NEAR does not expose vm_config, so either may legitimately appear.
- shape-sensitivity-bd369a8c.json: RTMR1 and RTMR2 are identical across every
  modeled shape (cpu 4/32/64, memory 8/32/64 GiB, 0/8 GPUs + hotplug_off,
  NVSwitches, hugepages, hotplug_off, pic, qemu 8.0/8.2.2/9.1.0), so they are
  image-level constants. RTMR0 moves with every shape knob and is pinned only
  where the provider exposes vm_config (Venice).
- derived-registers-per-image.json: the pinned values.

## Output validation (after derivation was recorded)

- Every retained NEAR quote whose image is published (45 attestations across
  27 captures) matched: MRTD one of the two derived variants, RTMR1 and RTMR2
  equal. Gateway deployments on da9a3d5c/8db40cb2 ran two-pass (qemu 8.x);
  model CVMs on 91fd5d69 ran single-pass (qemu 9.x).
- Venice capture 2026-11-05 (bd369a8c, 32 vCPU/32 GiB/qemu 8.2.2): derived
  MRTD/RTMR0/RTMR1/RTMR2 all equal the quote registers, and equal the aci
  lane's independent derivation for the identical VM shape.
- teep's pinned MRTD set {b24d3b24…, f06dfda6…, df4d77c8…} (capture-derived) is
  exactly {single-pass 0.5.4/0.5.9 firmware, two-pass 0.5.4/0.5.9 firmware,
  single-pass 0.5.12 firmware} from this build-derived set.

## Blocker

os_image_hash a6eafc5f007f642d8ea90c7fa8881f1e6715720ccb531941a28218f4f26d7b02
(dstack 0.5.11/0.5.12-family, NEAR model CVMs in 18/27 captures) is no longer
served at download.dstack.org (404 on 2026-11-05), so no independent
derivation exists for it; its quotes carry MRTD df4d77c8… (consistent with the
0.5.12 firmware's single-pass variant) but RTMR1/RTMR2 differ from every
published image. Admitted as no entry in verifiers/dstack_boot_registers.json;
such quotes fail boot_registers_derived with the archival reason recorded.
