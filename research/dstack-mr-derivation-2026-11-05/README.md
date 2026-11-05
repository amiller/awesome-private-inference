# Independent derivation of ACI expected boot registers (2026-11-05)

Reproduction of the pinned values in `verifiers/aci_boot_registers.json`
(issue #27: expected MRTD/RTMR0-2 must be derived independently of the
observed quote).

## Tool

dstack-mr 0.6.3, built from dstack-TEE/dstack commit `d7e15dc` (branch `next`,
cloned 2026-11-05). `Machine::measure()` is the same full-image TDX path the
upstream dstack verifier uses to check attested deployments
(`dstack/verifier/src/verification.rs::compute_measurements`): it parses the
TDVF out of the image's `ovmf.fd`, regenerates the QEMU ACPI blobs from the VM
shape, and replays the RTMR0-2 measurement sequence — no VM is started.

## Inputs

- OS image: `https://download.dstack.org/os-images/mr_bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033.tar.gz`
  (17,363,776 bytes; image `dstack-0.5.9-bd369a8c`, dstack 0.5.9, git_revision
  `e3655d1390feee3736476f4bda35c4354b4a12fc`, `is_dev: false`).
  `sha256(sha256sum.txt) == bd369a8c…` and every manifest entry
  (ovmf.fd, bzImage, initramfs.cpio.gz, metadata.json) re-verified on download.
- `vm_config-01680c7c.json`: the vm_config served by the gateway and retained
  in evidence `01680c7c…`. It is treated as an untrusted claim here; the
  hardware registers it is compared against are what authenticate it.

## Procedure (on zed, 2026-11-05)

```
cargo build --release          # in a clone of dstack at d7e15dc, workspace dstack/
# harness = Cargo.toml + src/main.rs in this directory (path-deps on dstack-mr)
glm-mr-harness <extracted_image_dir> vm_config-01680c7c.json > derived-registers.json
```

## Output

`derived-registers.json` — mrtd/rtmr0/rtmr1/rtmr2. All four matched the
observed quote body of evidence `01680c7c…` (tee.redpill.ai workload) on
first comparison, after the derivation had already been recorded.

Note: dstack-mr's own integration test (`dstack/dstack-mr/tests/tdvf_parse.rs`)
independently pins the same MRTD `f06dfda6…` as the baseline for dstack v0.5.5
firmware, which is the firmware shipped in the 0.5.9 image.
