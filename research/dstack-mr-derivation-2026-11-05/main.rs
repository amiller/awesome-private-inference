// Mirrors dstack/verifier/src/verification.rs::compute_measurements (the
// full-image TDX path) so expected MRTD/RTMR0-2 are recomputed from the
// published OS image files plus the deployment's vm_config, without running
// a VM. Inputs: image dir, path to vm_config JSON as served by the gateway.
use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct ImageMetadata {
    bios: String,
    kernel: String,
    initrd: String,
    cmdline: String,
    #[serde(default)]
    kernel_header_normalized: bool,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let image_dir = args.next().context("usage: harness <image_dir> <vm_config.json>")?;
    let vm_config_path = args.next().context("usage: harness <image_dir> <vm_config.json>")?;

    let vm_config: dstack_types::VmConfig = serde_json::from_str(&std::fs::read_to_string(
        &vm_config_path,
    )?)
    .context("failed to parse vm_config")?;

    let meta_path = Path::new(&image_dir).join("metadata.json");
    let meta: ImageMetadata =
        serde_json::from_str(&std::fs::read_to_string(&meta_path)?).context("parse metadata")?;
    let kernel_cmdline =
        dstack_mr::tdx::measured_kernel_cmdline(&meta.cmdline);

    let firmware = Path::new(&image_dir).join(&meta.bios).display().to_string();
    let kernel = Path::new(&image_dir).join(&meta.kernel).display().to_string();
    let initrd = Path::new(&image_dir).join(&meta.initrd).display().to_string();
    let ovmf_variant = vm_config.ovmf_variant.clone().unwrap_or_default();

    let measurements = dstack_mr::Machine::builder()
        .cpu_count(vm_config.cpu_count)
        .memory_size(vm_config.memory_size)
        .firmware(&firmware)
        .kernel(&kernel)
        .initrd(&initrd)
        .kernel_cmdline(&kernel_cmdline)
        .root_verity(true)
        .hotplug_off(vm_config.hotplug_off)
        .maybe_two_pass_add_pages(vm_config.qemu_single_pass_add_pages)
        .normalized_setup_header(meta.kernel_header_normalized)
        .maybe_pic(vm_config.pic)
        .maybe_qemu_version(vm_config.qemu_version.clone())
        .maybe_pci_hole64_size(if vm_config.pci_hole64_size > 0 {
            Some(vm_config.pci_hole64_size)
        } else {
            None
        })
        .hugepages(vm_config.hugepages)
        .numa_nodes(&vm_config.numa_nodes)
        .num_gpus(vm_config.num_gpus)
        .num_nics(vm_config.num_nics)
        .num_verity_volumes(vm_config.num_verity_volumes)
        .extra_root_devices(&vm_config.extra_root_devices)
        .swtpm(vm_config.swtpm)
        .num_nvswitches(vm_config.num_nvswitches)
        .host_share_mode(vm_config.host_share_mode.clone())
        .ovmf_variant(ovmf_variant)
        .build()
        .measure()
        .context("failed to compute measurements")?;

    println!(
        "{}",
        serde_json::json!({
            "mrtd": hex::encode(&measurements.mrtd),
            "rtmr0": hex::encode(&measurements.rtmr0),
            "rtmr1": hex::encode(&measurements.rtmr1),
            "rtmr2": hex::encode(&measurements.rtmr2),
        })
    );
    Ok(())
}
