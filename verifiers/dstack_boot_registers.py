"""Boot-register policy: observed dstack quote registers vs derived pins.

Expected values come from verifiers/dstack_boot_registers.json, derived with
dstack-mr from published OS image archives (provenance inside the file and in
research/dstack-mr-derivation-2026-11-05/). Copying an observed register into
that file is not how entries are accepted; see the file's review note.

Missing expectations are rejections with reasons, never a quiet pass: an OS
image with no pinned entry (e.g. an unpublished archive) fails
boot_registers_derived, and so does an unpinned VM shape where shapes are the
only way to pin RTMR0.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

POLICY_PATH = Path(__file__).resolve().parent / "dstack_boot_registers.json"

# vm_config keys that change dstack-mr's output for a given image (see the
# shape-sensitivity record); everything else is ignored when matching a shape.
SHAPE_KEYS = ("cpu_count", "memory_size", "qemu_version", "num_gpus", "num_nvswitches",
              "hugepages", "hotplug_off", "host_share_mode", "pci_hole64_size", "swtpm")


class PolicyError(ValueError):
    """The policy file itself is malformed; nothing may pass while it is."""


@lru_cache(maxsize=1)
def _policy() -> Dict:
    data = json.loads(POLICY_PATH.read_text())
    if data.get("schema") != "dstack-boot-registers/1":
        raise PolicyError("unsupported dstack boot-register policy schema")
    entries = {e["os_image_hash"].lower(): e for e in data.get("entries", [])}
    if not entries:
        raise PolicyError("dstack boot-register policy has no entries")
    for os_hash, e in entries.items():
        if len(os_hash) != 64 or any(c not in "0123456789abcdef" for c in os_hash):
            raise PolicyError(f"invalid os_image_hash {os_hash!r}")
        for field in ("mrtd_two_pass", "mrtd_single_pass", "rtmr1", "rtmr2"):
            if len(e.get(field, "")) != 96:
                raise PolicyError(f"{os_hash[:8]}: malformed {field}")
        for shape in e.get("vm_shapes", []):
            if len(shape.get("rtmr0", "")) != 96 or len(shape.get("mrtd", "")) != 96:
                raise PolicyError(f"{os_hash[:8]}: malformed vm_shape register")
    return {"revision": data["policy_revision"], "entries": entries}


def check_boot_registers(os_image_hash: str, registers: Dict[str, str],
                         vm_config: Optional[Dict] = None) -> Dict:
    """Compare one quote's registers against the pinned derivation.

    Returns {"ok": bool, "per_register": {...}, "reasons": [...]} plus the
    policy revision. RTMR0 is only checkable when the provider's vm_config
    matches a pinned shape; otherwise its reason says so.
    """
    os_hash = str(os_image_hash or "").lower().removeprefix("0x")
    policy = _policy()
    entry = policy["entries"].get(os_hash)
    if entry is None:
        return {"ok": False, "policy_revision": policy["revision"],
                "per_register": {},
                "reasons": [f"os image {os_hash[:16]}… has no pinned derivation; "
                            "archive not derivable or not yet reviewed"]}
    per: Dict[str, Optional[bool]] = {}
    reasons = []
    mrtd = registers.get("mrtd", "")
    per["mrtd"] = mrtd in (entry["mrtd_two_pass"], entry["mrtd_single_pass"])
    if not per["mrtd"]:
        reasons.append("mrtd matches neither derived page-add variant for this image")
    for reg in ("rtmr1", "rtmr2"):
        per[reg] = registers.get(reg, "") == entry[reg]
        if not per[reg]:
            reasons.append(f"{reg} does not match the derived value for this image")

    if entry.get("vm_shapes"):
        if vm_config is None:
            per["rtmr0"] = None
            reasons.append("rtmr0 requires the deployment vm_config, which this "
                           "attestation does not expose")
        else:
            shape = {k: vm_config.get(k) for k in SHAPE_KEYS}
            pinned = next((s for s in entry["vm_shapes"]
                           if {k: s["shape"].get(k) for k in SHAPE_KEYS} == shape), None)
            if pinned is None:
                per["rtmr0"] = False
                reasons.append("vm shape is not pinned for this os image")
            else:
                per["rtmr0"] = registers.get("rtmr0", "") == pinned["rtmr0"]
                per["mrtd"] = mrtd == pinned["mrtd"]
                if not per["rtmr0"]:
                    reasons.append("rtmr0 does not match the derived value for this "
                                   "os image and vm shape")
                if not per["mrtd"]:
                    reasons.append("mrtd does not match the derived value for this "
                                   "os image and vm shape")
    else:
        per["rtmr0"] = None
        reasons.append("rtmr0 depends on the VM shape and no shape is pinned for "
                       "this os image (provider does not expose vm_config)")

    ok = all(v is True for v in per.values())
    return {"ok": ok, "policy_revision": policy["revision"],
            "per_register": per, "reasons": reasons}
