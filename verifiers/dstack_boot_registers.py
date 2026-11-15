"""Boot-register policy: observed dstack quote registers vs derived pins.

Expected values come from verifiers/dstack_boot_registers.json, derived with
dstack-mr from published OS image archives (provenance inside the file and in
research/dstack-mr-derivation-2026-11-05/). Copying an observed register into
that file is not how entries are accepted; see the file's review note.

Two checks, split as teep splits tee_boot_config / tee_hardware_config:
  boot_config      MRTD (either QEMU page-add variant) + RTMR1 + RTMR2 equal the
                   per-image derivation. An unpinned image fails.
  hardware_config  (MRTD, RTMR0) is one of the derived tuples pinned for the
                   image's VM shapes. None when the image has no derived RTMR0.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict

POLICY_PATH = Path(__file__).resolve().parent / "dstack_boot_registers.json"


class PolicyError(ValueError):
    """The policy file itself is malformed; nothing may pass while it is."""


@lru_cache(maxsize=1)
def _policy() -> Dict:
    data = json.loads(POLICY_PATH.read_text())
    if data["schema"] != "dstack-boot-registers/1":
        raise PolicyError("unsupported dstack boot-register policy schema")
    entries = {e["os_image_hash"]: e for e in data["entries"]}
    if not entries:
        raise PolicyError("dstack boot-register policy has no entries")
    hexes = [(h, h, 64) for h in entries]
    for os_hash, e in entries.items():
        hexes += [(os_hash, e[f], 96) for f in ("mrtd_two_pass", "mrtd_single_pass", "rtmr1", "rtmr2")]
        hexes += [(os_hash, s[f], 96) for s in e.get("vm_shapes", []) for f in ("mrtd", "rtmr0")]
    for os_hash, value, length in hexes:
        if len(value) != length or any(c not in "0123456789abcdef" for c in value):
            raise PolicyError(f"{os_hash[:8]}: malformed value {value!r}")
    return {"revision": data["policy_revision"], "entries": entries}


def check_boot_registers(os_image_hash: str, registers: Dict[str, str]) -> Dict:
    """Compare one quote's MRTD/RTMR0-2 with the derivation for its log-bound image."""
    os_hash = os_image_hash.lower().removeprefix("0x")
    policy = _policy()
    entry = policy["entries"].get(os_hash)
    if entry is None:
        return {"boot_config": False, "hardware_config": None,
                "policy_revision": policy["revision"],
                "reasons": [f"os image {os_hash[:16]}… has no pinned derivation"]}
    boot = {"mrtd": registers["mrtd"] in (entry["mrtd_two_pass"], entry["mrtd_single_pass"]),
            "rtmr1": registers["rtmr1"] == entry["rtmr1"],
            "rtmr2": registers["rtmr2"] == entry["rtmr2"]}
    reasons = [f"{r} does not match the derivation for this image" for r, ok in boot.items() if not ok]
    hardware = None
    if entry.get("vm_shapes"):
        hardware = (registers["mrtd"], registers["rtmr0"]) in {
            (s["mrtd"], s["rtmr0"]) for s in entry["vm_shapes"]}
        if not hardware:
            reasons.append("(mrtd, rtmr0) matches no derived vm shape for this image")
    else:
        reasons.append("rtmr0 not derived for this image; hardware config unproven")
    return {"boot_config": all(boot.values()), "hardware_config": hardware,
            "policy_revision": policy["revision"], "reasons": reasons}
