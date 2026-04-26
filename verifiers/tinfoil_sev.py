"""AMD SEV-SNP attestation report parser (1184-byte v3 layout).

Field offsets per AMD SEV-SNP ABI rev 1.55. We parse the structural fields the
registry needs (measurement, report_data, debug bit, version, tcb). The VCEK
chain to AMD's Genoa root is *not* checked here — that's a follow-up.
"""
from __future__ import annotations

from dataclasses import dataclass


REPORT_LEN = 1184


@dataclass
class SnpReport:
    version: int
    guest_svn: int
    policy: int
    debug: bool
    vmpl: int
    signature_algo: int
    current_tcb: bytes
    flags: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    reported_tcb: bytes
    raw: bytes

    @property
    def measurement_hex(self) -> str:
        return self.measurement.hex()

    @property
    def report_data_hex(self) -> str:
        return self.report_data.hex()


def parse(report: bytes) -> SnpReport:
    if len(report) != REPORT_LEN:
        raise ValueError(f"expected {REPORT_LEN}-byte SEV-SNP report, got {len(report)}")

    policy = int.from_bytes(report[0x08:0x10], "little")
    return SnpReport(
        version=int.from_bytes(report[0x00:0x04], "little"),
        guest_svn=int.from_bytes(report[0x04:0x08], "little"),
        policy=policy,
        debug=bool(policy & (1 << 19)),  # SNP guest policy DEBUG bit
        vmpl=int.from_bytes(report[0x30:0x34], "little"),
        signature_algo=int.from_bytes(report[0x34:0x38], "little"),
        current_tcb=report[0x38:0x40],
        flags=int.from_bytes(report[0x48:0x4C], "little"),
        report_data=report[0x50:0x90],
        measurement=report[0x90:0xC0],
        host_data=report[0xC0:0xE0],
        reported_tcb=report[0x180:0x188],
        raw=report,
    )
