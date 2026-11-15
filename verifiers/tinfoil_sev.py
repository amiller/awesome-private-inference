"""AMD SEV-SNP attestation report parser (1184-byte layout, report versions 3 and 5).

Report layout per AMD's SEV-SNP ABI specification as encoded in Tinfoil's
published reference client (PyPI ``tinfoil`` 0.15.0, ``attestation/abi_sev.py``)
and confirmed against every retained deployment report: version 3 covers ABI
rev 1.56, version 5 rev 1.58. Version 2 is rejected: it carries no
family/model/stepping. The total structure is
0x4A0 bytes; the signature covers bytes [0x000, 0x2A0).

Offsets that matter to authentication, each independently corroborated:
  - chip_id 0x1A0-0x1E0: equals the VCEK ``hwID`` extension (1.3.6.1.4.1.3704.1.4)
    of the ASK-signed VCEK certificate.
  - reported_tcb 0x180-0x188: its bl/tee/snp/ucode bytes equal the VCEK SPL
    extensions (…1.3.1, …1.3.2, …1.3.3, …1.3.8).
  - signature: ECDSA P-384/SHA-384 over [0x000, 0x2A0), R = little-endian
    integer in 0x2A0-0x2E8, S = little-endian integer in 0x2E8-0x318.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

REPORT_SIZE = 0x4A0
SIGNATURE_OFFSET = 0x2A0
ECDSA_RS_SIZE = 72  # each of R, S occupies 72 bytes; value < 2^384, rest zero

SUPPORTED_VERSIONS = (3, 5)

ZEN3ZEN4_FAMILY = 0x19
ZEN5_FAMILY = 0x1A
MILAN_MODEL = 1
GENOA_MODEL = (1 << 4) | 1
TURIN_MODEL = 2


def _mbz(data: bytes, lo: int, hi: int, what: str) -> None:
    for i in range(lo, hi):
        if data[i]:
            raise ValueError(
                f"{what}: reserved bytes [0x{lo:x}:0x{hi:x}] not all zero "
                f"(first non-zero at 0x{i:x}) — layout/fields not trustworthy"
            )


def _mbz64(value: int, what: str, hi: int, lo: int) -> None:
    if (value >> lo) & ((1 << (hi - lo + 1)) - 1):
        raise ValueError(f"{what}: reserved bits [{lo}:{hi}] not all zero: {hex(value)}")


def tcb_parts(tcb: int) -> Dict[str, int]:
    """Decompose a packed 64-bit TCB value into its SPL components."""
    return {
        "bl": tcb & 0xFF,
        "tee": (tcb >> 8) & 0xFF,
        "snp": (tcb >> 48) & 0xFF,
        "ucode": (tcb >> 56) & 0xFF,
    }


@dataclass
class SnpReport:
    version: int
    guest_svn: int
    policy: int
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    current_tcb: int
    platform_info: int
    signer_info: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: int
    chip_id: bytes
    committed_tcb: int
    current_build: int
    current_minor: int
    current_major: int
    committed_build: int
    committed_minor: int
    committed_major: int
    launch_tcb: int
    family: int
    model: int
    stepping: int
    product_name: str
    signed_data: bytes = field(repr=False, default=b"")
    signature: bytes = field(repr=False, default=b"")
    raw: bytes = field(repr=False, default=b"")

    @property
    def measurement_hex(self) -> str:
        return self.measurement.hex()

    @property
    def report_data_hex(self) -> str:
        return self.report_data.hex()

    @property
    def debug(self) -> bool:
        return bool(self.policy & (1 << 19))  # SNP guest policy DEBUG bit

    @property
    def reported_tcb_hex(self) -> str:
        return f"{self.reported_tcb:016x}"

    @property
    def current_tcb_hex(self) -> str:
        return f"{self.current_tcb:016x}"

    def signature_rs(self) -> tuple[int, int]:
        """ECDSA (r, s) from the report's little-endian 72-byte halves."""
        r = int.from_bytes(self.signature[0:ECDSA_RS_SIZE], "little")
        s = int.from_bytes(self.signature[ECDSA_RS_SIZE:2 * ECDSA_RS_SIZE], "little")
        return r, s


def parse(report: bytes) -> SnpReport:
    if len(report) != REPORT_SIZE:
        raise ValueError(f"expected {REPORT_SIZE}-byte (0x4A0) SEV-SNP report, got {len(report)}")

    version = int.from_bytes(report[0x00:0x04], "little")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported SEV-SNP report version {version} (supported: {SUPPORTED_VERSIONS})")

    policy = int.from_bytes(report[0x08:0x10], "little")
    if not policy & (1 << 17):
        raise ValueError("policy reserved bit 17 must be 1")
    if policy >> 26:
        raise ValueError("policy reserved bits 63-26 must be zero")

    current_tcb = int.from_bytes(report[0x38:0x40], "little")
    _mbz64(current_tcb, "current_tcb", 47, 16)
    signer_info = int.from_bytes(report[0x48:0x4C], "little")
    _mbz64(signer_info, "signer_info", 31, 5)
    if (signer_info >> 2) & 7 != 0:  # 0 = VCEK-signed report
        raise ValueError(f"only VCEK-signed reports supported, signer_info={hex(signer_info)}")

    _mbz(report, 0x4C, 0x50, "report")

    reported_tcb = int.from_bytes(report[0x180:0x188], "little")
    _mbz64(reported_tcb, "reported_tcb", 47, 16)

    family, model, stepping = report[0x188], report[0x189], report[0x18A]
    product_name = "Unknown"
    if family == ZEN3ZEN4_FAMILY:
        if model == MILAN_MODEL:
            product_name = "Milan"
        elif model == GENOA_MODEL:
            product_name = "Genoa"
    elif family == ZEN5_FAMILY and model == TURIN_MODEL:
        product_name = "Turin"
    _mbz(report, 0x18B, 0x1A0, "report")

    committed_tcb = int.from_bytes(report[0x1E0:0x1E8], "little")
    _mbz64(committed_tcb, "committed_tcb", 47, 16)
    _mbz(report, 0x1EB, 0x1EC, "report")
    _mbz(report, 0x1EF, 0x1F0, "report")
    launch_tcb = int.from_bytes(report[0x1F0:0x1F8], "little")
    _mbz64(launch_tcb, "launch_tcb", 47, 16)
    # 0x1F8 launch_mit_vector and 0x200 current_mit_vector become valid in v5.
    _mbz(report, 0x208 if version >= 5 else 0x1F8, SIGNATURE_OFFSET, "report")

    signature_algo = int.from_bytes(report[0x34:0x38], "little")
    if signature_algo == 1:  # ECDSA P-384 + SHA-384
        _mbz(report, SIGNATURE_OFFSET + 2 * ECDSA_RS_SIZE, REPORT_SIZE, "report")

    return SnpReport(
        version=version,
        guest_svn=int.from_bytes(report[0x04:0x08], "little"),
        policy=policy,
        family_id=report[0x10:0x20],
        image_id=report[0x20:0x30],
        vmpl=int.from_bytes(report[0x30:0x34], "little"),
        signature_algo=signature_algo,
        current_tcb=current_tcb,
        platform_info=int.from_bytes(report[0x40:0x48], "little"),
        signer_info=signer_info,
        report_data=report[0x50:0x90],
        measurement=report[0x90:0xC0],
        host_data=report[0xC0:0xE0],
        id_key_digest=report[0xE0:0x110],
        author_key_digest=report[0x110:0x140],
        report_id=report[0x140:0x160],
        report_id_ma=report[0x160:0x180],
        reported_tcb=reported_tcb,
        chip_id=report[0x1A0:0x1E0],
        committed_tcb=committed_tcb,
        current_build=report[0x1E8],
        current_minor=report[0x1E9],
        current_major=report[0x1EA],
        committed_build=report[0x1EC],
        committed_minor=report[0x1ED],
        committed_major=report[0x1EE],
        launch_tcb=launch_tcb,
        family=family,
        model=model,
        stepping=stepping,
        product_name=product_name,
        signed_data=report[:SIGNATURE_OFFSET],
        signature=report[SIGNATURE_OFFSET:],
        raw=report,
    )
