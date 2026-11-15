"""Snapshot Google's public GCE TCB endorsement bucket, diff it against the previous snapshot,
and verify every TDX launch endorsement to Google's GCE-cc-tcb-root (issue #33).

Endorsements are cloud_vmm_proto.VMLaunchEndorsement (google/gce-tcb-verifier v0.3.1):
RSA-PSS(SHA-256, salt 32) by the leaf certificate in VMGoldenMeasurement.cert over
serialized_uefi_golden, with the leaf issued by https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt
(vendored at data/GCE-cc-tcb-root_1.der).
"""
import argparse, base64, datetime, hashlib, json, pathlib, urllib.parse, urllib.request

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

BUCKET = "https://storage.googleapis.com/storage/v1/b/gce_tcb_integrity/o"
OBJECT_BASE = "https://storage.googleapis.com/gce_tcb_integrity/"
ROOT = pathlib.Path(__file__).resolve().parent.parent / "data/GCE-cc-tcb-root_1.der"
TDX_PREFIX = "ovmf_x64_csm/tdx/"
# Upstream verify.go: endorsements after this date must carry provenance.
PROVENANCE_SINCE = datetime.datetime(2024, 8, 2, tzinfo=datetime.timezone.utc)
PSS_SHA256_SALT32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def listing():
    items, token = [], None
    while True:
        q = {"maxResults": "1000", "fields": "nextPageToken,items(name,size,generation,timeCreated,updated,md5Hash)"}
        if token:
            q["pageToken"] = token
        page = json.load(urllib.request.urlopen(BUCKET + "?" + urllib.parse.urlencode(q), timeout=60))
        items += page.get("items", [])
        token = page.get("nextPageToken")
        if not token:
            return {i["name"]: i for i in items}


def fetch_object(name):
    return urllib.request.urlopen(OBJECT_BASE + urllib.parse.quote(name), timeout=120).read()


def _varint(data, i):
    value, shift = 0, 0
    while True:
        if i >= len(data):
            raise ValueError("truncated varint")
        value |= (data[i] & 0x7F) << shift
        shift += 7
        i += 1
        if not data[i - 1] & 0x80:
            return value, i


def _fields(data):
    """Yield (field_number, value); value is bytes for wire type 2."""
    i = 0
    while i < len(data):
        key, i = _varint(data, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(data, i)
        elif wire == 2:
            length, i = _varint(data, i)
            if i + length > len(data):
                raise ValueError(f"field {number} length {length} exceeds message")
            value, i = data[i:i + length], i + length
        else:
            raise ValueError(f"field {number} has unsupported wire type {wire}")
        yield number, value


def _singular(items, number):
    found = [v for n, v in items if n == number]
    if len(found) > 1:
        raise ValueError(f"duplicate field {number}")
    return found[0] if found else None


def parse_launch_endorsement(raw):
    top = list(_fields(raw))
    golden_raw, signature = _singular(top, 1), _singular(top, 2)
    if golden_raw is None or signature is None:
        raise ValueError("VMLaunchEndorsement missing payload or signature")
    golden = list(_fields(golden_raw))
    timestamp = _singular(golden, 1)
    if timestamp is None:
        raise ValueError("VMGoldenMeasurement without timestamp")
    seconds = _singular(list(_fields(timestamp)), 1)
    if seconds is None:
        raise ValueError("timestamp message without seconds")
    parsed = {"golden_raw": golden_raw, "signature": signature, "timestamp": seconds,
              "cl_spec": _singular(golden, 2), "commit": _singular(golden, 3),
              "cert_der": _singular(golden, 4), "digest": _singular(golden, 5),
              "ca_bundle": _singular(golden, 6), "has_sev_snp": _singular(golden, 7) is not None,
              "svn": None, "measurements": []}
    tdx = _singular(golden, 8)
    if tdx is None:
        raise ValueError("VMGoldenMeasurement without tdx")
    for number, value in _fields(tdx):
        if number == 1:
            parsed["svn"] = value
        elif number == 2:
            entry = dict(_fields(value))
            parsed["measurements"].append({"ram_gib": entry.get(1), "early_accept": bool(entry.get(2, 0)),
                                           "mrtd": entry[3].hex()})
        else:
            raise ValueError(f"unknown VMTdx field {number}")
    return parsed


def _verifies(key, signature, data, pad, algorithm):
    try:
        key.verify(signature, data, pad, algorithm)
        return True
    except InvalidSignature:
        return False


def verify_endorsement(parsed, object_name, root, root_der, fd_names, now):
    """Return a record whose checks are each "ok" or "fail: <reason>"."""
    checks = {}

    def check(name, ok, reason):
        checks[name] = "ok" if ok else f"fail: {reason}"

    mrtd = object_name.rsplit("/", 1)[-1].removesuffix(".binarypb")
    check("name_mrtd", mrtd in [m["mrtd"] for m in parsed["measurements"]],
          "object-name MRTD not among the endorsed measurements")
    leaf = x509.load_der_x509_certificate(parsed["cert_der"])
    check("signature", _verifies(leaf.public_key(), parsed["signature"], parsed["golden_raw"],
                                 PSS_SHA256_SALT32, hashes.SHA256()),
          "RSA-PSS(SHA-256, salt 32) verification failed")
    check("chain_to_root", _verifies(root.public_key(), leaf.signature, leaf.tbs_certificate_bytes,
                                     leaf.signature_algorithm_parameters, leaf.signature_hash_algorithm),
          "root does not verify leaf certificate")
    bundle = x509.load_pem_x509_certificates(parsed["ca_bundle"])
    check("root_bundle_match", bundle[0].public_bytes(Encoding.DER) == root_der,
          "ca_bundle[0] is not the pinned GCE-cc-tcb-root")
    ts = datetime.datetime.fromtimestamp(parsed["timestamp"], datetime.timezone.utc)
    check("cert_valid_at_endorsement", leaf.not_valid_before_utc <= ts <= leaf.not_valid_after_utc,
          f"golden timestamp {ts.isoformat()} outside leaf validity")
    check("cert_valid_now", leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc,
          f"leaf certificate not valid at {now.isoformat()}")
    check("provenance", ts <= PROVENANCE_SINCE or parsed["cl_spec"] or parsed["commit"],
          f"no cl_spec or commit for golden timestamp {ts.isoformat()}")
    digest = parsed["digest"].hex()
    check("firmware_object", len(parsed["digest"]) == 48 and f"ovmf_x64_csm/{digest}.fd" in fd_names,
          f"no SHA-384 bucket object ovmf_x64_csm/{digest}.fd for endorsed digest")
    return {"firmware_sha384": digest, "golden_timestamp": ts.isoformat(), "cl_spec": parsed["cl_spec"],
            "commit_hex": parsed["commit"].hex() if parsed["commit"] else None, "svn": parsed["svn"],
            "sev_snp_present": parsed["has_sev_snp"], "measurements": parsed["measurements"],
            "signer": {"subject": leaf.subject.rfc4514_string(), "issuer": leaf.issuer.rfc4514_string(),
                       "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
                       "not_before": leaf.not_valid_before_utc.isoformat(),
                       "not_after": leaf.not_valid_after_utc.isoformat()},
            "checks": checks, "result": "verified" if all(v == "ok" for v in checks.values()) else "failed"}


def _presence(section, present, now_iso):
    """Add first sightings to a history section and mark entries that left the bucket."""
    for key, meta in present.items():
        section.setdefault(key, {"first_seen": now_iso, "bucket_created": meta["timeCreated"]}).pop("removed_at", None)
    for key, entry in section.items():
        if key not in present:
            entry.setdefault("removed_at", now_iso)


def update_history(history, current, records, store, now_iso):
    """Fold one bucket listing and its verification records into history. New intel_rims
    contents are downloaded into store, md5-checked against the listing, and retained."""
    tdx = {n.removeprefix(TDX_PREFIX).removesuffix(".binarypb"): m for n, m in current.items()
           if n.startswith(TDX_PREFIX) and n.endswith(".binarypb")}
    fds = {n.removeprefix("ovmf_x64_csm/").removesuffix(".fd"): m for n, m in current.items()
           if n.startswith("ovmf_x64_csm/") and n.endswith(".fd") and n.count("/") == 1 and n != "ovmf_x64_csm/.fd"}
    rims = {n: m for n, m in current.items() if n.startswith("intel_rims/") and n.endswith(".textproto")}
    for section, present in (("endorsements", tdx), ("firmware", fds), ("intel_rims", rims)):
        _presence(history.setdefault(section, {}), present, now_iso)
    for mrtd in tdx:
        history["endorsements"][mrtd].update(records[TDX_PREFIX + mrtd + ".binarypb"])
    for name, meta in sorted(rims.items()):
        entry = history["intel_rims"][name]
        if entry.get("md5") == meta["md5Hash"]:
            continue
        content = fetch_object(name)
        got = base64.b64encode(hashlib.md5(content).digest()).decode()
        if got != meta["md5Hash"]:
            raise ValueError(f"{name}: downloaded content md5 {got} != listing md5 {meta['md5Hash']}")
        path = pathlib.Path(name.removeprefix("intel_rims/").removesuffix(".textproto")) / f"{hashlib.md5(content).hexdigest()}.textproto"
        (store / path).parent.mkdir(parents=True, exist_ok=True)
        (store / path).write_bytes(content)
        entry.setdefault("retained_versions", []).append(
            {"at": now_iso, "from_md5": entry.get("md5"), "md5": hashlib.md5(content).hexdigest(),
             "generation": meta["generation"], "updated": meta["updated"], "size": len(content),
             "path": str(store.name / path)})
        entry.update(md5=meta["md5Hash"], generation=meta["generation"], updated=meta["updated"])
    return history


def verify_all(current, now):
    root_der = ROOT.read_bytes()
    root = x509.load_der_x509_certificate(root_der)
    fd_names = {n for n in current if n.endswith(".fd")}
    return {n: verify_endorsement(parse_launch_endorsement(fetch_object(n)), n, root, root_der, fd_names, now)
            for n in sorted(current) if n.startswith(TDX_PREFIX) and n.endswith(".binarypb")}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--snapshots", required=True, help="directory of prior gce-tcb-*.json snapshots")
    p.add_argument("--history", required=True, type=pathlib.Path, help="endorsement history JSON to update")
    p.add_argument("--output", required=True, help="diff report path")
    a = p.parse_args()
    snaps = pathlib.Path(a.snapshots)
    snaps.mkdir(parents=True, exist_ok=True)
    prior = sorted(snaps.glob("gce-tcb-*.json"))
    old = json.loads(prior[-1].read_text()) if prior else None
    new = listing()
    stamp = max(i["updated"] for i in new.values())
    (snaps / f"gce-tcb-{stamp[:19].replace(':', '')}.json").write_text(json.dumps(new, indent=1, sort_keys=True))
    lines = [f"GCE TCB endorsement bucket gce_tcb_integrity: {len(new)} objects, newest update {stamp}"]
    if old is None:
        lines.append(f"FIRST SNAPSHOT: no prior snapshot in {snaps}; nothing to diff.")
    else:
        lines.append(f"Compared with {prior[-1].name} ({len(old)} objects).")
        for n in sorted(set(new) - set(old)):
            lines.append(f"ADDED {new[n]['timeCreated']} {n} size={new[n]['size']}")
        for n in sorted(set(old) - set(new)):
            lines.append(f"REMOVED (was created {old[n]['timeCreated']}) {n}")
        for n in sorted(set(new) & set(old)):
            if new[n]["md5Hash"] != old[n]["md5Hash"]:
                lines.append(f"CHANGED {new[n]['updated']} {n} md5 {old[n]['md5Hash']} -> {new[n]['md5Hash']}")
    tdx = sorted((i["timeCreated"], n.split("/")[-1].split(".")[0]) for n, i in new.items() if "/tdx/" in n)
    lines.append(f"Latest TDX MRTD endorsement: {tdx[-1][0]} {tdx[-1][1]} ({len(tdx)} total)")
    now = datetime.datetime.now(datetime.timezone.utc)
    records = verify_all(new, now)
    failed = {n: r for n, r in records.items() if r["result"] != "verified"}
    lines.append(f"Signature verification to GCE-cc-tcb-root: {len(records) - len(failed)}/{len(records)} TDX endorsements verified.")
    for n, r in failed.items():
        lines.append(f"VERIFY FAILED {n}: " + "; ".join(f"{k} {v}" for k, v in r["checks"].items() if v != "ok"))
    history = json.loads(a.history.read_text()) if a.history.exists() else {"schema": "gce-tcb-endorsements/2"}
    update_history(history, new, records, a.history.parent / "gce-tcb-intel-rims", now.isoformat(timespec="seconds"))
    a.history.write_text(json.dumps(history, indent=1, sort_keys=True) + "\n")
    pathlib.Path(a.output).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
