"""Verify and track Google's signed GCE Confidential VM firmware launch endorsements.

Issue #33. Sibling of watch/firmware_endorsements.py (which lists and diffs the
gce_tcb_integrity bucket): this module downloads the small TDX launch
endorsements, verifies each ovmf_x64_csm/tdx/<MRTD>.binarypb against the vendored
GCE-cc-tcb-root certificate, checks the endorsed MRTD against the object name and
the referenced firmware digest, and appends history to
data/gce-tcb-endorsements.json.

Schema: cloud_vmm_proto.VMLaunchEndorsement from google/gce-tcb-verifier v0.3.1
(vendored at tests/fixtures/gce-tcb/schema/). Signature semantics follow upstream
verify.EndorsementProto: RSA-PSS(SHA-256, salt length 32) by the leaf certificate
in VMGoldenMeasurement.cert over serialized_uefi_golden, chained to
https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt.

Daily use: python3 watch/gce_tcb_endorsements.py [--history PATH] [--root PATH]
Lookup:    python3 watch/gce_tcb_endorsements.py --lookup <mrtd-hex>
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import sys
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

REPO = pathlib.Path(__file__).resolve().parent.parent
ROOT_DEFAULT = REPO / "tests/fixtures/gce-tcb/GCE-cc-tcb-root_1.der"
HISTORY_DEFAULT = REPO / "data/gce-tcb-endorsements.json"
BUCKET = "https://storage.googleapis.com/storage/v1/b/gce_tcb_integrity/o"
OBJECT_BASE = "https://storage.googleapis.com/gce_tcb_integrity/"
TDX_PREFIX = "ovmf_x64_csm/tdx/"
# Upstream verify.go: endorsements after this date must carry provenance.
PROVENANCE_SINCE = datetime.datetime(2024, 8, 2, tzinfo=datetime.timezone.utc)
PSS_SHA256_SALT32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _varint(data, i):
    value, shift = 0, 0
    while True:
        if i >= len(data):
            raise ValueError("truncated varint")
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def _fields(data):
    """Yield (field_number, wire_type, value); value is bytes for wire type 2."""
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
            value = data[i:i + length]
            i += length
        else:
            raise ValueError(f"field {number} has unsupported wire type {wire}")
        yield number, wire, value


def _singular(items, number, name):
    found = [v for n, _, v in items if n == number]
    if len(found) > 1:
        raise ValueError(f"duplicate field {number} ({name})")
    return found[0] if found else None


def _timestamp(message):
    seconds = _singular(list(_fields(message)), 1, "seconds")
    if seconds is None:
        raise ValueError("timestamp message without seconds")
    return seconds


def parse_launch_endorsement(raw):
    """Parse a VMLaunchEndorsement into a dict; raise ValueError when malformed."""
    top = list(_fields(raw))
    golden_raw = _singular(top, 1, "serialized_uefi_golden")
    signature = _singular(top, 2, "signature")
    if golden_raw is None or signature is None:
        raise ValueError("VMLaunchEndorsement missing payload or signature")
    golden = list(_fields(golden_raw))
    timestamp = _singular(golden, 1, "timestamp")
    if timestamp is None:
        raise ValueError("VMGoldenMeasurement without timestamp")
    parsed = {
        "golden_raw": golden_raw,
        "signature": signature,
        "timestamp": _timestamp(timestamp),
        "cl_spec": _singular(golden, 2, "cl_spec") or 0,
        "commit": _singular(golden, 3, "commit"),
        "cert_der": _singular(golden, 4, "cert"),
        "digest": _singular(golden, 5, "digest"),
        "ca_bundle": _singular(golden, 6, "ca_bundle") or b"",
        "has_sev_snp": _singular(golden, 7, "sev_snp") is not None,
        "svn": None,
        "measurements": [],
    }
    tdx = _singular(golden, 8, "tdx")
    if tdx is not None:
        for number, _, value in _fields(tdx):
            if number == 1:
                parsed["svn"] = value
            elif number == 2:
                entry = {k: v for k, _, v in _fields(value)}
                parsed["measurements"].append({
                    "ram_gib": entry.get(1),
                    "early_accept": bool(entry.get(2, 0)),
                    "mrtd": entry.get(3, b"").hex(),
                })
            else:
                raise ValueError(f"unknown VMTdx field {number}")
    return parsed


def _check_pss(params):
    return isinstance(params, padding.PSS)


def verify_endorsement(parsed, object_name, root, root_der, fd_names, now):
    """Run all checks; return a record. Failed checks are recorded, never hidden."""
    checks = {}

    def fail(name, reason):
        checks[name] = f"fail: {reason}"
        return False

    def ok(name):
        checks[name] = "ok"
        return True

    name_mrtd = object_name.rsplit("/", 1)[-1][: -len(".binarypb")]
    mrtds = [m["mrtd"] for m in parsed["measurements"]]
    if not mrtds:
        fail("name_mrtd", "endorsement carries no tdx measurements")
    elif name_mrtd not in mrtds:
        fail("name_mrtd", f"object-name MRTD not among the {len(mrtds)} endorsed measurements")
    else:
        ok("name_mrtd")

    leaf = None
    try:
        leaf = x509.load_der_x509_certificate(parsed["cert_der"])
    except Exception as exc:
        fail("signature", f"leaf certificate unparsable: {exc}")
    if leaf is not None:
        key = leaf.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            fail("signature", f"signer key is {type(key).__name__}, expected RSA")
        else:
            try:
                key.verify(parsed["signature"], parsed["golden_raw"], PSS_SHA256_SALT32, hashes.SHA256())
                ok("signature")
            except Exception as exc:
                fail("signature", f"RSA-PSS(SHA-256, salt 32) verification failed: {type(exc).__name__}")

    if leaf is not None:
        params = getattr(leaf, "signature_algorithm_parameters", None)
        if not _check_pss(params):
            fail("chain_to_root", "leaf certificate signature is not RSASSA-PSS")
        elif leaf.issuer != root.subject:
            fail("chain_to_root", f"leaf issuer {leaf.issuer.rfc4514_string()} is not the root subject")
        else:
            try:
                root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                         params, leaf.signature_hash_algorithm)
                ok("chain_to_root")
            except Exception as exc:
                fail("chain_to_root", f"root does not verify leaf certificate: {type(exc).__name__}")

    try:
        bundle = x509.load_pem_x509_certificates(parsed["ca_bundle"])
    except Exception:
        bundle = []
    if not bundle:
        fail("root_bundle_match", "ca_bundle carries no certificates")
    elif bundle[0].public_bytes(Encoding.DER) != root_der:
        fail("root_bundle_match", "ca_bundle[0] is not the pinned GCE-cc-tcb-root")
    else:
        ok("root_bundle_match")

    if leaf is not None:
        ts = datetime.datetime.fromtimestamp(parsed["timestamp"], datetime.timezone.utc)
        if leaf.not_valid_before_utc <= ts <= leaf.not_valid_after_utc:
            ok("cert_valid_at_endorsement")
        else:
            fail("cert_valid_at_endorsement",
                 f"golden timestamp {ts.isoformat()} outside leaf validity "
                 f"{leaf.not_valid_before_utc.isoformat()}..{leaf.not_valid_after_utc.isoformat()}")
        if leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
            ok("cert_valid_now")
        else:
            fail("cert_valid_now", f"leaf certificate not valid at {now.isoformat()}")

    ts_dt = datetime.datetime.fromtimestamp(parsed["timestamp"], datetime.timezone.utc)
    if ts_dt > PROVENANCE_SINCE and parsed["cl_spec"] == 0 and not parsed["commit"]:
        fail("provenance", f"no cl_spec or commit for golden timestamp {ts_dt.isoformat()}")
    else:
        ok("provenance")

    digest = parsed["digest"].hex() if parsed["digest"] is not None else None
    if digest is None or len(parsed["digest"]) != 48:
        fail("firmware_object", "golden digest is not a SHA-384 (48-byte) value")
    elif f"ovmf_x64_csm/{digest}.fd" not in fd_names:
        fail("firmware_object", f"no bucket object ovmf_x64_csm/{digest}.fd for endorsed digest")
    else:
        ok("firmware_object")

    record = {
        "mrtd_name": name_mrtd,
        "firmware_sha384": digest,
        "golden_timestamp": ts_dt.isoformat(),
        "cl_spec": parsed["cl_spec"],
        "commit_hex": parsed["commit"].hex() if parsed["commit"] else None,
        "svn": parsed["svn"],
        "sev_snp_present": parsed["has_sev_snp"],
        "measurements": parsed["measurements"],
    }
    if leaf is not None:
        record["signer"] = {
            "subject": leaf.subject.rfc4514_string(),
            "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
            "issuer": leaf.issuer.rfc4514_string(),
            "not_before": leaf.not_valid_before_utc.isoformat(),
            "not_after": leaf.not_valid_after_utc.isoformat(),
        }
    record["checks"] = checks
    record["result"] = "verified" if all(v == "ok" for v in checks.values()) else "failed"
    return record


def listing(prefix):
    items, token = [], None
    while True:
        query = {"prefix": prefix, "maxResults": "1000",
                 "fields": "nextPageToken,items(name,size,timeCreated,updated,md5Hash,generation)"}
        if token:
            query["pageToken"] = token
        url = BUCKET + "?" + urllib.parse.urlencode(query)
        page = json.load(urllib.request.urlopen(url, timeout=60))
        items += page.get("items", [])
        token = page.get("nextPageToken")
        if not token:
            return {i["name"]: i for i in items}


def fetch_object(name):
    url = OBJECT_BASE + urllib.parse.quote(name)
    return urllib.request.urlopen(url, timeout=120).read()


def _release_age(history, firmware_sha384):
    """Number of firmware releases published after this one, by first publication."""
    releases = sorted({(rec["bucket_created"], fw) for fw, rec in history["firmware"].items()})
    times = [t for t, fw in releases if fw == firmware_sha384]
    if not times:
        return None
    return sum(1 for t, fw in releases if t > times[0])


def update_history(history, current_names, records, now, now_iso):
    endorsements = history.setdefault("endorsements", {})
    for name, meta in current_names.items():
        if not name.startswith(TDX_PREFIX) or not name.endswith(".binarypb"):
            continue
        entry = endorsements.setdefault(name.rsplit("/", 1)[-1][: -len(".binarypb")], {})
        if not entry:
            entry["first_seen"] = now_iso
            entry["bucket_created"] = meta["timeCreated"]
        entry["last_present"] = now_iso
        entry["removed"] = False
        record = records[name]
        for key in ("firmware_sha384", "golden_timestamp", "cl_spec", "commit_hex",
                    "svn", "sev_snp_present", "measurements", "signer", "checks", "result"):
            entry[key] = record.get(key)
        entry["verified_at"] = now_iso
        if record["result"] != "verified":
            entry.setdefault("failures", []).append(
                {"at": now_iso, "reasons": [v for v in record["checks"].values() if v != "ok"]})
    for mrtd_name, entry in endorsements.items():
        object_name = TDX_PREFIX + mrtd_name + ".binarypb"
        if object_name not in current_names and not entry.get("removed"):
            entry["removed"] = True
            entry["removed_first_seen"] = now_iso
            entry.setdefault("failures", []).append(
                {"at": now_iso, "reasons": ["object absent from bucket listing"]})

    firmware = history.setdefault("firmware", {})
    for name, meta in current_names.items():
        if not name.endswith(".fd") or name == "ovmf_x64_csm/.fd":
            continue
        digest = name.split("/")[-1][: -len(".fd")]
        entry = firmware.setdefault(digest, {})
        if not entry:
            entry["first_seen"] = now_iso
            entry["bucket_created"] = meta["timeCreated"]
        entry["last_present"] = now_iso
        entry["removed"] = False
    for digest, entry in firmware.items():
        if f"ovmf_x64_csm/{digest}.fd" not in current_names and not entry.get("removed"):
            entry["removed"] = True
            entry["removed_first_seen"] = now_iso

    rims = history.setdefault("intel_rims", {})
    for name, meta in current_names.items():
        if not name.startswith("intel_rims/") or not name.endswith(".textproto"):
            continue
        entry = rims.setdefault(name, {})
        if not entry:
            entry["first_seen"] = now_iso
        if entry.get("md5") not in (None, meta["md5Hash"]):
            entry.setdefault("changes", []).append(
                {"at": now_iso, "from_md5": entry["md5"], "to_md5": meta["md5Hash"],
                 "to_updated": meta["updated"], "to_generation": meta["generation"]})
        entry.update({"md5": meta["md5Hash"], "generation": meta["generation"],
                      "updated": meta["updated"], "last_present": now_iso, "removed": False})
    for name, entry in rims.items():
        if name not in current_names and not entry.get("removed"):
            entry["removed"] = True
            entry["removed_first_seen"] = now_iso
    history["last_run"] = now_iso
    return history


def cross_check_fd(digest):
    """Download one firmware binary and check sha384(content) == endorsed digest == object name."""
    name = f"ovmf_x64_csm/{digest}.fd"
    content = fetch_object(name)
    actual = hashlib.sha384(content).hexdigest()
    return {"object": name, "endorsed_sha384": digest, "content_sha384": actual,
            "match": actual == digest}


def lookup(history, mrtd):
    entry = history["endorsements"].get(mrtd)
    if entry is None:
        return {"mrtd": mrtd, "endorsed": False,
                "note": "not among observed GCE TDX launch endorsements"}
    age = _release_age(history, entry["firmware_sha384"])
    return {"mrtd": mrtd, "endorsed": True, "result": entry.get("result"),
            "firmware_sha384": entry["firmware_sha384"],
            "golden_timestamp": entry.get("golden_timestamp"), "svn": entry.get("svn"),
            "signer_sha256": entry.get("signer", {}).get("sha256"),
            "newer_firmware_releases": age, "removed": entry.get("removed", False)}


def cross_reference_audits(history, audits_dir, now_iso):
    """Flag every retained TDX MRTD (data/audits/*.json ledgers keyed by identity_field
    "mrtd") against the verified GCE endorsement set. Results are recorded, not
    silently green: an unendorsed MRTD keeps its observation context."""
    refs = history.setdefault("provider_mrtd_refs", {})
    for path in sorted(pathlib.Path(audits_dir).glob("*.json")):
        ledger = json.loads(path.read_text())
        if ledger.get("identity_field") != "mrtd":
            continue
        rows = []
        for audit in ledger.get("audits", []):
            entry = lookup(history, audit["mrtd"].strip().lower())
            entry["ledger"] = ledger.get("source_repo", path.name)
            entry["signoff"] = audit.get("signoff")
            entry["verdict"] = audit.get("verdict")
            entry["last_seen"] = audit.get("last_seen")
            entry["checked_at"] = now_iso
            rows.append(entry)
        refs[path.name] = rows
    return refs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--history", default=HISTORY_DEFAULT, type=pathlib.Path)
    parser.add_argument("--root", default=ROOT_DEFAULT, type=pathlib.Path)
    parser.add_argument("--lookup", metavar="MRTD_HEX",
                        help="resolve an MRTD against the existing history and exit")
    parser.add_argument("--cross-check-fd", metavar="MRTD_HEX",
                        help="download one firmware binary and check its sha384 against the endorsement")
    parser.add_argument("--stale-after", type=int, default=3,
                        help="flag endorsed builds older than this many newer releases (default 3)")
    args = parser.parse_args(argv)

    if args.lookup:
        result = lookup(json.loads(args.history.read_text()), args.lookup.strip().lower())
        if result.get("endorsed") and (result.get("removed")
                                       or (result.get("newer_firmware_releases") or 0) > args.stale_after):
            result["flag"] = "stale"
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0

    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    root_der = args.root.read_bytes()
    root = x509.load_der_x509_certificate(root_der)
    history = json.loads(args.history.read_text()) if args.history.exists() else {
        "schema": "gce-tcb-endorsements/1",
        "root": json.loads((args.root.parent / "GCE-cc-tcb-root_1.meta.json").read_text())
        if (args.root.parent / "GCE-cc-tcb-root_1.meta.json").exists() else
        {"url": "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt", "file": str(args.root)},
    }

    ovmf = listing("ovmf_x64_csm/")
    rims = listing("intel_rims/")
    current = {**ovmf, **rims}
    fd_names = {n for n in ovmf if n.endswith(".fd")}
    records, failures = {}, []
    for name in sorted(ovmf):
        if not name.startswith(TDX_PREFIX) or not name.endswith(".binarypb"):
            continue
        raw = fetch_object(name)
        try:
            parsed = parse_launch_endorsement(raw)
        except ValueError as exc:
            failures.append((name, f"protobuf parse failed: {exc}"))
            records[name] = {"result": "failed",
                             "checks": {"protobuf_parse": f"fail: {exc}"},
                             "firmware_sha384": None, "golden_timestamp": None,
                             "cl_spec": None, "commit_hex": None, "svn": None,
                             "sev_snp_present": None, "measurements": [], "signer": None}
            continue
        record = verify_endorsement(parsed, name, root, root_der, fd_names, now)
        records[name] = record
        if record["result"] != "verified":
            failures.append((name, {k: v for k, v in record["checks"].items() if v != "ok"}))

    if args.cross_check_fd:
        entry = history["endorsements"].get(args.cross_check_fd.strip().lower())
        if entry is None:
            print(f"MRTD {args.cross_check_fd} not in history; run a full pass first", file=sys.stderr)
            return 2
        history["digest_cross_check"] = {"mrtd": args.cross_check_fd.strip().lower(),
                                         **cross_check_fd(entry["firmware_sha384"]),
                                         "checked_at": now_iso}

    update_history(history, current, records, now, now_iso)
    refs = cross_reference_audits(history, REPO / "data" / "audits", now_iso)
    args.history.parent.mkdir(parents=True, exist_ok=True)
    args.history.write_text(json.dumps(history, indent=1, sort_keys=True) + "\n")

    total = sum(1 for n in records)
    verified = sum(1 for r in records.values() if r["result"] == "verified")
    print(f"GCE TCB TDX endorsements: {verified}/{total} verified, history {args.history}")
    for name, reason in failures:
        print(f"FAILED {name}: {reason}", file=sys.stderr)
    withdrawn = sum(1 for e in history["endorsements"].values() if e.get("removed"))
    print(f"withdrawn-from-bucket endorsements in history: {withdrawn}")
    for ledger, rows in refs.items():
        unendorsed = [r for r in rows if not r["endorsed"]]
        print(f"provider mrtd ledger {ledger}: {len(rows)} retained, "
              f"{len(unendorsed)} NOT GCE-endorsed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
