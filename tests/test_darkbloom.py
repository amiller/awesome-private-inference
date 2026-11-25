import base64
import hashlib
import copy
import io
import json
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from probes import darkbloom as dbp
from verifiers import darkbloom

FIXTURE = json.loads((Path(__file__).parent / "fixtures/darkbloom_providers_sample.json").read_text())
AUG = datetime(2026, 8, 22, 20, 38, tzinfo=timezone.utc)
ROOT = darkbloom.load_root()


def aug(prefix):
    return copy.deepcopy(next(p for p in FIXTURE["2026-08-22"]["providers"] if p["provider_id"].startswith(prefix)))


def holding():
    return copy.deepcopy([p for p in FIXTURE["2026-08-22"]["providers"]
                          if p.get("mda_cert_chain_b64") and not p["provider_id"].startswith("415c509f")][0])


def test_recorded_feed_reproduces_binding_results():
    results = [darkbloom.binding(p, ROOT, AUG)["result"] for p in FIXTURE["2026-08-22"]["providers"]]
    assert results == ["fails", "holds", "holds", "holds", "not_checked"]
    assert darkbloom.binding(aug("415c509f"), ROOT, AUG)["valid_at_capture"] is True


def test_current_feed_publishes_no_chains():
    for p in FIXTURE["2026-11-24"]["providers"]:
        assert darkbloom.binding(p, ROOT, AUG) == {"result": "not_checked", "reason": "no_chain_published"}


def test_changed_se_key_fails_binding():
    p = holding()
    p["se_public_key"] = base64.b64encode(b"\x01" + base64.b64decode(p["se_public_key"])[1:]).decode()
    assert darkbloom.binding(p, ROOT, AUG)["result"] == "fails"


def test_flipped_leaf_byte_breaks_chain():
    p = holding()
    leaf = bytearray(base64.b64decode(p["mda_cert_chain_b64"][0]))
    leaf[200] ^= 1
    p["mda_cert_chain_b64"][0] = base64.b64encode(bytes(leaf)).decode()
    assert darkbloom.binding(p, ROOT, AUG)["result"] == "chain_invalid"


def test_impostor_root_with_apple_name_rejected():
    key = ec.generate_private_key(ec.SECP384R1())
    impostor = (x509.CertificateBuilder().subject_name(ROOT.subject).issuer_name(ROOT.subject)
                .public_key(key.public_key()).serial_number(1).not_valid_before(ROOT.not_valid_before_utc)
                .not_valid_after(ROOT.not_valid_after_utc).sign(key, hashes.SHA384()))
    assert darkbloom.binding(holding(), impostor, AUG)["result"] == "chain_invalid"


def test_expired_leaf_recorded_not_enforced():
    out = darkbloom.binding(holding(), ROOT, AUG + timedelta(days=3650))
    assert out["result"] == "holds" and out["valid_at_capture"] is False


RELEASE = {"version": "1.0.0", "bundle_hash": "b1", "binary_hash": "x1", "metallib_hash": "m1",
           "url": "https://example.invalid/b.tar.gz", "created_at": "2026-11-21T00:00:00Z",
           "platform": "macos-arm64", "backend": "mlx-swift", "active": True}


def test_release_history_only_appends_new_identities(tmp_path):
    path = tmp_path / "releases.jsonl"
    first = dbp.append_release(path, RELEASE, {"first_seen_at": "t1"})
    before = path.read_text()
    assert dbp.append_release(path, RELEASE | {"active": False, "created_at": "later"}, {"first_seen_at": "t2"}) is None
    assert path.read_text() == before
    second = dbp.append_release(path, RELEASE | {"version": "1.0.1", "bundle_hash": "b2"}, {"first_seen_at": "t3"})
    rehash = dbp.append_release(path, RELEASE | {"binary_hash": "x2"}, {"first_seen_at": "t4"})
    lines = path.read_text().splitlines()
    assert path.read_text().startswith(before) and [json.loads(x) for x in lines] == [first, second, rehash]
    assert (first["version_seen_with_other_hashes"], second["version_seen_with_other_hashes"],
            rehash["version_seen_with_other_hashes"]) == (False, False, True)


def tarball(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_bundle_hashes_checked_against_release(tmp_path):
    sha = lambda b: hashlib.sha256(b).hexdigest()
    blob = tarball({"./bin/darkbloom": b"binary", "./bin/mlx.metallib": b"metal", "./Darkbloom.app/x": b"y"})
    release = RELEASE | {"bundle_hash": sha(blob), "binary_hash": sha(b"binary"), "metallib_hash": sha(b"metal")}
    manifest = dbp.bundle_manifest(io.BytesIO(blob))
    assert manifest["bytes"] == len(blob) and set(manifest["files"]) == {"bin/darkbloom", "bin/mlx.metallib", "Darkbloom.app/x"}
    assert dbp.verify_release(release, manifest) == {"bundle_hash_matches": True, "binary_hash_matches": True,
                                                     "metallib_hash_matches": True, "code_signature": "not_checked"}
    swapped = dbp.bundle_manifest(io.BytesIO(tarball({"./bin/darkbloom": b"other", "./bin/mlx.metallib": b"metal"})))
    assert dbp.verify_release(release, swapped)["binary_hash_matches"] is False
    assert dbp.verify_release(release, swapped)["bundle_hash_matches"] is False


class Resp:
    def __init__(self, status, body, ctype="application/json"):
        self.status_code, self.headers = status, {"Content-Type": ctype}
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()

    def json(self):
        return json.loads(self.content)


def test_fetch_failure_exits_nonzero_after_writing_captures(monkeypatch, tmp_path):
    monkeypatch.setattr(dbp, "ROOT", tmp_path)
    monkeypatch.setattr(dbp, "OUT", tmp_path / "darkbloom")
    monkeypatch.setattr(dbp, "EVIDENCE", tmp_path / "evidence")
    def get(url, **kw):
        if url.endswith("/v1/releases/latest"):
            raise requests.ConnectionError("connection reset")
        if url.endswith("/v1/providers/attestation"):
            return Resp(200, FIXTURE["2026-11-24"])
        if url.endswith("/.well-known/attestation"):
            return Resp(404, b"404 page not found\n", "text/plain; charset=utf-8")
        return Resp(404, {"error": {"code": "invalid_request_error"}})
    monkeypatch.setattr(dbp.requests, "get", get)
    assert dbp.main([]) == 1
    run = json.loads(next((tmp_path / "darkbloom/runs").glob("*.json")).read_text())
    assert run["status"] == "failed" and run["failed"] == ["release"]
    assert run["steps"]["release"]["status"] == "fetch_failed" and "connection reset" in run["steps"]["release"]["error"]
    assert run["release"] is None and not (tmp_path / "darkbloom/releases.jsonl").exists()
    assert run["providers"]["providers"] == 3
    assert run["providers"]["mda_binding"] == {"not_checked:no_chain_published": 3}
    raw = dbp.load(run["steps"]["providers"]["raw_ref"], tmp_path)
    assert raw["body"] == FIXTURE["2026-11-24"] and raw["status"] == 200
    wk = run["coordinator"]["/.well-known/attestation"]
    assert wk["status"] == "ok" and wk["http_status"] == 404 and wk["verification"] == "not_checked"
    assert dbp.load(wk["raw_ref"], tmp_path)["body"] == "404 page not found\n"
    latest = json.loads((tmp_path / "darkbloom/latest.json").read_text())
    assert latest["last_run"]["status"] == "failed" and latest["release"] is None


def test_non_200_feed_is_a_fetch_failure_with_body_archived(monkeypatch, tmp_path):
    monkeypatch.setattr(dbp, "ROOT", tmp_path)
    monkeypatch.setattr(dbp, "OUT", tmp_path / "darkbloom")
    monkeypatch.setattr(dbp, "EVIDENCE", tmp_path / "evidence")
    monkeypatch.setattr(dbp, "fetch_bundle", lambda url: pytest.fail("bundle fetched"))
    monkeypatch.setattr(dbp.requests, "get", lambda url, **kw: Resp(503, {"error": "down"}))
    assert dbp.main([]) == 1
    run = json.loads(next((tmp_path / "darkbloom/runs").glob("*.json")).read_text())
    assert run["failed"] == ["providers", "release"]
    assert run["steps"]["providers"]["http_status"] == 503 and run["providers"] is None
    assert dbp.load(run["steps"]["providers"]["raw_ref"], tmp_path)["body"] == {"error": "down"}


def test_bundle_dropped_mid_stream_fails_run_but_keeps_release_and_feed(monkeypatch, tmp_path):
    import urllib3
    monkeypatch.setattr(dbp, "ROOT", tmp_path)
    monkeypatch.setattr(dbp, "OUT", tmp_path / "darkbloom")
    monkeypatch.setattr(dbp, "EVIDENCE", tmp_path / "evidence")
    class Broken(io.BytesIO):
        def read(self, n=-1):
            if self.tell() > 100:
                raise urllib3.exceptions.ProtocolError("Connection broken")
            return super().read(min(n, 64))
    class Stream:
        status_code, raw = 200, Broken(tarball({"./bin/darkbloom": bytes(4096)}))
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def raise_for_status(self): pass
    def get(url, stream=False, **kw):
        if stream:
            return Stream()
        if url.endswith("/v1/releases/latest"):
            return Resp(200, RELEASE)
        if url.endswith("/v1/providers/attestation"):
            return Resp(200, FIXTURE["2026-11-24"])
        return Resp(404, {"error": {}})
    monkeypatch.setattr(dbp.requests, "get", get)
    assert dbp.main([]) == 1
    run = json.loads(next((tmp_path / "darkbloom/runs").glob("*.json")).read_text())
    assert run["failed"] == ["bundle"] and "Connection broken" in run["steps"]["bundle"]["error"]
    assert run["providers"]["providers"] == 3 and run["release"]["verification"] == "not_checked"
    [row] = [json.loads(x) for x in (tmp_path / "darkbloom/releases.jsonl").read_text().splitlines()]
    assert row["version"] == "1.0.0" and row["verification"] == "not_checked" and row["bundle_bytes"] is None
