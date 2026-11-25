"""Daily public reference observations of Darkbloom (api.darkbloom.dev). No account, no payment.

Raw responses go to the content-addressed evidence store before anything is derived.
A fetch failure is recorded in the run record and makes the run exit 1; nothing is retried
or substituted. Run records and releases.jsonl are append-only; latest.json and
timeline.json are regenerated from the run records.

    python -m probes.darkbloom
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
import tarfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import requests
import urllib3

from probes.observations import _replace, _write_new, digest, new_run_id, utc_now
from verifiers import darkbloom

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "darkbloom"
EVIDENCE = ROOT / "data" / "observations" / "evidence" / "sha256"
API = "https://api.darkbloom.dev"
HEADERS = {"User-Agent": "awesome-private-inference-reference-observatory/1.0"}
COORDINATOR_PATHS = ("/v1/coordinator/attestation", "/.well-known/attestation", "/health", "/v1/encryption-key")
FETCH_ERRORS = (requests.RequestException, urllib3.exceptions.HTTPError, ValueError, tarfile.TarError)


class HTTPStatusError(ValueError):
    pass


def store(value) -> str:
    path = EVIDENCE / f"{digest(value)}.json.gz"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as f:
            f.write(gzip.compress(json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), mtime=0))
    return str(path.relative_to(ROOT))


def load(ref: str, root: Path = ROOT):
    return json.loads(gzip.decompress((root / ref).read_bytes()))


def fetch(path: str) -> dict:
    r = requests.get(API + path, headers=HEADERS, timeout=60)
    ctype = r.headers.get("Content-Type", "")
    body = r.json() if ctype.startswith("application/json") else r.content.decode()
    return {"url": API + path, "status": r.status_code, "content_type": ctype, "body": body,
            "body_sha256": hashlib.sha256(r.content).hexdigest(), "bytes": len(r.content)}


def observe(path: str, require_200: bool) -> tuple[dict, dict]:
    """Archive the response (without its fetch time, so repeats dedupe) and describe it."""
    at = utc_now()
    env = fetch(path)
    ref = store({k: env[k] for k in ("url", "status", "content_type", "body")})
    obs = {"status": "ok", "fetched_at": at, "http_status": env["status"], "raw_ref": ref,
           "body_sha256": env["body_sha256"], "bytes": env["bytes"]}
    if require_200 and env["status"] != 200:
        raise HTTPStatusError(f"HTTP {env['status']}", obs)
    return env, obs


class _Hashing:
    def __init__(self, stream):
        self.stream, self.sha, self.bytes = stream, hashlib.sha256(), 0

    def read(self, n=-1):
        b = self.stream.read(n)
        self.sha.update(b)
        self.bytes += len(b)
        return b


def bundle_manifest(stream) -> dict:
    """sha256 of the whole stream and of every regular file inside the tarball, in one pass."""
    reader, files = _Hashing(stream), {}
    with tarfile.open(fileobj=reader, mode="r|*") as tar:
        for m in tar:
            if m.isfile():
                h, f = hashlib.sha256(), tar.extractfile(m)
                while chunk := f.read(1 << 20):
                    h.update(chunk)
                files[m.name.removeprefix("./")] = {"size": m.size, "sha256": h.hexdigest()}
    while reader.read(1 << 20):
        pass
    return {"sha256": reader.sha.hexdigest(), "bytes": reader.bytes, "files": files}


def fetch_bundle(url: str) -> dict:
    with requests.get(url, headers=HEADERS, stream=True, timeout=60) as r:
        r.raise_for_status()
        return bundle_manifest(r.raw)


def verify_release(release: dict, manifest: dict) -> dict:
    files = manifest["files"]
    return {"bundle_hash_matches": manifest["sha256"] == release["bundle_hash"],
            "binary_hash_matches": files.get("bin/darkbloom", {}).get("sha256") == release["binary_hash"],
            "metallib_hash_matches": files.get("bin/mlx.metallib", {}).get("sha256") == release["metallib_hash"],
            "code_signature": "not_checked"}


RELEASE_KEY = ("version", "bundle_hash", "binary_hash", "metallib_hash")


def append_release(path: Path, release: dict, row: dict) -> dict | None:
    """Append once per (version, bundle, binary, metallib); existing lines are never rewritten."""
    known = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    if any(all(row[k] == release[k] for k in RELEASE_KEY) for row in known):
        return None
    entry = {**{k: release[k] for k in (*RELEASE_KEY, "url", "created_at", "platform", "backend")}, **row,
             "version_seen_with_other_hashes": any(r["version"] == release["version"] for r in known)}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def summarize_providers(feed: dict, at: datetime) -> dict:
    ps, root = feed["providers"], darkbloom.load_root()
    count = lambda f: dict(Counter(f(p) for p in ps).most_common())
    bindings = {p["provider_id"]: darkbloom.binding(p, root, at) for p in ps}
    label = lambda b: f"{b['result']}:{b['reason']}" if "reason" in b else b["result"]
    return {"providers": len(ps), "by_status": count(lambda p: p["status"]),
            "by_trust_level": count(lambda p: p["trust_level"]), "by_chip": count(lambda p: p["chip_name"]),
            "by_model": dict(Counter(m for p in ps for m in p["models"]).most_common()),
            "app_attest_state": count(lambda p: p["verification"]["app_attest"]["state"]),
            "legacy_state": count(lambda p: p["verification"]["legacy"]["state"]),
            "app_attest_authorized": count(lambda p: str(p["app_attest_authorized"]).lower()),
            "mda_verified": count(lambda p: str(p["mda_verified"]).lower()),
            "mda_binding": count(lambda p: label(bindings[p["provider_id"]])),
            "mda_binding_checked": {pid: b for pid, b in sorted(bindings.items()) if b["result"] != "not_checked"}}


def collect() -> dict:
    run_id, started = new_run_id(), utc_now()
    rec = {"run_id": run_id, "started_at": started, "api": API, "steps": {}, "release": None,
           "providers": None, "coordinator": {}}

    def failed(exc: Exception) -> dict:
        obs = exc.args[1] if isinstance(exc, HTTPStatusError) else {}
        return {**obs, "status": "fetch_failed", "error": f"{type(exc).__name__}: {exc.args[0] if exc.args else exc}"}

    try:
        feed, rec["steps"]["providers"] = observe("/v1/providers/attestation", True)
    except FETCH_ERRORS as exc:
        feed, rec["steps"]["providers"] = None, failed(exc)

    try:
        env, rec["steps"]["release"] = observe("/v1/releases/latest", True)
    except FETCH_ERRORS as exc:
        env, rec["steps"]["release"] = None, failed(exc)
    if env:
        release = env["body"]
        rec["release"] = {k: release[k] for k in (*RELEASE_KEY, "url", "created_at", "active")}
        try:
            manifest = fetch_bundle(release["url"])
        except FETCH_ERRORS as exc:
            manifest, rec["steps"]["bundle"] = None, failed(exc)
        if manifest:
            rec["steps"]["bundle"] = {"status": "ok", "bytes": manifest["bytes"], "sha256": manifest["sha256"]}
            rec["release"].update(bundle_files=manifest["files"], verification=verify_release(release, manifest))
        else:
            rec["release"]["verification"] = "not_checked"
        rec["release"]["history_entry"] = append_release(OUT / "releases.jsonl", release, {
            "first_seen_at": rec["steps"]["release"]["fetched_at"], "first_run_id": run_id,
            "release_ref": rec["steps"]["release"]["raw_ref"], "bundle_bytes": manifest and manifest["bytes"],
            "verification": rec["release"]["verification"]}) is not None

    for path in COORDINATOR_PATHS:
        try:
            _, obs = observe(path, False)
            rec["coordinator"][path] = {**obs, "verification": "not_checked"}
        except FETCH_ERRORS as exc:
            rec["coordinator"][path] = failed(exc)

    if feed:
        rec["providers"] = summarize_providers(feed["body"], datetime.fromisoformat(rec["steps"]["providers"]["fetched_at"]))

    statuses = {**rec["steps"], **rec["coordinator"]}
    rec["failed"] = sorted(k for k, v in statuses.items() if v["status"] != "ok")
    rec.update(finished_at=utc_now(), status="failed" if rec["failed"] else "ok")
    _write_new(OUT / "runs" / f"{run_id}.json", rec)
    derive()
    return rec


def derive() -> None:
    runs = sorted((json.loads(p.read_text()) for p in (OUT / "runs").glob("*.json")), key=lambda r: r["started_at"])
    rows = [{"run_id": r["run_id"], "started_at": r["started_at"], "status": r["status"], "failed": r["failed"],
             "providers": r["providers"] and {k: r["providers"][k] for k in (
                 "providers", "by_status", "by_trust_level", "app_attest_authorized", "mda_binding")},
             "release": r["release"] and {k: r["release"][k] for k in ("version", "bundle_hash", "verification")},
             "coordinator": {p: c.get("http_status") for p, c in r["coordinator"].items()}} for r in runs]
    _replace(OUT / "timeline.json", {"runs": rows})
    last = runs[-1]
    _replace(OUT / "latest.json", {
        "meaning": "Coordinator-published feed and release metadata as observed; the MDA binding is our check, "
                   "everything marked not_checked was not verified.",
        "last_run": {k: last[k] for k in ("run_id", "started_at", "finished_at", "status", "failed")},
        "providers": last["providers"] and {k: v for k, v in last["providers"].items() if k != "mda_binding_checked"},
        "release": last["release"] and {k: v for k, v in last["release"].items() if k != "bundle_files"},
        "coordinator": last["coordinator"], "releases_seen": len((OUT / "releases.jsonl").read_text().splitlines())
        if (OUT / "releases.jsonl").exists() else 0})


def main(argv=None) -> int:
    rec = collect()
    print(json.dumps({k: rec[k] for k in ("run_id", "status", "failed")}))
    return 1 if rec["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
