"""Daily per-machine archive of NEAR AI Cloud model machines (tasks/near-machine-archive-plan.md).

Each report is archived (whitelisted) before it is appraised; a policy rejection is
an appraisal outcome, a fetch or appraisal failure fails the run. Captures, run
records and actions.jsonl are append-only; index, timelines and changes are derived.

    python -m probes.near_machines
    python -m probes.near_machines --backfill PATH[@ISO_TIME] ...
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from probes.observations import _replace, _write_new, digest, new_run_id, utc_now
from verifiers import dstack_tdx, near_ai, near_deployments

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "near-machines"
EVIDENCE = ROOT / "data" / "observations" / "evidence" / "sha256"
GATEWAY = "https://cloud-api.near.ai"
DIRECT = "https://completions.near.ai"
# Direct is the only cert->instance binding and fleet count. Remove this stage in its own commit on 2026-12-06.
DIRECT_UNTIL = date(2026, 12, 6)
EXCLUDED: dict[str, str] = {}  # attested nearai-owned models deliberately not collected: model -> reason
RETENTION = timedelta(days=6)
LABEL_RE = re.compile(r"INSTANCE_LABEL=(\w+)")
FETCH_ERRORS = (near_ai.FetchError, requests.RequestException, OSError, ValueError)


def store(value) -> str:
    path = EVIDENCE / f"{digest(value)}.json"
    if not path.exists():
        _write_new(path, value)
    return str(path.relative_to(ROOT))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def iid_of(att: dict) -> str:
    return att["info"]["instance_id"]


def reduce(att: dict, full: set) -> dict:
    """One full raw entry per machine per run; a repeat keeps its quotes and per-model keys."""
    pub = near_ai._public_attestation_fields(att)
    q = dstack_tdx.parse_quote(att["intel_quote"])
    machine = (iid_of(att), *(q[r] for r in (*near_deployments.REGISTERS, "mrconfigid")))
    if machine in full:
        pub.pop("nvidia_payload", None)
        pub["info"] = {k: pub["info"][k] for k in ("instance_id", "app_id", "compose_hash") if k in pub["info"]}
        pub["reduced"] = ["nvidia_payload", "info"]
    full.add(machine)
    cm = pub.get("compose_manager_attestation")
    if cm:
        log = (iid_of(att), cm["actions_hash"])
        if log in full:
            pub["compose_manager_attestation"] = {k: cm[k] for k in (
                "quote", "report_data", "nonce", "nonce_source", "actions_hash") if k in cm}
            pub["reduced"] = pub.get("reduced", []) + ["compose_manager_attestation"]
        full.add(log)
    return pub


def entry_record(m: dict, model: str, source: str, nonce: str, nonce_ours: bool, raw_ref: str) -> dict:
    q = dstack_tdx.parse_quote(m["intel_quote"])
    tcb, info = near_ai._tcb_info(m), m["info"]
    compose = tcb.get("app_compose")
    label = LABEL_RE.search(compose) if compose else None
    rec = {"model": model, "served_model": m.get("model_name"), "source": source, "nonce": nonce,
           "nonce_ours": nonce_ours, "raw_ref": raw_ref,
           "quote_sha256": hashlib.sha256(bytes.fromhex(m["intel_quote"].removeprefix("0x"))).hexdigest(),
           "identity": {"label": label and label.group(1), "app_id": info.get("app_id"),
                        "compose_hash": tcb.get("compose_hash") or info.get("compose_hash"),
                        "app_compose_sha256": compose and sha256(compose),
                        "os_image_hash": tcb.get("os_image_hash") or info.get("os_image_hash"),
                        "vm_config": info.get("vm_config"), "device_id": info.get("device_id"),
                        "debug_disabled": dstack_tdx.tee_debug_disabled(q["td_attributes"]),
                        **{r: q[r] for r in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mrconfigid")}},
           **{k: m.get(k) for k in ("signing_algo", "signing_public_key", "signing_address",
                                    "tls_cert_fingerprint", "ohttp_key_config")},
           "compose_manager": None}
    cm = m.get("compose_manager_attestation")
    if cm:
        cq = dstack_tdx.parse_quote(cm["quote"])
        recomputed = near_deployments.actions_hash(cm["actions"])
        c = rec["compose_manager"] = {
            "actions_hash": cm["actions_hash"], "recomputed_ok": recomputed == cm["actions_hash"].lower(),
            "report_data_binds_nonce": cq["report_data"].lower() == recomputed + nonce.lower(),
            "same_cvm_as_model": all(cq[r] == q[r] for r in near_deployments.REGISTERS),
            "nonce_source": cm.get("nonce_source"),
            "quote_sha256": hashlib.sha256(bytes.fromhex(cm["quote"].removeprefix("0x"))).hexdigest(),
            "action_digests": [digest(a) for a in cm["actions"]],
            "running": near_deployments.running_deployments(cm["actions"])}
        # Fresh only against a nonce we chose; an echoed nonce proves self-consistency, not freshness.
        c["bound"] = nonce_ours and c["recomputed_ok"] and c["report_data_binds_nonce"] and c["same_cvm_as_model"]
    return rec


def appraisal_for(report, i: int) -> dict:
    d = report.details
    out = {"verification_status": d.get("verification_status", "rejected"), "error": report.error}
    if "entries" in d:
        tdx = d["tdx"]["models"][i]
        comp = next((c for c in d.get("model_composes", []) if c["entry"] == i), None)
        out.update(d["entries"][i], advisory_ids=tdx["advisory_ids"],
                   boot_registers=tdx["measurements"]["boot_registers"],
                   deployments=comp and comp["deployments"], chain_authorized=comp and comp["chain_authorized"])
    return out


class Run:
    def __init__(self, kind: str, captured_at: str, run_id: str):
        self.record = {"run_id": run_id, "kind": kind, "started_at": captured_at, "models": {},
                       "direct": {}, "findings": []}
        self.machines: dict[str, list] = {}
        self.logs: dict[str, list] = {}
        self.full: set = set()

    def add(self, m: dict, rec: dict) -> None:
        self.machines.setdefault(iid_of(m), []).append(rec)
        if rec["compose_manager"]:
            self.logs.setdefault(iid_of(m), []).append((m["compose_manager_attestation"]["actions"],
                                                        rec["compose_manager"]["bound"]))

    def gateway_report(self, report: dict, model: str, nonce: str, nonce_ours: bool, source: str,
                       fetched_at: str, appraise: bool, raw_ref: str | None = None) -> dict:
        atts = report.get("model_attestations") or []
        gw = report.get("gateway_attestation")
        raw_ref = raw_ref or store({
            "source": source, "requested_model": model, "nonce": nonce, "fetched_at": fetched_at,
            "gateway_attestation": gw and reduce(gw, self.full),
            "model_attestations": [reduce(m, self.full) for m in atts],
            **{k: report.get(k) for k in ("tls_certificate", "ohttp_key_config", "ohttp_attestation")}})
        out = {"status": "ok", "nonce": nonce, "raw_ref": raw_ref, "instances": [iid_of(m) for m in atts]}
        appraisal = None
        if appraise:
            try:
                appraisal = near_ai.appraise_report(report, model, nonce, near_deployments.load_archive(), GATEWAY)
                out.update(verification_status=appraisal.details.get("verification_status", "rejected"),
                           error=appraisal.error)
            except Exception as exc:  # recorded and fails the run
                out.update(status="appraisal_error", error=f"{type(exc).__name__}: {exc}")
        for i, m in enumerate(atts):
            rec = entry_record(m, model, source, nonce, nonce_ours, raw_ref)
            rec["raw_index"] = i
            if appraisal:
                rec["appraisal"] = appraisal_for(appraisal, i)
            self.add(m, rec)
        return out

    def direct_report(self, m: dict, nonce: str, nonce_ours: bool, source: str, fetched_at: str,
                      presented: dict | None = None) -> str:
        raw_ref = store({"source": source, "nonce": nonce, "fetched_at": fetched_at, "presented": presented,
                         "attestation": reduce(m, self.full),
                         "all_attestations": [reduce(a, self.full) for a in m.get("all_attestations") or []]})
        rec = entry_record(m, m["model_name"], source, nonce, nonce_ours, raw_ref)
        if presented:
            rec["presented_spki_matches"] = presented["spki_sha256"] == m.get("tls_cert_fingerprint")
        self.add(m, rec)
        return iid_of(m)

    def finish(self, now: datetime) -> dict:
        run_id = self.record["run_id"]
        for iid, entries in self.machines.items():
            path = OUT / iid / "captures" / f"{run_id}.json"
            _write_new(path, {"run_id": run_id, "kind": self.record["kind"], "instance_id": iid,
                              "captured_at": self.record["started_at"],
                              "label": entries[0]["identity"]["label"], "entries": entries})
            self.record["findings"] += update_actions(iid, self.logs.get(iid, []), self.record["started_at"],
                                                      str(path.relative_to(ROOT)), now)
        failed = [m for m, r in {**self.record["models"], **self.record["direct"]}.items() if r["status"] != "ok"]
        self.record.update(finished_at=utc_now(), status="failed" if failed else "ok", failed=failed)
        _write_new(OUT / "runs" / f"{run_id}.json", self.record)
        derive()
        return self.record


def update_actions(iid: str, logs: list, captured_at: str, capture_ref: str, now: datetime) -> list:
    path = OUT / iid / "actions.jsonl"
    known = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    seen, seen_bound = {a["sha256"] for a in known}, {a["sha256"] for a in known if a["bound"]}
    new = []
    for actions, bound in logs:
        for a in actions:
            h = digest(a)
            if h not in seen or (bound and h not in seen_bound):
                new.append({"sha256": h, "action": a, "first_seen_at": captured_at,
                            "first_capture": capture_ref, "bound": bound})
                seen.add(h)
                if bound:
                    seen_bound.add(h)
    if new:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.writelines(json.dumps(a, sort_keys=True) + "\n" for a in new)
    today = {digest(a) for actions, bound in logs if bound for a in actions}
    if not today:
        return []
    missing = sorted({a["sha256"] for a in known if a["sha256"] not in today
                      and datetime.fromisoformat(a["action"]["timestamp"]) >= now - RETENTION})
    return [{"kind": "actions_missing_within_retention", "instance_id": iid, "sha256": missing}] if missing else []


def get_json(url: str, **params):
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def fetch_direct(domain: str, i: int, nonce: str) -> tuple[dict, dict]:
    """Read the report and the leaf certificate from the same TLS connection."""
    host = domain.replace(".completions.near.ai", f"-i{i}.completions.near.ai")
    conn = http.client.HTTPSConnection(host, timeout=30)
    conn.request("GET", "/v1/attestation/report?" + urlencode(
        {"nonce": nonce, "signing_algo": "ecdsa", "include_tls_fingerprint": "true"}))
    resp, cert = conn.getresponse(), x509.load_der_x509_certificate(conn.sock.getpeercert(True))
    body = resp.read()
    conn.close()
    if resp.status != 200:
        raise near_ai.FetchError(f"{host}: HTTP {resp.status}: {body[:200]!r}")
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return json.loads(body), {"host": host, "leaf_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
                              "spki_sha256": hashlib.sha256(spki).hexdigest()}


def collect(api_key: str | None, now: datetime) -> dict:
    run = Run("live", utc_now(), new_run_id())
    listing = get_json(f"{GATEWAY}/v1/model/list")
    if listing["total"] > len(listing["models"]):
        raise ValueError(f"model list is paged: {len(listing['models'])} of {listing['total']}")
    attested = [m for m in listing["models"] if m["metadata"].get("attestationSupported")]
    selected = [m["modelId"] for m in attested
                if m["metadata"].get("ownedBy") == "nearai" and m["modelId"] not in EXCLUDED]
    run.record.update(model_list_ref=store(listing), selected=selected, excluded=EXCLUDED,
                      not_nearai={m["modelId"]: m["metadata"].get("ownedBy") for m in attested
                                  if m["metadata"].get("ownedBy") != "nearai"})
    for model in selected:
        nonce = secrets.token_hex(32)
        try:
            report = near_ai.fetch_report(api_key, GATEWAY, model, nonce)
        except FETCH_ERRORS as exc:
            run.record["models"][model] = {"status": "fetch_failed", "nonce": nonce,
                                           "error": f"{type(exc).__name__}: {exc}"}
            continue
        run.record["models"][model] = run.gateway_report(report, model, nonce, True, "gateway", utc_now(), True)
    if now.date() < DIRECT_UNTIL:
        try:
            fleet = [(ep["domain"], get_json(f"{DIRECT}/backends/count", domain=ep["domain"]))
                     for ep in get_json(f"{DIRECT}/endpoints")["endpoints"]]
        except FETCH_ERRORS as exc:
            run.record["direct"]["endpoints"] = {"status": "fetch_failed", "error": f"{type(exc).__name__}: {exc}"}
            fleet = []
        for domain, count in fleet:
            for i in range(count["total"]):
                nonce, key = secrets.token_hex(32), f"{domain}#i{i}"
                try:
                    report, presented = fetch_direct(domain, i, nonce)
                except FETCH_ERRORS as exc:
                    run.record["direct"][key] = {"status": "fetch_failed", "error": f"{type(exc).__name__}: {exc}"}
                    continue
                iid = run.direct_report(report, nonce, True, f"direct:{presented['host']}", utc_now(), presented)
                run.record["direct"][key] = {"status": "ok", "instance_id": iid, "backends": count}
    return run.finish(now)


def backfill(specs: list[str]) -> list[dict]:
    """Each PATH becomes its own run. Repo evidence takes its time from the observation
    record citing it; a directory with fetched_at.txt from that; otherwise pass @ISO_TIME."""
    cited = {}
    for rec in (OUT.parent / "observations" / "records").glob("*/*.json"):
        r = json.loads(rec.read_text())
        cited.setdefault(r["evidence"].get("raw_evidence_sha256"), r["captured_at"])
    jobs = []
    for spec in specs:
        path, _, at = spec.partition("@")
        p = Path(path).resolve()
        if not at:
            at = cited[p.stem] if p.parent == EVIDENCE else (p.parent / "fetched_at.txt").read_text().strip()
        jobs.append((datetime.fromisoformat(at.replace("Z", "+00:00")).astimezone(timezone.utc), p))
    records = []
    for at, p in sorted(jobs):
        data = p.read_bytes()
        rel = p.relative_to(ROOT) if p.is_relative_to(ROOT) else p.relative_to(Path.home() / "projects")
        source = f"backfill:{rel}@sha256:{hashlib.sha256(data).hexdigest()}"
        doc = json.loads(data)
        stamp = at.isoformat(timespec="microseconds").replace("+00:00", "Z")
        run = Run("backfill", stamp, f"backfill-{at.strftime('%Y%m%dT%H%M%SZ')}-{hashlib.sha256(data).hexdigest()[:12]}")
        run.record["source"] = source
        nonce_file = p.with_name(p.name + ".nonce")
        if p.parent == EVIDENCE:  # already archived by the probe, with our nonce
            run.record["models"][doc["requested_model"]] = run.gateway_report(
                doc, doc["requested_model"], doc["nonce"], True, source, stamp, False, str(rel))
        elif "model_attestations" in doc:
            nonce, ours = ((nonce_file.read_text().strip(), True) if nonce_file.exists() else
                           (doc["model_attestations"][0]["request_nonce"], False))
            model = p.stem.removeprefix("att_").replace("_", "/", 1)
            run.record["models"][model] = run.gateway_report(doc, model, nonce, ours, source, stamp, False)
        else:  # a Direct report; we hold only the nonce it echoes
            run.direct_report(doc, doc["request_nonce"], False, source, stamp)
            run.record["direct"][str(rel)] = {"status": "ok"}
        records.append(run.finish(at))
    return records


def facts(capture: dict) -> dict:
    """Comparable facts of one capture; a value the capture did not retain is unknown, not a change."""
    f: dict = {}

    def add(key, value):
        if value is not None:
            f.setdefault(key, set()).add(value)
    for e in capture["entries"]:
        for k in ("label", "compose_hash", "app_compose_sha256", "os_image_hash", "vm_config",
                  "mrtd", "rtmr0", "rtmr1", "rtmr2"):
            add(k, e["identity"][k])
        m = f"{e['model']}/{e['signing_algo']}"
        for k in ("signing_address", "tls_cert_fingerprint", "ohttp_key_config"):
            add(f"{k}[{m}]", e[k])
        if "appraisal" in e:
            add(f"tcb_status[{m}]", e["appraisal"].get("tcb_status"))
            add(f"gpu_verdict[{m}]", e["appraisal"].get("gpu_verdict"))
        if e["compose_manager"] and e["compose_manager"]["bound"]:
            for d in e["compose_manager"]["running"]:
                add("running", f"{d['file']}@{d['commit']}:{d['file_sha256']}")
    if capture["kind"] == "live":
        f["models"] = {e["model"] for e in capture["entries"]}
        for m in f["models"]:
            f[f"entries[{m}]"] = {sum(e["model"] == m for e in capture["entries"])}
    return {k: sorted(v, key=str) for k, v in f.items()}


def derive() -> None:
    """Regenerate index.json, <instance>/timeline.json and changes/<run_id>.json."""
    machines, changes = {}, {}
    for d in sorted(p for p in OUT.iterdir() if (p / "captures").is_dir()):
        caps = sorted((json.loads(p.read_text()) for p in (d / "captures").glob("*.json")),
                      key=lambda c: c["captured_at"])
        actions = [json.loads(line) for line in (d / "actions.jsonl").read_text().splitlines()] \
            if (d / "actions.jsonl").exists() else []
        events, prev = [], None
        for c in caps:
            cur = facts(c)
            for k in sorted(set(cur) & set(prev or {})):
                if cur[k] != prev[k]:
                    ev = {"at": c["captured_at"], "run_id": c["run_id"], "field": k, "old": prev[k], "new": cur[k]}
                    events.append(ev)
                    changes.setdefault(c["run_id"], []).append({"instance_id": d.name, "label": c["label"], **ev})
            prev = {**(prev or {}), **cur}
        _replace(d / "timeline.json", {
            "instance_id": d.name, "label": caps[-1]["label"], "first_seen": caps[0]["captured_at"],
            "last_seen": caps[-1]["captured_at"], "captures": len(caps), "changes": events,
            "deploy_actions": sorted(({**a["action"], "sha256": a["sha256"], "bound": a["bound"]} for a in actions),
                                     key=lambda a: a.get("timestamp", ""))})
        machines[d.name] = {"label": caps[-1]["label"], "first_seen": caps[0]["captured_at"],
                            "last_seen": caps[-1]["captured_at"], "captures": len(caps),
                            "models": sorted({e["model"] for e in caps[-1]["entries"]}),
                            "actions": len({a["sha256"] for a in actions})}
    runs = sorted((json.loads(p.read_text()) for p in (OUT / "runs").glob("*.json")), key=lambda r: r["started_at"])
    for r in runs:
        _replace(OUT / "changes" / f"{r['run_id']}.json", {
            "run_id": r["run_id"], "kind": r["kind"], "status": r["status"], "failed": r["failed"],
            "findings": r["findings"], "changes": changes.get(r["run_id"], [])})
    live = [r for r in runs if r["kind"] == "live"]
    _replace(OUT / "index.json", {"machines": machines, "last_live_run": {
        k: live[-1][k] for k in ("run_id", "started_at", "finished_at", "status", "failed")} if live else None})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backfill", nargs="+", metavar="PATH[@ISO_TIME]")
    args = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    records = backfill(args.backfill) if args.backfill else [collect(os.environ.get("NEAR_API_KEY"), now)]
    for r in records:
        print(json.dumps({k: r[k] for k in ("run_id", "status", "failed", "findings")}))
    return 1 if any(r["status"] != "ok" for r in records) else 0


if __name__ == "__main__":
    sys.exit(main())
