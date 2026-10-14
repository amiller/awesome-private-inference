"""Public-reference capture contracts; no live network required."""
import hashlib
from pathlib import Path

from probes import references


class Response:
    def __init__(self, code, body, url):
        self.status_code, self.body, self.url = code, body, url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, chunk_size):
        yield self.body


class Session:
    def __init__(self, responses):
        self.responses = responses
        self.headers_seen = []

    def get(self, url, headers, **kwargs):
        self.headers_seen.append(headers)
        status, body = self.responses.pop(0)
        return Response(status, body, url)


def test_capture_keeps_raw_bytes_and_per_source_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(references, "sources", lambda: [
        {"id": "ok", "provider": "maple", "kind": "pcr_publication", "url": "https://example.test/ok"},
        {"id": "no", "provider": "maple", "kind": "pcr_publication", "url": "https://example.test/no"},
        {"id": "private-inference-chat-html", "provider": "private-inference", "kind": "browser_entrypoint", "url": "https://example.test/chat"},
    ])
    session = Session([(200, b"exact bytes\n"), (404, b"missing"), (200, b"<html></html>")])
    rows = references.capture_publications(tmp_path, session=session)
    assert rows[0]["status"] == "observed"
    assert (tmp_path / rows[0]["raw_path"]).read_bytes() == b"exact bytes\n"
    assert rows[0]["raw_base"] is None  # external temp paths cannot leak into a published index
    assert rows[0]["verification"] == "not_performed"
    assert rows[1]["status"] == "error" and rows[1]["error"] == "HTTP 404"
    assert any(row.get("error") == "module script absent from captured HTML" for row in rows)
    assert rows[-1]["source_id"] == "private-inference-browser-verifier"
    assert len(list(tmp_path.glob("publications-*.json"))) == 1


def test_index_events_preserve_last_success_through_error_and_recovery(tmp_path):
    path = tmp_path / "latest.json"
    base = {"source_id": "manifest", "provider": "privatemode", "kind": "manifest", "url": "https://example.test/m", "verification": "not_performed"}
    first = {**base, "status": "observed", "observed_at": "2026-10-14T00:00:00Z", "sha256": "abc", "bytes": 3, "raw_path": "raw/a"}
    assert references.write_index([first], path)["changes"] == []
    error = {**base, "status": "error", "observed_at": "2026-10-14T01:00:00Z", "error": "HTTP 503"}
    unavailable = references.write_index([error], path)
    assert unavailable["observations"][0]["last_success"]["sha256"] == "abc"
    assert unavailable["changes"][0]["type"] == "publication_error"
    recovered = references.write_index([{**first, "observed_at": "2026-10-14T02:00:00Z"}], path)
    assert recovered["changes"][0]["type"] == "publication_recovered"
    assert recovered["changes"][0]["previous_sha256"] == "abc"
    assert len(list((tmp_path / "events").glob("*.json"))) == 2
    changed = references.write_index([{**first, "observed_at": "2026-10-14T03:00:00Z", "sha256": "def"}], path)
    assert changed["changes"][0]["type"] == "publication_changed"
    missing = references.write_index([{**error, "observed_at": "2026-10-14T04:00:00Z", "http_status": 404}], path)
    assert missing["changes"][0]["type"] == "publication_missing"
    assert missing["observations"][0]["last_success"]["sha256"] == "def"


def test_catalog_credentials_never_appear_in_observation(tmp_path, monkeypatch):
    monkeypatch.setattr(references, "CATALOGS", [{"id": "models", "provider": "venice", "kind": "model_catalog", "env": "NONE", "url": "https://example.test/models"}])
    session = Session([(200, b'{"data":[{"id":"b"},{"id":"a"}]}')])
    rows = references.discover_catalogs(tmp_path, api_keys={"venice": "SECRET"}, session=session)
    assert rows[0]["model_ids"] == ["a", "b"]
    assert rows[0]["credential_used"] is True
    assert session.headers_seen[0]["Authorization"] == "Bearer SECRET"
    assert "SECRET" not in (tmp_path / rows[0]["raw_path"]).read_text()
    assert "SECRET" not in list(tmp_path.glob("discovery-*.json"))[0].read_text()


def test_portable_archive_base_accepts_only_repository_paths(tmp_path):
    root = Path(references.__file__).resolve().parents[1]
    assert references._portable_base(root / "data/references/observations") == "data/references/observations"
    assert references._portable_base(tmp_path) is None


def test_capture_follows_bounded_private_verifier_import(tmp_path, monkeypatch):
    monkeypatch.setattr(references, "sources", lambda: [
        {"id": "private-inference-chat-html", "provider": "private-inference", "kind": "browser_entrypoint", "url": "https://example.test/chat"},
    ])
    session = Session([
        (200, b'<script type="module" src="/chat/js/main-v1.js"></script>'),
        (200, b'const verifier = import("./browser-v2.js")'),
        (200, b"verifier bytes"),
    ])
    rows = references.capture_publications(tmp_path, session=session)
    assert [row["source_id"] for row in rows] == [
        "private-inference-chat-html", "private-inference-chat-main", "private-inference-browser-verifier"]
    assert rows[-1]["url"] == "https://privateinference.gg/chat/js/browser-v2.js"
    assert (tmp_path / rows[-1]["raw_path"]).read_bytes() == b"verifier bytes"


def test_existing_raw_archive_cannot_be_silently_rewritten(tmp_path):
    body = b"correct"
    digest = hashlib.sha256(body).hexdigest()
    path = tmp_path / "raw" / f"x-{digest}.bin"
    path.parent.mkdir()
    path.write_bytes(b"corrupt")
    row = references._observe({"id": "x", "provider": "maple", "kind": "pcr_publication",
                               "url": "https://example.test/x"}, tmp_path, Session([(200, body)]), 1)
    assert row["status"] == "error"
    assert "stored archive hash mismatch" in row["error"]
    assert path.read_bytes() == b"corrupt"


def test_unpolled_weekly_catalog_survives_daily_index(tmp_path):
    path = tmp_path / "latest.json"
    catalog = {"source_id": "catalog", "provider": "near-ai", "kind": "model_catalog", "status": "error", "observed_at": "2026-10-14T00:00:00Z"}
    references.write_index([catalog], path)
    index = references.write_index([], path)
    assert index["observations"] == [catalog]


def test_catalog_price_churn_is_not_route_change(tmp_path):
    path = tmp_path / "latest.json"
    base = {"source_id": "models", "provider": "private-inference", "kind": "model_catalog",
            "status": "observed", "url": "https://example.test/models", "bytes": 5, "raw_path": "raw/models",
            "verification": "not_performed", "semantic_sha256": "stable"}
    references.write_index([{**base, "observed_at": "2026-10-14T00:00:00Z", "sha256": "price1"}], path)
    unchanged = references.write_index([{**base, "observed_at": "2026-10-14T01:00:00Z", "sha256": "price2"}], path)
    assert unchanged["changes"] == []
    changed = references.write_index([{**base, "observed_at": "2026-10-14T02:00:00Z",
                                       "sha256": "price3", "semantic_sha256": "new_route"}], path)
    assert changed["changes"][0]["type"] == "catalog_changed"
    assert changed["changes"][0]["route_id"] == "publication/models"


def test_maple_mirror_mismatch_is_high_priority(tmp_path):
    path = tmp_path / "latest.json"
    rows = [{"source_id": f"maple-{side}-pcrProd.json", "provider": "maple", "kind": "pcr_publication",
             "status": "observed", "url": f"https://example.test/{side}", "observed_at": "2026-10-14T00:00:00Z",
             "sha256": digest, "bytes": 1, "raw_path": f"raw/{side}", "verification": "not_performed"}
            for side, digest in (("canonical", "aaa"), ("legacy", "bbb"))]
    result = references.write_index(rows, path)
    assert result["mirror_agreements"]["pcrProd.json"] is False
    mismatch = result["changes"][0]
    assert mismatch["kind"] == "reference_mismatch" and mismatch["priority"] == "high"
    assert mismatch["affected_routes"]
    rows[1]["sha256"] = "aaa"
    restored = references.write_index(rows, path)
    assert any(event["kind"] == "reference_agreement_restored" for event in restored["changes"])
