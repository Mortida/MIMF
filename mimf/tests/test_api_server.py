from __future__ import annotations

import io

from fastapi.testclient import TestClient


def test_api_inspect_normalize_export_verify_roundtrip(monkeypatch, tmp_path):
    """API smoke test: inspect -> normalize -> export-bundle -> verify-bundle.

    Security notes:
    - Uses an in-memory JSON file (no sensitive data).

    """

    # Configure one API key.
    monkeypatch.setenv(
        "MIMF_API_KEYS",
        "testkey:alice:export:document.basic,export:document.identifying,export:document.tooling,runtime:read,runtime:write",
    )
    monkeypatch.delenv("MIMF_REQUIRE_AUTH", raising=False)

    from mimf.api.server import create_app

    app = create_app(db_path=str(tmp_path / "mimf_runtime.db"))
    client = TestClient(app)

    payload = b'{"hello": "world", "n": 1}\n'

    # Inspect
    r = client.post(
        "/inspect",
        headers={"X-MIMF-API-Key": "testkey"},
        files={"file": ("sample.data", io.BytesIO(payload), "application/octet-stream")},
    )
    assert r.status_code == 200
    # Request correlation header
    assert r.headers.get("x-request-id")
    data = r.json()
    assert data["file"]["mime_type"] in {"application/json", "application/octet-stream"}
    assert data["metadata"].get("sha256")

    # Normalize
    r2 = client.post(
        "/normalize",
        headers={"X-MIMF-API-Key": "testkey"},
        files={"file": ("sample.data", io.BytesIO(payload), "application/octet-stream")},
        data={"boundary_caps": "export:document.basic"},
    )
    assert r2.status_code == 200
    norm = r2.json()
    assert norm["export_policy"]["status"] in {"ALLOW", "DENY"}

    # Export bundle
    r3 = client.post(
        "/export-bundle",
        headers={"X-MIMF-API-Key": "testkey"},
        files={"file": ("sample.data", io.BytesIO(payload), "application/octet-stream")},
        data={"include_original": False, "persist": True},
    )
    assert r3.status_code == 200
    ctx_id = r3.headers.get("x-mimf-context-id")
    assert ctx_id

    # List contexts
    rctx = client.get("/contexts", headers={"X-MIMF-API-Key": "testkey"})
    assert rctx.status_code == 200
    contexts = rctx.json()
    assert any(c["context_id"] == ctx_id for c in contexts)

    # Get context detail (bounded)
    rdet = client.get(f"/contexts/{ctx_id}", headers={"X-MIMF-API-Key": "testkey"})
    assert rdet.status_code == 200
    detail = rdet.json()
    assert detail["context"]["context_id"] == ctx_id
    assert detail["integrity_ok"] is True
    assert r3.headers.get("x-request-id")
    assert r3.headers.get("x-mimf-bundle-id")
    assert r3.headers.get("content-type", "").startswith("application/zip")
    bundle_bytes = r3.content
    assert len(bundle_bytes) > 100

    # Verify bundle
    r4 = client.post(
        "/verify-bundle",
        headers={"X-MIMF-API-Key": "testkey"},
        files={"bundle_zip": ("bundle.zip", io.BytesIO(bundle_bytes), "application/zip")},
    )
    assert r4.status_code == 200
    v = r4.json()
    assert v["ok"] is True


def test_api_rate_limit_and_upload_cap(monkeypatch, tmp_path):
    """API hardening: rate limiting + upload size cap.

    Security notes:
    - Rate limiting is best-effort (memory-only), but should fail closed with 429.
    - Upload cap should reject oversize inputs with 413.

    """

    monkeypatch.setenv(
        "MIMF_API_KEYS",
        "k:alice:export:document.basic",
    )
    monkeypatch.setenv("MIMF_RATE_LIMIT_RPM", "1")
    monkeypatch.setenv("MIMF_RATE_LIMIT_BURST", "1")
    monkeypatch.setenv("MIMF_MAX_UPLOAD_BYTES", "16")

    from mimf.api.server import create_app

    app = create_app(db_path=str(tmp_path / "mimf_runtime.db"))
    client = TestClient(app)

    small = b'{"a":1}\n'
    r1 = client.post(
        "/inspect",
        headers={"X-MIMF-API-Key": "k"},
        files={"file": ("s.json", io.BytesIO(small), "application/octet-stream")},
    )
    assert r1.status_code == 200

    # Second request should be rate limited.
    r2 = client.post(
        "/inspect",
        headers={"X-MIMF-API-Key": "k"},
        files={"file": ("s.json", io.BytesIO(small), "application/octet-stream")},
    )
    assert r2.status_code == 429
    assert r2.headers.get("retry-after")

    # For upload cap, spin up a new app with a permissive rate limit.
    monkeypatch.setenv("MIMF_RATE_LIMIT_RPM", "1000")
    monkeypatch.setenv("MIMF_RATE_LIMIT_BURST", "1000")
    app2 = create_app(db_path=None)
    client2 = TestClient(app2)

    # Oversize upload should be rejected.
    big = b"x" * 64
    r3 = client2.post(
        "/inspect",
        headers={"X-MIMF-API-Key": "k"},
        files={"file": ("b.bin", io.BytesIO(big), "application/octet-stream")},
    )
    assert r3.status_code == 413
