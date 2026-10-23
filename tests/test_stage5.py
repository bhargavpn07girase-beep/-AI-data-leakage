from __future__ import annotations

from pathlib import Path

from leakguard.dashboard import build_dashboard_summary, validate_upload
from leakguard.incident import IncidentStore


def test_dashboard_summary_and_upload_enforcement(tmp_path: Path) -> None:
    db_path = tmp_path / "incidents.db"
    store = IncidentStore(db_path)
    store.record_incident(
        path=tmp_path / "secret.jsonl",
        risk_score=0.91,
        status="quarantined",
        reasons=["email", "phone"],
        quarantined_at="2026-01-01T00:00:00+00:00",
    )
    store.record_incident(
        path=tmp_path / "safe.txt",
        risk_score=0.12,
        status="normal",
        reasons=["no_sensitive_patterns_detected"],
        quarantined_at=None,
    )

    summary = build_dashboard_summary(store)
    assert summary.total == 2
    assert summary.quarantined == 1
    assert summary.normal == 1

    upload_file = tmp_path / "upload.jsonl"
    upload_file.write_text('{"email": "user@example.com", "phone": "555-123-4567"}\n', encoding="utf-8")
    allowed, reason, risk_score = validate_upload(upload_file)

    assert allowed is False
    assert risk_score >= 0.5
    assert "blocked" in reason.lower()
