from __future__ import annotations

from pathlib import Path

from leakguard.incident import IncidentStore, RiskEngine, RiskPolicy


def test_store_persists_incident_and_quarantine(tmp_path: Path) -> None:
    db_path = tmp_path / "incidents.db"
    quarantine_dir = tmp_path / "quarantine"
    store = IncidentStore(db_path)
    engine = RiskEngine(
        policy=RiskPolicy(
            suspicious_threshold=0.5,
            quarantine_threshold=0.7,
            quarantine_dir=quarantine_dir,
        ),
        store=store,
    )

    source = tmp_path / "sensitive.jsonl"
    source.write_text(
        '{"email": "user@example.com", "phone": "555-123-4567"}\n',
        encoding="utf-8",
    )

    incident = engine.evaluate_file(source)

    assert incident.risk_score >= 0.5
    assert incident.status in {"open", "quarantined"}
    assert incident.path == str(source)
    assert store.list_incidents()[-1].path == str(source)
    assert (quarantine_dir / source.name).exists() or incident.status == "quarantined"
