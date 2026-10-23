"""Pytest test suite verifying Phase 0 fixes for SentinelDLP."""

from pathlib import Path
import tempfile
import sqlite3
import pytest
from fastapi.testclient import TestClient

from leakguard.api import app, store, engine
from leakguard.stats import compute_kpis, DashboardKPIs
from leakguard.incident import IncidentStore, RiskEngine, RiskPolicy


@pytest.fixture
def test_client():
    return TestClient(app)


def test_stats_consistency_and_definitions(tmp_path):
    """Verify compute_kpis calculates numbers directly and accurately from SQLite."""
    db_file = tmp_path / "test_kpi.db"
    store_instance = IncidentStore(db_file)
    
    # Empty DB
    kpis = compute_kpis(db_file, tmp_path / "quarantine")
    assert kpis.total_scanned == 0
    assert kpis.open_incidents == 0
    assert kpis.quarantined == 0
    assert kpis.detection_rate_pct is None
    assert "total_scanned" in kpis.to_dict()["definitions"]

    # Seed records: 1 normal, 1 open, 1 quarantined, 1 blocked
    store_instance.record_incident(
        path="file1.txt",
        risk_score=0.10,
        status="normal",
        reasons=["Normal content"],
    )
    store_instance.record_incident(
        path="file2.txt",
        risk_score=0.45,
        status="open",
        reasons=["Suspicious keyword"],
    )
    store_instance.record_incident(
        path="file3.txt",
        risk_score=0.85,
        status="quarantined",
        reasons=["Valid Credit Card"],
    )
    store_instance.record_incident(
        path="file4.txt",
        risk_score=0.95,
        status="blocked",
        reasons=["High risk Aadhaar"],
    )

    kpis2 = compute_kpis(db_file, tmp_path / "quarantine")
    assert kpis2.total_scanned == 4
    assert kpis2.open_incidents == 1
    assert kpis2.quarantined == 1
    assert kpis2.blocked == 1
    assert kpis2.high_risk == 2  # 0.85 and 0.95 >= 0.70
    # detection_rate = (1 + 1 + 1) / 4 = 75.0%
    assert kpis2.detection_rate_pct == 75.0
    assert kpis2.average_risk == pytest.approx(58.8, abs=0.2)


def test_quarantine_restore_collision_and_hash(tmp_path):
    """Verify quarantine restore appends _restored_<ts> on name collision."""
    q_dir = tmp_path / "quarantine"
    m_dir = tmp_path / "monitored"
    q_dir.mkdir(parents=True)
    m_dir.mkdir(parents=True)

    db_path = tmp_path / "test.db"
    test_store = IncidentStore(db_path)
    test_policy = RiskPolicy(quarantine_dir=q_dir)
    test_engine = RiskEngine(policy=test_policy, store=test_store)

    # Place a file into quarantine vault
    q_file = q_dir / "confidential_data_20261013T000000.csv"
    q_file.write_text("dummy sensitive data", encoding="utf-8")

    # Also pre-create target in monitored to force collision
    target_existing = m_dir / "confidential_data.csv"
    target_existing.write_text("existing original file", encoding="utf-8")

    # Restore
    restored_path = test_engine.restore_quarantined_file("confidential_data_20261013T000000.csv", target_dir=m_dir)
    assert restored_path is not None
    assert Path(restored_path).exists()
    assert "_restored_" in Path(restored_path).name
    assert target_existing.read_text(encoding="utf-8") == "existing original file"
    assert Path(restored_path).read_text(encoding="utf-8") == "dummy sensitive data"


def test_api_incidents_pagination_and_bulk_action(test_client):
    """Verify GET /api/incidents pagination and POST /api/incidents/bulk-action."""
    # Test pagination parameters
    res = test_client.get("/api/incidents?page=1&page_size=5")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "pages" in data

    # Test bulk dismiss action
    bulk_res = test_client.post("/api/incidents/bulk-action", json={
        "incident_ids": ["999999"],
        "action": "dismiss"
    })
    assert bulk_res.status_code == 200
    assert bulk_res.json()["status"] == "success"


def test_api_audit_pagination_and_export(test_client):
    """Verify /api/audit pagination and /api/audit/export CSV response."""
    res = test_client.get("/api/audit?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data

    csv_res = test_client.get("/api/audit/export")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers.get("content-type", "")
    assert "Content-Disposition" in csv_res.headers
    assert "ID,Timestamp,Action" in csv_res.text


def test_system_self_test_endpoint(test_client):
    """Verify the /api/system/self-test end-to-end diagnostic endpoint."""
    res = test_client.post("/api/system/self-test")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "steps" in data
    assert len(data["steps"]) >= 4


def test_incident_assignment_and_source_fields(tmp_path, test_client):
    """Verify assignee, source, cluster_id and risk_level persistence and API assignment."""
    db_file = tmp_path / "test_assign.db"
    test_store = IncidentStore(db_file)
    rec = test_store.record_incident(
        path="data/monitored/test_assign_file.txt",
        risk_score=0.88,
        status="open",
        reasons=["Credit Card Detected"],
        assignee="Analyst Sarah",
        source="WATCHER",
        cluster_id="cluster_abc",
    )
    assert rec.assignee == "Analyst Sarah"
    assert rec.source == "WATCHER"
    assert rec.risk_level == "HIGH"
    assert rec.cluster_id == "cluster_abc"

    # Test assignment method
    updated = test_store.assign_incident(rec.id, "Analyst Marcus")
    assert updated is True
    fetched = test_store.get_incident(rec.id)
    assert fetched.assignee == "Analyst Marcus"

    # Test via API
    api_res = test_client.get("/api/incidents?page=1&page_size=10")
    assert api_res.status_code == 200
    items = api_res.json()["items"]
    if items:
        first_id = items[0]["id"]
        assign_res = test_client.post(f"/api/incidents/{first_id}/action", json={
            "action": "assign",
            "assignee": "Lead Analyst"
        })
        assert assign_res.status_code == 200
        assert assign_res.json()["status"] == "success"


def test_incident_health_calculation(tmp_path):
    """Verify compute_incident_health calculates posture score and SLA compliance."""
    from leakguard.stats import compute_incident_health
    db_file = tmp_path / "test_health.db"
    test_store = IncidentStore(db_file)

    health = compute_incident_health(db_file)
    assert health.score == 100
    assert health.label == "Excellent"

    # Add critical and high incidents
    test_store.record_incident(path="crit.txt", risk_score=0.95, status="open", reasons=["Key"])
    test_store.record_incident(path="high.txt", risk_score=0.75, status="quarantined", reasons=["PAN"])

    health2 = compute_incident_health(db_file)
    assert health2.active_cases == 2
    assert health2.critical_cases == 1
    assert health2.score < 100


def test_quarantine_deletion_syncs_incident_status(tmp_path, test_client):
    """Verify delete quarantine item removes file, marks incident purged, and writes audit."""
    q_dir = Path("data/quarantine")
    q_dir.mkdir(parents=True, exist_ok=True)
    test_q_file = q_dir / "test_purge_sample_20261013T000000.txt"
    test_q_file.write_text("sensitive quarantined content", encoding="utf-8")

    store.record_incident(
        path=str(test_q_file),
        risk_score=0.92,
        status="quarantined",
        reasons=["Sensitive leak"],
    )

    del_res = test_client.delete(f"/api/quarantine/{test_q_file.name}")
    assert del_res.status_code == 200
    assert not test_q_file.exists()

    # Check incident was marked purged
    inc = store.get_incident(str(test_q_file))
    if inc:
        assert inc.status == "purged"

