"""Tests for Phase 11: Gap-closing additions (Roles, Watched Folders, Engines, Workflows, Extra Filters)."""

import pytest
from starlette.testclient import TestClient

from leakguard.api import app, store, engine


@pytest.fixture
def client():
    return TestClient(app)


def test_role_enforcement_auditor_cannot_mutate(client):
    """Auditor role must receive 403 Forbidden on mutation attempts."""
    auditor_headers = {"X-Role": "Auditor"}

    # 1. Bulk action mutation
    res = client.post("/api/incidents/bulk-action", json={"incident_ids": ["1"], "action": "quarantine"}, headers=auditor_headers)
    assert res.status_code == 403
    assert "Auditor role is read-only" in res.json()["detail"]

    # 2. Single incident action mutation
    res = client.post("/api/incidents/1/action", json={"action": "quarantine"}, headers=auditor_headers)
    assert res.status_code == 403
    assert "Auditor role is read-only" in res.json()["detail"]

    # 3. Quarantine restore
    res = client.post("/api/quarantine/restore", json={"filename": "test.txt"}, headers=auditor_headers)
    assert res.status_code == 403
    assert "Auditor role is read-only" in res.json()["detail"]

    # 4. Quarantine delete
    res = client.delete("/api/quarantine/test.txt", headers=auditor_headers)
    assert res.status_code == 403
    assert "Auditor role is read-only" in res.json()["detail"]

    # 5. Settings update
    res = client.post(
        "/api/settings",
        json={"suspicious_threshold": 30.0, "quarantine_threshold": 70.0, "auto_quarantine": True},
        headers=auditor_headers,
    )
    assert res.status_code == 403


def test_role_enforcement_analyst_permissions(client):
    """SOC Analyst can perform operational mutations but is forbidden from Admin controls."""
    analyst_headers = {"X-Role": "SOC Analyst"}

    # Admin actions must fail for SOC Analyst
    res = client.post(
        "/api/settings",
        json={"suspicious_threshold": 30.0, "quarantine_threshold": 70.0, "auto_quarantine": True},
        headers=analyst_headers,
    )
    assert res.status_code == 403
    assert "Admin role required" in res.json()["detail"]

    res = client.post(
        "/api/workflows",
        json={
            "name": "Test Rule",
            "condition_field": "severity",
            "condition_op": "eq",
            "condition_val": "high",
            "action": "quarantine",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 403
    assert "Admin role required" in res.json()["detail"]

    # Operational bulk action is permitted for Analyst (even if incident not found, it's not a 403)
    res = client.post(
        "/api/incidents/bulk-action",
        json={"incident_ids": ["99999"], "action": "quarantine"},
        headers=analyst_headers,
    )
    assert res.status_code == 200


def test_role_enforcement_admin_permissions(client):
    """Admin role has full access to settings, workflows, and mutations."""
    admin_headers = {"X-Role": "Admin"}

    res = client.post(
        "/api/settings",
        json={
            "suspicious_threshold": engine.policy.suspicious_threshold * 100,
            "quarantine_threshold": engine.policy.quarantine_threshold * 100,
            "auto_quarantine": engine.policy.auto_quarantine,
        },
        headers=admin_headers,
    )
    assert res.status_code == 200


def test_role_change_audit_logging(client):
    """Switching roles writes an entry to the audit log."""
    res = client.post(
        "/api/audit/role-change",
        json={"old_role": "SOC Analyst", "new_role": "Admin", "user": "soc-lead"},
        headers={"X-Role": "Admin"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["role"] == "Admin"

    # Verify audit entry exists
    audit_entries = store.list_audit_log(action="role_change", limit=5)
    assert len(audit_entries) > 0
    assert "Switched role from SOC Analyst to Admin" in audit_entries[0].details


def test_watched_folders_endpoint_and_safety(client):
    """Watched folders endpoint lists folders and marks safety scope."""
    res = client.get("/api/watched-folders")
    assert res.status_code == 200
    folders = res.json()
    assert len(folders) >= 3

    # Primary folder is data/monitored with SCOPED_SAFE
    primary = next((f for f in folders if f["id"] == "wf-monitored"), None)
    assert primary is not None
    assert primary["scoped_status"] == "SCOPED_SAFE"
    assert primary["is_primary"] is True

    # Desktop and Downloads are protected out-of-bounds
    desktop = next((f for f in folders if f["id"] == "wf-desktop"), None)
    assert desktop is not None
    assert desktop["scoped_status"] == "OUT_OF_BOUNDS_PROTECTED"


def test_engines_catalog_endpoint(client):
    """Detection engines endpoint returns all 5 engines with versions, states, and hit counts."""
    res = client.get("/api/engines")
    assert res.status_code == 200
    engines = res.json()
    assert len(engines) == 5

    names = {e["name"] for e in engines}
    assert "Regex Library" in names
    assert "Luhn Validator" in names
    assert "Keyword Classifier" in names
    assert "IsolationForest Anomaly Detector" in names
    assert "Prompt Guard" in names

    for eng in engines:
        assert "version" in eng
        assert "status" in eng
        assert "last_updated" in eng
        assert "hits" in eng
        assert isinstance(eng["hits"], int)


def test_workflows_crud_and_dry_run(client):
    """Workflows CRUD and dry-run tester."""
    admin_headers = {"X-Role": "Admin"}

    # 1. List initial workflows
    res = client.get("/api/workflows")
    assert res.status_code == 200
    initial_rules = res.json()
    assert len(initial_rules) >= 1

    # 2. Create new workflow
    res = client.post(
        "/api/workflows",
        json={
            "name": "Auto-Quarantine Critical Leaks",
            "condition_field": "severity",
            "condition_op": "eq",
            "condition_val": "CRITICAL",
            "action": "quarantine",
            "action_val": "",
            "enabled": True,
        },
        headers=admin_headers,
    )
    assert res.status_code == 200
    created = res.json()["rule"]
    rule_id = created["id"]
    assert created["name"] == "Auto-Quarantine Critical Leaks"

    # 3. Toggle workflow
    res = client.put(f"/api/workflows/{rule_id}/toggle", headers=admin_headers)
    assert res.status_code == 200

    # 4. Dry-run test rule
    res = client.post(
        "/api/workflows/test",
        json={
            "rule": {
                "name": "Test Severity Filter",
                "condition_field": "severity",
                "condition_op": "eq",
                "condition_val": "CRITICAL",
                "action": "quarantine",
                "action_val": "",
                "enabled": True,
            },
            "sample_size": 20,
        },
    )
    assert res.status_code == 200
    test_result = res.json()
    assert test_result["status"] == "success"
    assert "evaluated_incidents" in test_result
    assert "matches" in test_result

    # 5. Delete workflow
    res = client.delete(f"/api/workflows/{rule_id}", headers=admin_headers)
    assert res.status_code == 200


def test_team_and_region_filtering(client):
    """GET /api/incidents and GET /api/overview respect team and region filters."""
    # Overview with filters
    res_ov = client.get("/api/overview?team=Unassigned&region=monitored")
    assert res_ov.status_code == 200
    ov_data = res_ov.json()
    assert "violations_summary" in ov_data
    assert "risk_distribution" in ov_data

    # Incidents list with filters
    res_inc = client.get("/api/incidents?team=Unassigned&region=monitored&page=1&page_size=10")
    assert res_inc.status_code == 200
    inc_data = res_inc.json()
    assert "items" in inc_data
    assert "total" in inc_data
