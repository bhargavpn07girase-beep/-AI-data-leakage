from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from leakguard.api import app, store, engine, policy


@pytest.fixture
def client():
    return TestClient(app)


def test_api_status_endpoint(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "watched_folder" in data
    assert "policy" in data


def test_api_overview_endpoint(client):
    response = client.get("/api/overview")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert "total_scanned" in data["kpis"]
    assert "category_counts" in data
    assert "risk_distribution" in data


def test_api_incidents_list(client):
    response = client.get("/api/incidents")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_api_upload_blocking(client):
    # Upload clean content -> Allowed
    clean_file = ("clean.txt", b"Project roadmap and feature checklist for Q4 release. Everything is on schedule.")
    res_clean = client.post("/api/upload", files={"file": clean_file})
    assert res_clean.status_code == 200
    data_clean = res_clean.json()
    assert data_clean["allowed"] is True
    assert data_clean["verdict"] == "Allowed"


    # Upload highly sensitive content -> Blocked
    sensitive_content = b'{"email": "user@example.com", "credit_card": "4532 0151 8293 4128", "pan_number": "ABCDE1234F", "classification": "CONFIDENTIAL"}'
    res_sens = client.post("/api/upload", files={"file": ("sensitive.json", sensitive_content)})
    assert res_sens.status_code == 200
    data_sens = res_sens.json()
    assert data_sens["allowed"] is False
    assert data_sens["verdict"] in ("Needs Review", "Blocked")


def test_api_settings(client):
    res_get = client.get("/api/settings")
    assert res_get.status_code == 200

    res_post = client.post("/api/settings", json={
        "suspicious_threshold": 25.0,
        "quarantine_threshold": 65.0,
        "auto_quarantine": True
    })
    assert res_post.status_code == 200
    assert res_post.json()["status"] == "success"
