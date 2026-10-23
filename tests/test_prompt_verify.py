import pytest
from leakguard.prompt_verification import verify_prompt, PromptHistoryStore
from leakguard.api import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_safe_prompt_verification():
    prompt = "How do I reverse a string in Python using slicing?"
    result = verify_prompt(prompt)
    assert result["verdict"] == "SAFE"
    assert result["risk_score"] < 40
    assert len(result["findings"]) == 0
    assert result["sanitized_prompt"] == prompt

def test_pii_prompt_sanitization_and_masking():
    prompt = "Customer email is alice.smith@example.com with credit card 4532 0151 8293 4122 and PAN ABCDE1234F."
    result = verify_prompt(prompt)
    assert result["verdict"] in ("REVIEW", "BLOCK")
    assert result["risk_score"] >= 40
    assert len(result["findings"]) >= 2
    
    # Assert raw sensitive values are not in sanitized prompt
    assert "4532 0151 8293 4122" not in result["sanitized_prompt"]
    assert "ABCDE1234F" not in result["sanitized_prompt"]
    assert "[CREDIT_CARD]" in result["sanitized_prompt"]
    assert "[PAN_CARD]" in result["sanitized_prompt"]

def test_prompt_verification_api():
    response = client.post("/api/prompt/verify", json={"prompt": "Server password=supersecretpass and token ghp_123456789012345678901234567890123456"})
    assert response.status_code == 200
    data = response.json()
    assert "sanitized_prompt" in data
    assert "supersecretpass" not in data["sanitized_prompt"]
    assert data["verdict"] in ("REVIEW", "BLOCK")

def test_prompt_history_api():
    # Verify records history
    res = client.get("/api/prompt/history?limit=10")
    assert res.status_code == 200
    history = res.json()
    assert isinstance(history, list)
    assert len(history) > 0
    # Confirm no raw prompt stored
    for item in history:
        assert "prompt_hash" in item
        assert "password" not in item.get("prompt_hash", "")
