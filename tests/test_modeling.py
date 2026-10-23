from __future__ import annotations

from leakguard.modeling import LeakRiskModel


def test_model_scores_sensitive_text_higher_than_safe_text() -> None:
    model = LeakRiskModel(random_state=42)
    training = [
        "Project planning notes for the office renovation and vendor coordination.",
        "Weekly summary of internal team meetings and scheduling updates.",
        "Quarterly review of the marketing campaign and customer outreach plan.",
    ]
    model.fit(training)

    safe_score = model.score_text("Internal schedule update for the next product review meeting.")
    risky_score = model.score_text(
        "Please contact jane.smith@example.com or 555-123-4567 about the patient record "
        "at 123 Main Street, and review the uploaded contract at https://example.com/legal"
    )

    assert risky_score > safe_score
    assert model.predict_label("This is a routine project update") == "normal"
    assert model.predict_label("Email jane@example.com and call 555-123-4567") == "suspicious"
