"""Dashboard summary and upload enforcement for the local data leakage monitor."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from leakguard.incident import IncidentStore, RiskEngine, RiskPolicy


@dataclass(frozen=True)
class DashboardSummary:
    total: int
    open: int
    quarantined: int
    normal: int
    recent_files: list[str]
    latest_scan: str | None


def build_dashboard_summary(store: IncidentStore | None = None, db_path: str | Path = "data/leakguard.db") -> DashboardSummary:
    registry = store or IncidentStore(db_path)
    incidents = registry.list_incidents()
    total = len(incidents)
    open_count = sum(1 for incident in incidents if incident.status == "open")
    quarantined_count = sum(1 for incident in incidents if incident.status == "quarantined")
    normal_count = sum(1 for incident in incidents if incident.status == "normal")
    recent_files = [incident.path for incident in incidents if incident.status in {"open", "quarantined"}][-10:]
    latest_scan = incidents[-1].scanned_at if incidents else None
    return DashboardSummary(
        total=total,
        open=open_count,
        quarantined=quarantined_count,
        normal=normal_count,
        recent_files=recent_files,
        latest_scan=latest_scan,
    )


def validate_upload(file_path: str | Path, *, threshold: float = 0.5) -> tuple[bool, str, float]:
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Upload file does not exist: {file_path}")

    engine = RiskEngine(
        policy=RiskPolicy(
            suspicious_threshold=threshold,
            quarantine_threshold=max(threshold + 0.2, 0.7),
        )
    )
    incident = engine.evaluate_file(file_path)
    allowed = incident.status == "normal"
    risk_score = float(incident.risk_score)
    if allowed:
        return True, "accepted for local review", risk_score
    reason = (
        f"File blocked because risk score {risk_score:.2f} exceeds local policy threshold {threshold:.2f}."
    )
    if incident.status == "quarantined":
        reason = (
            f"File blocked and quarantined because risk score {risk_score:.2f} exceeds quarantine threshold."
        )
    return False, reason, risk_score
