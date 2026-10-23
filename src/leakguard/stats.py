"""Centralized metrics, statistics, and KPI calculations for SentinelDLP.

Provides single-source-of-truth definitions and direct database queries to reconcile
all SOC numbers: Total Scanned, Open Incidents, Quarantined, Blocked, High Risk,
Detection Rate, and Average Risk Score.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


METRIC_DEFINITIONS: dict[str, str] = {
    "total_scanned": "Total unique files processed and recorded across monitored directory and uploads.",
    "open_incidents": "Active incidents with status 'open' requiring security team review (risk score >= suspicious threshold).",
    "quarantined": "Total files currently isolated in the quarantine vault (status 'quarantined').",
    "blocked": "Total uploads permanently prevented from being written to the monitored directory (status 'blocked').",
    "high_risk": "Incidents with a combined risk score of 70% or higher (risk_score >= 0.70).",
    "detection_rate": "Percentage of total scanned files flagged as risky (status in 'open', 'quarantined', 'blocked').",
    "average_risk": "Mean risk score across all processed files on a 0-100 scale.",
    "incident_health": "Aggregated posture score (0-100) based on active critical, high, and medium severity incidents.",
    "sla_compliance": "Percentage of resolved incidents completed within the target SLA window (default 24h).",
    "active_cases": "Total non-resolved incidents requiring active investigation.",
    "critical_cases": "Active incidents with critical risk score >= 90%.",
    "avg_resolution_time": "Average duration in hours from detection to resolution across resolved incidents.",
}


@dataclass(frozen=True)
class IncidentHealthScore:
    score: int
    label: str  # Excellent / Good / Elevated / Critical
    active_cases: int
    critical_cases: int
    avg_resolution_hours: float
    sla_compliance_pct: float
    status: str = "Operational"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "label": self.label,
            "active_cases": self.active_cases,
            "critical_cases": self.critical_cases,
            "avg_resolution_hours": self.avg_resolution_hours,
            "sla_compliance_pct": self.sla_compliance_pct,
            "status": self.status,
        }


def compute_incident_health(db_path: str | Path, sla_hours: float = 24.0) -> IncidentHealthScore:
    """Compute verified Incident Health Score gauge and SLA compliance."""
    path = Path(db_path)
    if not path.exists():
        return IncidentHealthScore(score=100, label="Excellent", active_cases=0, critical_cases=0, avg_resolution_hours=0.0, sla_compliance_pct=100.0)

    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'quarantined', 'blocked')")
        active_cases = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'quarantined', 'blocked') AND risk_score >= 0.90")
        critical_cases = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'quarantined', 'blocked') AND risk_score >= 0.70 AND risk_score < 0.90")
        high_cases = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'quarantined', 'blocked') AND risk_score >= 0.40 AND risk_score < 0.70")
        med_cases = cursor.fetchone()[0]

        cursor.execute("SELECT scanned_at, resolved_at FROM incidents WHERE resolved_at IS NOT NULL AND status IN ('released', 'purged', 'resolved', 'dismissed')")
        resolved_rows = cursor.fetchall()

    penalty = critical_cases * 15 + high_cases * 8 + med_cases * 3
    health_score = max(0, min(100, 100 - penalty))
    if health_score >= 85:
        label = "Excellent"
    elif health_score >= 70:
        label = "Good"
    elif health_score >= 50:
        label = "Elevated"
    else:
        label = "Critical"

    sla_compliant_count = 0
    total_resolution_hours = 0.0
    for s_at, r_at in resolved_rows:
        try:
            from datetime import datetime
            t_start = datetime.fromisoformat(s_at.replace("Z", "+00:00")).timestamp()
            t_end = datetime.fromisoformat(r_at.replace("Z", "+00:00")).timestamp()
            diff_hours = max(0.0, (t_end - t_start) / 3600.0)
            total_resolution_hours += diff_hours
            if diff_hours <= sla_hours:
                sla_compliant_count += 1
        except Exception:
            pass

    if resolved_rows:
        avg_res_hours = round(total_resolution_hours / len(resolved_rows), 1)
        sla_pct = round((sla_compliant_count / len(resolved_rows)) * 100.0, 1)
    else:
        avg_res_hours = 0.0
        sla_pct = 100.0

    return IncidentHealthScore(
        score=health_score,
        label=label,
        active_cases=active_cases,
        critical_cases=critical_cases,
        avg_resolution_hours=avg_res_hours,
        sla_compliance_pct=sla_pct,
        status="Operational",
    )


@dataclass(frozen=True)
class DashboardKPIs:
    total_scanned: int
    open_incidents: int
    quarantined: int
    blocked: int
    high_risk: int
    average_risk: float
    detection_rate_pct: float | None
    detection_rate_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_scanned": self.total_scanned,
            "open_incidents": self.open_incidents,
            "quarantined": self.quarantined,
            "blocked": self.blocked,
            "high_risk": self.high_risk,
            "average_risk": self.average_risk,
            "detection_rate_pct": self.detection_rate_pct,
            "detection_rate_status": self.detection_rate_status,
            "definitions": METRIC_DEFINITIONS,
        }


def compute_kpis(db_path: str | Path, quarantine_dir: str | Path = "data/quarantine") -> DashboardKPIs:
    """Compute verified, consistent KPIs directly from the SQLite database."""
    path = Path(db_path)
    if not path.exists():
        return DashboardKPIs(
            total_scanned=0,
            open_incidents=0,
            quarantined=0,
            blocked=0,
            high_risk=0,
            average_risk=0.0,
            detection_rate_pct=None,
            detection_rate_status="No data available",
        )

    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()
        
        # 1. Total Scanned
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_scanned = cursor.fetchone()[0]

        # 2. Open Incidents
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        open_incidents = cursor.fetchone()[0]

        # 3. Quarantined (Count by DB status)
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'quarantined'")
        db_quarantined = cursor.fetchone()[0]

        # 4. Blocked
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'blocked'")
        blocked = cursor.fetchone()[0]

        # 5. High Risk (risk_score >= 0.70)
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE risk_score >= 0.70")
        high_risk = cursor.fetchone()[0]

        # 6. Average Risk Score (0-100 scale)
        cursor.execute("SELECT AVG(risk_score) FROM incidents")
        raw_avg = cursor.fetchone()[0]
        average_risk = round((raw_avg * 100.0), 1) if raw_avg is not None else 0.0

    # Physical verification: ensure quarantine count accounts for vault items
    q_path = Path(quarantine_dir)
    physical_q = len([f for f in q_path.glob("*") if f.is_file()]) if q_path.exists() else 0
    quarantined = max(db_quarantined, physical_q)

    # 7. Detection Rate %: (open + quarantined + blocked) / total_scanned * 100
    risky_count = open_incidents + db_quarantined + blocked
    if total_scanned > 0:
        detection_rate_pct = round((risky_count / total_scanned) * 100.0, 1)
        detection_rate_status = "Calculated"
    else:
        detection_rate_pct = None
        detection_rate_status = "Insufficient data"

    return DashboardKPIs(
        total_scanned=total_scanned,
        open_incidents=open_incidents,
        quarantined=quarantined,
        blocked=blocked,
        high_risk=high_risk,
        average_risk=average_risk,
        detection_rate_pct=detection_rate_pct,
        detection_rate_status=detection_rate_status,
    )
