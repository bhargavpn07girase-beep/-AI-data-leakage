"""Persistent incident logging, detailed findings, audit trail, and quarantine enforcement."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from shutil import move
from typing import Any, List, Optional

from leakguard.modeling import LeakRiskModel, load_project_documents
from leakguard.scanning import scan_file, ContentFinding, ScanResult


@dataclass(frozen=True)
class RiskPolicy:
    suspicious_threshold: float = 0.3
    quarantine_threshold: float = 0.7
    auto_quarantine: bool = True
    quarantine_dir: Path = Path("data/quarantine")
    max_scan_bytes: int = 50_000_000
    max_upload_size_bytes: int = 100_000_000  # 100 MB per file limit
    max_batch_files: int = 100
    allowed_extensions: tuple[str, ...] = (
        ".txt", ".csv", ".tsv", ".json", ".jsonl", ".log", ".md", ".pdf", ".docx", ".doc",
        ".pptx", ".xlsx", ".env", ".yaml", ".yml", ".py", ".js", ".ts", ".html", ".xml",
        ".sql", ".sh", ".bash", ".ini", ".cfg", ".conf", ".properties", ".toml", ".parquet",
        ".key", ".pem", ".crt", ".config", ".gitignore", ".env.local", ".env.production"
    )
    include_extra_signals: bool = False  # Toggle for Phase 4 advisory extra signals (default OFF)

    def __post_init__(self) -> None:
        object.__setattr__(self, "quarantine_dir", Path(self.quarantine_dir))


@dataclass(frozen=True)
class IncidentRecord:
    path: str
    risk_score: float
    status: str
    reasons: list[str]
    scanned_at: str
    quarantined_at: str | None = None
    id: int | None = None
    heuristic_score: float = 0.0
    model_score: float = 0.0
    category_counts: dict[str, int] = field(default_factory=dict)
    masked_preview: str = ""
    sha256: str = ""
    assignee: str = "Unassigned"
    source: str = "WATCHER"
    resolved_at: str | None = None
    cluster_id: str = ""
    created_at: str | None = None
    risk_level_stored: str = ""

    @property
    def risk_score_100(self) -> float:
        return round(self.risk_score * 100.0, 1)

    @property
    def risk_level(self) -> str:
        if self.risk_level_stored:
            return self.risk_level_stored
        score_100 = self.risk_score_100
        if score_100 >= 90.0:
            return "CRITICAL"
        elif score_100 >= 70.0:
            return "HIGH"
        elif score_100 >= 40.0:
            return "MEDIUM"
        return "LOW"


@dataclass(frozen=True)
class AuditEntry:
    id: int
    timestamp: str
    action: str
    target_path: str
    details: str
    performed_by: str
    created_at: str | None = None


@dataclass
class WorkflowRule:
    id: int | None
    name: str
    condition_field: str  # 'severity', 'file_type', 'category', 'source', 'risk_score'
    condition_op: str     # 'eq', 'contains', 'gte', 'lte'
    condition_val: str
    action: str           # 'quarantine', 'dismiss', 'assign', 'notify', 'tag'
    action_val: str = ""
    enabled: bool = True
    created_at: str = ""


class IncidentStore:
    """Persist incidents, findings, and audit log entries in SQLite for audit and review."""

    def __init__(self, db_path: str | Path = "data/leakguard.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL UNIQUE,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    quarantined_at TEXT
                )
                """
            )
            cursor.execute("PRAGMA table_info(incidents)")
            existing_cols = {col[1] for col in cursor.fetchall()}
            if "heuristic_score" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN heuristic_score REAL DEFAULT 0.0")
            if "model_score" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN model_score REAL DEFAULT 0.0")
            if "category_counts" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN category_counts TEXT DEFAULT '{}'")
            if "masked_preview" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN masked_preview TEXT DEFAULT ''")
            if "sha256" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN sha256 TEXT DEFAULT ''")
            if "assignee" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN assignee TEXT DEFAULT 'Unassigned'")
            if "source" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN source TEXT DEFAULT 'WATCHER'")
            if "resolved_at" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN resolved_at TEXT DEFAULT NULL")
            if "cluster_id" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN cluster_id TEXT DEFAULT ''")
            if "created_at" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN created_at TEXT DEFAULT NULL")
                cursor.execute("UPDATE incidents SET created_at = scanned_at WHERE created_at IS NULL")
            if "risk_level" not in existing_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN risk_level TEXT DEFAULT ''")
                cursor.execute(
                    """
                    UPDATE incidents SET risk_level = CASE
                        WHEN risk_score >= 0.90 THEN 'CRITICAL'
                        WHEN risk_score >= 0.70 THEN 'HIGH'
                        WHEN risk_score >= 0.40 THEN 'MEDIUM'
                        ELSE 'LOW'
                    END WHERE risk_level IS NULL OR risk_level = ''
                    """
                )

            # Indexes on incidents for filtering, source, assignee, risk, and timeline
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status_risk ON incidents(status, risk_score, scanned_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_scanned ON incidents(scanned_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(source)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents(assignee)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status_risk_created ON incidents(status, risk_level, created_at)")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_path TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    line_number INTEGER,
                    masked_value TEXT NOT NULL,
                    FOREIGN KEY(incident_path) REFERENCES incidents(path) ON DELETE CASCADE
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    details TEXT NOT NULL,
                    performed_by TEXT DEFAULT 'system'
                )
                """
            )
            cursor.execute("PRAGMA table_info(audit_log)")
            audit_cols = {col[1] for col in cursor.fetchall()}
            if "created_at" not in audit_cols:
                cursor.execute("ALTER TABLE audit_log ADD COLUMN created_at TEXT DEFAULT NULL")
                cursor.execute("UPDATE audit_log SET created_at = timestamp WHERE created_at IS NULL")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC)")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS batch_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL UNIQUE,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    risk_score REAL,
                    verdict TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    reasons TEXT DEFAULT '[]',
                    category_counts TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_batch_scans_batch ON batch_scans(batch_id)")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    condition_field TEXT NOT NULL,
                    condition_op TEXT NOT NULL DEFAULT 'eq',
                    condition_val TEXT NOT NULL,
                    action TEXT NOT NULL,
                    action_val TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_workflow_rules_enabled ON workflow_rules(enabled)")

            cursor.execute("SELECT COUNT(*) FROM workflow_rules")
            if cursor.fetchone()[0] == 0:
                ts = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "INSERT INTO workflow_rules (name, condition_field, condition_op, condition_val, action, action_val, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("Auto-Quarantine Critical Incidents", "severity", "eq", "critical", "quarantine", "", 1, ts),
                )
                cursor.execute(
                    "INSERT INTO workflow_rules (name, condition_field, condition_op, condition_val, action, action_val, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("Assign Financial Secrets to Tier 2", "category", "contains", "financial", "assign", "SOC Tier 2", 1, ts),
                )
                cursor.execute(
                    "INSERT INTO workflow_rules (name, condition_field, condition_op, condition_val, action, action_val, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("Alert on Credential File Uploads", "file_type", "eq", "log", "notify", "bell", 1, ts),
                )
            connection.commit()


    def log_audit(self, action: str, target_path: str, details: str = "", performed_by: str = "system") -> AuditEntry:
        timestamp = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (timestamp, action, target_path, details, performed_by)
                VALUES (?, ?, ?, ?, ?)
                """,
                (timestamp, action, target_path, details, performed_by),
            )
            connection.commit()
            row_id = cursor.lastrowid
        return AuditEntry(id=row_id, timestamp=timestamp, action=action, target_path=target_path, details=details, performed_by=performed_by)

    def list_audit_log(
        self,
        *,
        action: str | None = None,
        performed_by: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        with sqlite3.connect(self.db_path) as connection:
            conditions = []
            params: list[Any] = []
            if action:
                conditions.append("LOWER(action) LIKE LOWER(?)")
                params.append(f"%{action}%")
            if performed_by:
                conditions.append("LOWER(performed_by) = LOWER(?)")
                params.append(performed_by)
            if start_date:
                conditions.append("timestamp >= ?")
                params.append(start_date)
            if end_date:
                conditions.append("timestamp <= ?")
                params.append(end_date)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"SELECT id, timestamp, action, target_path, details, performed_by FROM audit_log {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = connection.execute(query, params).fetchall()
        return [AuditEntry(id=row[0], timestamp=row[1], action=row[2], target_path=row[3], details=row[4], performed_by=row[5]) for row in rows]

    def count_audit_log(
        self,
        *,
        action: str | None = None,
        performed_by: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        with sqlite3.connect(self.db_path) as connection:
            conditions = []
            params: list[Any] = []
            if action:
                conditions.append("LOWER(action) LIKE LOWER(?)")
                params.append(f"%{action}%")
            if performed_by:
                conditions.append("LOWER(performed_by) = LOWER(?)")
                params.append(performed_by)
            if start_date:
                conditions.append("timestamp >= ?")
                params.append(start_date)
            if end_date:
                conditions.append("timestamp <= ?")
                params.append(end_date)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"SELECT COUNT(*) FROM audit_log {where_clause}"
            return connection.execute(query, params).fetchone()[0]

    def record_batch_scan(
        self,
        *,
        batch_id: str,
        scan_id: str,
        filename: str,
        file_size: int,
        status: str,
        risk_score: float | None,
        verdict: str,
        findings_count: int = 0,
        reasons: list[str] | None = None,
        category_counts: dict[str, int] | None = None,
    ) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO batch_scans (batch_id, scan_id, filename, file_size, status, risk_score, verdict, findings_count, reasons, category_counts, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status=excluded.status,
                    risk_score=excluded.risk_score,
                    verdict=excluded.verdict,
                    findings_count=excluded.findings_count,
                    reasons=excluded.reasons,
                    category_counts=excluded.category_counts
                """,
                (
                    batch_id,
                    scan_id,
                    filename,
                    file_size,
                    status,
                    risk_score,
                    verdict,
                    findings_count,
                    json.dumps(reasons or []),
                    json.dumps(category_counts or {}),
                    created_at,
                ),
            )
            connection.commit()

    def list_batch_scans(self, batch_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as connection:
            if batch_id:
                query = "SELECT id, batch_id, scan_id, filename, file_size, status, risk_score, verdict, findings_count, reasons, category_counts, created_at FROM batch_scans WHERE batch_id = ? ORDER BY id DESC LIMIT ?"
                params = (batch_id, limit)
            else:
                query = "SELECT id, batch_id, scan_id, filename, file_size, status, risk_score, verdict, findings_count, reasons, category_counts, created_at FROM batch_scans ORDER BY id DESC LIMIT ?"
                params = (limit,)
            rows = connection.execute(query, params).fetchall()

        return [
            {
                "id": r[0],
                "batch_id": r[1],
                "scan_id": r[2],
                "filename": r[3],
                "file_size": r[4],
                "status": r[5],
                "risk_score": r[6],
                "verdict": r[7],
                "findings_count": r[8],
                "reasons": json.loads(r[9] or "[]"),
                "category_counts": json.loads(r[10] or "{}"),
                "created_at": r[11],
            }
            for r in rows
        ]

    def record_incident(
        self,
        *,
        path: str | Path,
        risk_score: float,
        status: str,
        reasons: list[str],
        quarantined_at: str | None = None,
        heuristic_score: float = 0.0,
        model_score: float = 0.0,
        category_counts: dict[str, int] | None = None,
        masked_preview: str = "",
        sha256: str = "",
        assignee: str = "Unassigned",
        source: str = "WATCHER",
        resolved_at: str | None = None,
        cluster_id: str = "",
        findings: list[ContentFinding] | None = None,
    ) -> IncidentRecord:
        timestamp = datetime.now(timezone.utc).isoformat()
        record_path = str(Path(path))
        reasons_payload = json.dumps(reasons, ensure_ascii=True)
        counts_payload = json.dumps(category_counts or {}, ensure_ascii=True)
        score_100 = round(float(risk_score) * 100.0, 1)
        risk_level = "CRITICAL" if score_100 >= 90.0 else "HIGH" if score_100 >= 70.0 else "MEDIUM" if score_100 >= 40.0 else "LOW"

        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO incidents (
                    path, risk_score, status, reasons, scanned_at, quarantined_at,
                    heuristic_score, model_score, category_counts, masked_preview, sha256,
                    assignee, source, resolved_at, cluster_id, created_at, risk_level
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    status = excluded.status,
                    reasons = excluded.reasons,
                    scanned_at = excluded.scanned_at,
                    quarantined_at = excluded.quarantined_at,
                    heuristic_score = excluded.heuristic_score,
                    model_score = excluded.model_score,
                    category_counts = excluded.category_counts,
                    masked_preview = excluded.masked_preview,
                    sha256 = CASE WHEN excluded.sha256 != '' THEN excluded.sha256 ELSE incidents.sha256 END,
                    assignee = CASE WHEN excluded.assignee != 'Unassigned' THEN excluded.assignee ELSE incidents.assignee END,
                    source = excluded.source,
                    resolved_at = excluded.resolved_at,
                    cluster_id = CASE WHEN excluded.cluster_id != '' THEN excluded.cluster_id ELSE incidents.cluster_id END,
                    risk_level = excluded.risk_level
                """,
                (
                    record_path,
                    float(risk_score),
                    status,
                    reasons_payload,
                    timestamp,
                    quarantined_at,
                    float(heuristic_score),
                    float(model_score),
                    counts_payload,
                    masked_preview[:500],
                    sha256,
                    assignee,
                    source,
                    resolved_at,
                    cluster_id,
                    timestamp,
                    risk_level,
                ),
            )
            connection.commit()

            cursor.execute("SELECT id FROM incidents WHERE path = ?", (record_path,))
            row = cursor.fetchone()
            row_id = row[0] if row else None

            # Record detailed findings if provided
            if findings:
                cursor.execute("DELETE FROM findings WHERE incident_path = ?", (record_path,))
                for finding in findings:
                    cursor.execute(
                        "INSERT INTO findings (incident_path, rule, line_number, masked_value) VALUES (?, ?, ?, ?)",
                        (record_path, finding.rule, finding.line_number, finding.masked_value),
                    )
                connection.commit()

        self.log_audit(
            action=f"record_incident_{status}",
            target_path=record_path,
            details=f"Risk: {risk_score:.2f}, Reasons: {', '.join(reasons)}",
        )

        return IncidentRecord(
            id=row_id,
            path=record_path,
            risk_score=float(risk_score),
            status=status,
            reasons=reasons,
            scanned_at=timestamp,
            quarantined_at=quarantined_at,
            heuristic_score=heuristic_score,
            model_score=model_score,
            category_counts=category_counts or {},
            masked_preview=masked_preview[:500],
            sha256=sha256,
            assignee=assignee,
            source=source,
            resolved_at=resolved_at,
            cluster_id=cluster_id,
            created_at=timestamp,
            risk_level_stored=risk_level,
        )

    def get_incident(self, path_or_id: str | int) -> IncidentRecord | None:
        with sqlite3.connect(self.db_path) as connection:
            if isinstance(path_or_id, int) or (isinstance(path_or_id, str) and str(path_or_id).isdigit()):
                query = """
                    SELECT id, path, risk_score, status, reasons, scanned_at, quarantined_at,
                           heuristic_score, model_score, category_counts, masked_preview, sha256,
                           assignee, source, resolved_at, cluster_id, created_at, risk_level
                    FROM incidents WHERE id = ?
                """
                params = (int(path_or_id),)
            else:
                query = """
                    SELECT id, path, risk_score, status, reasons, scanned_at, quarantined_at,
                           heuristic_score, model_score, category_counts, masked_preview, sha256,
                           assignee, source, resolved_at, cluster_id, created_at, risk_level
                    FROM incidents WHERE path = ?
                """
                params = (str(path_or_id),)
            row = connection.execute(query, params).fetchone()
            if not row:
                return None
            return IncidentRecord(
                id=row[0],
                path=row[1],
                risk_score=float(row[2]),
                status=row[3],
                reasons=json.loads(row[4]),
                scanned_at=row[5],
                quarantined_at=row[6],
                heuristic_score=float(row[7] or 0.0),
                model_score=float(row[8] or 0.0),
                category_counts=json.loads(row[9] or "{}"),
                masked_preview=row[10] or "",
                sha256=row[11] or "" if len(row) > 11 else "",
                assignee=row[12] or "Unassigned" if len(row) > 12 else "Unassigned",
                source=row[13] or "WATCHER" if len(row) > 13 else "WATCHER",
                resolved_at=row[14] if len(row) > 14 else None,
                cluster_id=row[15] or "" if len(row) > 15 else "",
                created_at=row[16] or row[5] if len(row) > 16 else row[5],
                risk_level_stored=row[17] or "" if len(row) > 17 else "",
            )

    def get_findings_for_incident(self, incident_path: str) -> list[ContentFinding]:
        with sqlite3.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT incident_path, rule, line_number, masked_value FROM findings WHERE incident_path = ?",
                (incident_path,),
            ).fetchall()
        return [ContentFinding(file_path=r[0], rule=r[1], line_number=r[2], masked_value=r[3]) for r in rows]

    def assign_incident(self, path_or_id: str | int, assignee: str) -> bool:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            if isinstance(path_or_id, int) or (isinstance(path_or_id, str) and str(path_or_id).isdigit()):
                cursor.execute("UPDATE incidents SET assignee = ? WHERE id = ?", (assignee, int(path_or_id)))
            else:
                cursor.execute("UPDATE incidents SET assignee = ? WHERE path = ?", (assignee, str(path_or_id)))
            connection.commit()
            updated = cursor.rowcount > 0
        if updated:
            self.log_audit(action="assign_incident", target_path=str(path_or_id), details=f"Assigned to {assignee}")
        return updated

    def update_status(self, path: str, status: str, resolved_at: str | None = None) -> bool:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            res_val = resolved_at
            if status in ("released", "purged", "dismissed", "resolved") and not res_val:
                res_val = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE incidents SET status = ?, resolved_at = ? WHERE path = ?", (status, res_val, path))
            connection.commit()
            updated = cursor.rowcount > 0
        if updated:
            self.log_audit(action=f"update_status_{status}", target_path=path)
        return updated

    def delete_incident(self, path: str) -> bool:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM findings WHERE incident_path = ?", (path,))
            cursor.execute("DELETE FROM incidents WHERE path = ?", (path,))
            connection.commit()
            deleted = cursor.rowcount > 0
        if deleted:
            self.log_audit(action="delete_incident", target_path=path)
        return deleted

    def list_incidents(
        self,
        *,
        status: str | None = None,
        source: str | None = None,
        assignee: str | None = None,
        cluster_id: str | None = None,
        time_range: str | None = None,
        team: str | None = None,
        region: str | None = None,
        min_risk: float | None = None,
        max_risk: float | None = None,
        search: str | None = None,
        sort_by: str = "id_desc",
        limit: int | None = None,
        offset: int = 0,
    ) -> list[IncidentRecord]:
        with sqlite3.connect(self.db_path) as connection:
            conditions = []
            params: list[Any] = []

            if status and status.lower() != "all":
                conditions.append("LOWER(status) = LOWER(?)")
                params.append(status)
            if source and source.lower() != "all":
                conditions.append("LOWER(source) = LOWER(?)")
                params.append(source)
            if assignee and assignee.lower() != "all":
                conditions.append("LOWER(assignee) = LOWER(?)")
                params.append(assignee)
            if cluster_id:
                conditions.append("cluster_id = ?")
                params.append(cluster_id)
            if team and team.lower() != "all":
                team_clean = team.strip().lower()
                if team_clean in ("unassigned", "none"):
                    conditions.append("(assignee IS NULL OR assignee = '' OR LOWER(assignee) = 'unassigned')")
                elif team_clean == "me":
                    conditions.append("(LOWER(assignee) = 'me' OR LOWER(assignee) = 'analyst' OR LOWER(assignee) = 'current_user' OR LOWER(assignee) = 'soc analyst')")
                else:
                    conditions.append("LOWER(assignee) = LOWER(?)")
                    params.append(team.strip())
            if region and region.lower() != "all":
                region_clean = region.strip().lower()
                if "desktop" in region_clean:
                    conditions.append("(LOWER(path) LIKE '%desktop%' OR LOWER(source) LIKE '%desktop%')")
                elif "downloads" in region_clean:
                    conditions.append("(LOWER(path) LIKE '%downloads%' OR LOWER(source) LIKE '%downloads%')")
                elif "monitored" in region_clean or "root" in region_clean:
                    conditions.append("(LOWER(path) LIKE '%data/monitored%' OR LOWER(path) LIKE '%data\\monitored%' OR LOWER(path) NOT LIKE '%quarantine%')")
                else:
                    conditions.append("(LOWER(path) LIKE LOWER(?) OR LOWER(source) LIKE LOWER(?))")
                    params.extend([f"%{region_clean}%", f"%{region_clean}%"])

            if time_range and time_range != "all":
                now_ts = datetime.now(timezone.utc).timestamp()
                sec_map = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
                cutoff = sec_map.get(time_range)
                if cutoff:
                    cutoff_iso = datetime.fromtimestamp(now_ts - cutoff, timezone.utc).isoformat()
                    conditions.append("scanned_at >= ?")
                    params.append(cutoff_iso)
            if min_risk is not None:
                conditions.append("risk_score >= ?")
                params.append(min_risk / 100.0 if min_risk > 1.0 else min_risk)
            if max_risk is not None:
                conditions.append("risk_score <= ?")
                params.append(max_risk / 100.0 if max_risk > 1.0 else max_risk)
            if search:
                conditions.append("(LOWER(path) LIKE LOWER(?) OR LOWER(reasons) LIKE LOWER(?))")
                param_s = f"%{search}%"
                params.extend([param_s, param_s])

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

            order_clause = "ORDER BY id DESC"
            if sort_by == "risk_desc":
                order_clause = "ORDER BY risk_score DESC, id DESC"
            elif sort_by == "risk_asc":
                order_clause = "ORDER BY risk_score ASC, id ASC"
            elif sort_by == "date_desc":
                order_clause = "ORDER BY scanned_at DESC"
            elif sort_by == "date_asc":
                order_clause = "ORDER BY scanned_at ASC"
            elif sort_by == "id_asc":
                order_clause = "ORDER BY id ASC"

            limit_clause = ""
            if limit is not None:
                limit_clause = "LIMIT ? OFFSET ?"
                params.extend([limit, offset])

            query = f"""
                SELECT id, path, risk_score, status, reasons, scanned_at, quarantined_at,
                       heuristic_score, model_score, category_counts, masked_preview, sha256,
                       assignee, source, resolved_at, cluster_id, created_at, risk_level
                FROM incidents {where_clause} {order_clause} {limit_clause}
            """
            rows = connection.execute(query, params).fetchall()

        incidents: list[IncidentRecord] = []
        for row in rows:
            incidents.append(
                IncidentRecord(
                    id=row[0],
                    path=row[1],
                    risk_score=float(row[2]),
                    status=row[3],
                    reasons=json.loads(row[4]),
                    scanned_at=row[5],
                    quarantined_at=row[6],
                    heuristic_score=float(row[7] or 0.0),
                    model_score=float(row[8] or 0.0),
                    category_counts=json.loads(row[9] or "{}"),
                    masked_preview=row[10] or "",
                    sha256=row[11] or "" if len(row) > 11 else "",
                    assignee=row[12] or "Unassigned" if len(row) > 12 else "Unassigned",
                    source=row[13] or "WATCHER" if len(row) > 13 else "WATCHER",
                    resolved_at=row[14] if len(row) > 14 else None,
                    cluster_id=row[15] or "" if len(row) > 15 else "",
                    created_at=row[16] or row[5] if len(row) > 16 else row[5],
                    risk_level_stored=row[17] or "" if len(row) > 17 else "",
                )
            )
        return incidents

    def count_incidents(
        self,
        *,
        status: str | None = None,
        source: str | None = None,
        assignee: str | None = None,
        cluster_id: str | None = None,
        time_range: str | None = None,
        team: str | None = None,
        region: str | None = None,
        min_risk: float | None = None,
        max_risk: float | None = None,
        search: str | None = None,
    ) -> int:
        with sqlite3.connect(self.db_path) as connection:
            conditions = []
            params: list[Any] = []

            if status and status.lower() != "all":
                conditions.append("LOWER(status) = LOWER(?)")
                params.append(status)
            if source and source.lower() != "all":
                conditions.append("LOWER(source) = LOWER(?)")
                params.append(source)
            if assignee and assignee.lower() != "all":
                conditions.append("LOWER(assignee) = LOWER(?)")
                params.append(assignee)
            if cluster_id:
                conditions.append("cluster_id = ?")
                params.append(cluster_id)
            if team and team.lower() != "all":
                team_clean = team.strip().lower()
                if team_clean in ("unassigned", "none"):
                    conditions.append("(assignee IS NULL OR assignee = '' OR LOWER(assignee) = 'unassigned')")
                elif team_clean == "me":
                    conditions.append("(LOWER(assignee) = 'me' OR LOWER(assignee) = 'analyst' OR LOWER(assignee) = 'current_user' OR LOWER(assignee) = 'soc analyst')")
                else:
                    conditions.append("LOWER(assignee) = LOWER(?)")
                    params.append(team.strip())
            if region and region.lower() != "all":
                region_clean = region.strip().lower()
                if "desktop" in region_clean:
                    conditions.append("(LOWER(path) LIKE '%desktop%' OR LOWER(source) LIKE '%desktop%')")
                elif "downloads" in region_clean:
                    conditions.append("(LOWER(path) LIKE '%downloads%' OR LOWER(source) LIKE '%downloads%')")
                elif "monitored" in region_clean or "root" in region_clean:
                    conditions.append("(LOWER(path) LIKE '%data/monitored%' OR LOWER(path) LIKE '%data\\monitored%' OR LOWER(path) NOT LIKE '%quarantine%')")
                else:
                    conditions.append("(LOWER(path) LIKE LOWER(?) OR LOWER(source) LIKE LOWER(?))")
                    params.extend([f"%{region_clean}%", f"%{region_clean}%"])

            if time_range and time_range != "all":
                now_ts = datetime.now(timezone.utc).timestamp()
                sec_map = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
                cutoff = sec_map.get(time_range)
                if cutoff:
                    cutoff_iso = datetime.fromtimestamp(now_ts - cutoff, timezone.utc).isoformat()
                    conditions.append("scanned_at >= ?")
                    params.append(cutoff_iso)
            if min_risk is not None:
                conditions.append("risk_score >= ?")
                params.append(min_risk / 100.0 if min_risk > 1.0 else min_risk)
            if max_risk is not None:
                conditions.append("risk_score <= ?")
                params.append(max_risk / 100.0 if max_risk > 1.0 else max_risk)
            if search:
                conditions.append("(LOWER(path) LIKE LOWER(?) OR LOWER(reasons) LIKE LOWER(?))")
                param_s = f"%{search}%"
                params.extend([param_s, param_s])

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"SELECT COUNT(*) FROM incidents {where_clause}"
            return connection.execute(query, params).fetchone()[0]


    def list_workflow_rules(self, enabled_only: bool = False) -> list[WorkflowRule]:
        with sqlite3.connect(self.db_path) as connection:
            if enabled_only:
                rows = connection.execute(
                    "SELECT id, name, condition_field, condition_op, condition_val, action, action_val, enabled, created_at FROM workflow_rules WHERE enabled = 1 ORDER BY id ASC"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT id, name, condition_field, condition_op, condition_val, action, action_val, enabled, created_at FROM workflow_rules ORDER BY id ASC"
                ).fetchall()
        return [
            WorkflowRule(
                id=r[0],
                name=r[1],
                condition_field=r[2],
                condition_op=r[3],
                condition_val=r[4],
                action=r[5],
                action_val=r[6] or "",
                enabled=bool(r[7]),
                created_at=r[8] or "",
            )
            for r in rows
        ]

    def create_workflow_rule(
        self,
        name: str,
        condition_field: str,
        condition_op: str,
        condition_val: str,
        action: str,
        action_val: str = "",
        enabled: bool = True,
    ) -> WorkflowRule:
        timestamp = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO workflow_rules (name, condition_field, condition_op, condition_val, action, action_val, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (name, condition_field, condition_op, condition_val, action, action_val, 1 if enabled else 0, timestamp),
            )
            connection.commit()
            rule_id = cursor.lastrowid
        self.log_audit(
            action="create_workflow_rule",
            target_path=f"rule://{rule_id}",
            details=f"Created rule '{name}': IF {condition_field} {condition_op} '{condition_val}' THEN {action} '{action_val}'",
            performed_by="operator:admin",
        )
        return WorkflowRule(
            id=rule_id,
            name=name,
            condition_field=condition_field,
            condition_op=condition_op,
            condition_val=condition_val,
            action=action,
            action_val=action_val,
            enabled=enabled,
            created_at=timestamp,
        )

    def toggle_workflow_rule(self, rule_id: int) -> bool:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("UPDATE workflow_rules SET enabled = 1 - enabled WHERE id = ?", (rule_id,))
            connection.commit()
            updated = cursor.rowcount > 0
        if updated:
            self.log_audit(action="toggle_workflow_rule", target_path=f"rule://{rule_id}", performed_by="operator:admin")
        return updated

    def delete_workflow_rule(self, rule_id: int) -> bool:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM workflow_rules WHERE id = ?", (rule_id,))
            connection.commit()
            deleted = cursor.rowcount > 0
        if deleted:
            self.log_audit(action="delete_workflow_rule", target_path=f"rule://{rule_id}", performed_by="operator:admin")
        return deleted

    def evaluate_incident_workflows(self, incident: Any, dry_run: bool = False) -> list[dict[str, Any]]:
        if hasattr(incident, "risk_score_100"):
            score = incident.risk_score_100
            severity = incident.risk_level.upper()
            path = str(incident.path)
            source = str(getattr(incident, "source", "WATCHER") or "WATCHER").upper()
            reasons = list(getattr(incident, "reasons", []) or [])
            cat_counts = dict(getattr(incident, "category_counts", {}) or {})
        elif isinstance(incident, dict):
            score = float(incident.get("risk_score", 0.0)) * (100.0 if incident.get("risk_score", 0.0) <= 1.0 else 1.0)
            severity = str(incident.get("severity") or incident.get("risk_level") or "LOW").upper()
            path = str(incident.get("path") or incident.get("filename") or "")
            source = str(incident.get("source") or "WATCHER").upper()
            reasons = list(incident.get("reasons") or [])
            cat_counts = dict(incident.get("category_counts") or {})
        else:
            return []

        file_ext = Path(path).suffix.lower().lstrip(".")
        categories = [k.lower() for k in cat_counts.keys()]
        reasons_text = " ".join(reasons).lower()

        rules = self.list_workflow_rules(enabled_only=not dry_run)
        executed = []

        for rule in rules:
            cond_field = rule.condition_field.lower().strip()
            cond_op = rule.condition_op.lower().strip()
            cond_val = rule.condition_val.lower().strip()

            matched = False
            if cond_field in ("severity", "risk_level"):
                actual = severity.lower()
                matched = (actual == cond_val) if cond_op == "eq" else (cond_val in actual)
            elif cond_field in ("file_type", "extension", "type"):
                actual = file_ext
                matched = (actual == cond_val) if cond_op == "eq" else (cond_val in actual)
            elif cond_field in ("category", "pii_type"):
                matched = any(cond_val in c for c in categories) or (cond_val in reasons_text)
            elif cond_field == "source":
                actual = source.lower()
                matched = (actual == cond_val) if cond_op == "eq" else (cond_val in actual)
            elif cond_field in ("risk_score", "score"):
                try:
                    val_num = float(cond_val)
                    if cond_op == "gte":
                        matched = score >= val_num
                    elif cond_op == "lte":
                        matched = score <= val_num
                    else:
                        matched = score == val_num
                except ValueError:
                    matched = False

            if matched:
                action_result = {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "action": rule.action,
                    "action_val": rule.action_val,
                    "matched": True,
                    "dry_run": dry_run,
                    "path": path,
                }
                executed.append(action_result)

                if not dry_run:
                    if rule.action == "assign" and rule.action_val:
                        self.assign_incident(path, rule.action_val)
                    elif rule.action == "dismiss":
                        self.update_status(path, "normal")
                    elif rule.action == "quarantine":
                        self.update_status(path, "quarantined")
                    elif rule.action == "tag" and rule.action_val:
                        inc = self.get_incident(path)
                        if inc and rule.action_val not in inc.reasons:
                            new_reasons = list(inc.reasons) + [f"tag:{rule.action_val}"]
                            with sqlite3.connect(self.db_path) as conn:
                                conn.execute("UPDATE incidents SET reasons = ? WHERE path = ?", (json.dumps(new_reasons), path))
                                conn.commit()

                    self.log_audit(
                        action="workflow_rule_execution",
                        target_path=path,
                        details=f"Rule '{rule.name}' triggered: {rule.action} {rule.action_val}".strip(),
                        performed_by="system:workflow_engine",
                    )

        return executed

class RiskEngine:
    """Turn content and model detections into a persisted risk assessment."""

    def __init__(
        self,
        *,
        policy: RiskPolicy | None = None,
        store: IncidentStore | None = None,
        model: LeakRiskModel | None = None,
    ) -> None:
        self.policy = policy or RiskPolicy()
        self.store = store or IncidentStore("data/leakguard.db")
        self.model = model or LeakRiskModel()

        if not self.model._fitted:
            try:
                documents = load_project_documents("data/monitored/datasets")
                if documents:
                    self.model.fit(documents[:25])
                else:
                    raise FileNotFoundError
            except (FileNotFoundError, ValueError):
                self.model.fit([
                    "Project planning notes for office scheduling and vendor coordination.",
                    "Internal meeting summary and team status update.",
                    "Quarterly review of marketing campaign and customer outreach plan.",
                ])

    def _score_file(self, path: str | Path) -> tuple[float, list[str], str, float, float, dict[str, int], str, list[ContentFinding]]:
        file_path = Path(path)
        result = scan_file(file_path, max_size_bytes=self.policy.max_scan_bytes)
        if result.skipped:
            # A skipped or unreadable file cannot be confirmed safe.
            # Under fail-closed policy, set to open/review with explicit explanation.
            reason_msg = f"scan_skipped:{result.reason}"
            return 0.5, [reason_msg, "File uninspected or limit exceeded (Review Required)"], "open", 0.0, 0.0, {}, "", []

        try:
            from leakguard.scanning import extract_file_text
            text = extract_file_text(file_path, max_chars=1_000_000)
        except OSError:
            text = ""

        eval_details = self.model.evaluate_details(text) if text else {
            "score_0_1": 0.0,
            "heuristic_score": 0.0,
            "model_anomaly_score": 0.0,
            "top_reasons": ["Empty or unreadable file"],
        }

        # Boost risk score if explicit scan findings exist (from chunked or regular scan)
        if result.findings:
            eval_details["score_0_1"] = max(eval_details["score_0_1"], min(1.0, 0.5 + len(result.findings) * 0.1))
            finding_summaries = [f"Found {rule} ({cnt}x)" for rule, cnt in result.category_counts.items()]
            reasons = finding_summaries + [r for r in eval_details["top_reasons"] if r not in finding_summaries]
        else:
            reasons = eval_details["top_reasons"]

        if result.reason == "partial_scan_exceeded_stream_limit":
            reasons.append("Stream limit reached: scanned first 50MB of file")

        risk_score = float(eval_details["score_0_1"])

        if self.policy.auto_quarantine and risk_score >= self.policy.quarantine_threshold:
            status = "quarantined"
        elif risk_score >= self.policy.suspicious_threshold:
            status = "open"
        else:
            status = "normal"

        return (
            risk_score,
            reasons,
            status,
            float(eval_details.get("heuristic_score", 0.0)),
            float(eval_details.get("model_anomaly_score", 0.0)),
            result.category_counts,
            result.masked_text[:500],
            result.findings,
        )

    def _quarantine_file(self, path: str | Path) -> str | None:
        source = Path(path)
        if not source.exists():
            return None

        quarantine_root = self.policy.quarantine_dir
        quarantine_root.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        destination = quarantine_root / f"{source.stem}_{timestamp}{source.suffix}"
        if destination.exists():
            counter = 1
            while destination.exists():
                destination = quarantine_root / f"{source.stem}_{timestamp}_{counter}{source.suffix}"
                counter += 1
        move(str(source), str(destination))
        self.store.log_audit("quarantine_file", str(source), f"Moved to {destination}")
        return str(destination)

    def restore_quarantined_file(self, quarantined_filename: str, target_dir: str | Path = "data/monitored") -> str | None:
        quarantine_root = self.policy.quarantine_dir
        source = quarantine_root / quarantined_filename
        if not source.exists():
            # Check matching filename anywhere in quarantine dir
            matches = list(quarantine_root.glob(f"*{quarantined_filename}*"))
            if matches:
                source = matches[0]
            else:
                return None

        # Baseline SHA-256 check
        sha_mismatch = False
        try:
            curr_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            matching_inc = self.store.get_incident(str(source))
            if not matching_inc:
                for inc in self.store.list_incidents():
                    if source.name in inc.path or clean_name in inc.path:
                        matching_inc = inc
                        break
            if matching_inc and matching_inc.sha256 and matching_inc.sha256 != curr_sha:
                sha_mismatch = True
                self.store.log_audit(
                    "restore_sha256_mismatch_warning",
                    str(source),
                    f"Warning: Current SHA-256 {curr_sha} does not match baseline {matching_inc.sha256}",
                )
        except Exception:
            pass

        dest_dir = Path(target_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Restore with clean original name
        clean_name = re.sub(r'_\d{8}T\d{6}(?:_\d+)?', '', source.name)
        destination = dest_dir / clean_name

        # Handle name collision on restore: append _restored_<ts> if destination exists
        if destination.exists():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            destination = dest_dir / f"{destination.stem}_restored_{ts}{destination.suffix}"

        try:
            move(str(source), str(destination))
        except (PermissionError, OSError) as err:
            self.store.log_audit("restore_file_failed", str(source), f"I/O error during restore: {err}")
            raise OSError(f"Failed to restore {source.name} due to locking or permission: {err}") from err

        details_msg = f"Restored to {destination}"
        if sha_mismatch:
            details_msg += " (Warning: SHA-256 mismatch with baseline)"
        self.store.log_audit("restore_file", str(source), details_msg)
        return str(destination)

    def evaluate_file(self, file_path: str | Path) -> IncidentRecord:
        file_path = Path(file_path)
        sha_val = ""
        if file_path.exists() and file_path.is_file():
            try:
                data = file_path.read_bytes()
                sha_val = hashlib.sha256(data).hexdigest()
            except OSError:
                sha_val = ""

        risk_score, reasons, status, h_score, m_score, cat_counts, masked_preview, findings = self._score_file(file_path)

        quarantined_at: str | None = None
        if status == "quarantined" and self.policy.auto_quarantine:
            quarantine_target = self._quarantine_file(file_path)
            if quarantine_target is not None:
                quarantined_at = datetime.now(timezone.utc).isoformat()
                status = "quarantined"

        src_val = "UPLOAD" if "temp_upload" in str(file_path) else "WATCHER"

        record = self.store.record_incident(
            path=file_path,
            risk_score=risk_score,
            status=status,
            reasons=reasons,
            quarantined_at=quarantined_at,
            heuristic_score=h_score,
            model_score=m_score,
            category_counts=cat_counts,
            masked_preview=masked_preview,
            sha256=sha_val,
            source=src_val,
            findings=findings,
        )

        # Run automated workflow rules in incident pipeline after scoring
        try:
            self.store.evaluate_incident_workflows(record)
        except Exception:
            pass

        return record

