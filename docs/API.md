# SentinelDLP API Schema Reference (v2.1)

SentinelDLP provides a 100% offline, local REST API and real-time SSE stream. All sensitive entities are masked in memory and persistent storage prior to API serialization.

---

## 1. System & Metrics Endpoints

### `GET /api/status`
Returns service uptime, monitoring state, and active policy parameters.
- **Response**:
```json
{
  "status": "active",
  "monitoring_active": true,
  "watched_folder": "data/monitored",
  "last_scan_time": "2026-10-13T00:30:00Z",
  "uptime_seconds": 3600,
  "is_scanning": false,
  "model_fitted": true,
  "policy": {
    "suspicious_threshold": 30.0,
    "quarantine_threshold": 70.0,
    "auto_quarantine": true
  }
}
```

### `GET /api/overview`
Returns reconciled SOC metrics, incident health score, risk score distribution, top risky files, and recent events.
- **Response**:
```json
{
  "kpis": {
    "total_scanned": 42,
    "open_incidents": 5,
    "quarantined": 12,
    "blocked": 4,
    "high_risk": 16,
    "average_risk": 44.5,
    "detection_rate_pct": 50.0,
    "detection_rate_status": "Calculated",
    "definitions": {
      "total_scanned": "...",
      "open_incidents": "...",
      "quarantined": "...",
      "blocked": "...",
      "high_risk": "...",
      "detection_rate": "...",
      "average_risk": "...",
      "incident_health": "...",
      "sla_compliance": "..."
    }
  },
  "incident_health": {
    "score": 88,
    "label": "Excellent",
    "active_cases": 5,
    "critical_cases": 0,
    "avg_resolution_hours": 1.4,
    "sla_compliance_pct": 100.0,
    "status": "Operational"
  },
  "category_counts": { "credit_card": 10, "aadhaar": 6, "email": 14 },
  "risk_distribution": { "0-20": 10, "21-40": 8, "41-60": 8, "61-80": 8, "81-100": 8 },
  "top_risky_files": [...],
  "recent_security_events": [...],
  "service_health": {
    "database_connected": true,
    "monitoring_active": true,
    "quarantine_vault_ready": true,
    "model_loaded": true
  },
  "last_updated": "2026-10-13T00:30:00Z"
}
```

---

## 2. Incident Management Endpoints

### `GET /api/incidents`
Lists incidents with optional server-side pagination, source filtering, assignment filtering, and sorting.
- **Query Parameters**:
  - `status` (`string`, optional): `open`, `quarantined`, `normal`, `released`, `blocked`, `purged`.
  - `source` (`string`, optional): `WATCHER`, `UPLOAD`, `PROMPT`.
  - `assignee` (`string`, optional): Filter by assigned analyst name.
  - `time_range` (`string`, optional): `1h`, `24h`, `7d`, `30d`, `all`.
  - `cluster_id` (`string`, optional): Simhash / near-duplicate cluster id.
  - `min_risk` (`float`, optional): Minimum risk score (0-100).
  - `max_risk` (`float`, optional): Maximum risk score (0-100).
  - `search` (`string`, optional): Substring filter on file path or reasons.
  - `sort_by` (`string`, optional): `id_desc`, `id_asc`, `risk_desc`, `risk_asc`, `date_desc`, `date_asc`.
  - `page` (`int`, optional): 1-indexed page number (if provided, returns paginated envelope).
  - `page_size` (`int`, optional): Items per page.
- **Paginated Response** (when `page` is passed):
```json
{
  "items": [
    {
      "id": 1,
      "path": "data/monitored/customer_records.csv",
      "file_name": "customer_records.csv",
      "risk_score": 85.0,
      "risk_level": "HIGH",
      "heuristic_score": 80.0,
      "model_score": 90.0,
      "status": "quarantined",
      "reasons": ["Valid Credit Card (Luhn checked)", "Aadhaar Number"],
      "scanned_at": "2026-10-13T00:15:00Z",
      "quarantined_at": "2026-10-13T00:15:01Z",
      "category_counts": { "credit_card": 2 },
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "assignee": "Analyst Sarah",
      "source": "WATCHER",
      "resolved_at": null,
      "cluster_id": "",
      "created_at": "2026-10-13T00:15:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 25,
  "pages": 1
}
```

### `GET /api/incidents/{incident_id}`
Returns full incident details, score breakdown, findings, extra signals, and masked content preview.

### `POST /api/incidents/{incident_id}/action`
Performs lifecycle actions on an incident.
- **Payload**:
  - Assign: `{"action": "assign", "assignee": "Analyst Name"}`
  - Quarantine: `{"action": "quarantine"}`
  - Dismiss: `{"action": "dismiss"}`
  - Restore: `{"action": "restore"}`
  - Block: `{"action": "block"}`
  - Delete: `{"action": "delete"}`

### `POST /api/incidents/bulk-action`
Executes batch operations across multiple incidents.
- **Payload**: `{"incident_ids": ["1", "2", "3"], "action": "quarantine" | "dismiss" | "delete" | "assign", "assignee": "Optional Name"}`

---

## 3. Quarantine Vault Endpoints

### `GET /api/quarantine`
Lists all files currently residing in `data/quarantine`.

### `POST /api/quarantine/restore`
Restores a file from the quarantine vault to `data/monitored/`. Appends `_restored_<timestamp>` if a destination file exists with the same name. Emits SSE `quarantine_change`.
- **Payload**: `{"filename": "customer_records_20261013T001501.csv"}`

### `DELETE /api/quarantine/{filename}`
Permanently purges a file from the quarantine directory, marks corresponding incident as `purged`, and emits SSE `quarantine_change`.

---

## 4. Audit Trail Endpoints

### `GET /api/audit`
Paginated, append-only audit log entries with optional action and date range filters.
- **Query Parameters**: `action`, `performed_by`, `start_date`, `end_date`, `page`, `page_size`, `limit`.

### `GET /api/audit/export`
Exports audit log entries as a downloadable CSV stream with `Content-Disposition` header.
- **Query Parameters**: `action`, `performed_by`, `start_date`, `end_date`.
Exports audit logs as a downloadable CSV file (`sentinel_dlp_audit_trail.csv`) with `Content-Disposition` header.

---

## 5. Upload Review Endpoints

### `POST /api/upload`
Single-file pre-acceptance scanner. Scans in memory and writes to `data/monitored/` only if Allowed.

### `POST /api/upload/batch`
Multi-file pre-acceptance scanner with bounded concurrency.

---

## 6. Real-Time Streaming & Self-Test

### `GET /api/stream/events`
Server-Sent Events (SSE) feed emitting `scan_start`, `scan_complete`, and a 15-second `heartbeat`. Every message includes an `event_id` for client-side deduplication.

### `POST /api/system/self-test`
Executes an end-to-end self-test verifying detection, quarantine isolation, file restoration, purge, and audit logging.
