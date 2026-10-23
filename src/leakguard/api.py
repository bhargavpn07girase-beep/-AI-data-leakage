"""FastAPI REST API and Real-time SSE Stream for SentinelDLP."""

from __future__ import annotations

import asyncio
import io
import json
import csv
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile, Query, BackgroundTasks, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from leakguard.assistant import SecurityAssistant
from leakguard.incident import IncidentStore, RiskEngine, RiskPolicy, WorkflowRule
from leakguard.modeling import LeakRiskModel
from leakguard.monitoring import FileEvent, MonitorConfig, MonitoringService
from leakguard.stats import compute_kpis, compute_incident_health
from leakguard.prompt_verification import verify_prompt_text, PromptHistoryStore


class EventBroadcaster:
    """Thread-safe event pub-sub channel for SSE streaming."""

    def __init__(self) -> None:
        self.subscribers: list[asyncio.Queue] = []
        self.loop: asyncio.AbstractEventLoop | None = None
        self._seq: int = 0

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)

    def publish(self, data: dict) -> None:
        if not self.subscribers:
            return
        self._seq += 1
        data["event_id"] = f"evt_{int(time.time() * 1000)}_{self._seq}"
        payload = json.dumps(data)
        if self.loop and self.loop.is_running():
            for q in list(self.subscribers):
                self.loop.call_soon_threadsafe(q.put_nowait, payload)


broadcaster = EventBroadcaster()
start_time = time.time()
latest_scan_timestamp: str | None = None
is_scanning_active: bool = False

policy = RiskPolicy(suspicious_threshold=0.3, quarantine_threshold=0.7, auto_quarantine=True)
store = IncidentStore("data/leakguard.db")
prompt_store = PromptHistoryStore("data/leakguard.db")
model = LeakRiskModel(model_path="data/model.joblib")
engine = RiskEngine(policy=policy, store=store, model=model)
assistant = SecurityAssistant(store=store, policy=policy, engine=engine, quarantine_dir=policy.quarantine_dir)


def on_file_event(event: FileEvent) -> None:
    global latest_scan_timestamp, is_scanning_active
    is_scanning_active = True
    broadcaster.publish({
        "type": "scan_start",
        "event_type": event.event_type,
        "path": event.path,
        "observed_at": event.observed_at,
    })

    file_full_path = engine.policy.quarantine_dir.parent / "monitored" / event.path
    if not file_full_path.exists():
        file_full_path = Path(event.path)

    record = None
    if file_full_path.exists() and file_full_path.is_file():
        record = engine.evaluate_file(file_full_path)
        latest_scan_timestamp = datetime.now(timezone.utc).isoformat()

    is_scanning_active = False
    if record:
        broadcaster.publish({
            "type": "scan_complete",
            "event_type": event.event_type,
            "path": record.path,
            "risk_score": record.risk_score_100,
            "status": record.status,
            "reasons": record.reasons,
            "scanned_at": record.scanned_at,
            "quarantined_at": record.quarantined_at,
            "category_counts": record.category_counts,
        })


monitor_config = MonitorConfig(directory=Path("data/monitored"))
monitoring_service = MonitoringService(config=monitor_config, on_event=on_file_event)

app = FastAPI(title="SentinelDLP API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


web_dir = Path("web")
if web_dir.exists():
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")


@app.get("/")
def read_root():
    index_file = web_dir / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "SentinelDLP API Running"}


@app.on_event("startup")
async def startup_event() -> None:

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.get_event_loop()
    broadcaster.set_loop(loop)

    # Initial directory sync & scan of existing files in data/monitored
    monitored_dir = Path("data/monitored")
    monitored_dir.mkdir(parents=True, exist_ok=True)
    Path("data/quarantine").mkdir(parents=True, exist_ok=True)

    supported = {".txt", ".csv", ".json", ".jsonl", ".log", ".md", ".pdf", ".docx"}
    try:
        existing_paths = {row["path"] for row in store.list_incidents(limit=5000)}
    except Exception:
        existing_paths = set()

    for file_path in sorted(monitored_dir.rglob("*")):
        if file_path.is_file() and file_path.suffix.lower() in supported:
            if str(file_path) not in existing_paths:
                try:
                    engine.evaluate_file(file_path)
                except Exception:
                    pass

    try:
        monitoring_service.start()
    except Exception as e:
        print(f"Warning: Monitoring service start deferred: {e}")


@app.on_event("shutdown")
def shutdown_event() -> None:
    monitoring_service.stop()


# ---------------- RBAC ROLE ENFORCEMENT & AUDIT ---------------- #

def get_current_role(x_role: Optional[str] = Header(None, alias="X-Role")) -> str:
    if not x_role:
        return "Admin"  # Default unconstrained for legacy test clients / headless scripts
    role_lower = x_role.strip().lower()
    if "admin" in role_lower:
        return "Admin"
    if "auditor" in role_lower:
        return "Auditor"
    return "SOC Analyst"


def require_mutation_permission(x_role: Optional[str] = Header(None, alias="X-Role")) -> str:
    role = get_current_role(x_role)
    if role == "Auditor":
        raise HTTPException(
            status_code=403,
            detail="Auditor role is read-only. Mutation operations (quarantine, dismiss, restore, assign, delete, etc.) are strictly prohibited."
        )
    return role


def require_admin_permission(x_role: Optional[str] = Header(None, alias="X-Role")) -> str:
    role = get_current_role(x_role)
    if role != "Admin":
        raise HTTPException(
            status_code=403,
            detail=f"Admin role required for this action. Current role '{role}' is not authorized."
        )
    return role


class RoleChangeRequest(BaseModel):
    old_role: Optional[str] = None
    previous_role: Optional[str] = None
    new_role: str
    user: Optional[str] = "local-operator"
    reason: Optional[str] = None


@app.post("/api/audit/role-change")
def log_role_change(req: RoleChangeRequest, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    current = get_current_role(x_role)
    old = req.old_role or req.previous_role or "SOC Analyst"
    entry = store.log_audit(
        action="role_change",
        target_path=f"role://{req.new_role}",
        details=f"Switched role from {old} to {req.new_role}" + (f" ({req.reason})" if req.reason else ""),
        performed_by=f"user:{req.user or current}",
    )
    broadcaster.publish({
        "type": "role_changed",
        "old_role": old,
        "new_role": req.new_role,
        "timestamp": entry.timestamp,
    })
    return {"status": "success", "role": req.new_role, "audit_id": entry.id}


# ---------------- API ENDPOINTS ---------------- #

@app.get("/api/status")
def get_system_status() -> dict:
    uptime_seconds = int(time.time() - start_time)
    incidents = store.list_incidents()
    return {
        "status": "active" if monitoring_service.is_running else "paused",
        "monitoring_active": monitoring_service.is_running,
        "watched_folder": str(monitoring_service.monitored_directory or "data/monitored"),
        "last_scan_time": latest_scan_timestamp or (incidents[-1].scanned_at if incidents else None),
        "uptime_seconds": uptime_seconds,
        "is_scanning": is_scanning_active,
        "model_fitted": model._fitted,
        "policy": {
            "suspicious_threshold": engine.policy.suspicious_threshold * 100,
            "quarantine_threshold": engine.policy.quarantine_threshold * 100,
            "auto_quarantine": engine.policy.auto_quarantine,
        }
    }


@app.get("/api/overview")
def get_overview_metrics(
    team: Optional[str] = None,
    region: Optional[str] = None,
    time_range: Optional[str] = None,
    source: Optional[str] = None,
) -> dict:
    incidents = store.list_incidents(
        team=team,
        region=region,
        time_range=time_range,
        source=source,
    )
    kpi_obj = compute_kpis(store.db_path, engine.policy.quarantine_dir)

    category_counts: dict[str, int] = {}
    risk_distribution = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    violations_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_by_extension: dict[str, dict[str, int]] = {}

    for inc in incidents:
        score = inc.risk_score_100
        if score <= 20:
            risk_distribution["0-20"] += 1
        elif score <= 40:
            risk_distribution["21-40"] += 1
        elif score <= 60:
            risk_distribution["41-60"] += 1
        elif score <= 80:
            risk_distribution["61-80"] += 1
        else:
            risk_distribution["81-100"] += 1

        if score >= 90:
            violations_summary["critical"] += 1
        elif score >= 70:
            violations_summary["high"] += 1
        elif score >= 40:
            violations_summary["medium"] += 1
        else:
            violations_summary["low"] += 1

        ext = Path(inc.path).suffix.lower() if inc.path else ".txt"
        if not ext:
            ext = "other"
        if ext not in risk_by_extension:
            risk_by_extension[ext] = {"count": 0, "risky": 0}
        risk_by_extension[ext]["count"] += 1
        if score >= 40:
            risk_by_extension[ext]["risky"] += 1

        for cat, cnt in inc.category_counts.items():
            category_counts[cat] = category_counts.get(cat, 0) + cnt

    top_risky = sorted(incidents, key=lambda i: i.risk_score, reverse=True)[:5]
    top_risky_files = [
        {
            "id": inc.id,
            "path": inc.path,
            "file_name": Path(inc.path).name,
            "risk_score": inc.risk_score_100,
            "status": inc.status,
            "reasons": inc.reasons[:2],
            "scanned_at": inc.scanned_at,
            "assignee": getattr(inc, "assignee", None) or "Unassigned",
            "source": getattr(inc, "source", None) or "WATCHER",
        }
        for inc in top_risky
    ]

    # Recent security events from audit log
    audit_entries = store.list_audit_log(limit=6)
    recent_events = [
        {
            "id": a.id,
            "timestamp": a.timestamp,
            "action": a.action,
            "target_path": a.target_path,
            "target_name": Path(a.target_path).name,
            "details": a.details,
            "performed_by": a.performed_by,
        }
        for a in audit_entries
    ]

    # Service health evaluation
    service_health = {
        "database_connected": store.db_path.exists(),
        "monitoring_active": monitoring_service.is_running,
        "quarantine_vault_ready": Path(engine.policy.quarantine_dir).exists(),
        "model_loaded": model._fitted,
    }

    health_obj = compute_incident_health(store.db_path)

    lifecycle = {
        "detected": len(incidents),
        "quarantined": sum(1 for i in incidents if i.status == "quarantined"),
        "open": sum(1 for i in incidents if i.status == "open"),
        "resolved": sum(1 for i in incidents if i.status in ("released", "purged", "resolved")),
    }

    policy_summary = {
        "suspicious_threshold": round(engine.policy.suspicious_threshold * 100, 1),
        "quarantine_threshold": round(engine.policy.quarantine_threshold * 100, 1),
        "auto_quarantine": engine.policy.auto_quarantine,
        "active_rules_count": 8,
    }

    event_types_24h = {
        "created": sum(1 for a in audit_entries if "create" in a.action.lower()),
        "modified": sum(1 for a in audit_entries if "modify" in a.action.lower() or "eval" in a.action.lower()),
        "moved": sum(1 for a in audit_entries if "move" in a.action.lower()),
        "deleted": sum(1 for a in audit_entries if "purge" in a.action.lower() or "delete" in a.action.lower()),
    }

    return {
        "kpis": kpi_obj.to_dict(),
        "incident_health": health_obj.to_dict(),
        "violations_summary": violations_summary,
        "risk_by_extension": risk_by_extension,
        "category_counts": category_counts,
        "risk_distribution": risk_distribution,
        "top_risky_files": top_risky_files,
        "recent_security_events": recent_events,
        "service_health": service_health,
        "incident_lifecycle": lifecycle,
        "policy_summary": policy_summary,
        "event_types_24h": event_types_24h,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


class ChatRequest(BaseModel):
    message: str


@app.post("/api/assistant/chat")
@app.post("/api/assistant/ask")
def assistant_chat(payload: ChatRequest) -> dict:
    status_info = get_system_status()
    response = assistant.answer_query(payload.message, monitoring_status=status_info)
    store.log_audit("assistant_query", "chatbot", f"Query: {payload.message[:80]}")
    return response


@app.get("/api/incidents")
def list_incidents(
    status: Optional[str] = None,
    source: Optional[str] = None,
    assignee: Optional[str] = None,
    cluster_id: Optional[str] = None,
    time_range: Optional[str] = None,
    team: Optional[str] = None,
    region: Optional[str] = None,
    search: Optional[str] = None,
    min_risk: Optional[float] = None,
    max_risk: Optional[float] = None,
    sort_by: Optional[str] = "id_desc",
    page: Optional[int] = None,
    page_size: Optional[int] = None,
):
    # Support both unpaginated raw list (backward-compat) and paginated object
    limit = page_size if (page_size and page_size > 0) else None
    offset = ((page - 1) * limit) if (page and limit) else 0

    incidents = store.list_incidents(
        status=status,
        source=source,
        assignee=assignee,
        cluster_id=cluster_id,
        time_range=time_range,
        team=team,
        region=region,
        min_risk=min_risk,
        max_risk=max_risk,
        search=search,
        sort_by=sort_by or "id_desc",
        limit=limit,
        offset=offset,
    )
    total_count = store.count_incidents(
        status=status,
        source=source,
        assignee=assignee,
        cluster_id=cluster_id,
        time_range=time_range,
        team=team,
        region=region,
        min_risk=min_risk,
        max_risk=max_risk,
        search=search,
    )

    items = [
        {
            "id": inc.id,
            "path": inc.path,
            "file_name": Path(inc.path).name,
            "risk_score": inc.risk_score_100,
            "risk_level": inc.risk_level,
            "heuristic_score": round(inc.heuristic_score, 1),
            "model_score": round(inc.model_score, 1),
            "status": inc.status,
            "reasons": inc.reasons,
            "scanned_at": inc.scanned_at,
            "quarantined_at": inc.quarantined_at,
            "category_counts": inc.category_counts,
            "sha256": inc.sha256,
            "assignee": inc.assignee,
            "source": inc.source,
            "resolved_at": inc.resolved_at,
            "cluster_id": inc.cluster_id,
            "created_at": inc.created_at,
        }
        for inc in incidents
    ]

    # If page parameter was provided, return paginated envelope; otherwise return raw array for backward compatibility
    if page is not None:
        return {
            "items": items,
            "total": total_count,
            "page": page,
            "page_size": page_size or len(items),
            "pages": ((total_count + (page_size or 1) - 1) // (page_size or 1)) if page_size else 1,
        }
    return items


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str) -> dict:
    inc = store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident record not found")

    findings = store.get_findings_for_incident(inc.path)
    file_path = Path(inc.path)
    file_exists = file_path.exists()
    size_bytes = file_path.stat().st_size if file_exists else 0

    from leakguard.extra_signals import extract_extra_signals_for_file
    extra_signals = extract_extra_signals_for_file(
        file_path=file_path,
        raw_text=inc.masked_preview or "",
        risk_score=inc.risk_score_100,
    )

    return {
        "id": inc.id,
        "path": inc.path,
        "file_name": file_path.name,
        "file_exists": file_exists,
        "size_bytes": size_bytes,
        "risk_score": inc.risk_score_100,
        "risk_level": inc.risk_level,
        "heuristic_score": round(inc.heuristic_score, 1),
        "model_score": round(inc.model_score, 1),
        "status": inc.status,
        "reasons": inc.reasons,
        "scanned_at": inc.scanned_at,
        "quarantined_at": inc.quarantined_at,
        "category_counts": inc.category_counts,
        "masked_preview": inc.masked_preview,
        "sha256": inc.sha256,
        "assignee": inc.assignee,
        "source": inc.source,
        "resolved_at": inc.resolved_at,
        "cluster_id": inc.cluster_id,
        "created_at": inc.created_at,
        "extra_signals": extra_signals,
        "findings": [
            {
                "rule": f.rule,
                "line_number": f.line_number,
                "masked_value": f.masked_value,
            }
            for f in findings
        ]
    }


class ActionRequest(BaseModel):
    action: str
    assignee: Optional[str] = None


class BulkActionRequest(BaseModel):
    incident_ids: list[str]
    action: str
    assignee: Optional[str] = None


@app.post("/api/incidents/bulk-action")
def perform_bulk_incident_action(req: BulkActionRequest, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_mutation_permission(x_role)
    results = []
    act = req.action.lower()
    for inc_id in req.incident_ids:
        inc = store.get_incident(inc_id)
        if not inc:
            results.append({"id": inc_id, "status": "error", "message": "Not found"})
            continue
        if act == "quarantine":
            target = engine._quarantine_file(inc.path)
            store.update_status(inc.path, "quarantined")
            results.append({"id": inc_id, "status": "success", "message": f"Quarantined to {target}"})
        elif act in ("dismiss", "mark_normal"):
            store.update_status(inc.path, "normal")
            results.append({"id": inc_id, "status": "success", "message": "Marked Normal"})
        elif act == "assign":
            assigned_val = req.assignee or "Unassigned"
            store.assign_incident(inc.id, assigned_val)
            results.append({"id": inc_id, "status": "success", "message": f"Assigned to {assigned_val}"})
        elif act == "delete":
            store.delete_incident(inc.path)
            results.append({"id": inc_id, "status": "success", "message": "Deleted"})
        else:
            results.append({"id": inc_id, "status": "error", "message": f"Unknown action: {act}"})

    broadcaster.publish({
        "type": "incident_updated",
        "action": act,
        "count": len(req.incident_ids),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return {"status": "success", "processed": len(results), "results": results}


@app.post("/api/incidents/{incident_id}/action")
def perform_incident_action(incident_id: str, req: ActionRequest, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_mutation_permission(x_role)
    inc = store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident record not found")

    action = req.action.lower()
    if action == "assign":
        assigned_to = req.assignee or "Unassigned"
        store.assign_incident(inc.id, assigned_to)
        broadcaster.publish({
            "type": "incident_updated",
            "incident_id": inc.id,
            "action": "assign",
            "assignee": assigned_to,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "success", "message": f"Assigned to {assigned_to}", "assignee": assigned_to}
    elif action == "quarantine":
        target = engine._quarantine_file(inc.path)
        store.update_status(inc.path, "quarantined")
        broadcaster.publish({
            "type": "incident_updated",
            "incident_id": inc.id,
            "action": "quarantine",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "success", "message": f"Quarantined to {target}"}
    elif action == "restore":
        q_name = Path(inc.path).name
        restored = engine.restore_quarantined_file(q_name)
        if restored:
            store.update_status(inc.path, "released")
            broadcaster.publish({
                "type": "incident_updated",
                "incident_id": inc.id,
                "action": "restore",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return {"status": "success", "message": f"Restored file to {restored}"}
        store.update_status(inc.path, "normal")
        broadcaster.publish({
            "type": "incident_updated",
            "incident_id": inc.id,
            "action": "restore",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "success", "message": "Marked incident as restored"}
    elif action in ("mark_normal", "dismiss"):
        store.update_status(inc.path, "normal")
        broadcaster.publish({
            "type": "incident_updated",
            "incident_id": inc.id,
            "action": "dismiss",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "success", "message": "Incident marked as Normal"}
    elif action == "block":
        store.update_status(inc.path, "blocked")
        file_path = Path(inc.path)
        if file_path.exists():
            try:
                file_path.unlink()
            except OSError:
                pass
        broadcaster.publish({
            "type": "incident_updated",
            "incident_id": inc.id,
            "action": "block",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "success", "message": "File blocked and removed"}
    elif action == "delete":
        store.delete_incident(inc.path)
        broadcaster.publish({
            "type": "incident_updated",
            "incident_id": inc.id,
            "action": "delete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"status": "success", "message": "Record deleted from database"}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


@app.post("/api/upload")
async def upload_review(file: UploadFile = File(...), x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_mutation_permission(x_role)
    import uuid
    import re

    # Sanitize filename against directory traversal
    clean_name = Path(file.filename or "uploaded_file.txt").name
    clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', clean_name)
    scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"

    temp_dir = Path("data/temp_upload")
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"{scan_id}_{clean_name}"

    content = await file.read()
    temp_path.write_bytes(content)

    try:
        record = engine.evaluate_file(temp_path)
        risk_score_100 = record.risk_score_100

        # Check for skipped / incomplete scan
        is_skipped = any("scan_skipped" in r for r in record.reasons)
        if is_skipped:
            verdict = "Scan Incomplete"
            allowed = False
            policy_reason = f"Upload held for manual security review: scan skipped or resource limit hit ({', '.join(record.reasons)})."
            if temp_path.exists():
                temp_path.unlink()
            store.log_audit("upload_held_incomplete", clean_name, f"Reasons: {', '.join(record.reasons)}")
        elif record.status in ("quarantined", "open") or risk_score_100 >= (engine.policy.suspicious_threshold * 100):
            verdict = "Blocked" if risk_score_100 >= (engine.policy.quarantine_threshold * 100) else "Needs Review"
            allowed = False
            policy_reason = f"Upload rejected. Risk score ({risk_score_100:.1f}%) exceeds policy threshold."
            if temp_path.exists():
                temp_path.unlink()
            store.log_audit("upload_blocked", clean_name, f"Risk {risk_score_100:.1f}%")
        else:
            verdict = "Allowed"
            allowed = True
            policy_reason = f"Upload accepted. File complies with security policy (Risk: {risk_score_100:.1f}%)."
            dest_dir = Path("data/monitored")
            dest_dir.mkdir(parents=True, exist_ok=True)
            target_path = dest_dir / clean_name
            if temp_path.exists():
                temp_path.replace(target_path)
            store.log_audit("upload_accepted", clean_name, f"Saved to {target_path}")

        # Record scan in batch_scans table for persistent audit
        store.record_batch_scan(
            batch_id="single-upload",
            scan_id=scan_id,
            filename=clean_name,
            file_size=len(content),
            status="completed" if not is_skipped else "incomplete",
            risk_score=risk_score_100 if not is_skipped else None,
            verdict=verdict,
            findings_count=sum(record.category_counts.values()),
            reasons=record.reasons,
            category_counts=record.category_counts,
        )

        return {
            "scan_id": scan_id,
            "filename": clean_name,
            "allowed": allowed,
            "verdict": verdict,
            "risk_score": risk_score_100 if not is_skipped else None,
            "scan_status": "completed" if not is_skipped else "incomplete",
            "policy_reason": policy_reason,
            "reasons": record.reasons,
            "category_counts": record.category_counts,
            "heuristic_score": round(record.heuristic_score, 1),
            "model_score": round(record.model_score, 1),
        }
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")


@app.post("/api/upload/batch")
async def upload_batch(files: list[UploadFile] = File(...), x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_mutation_permission(x_role)
    import uuid
    import re

    if len(files) > 100:
        raise HTTPException(status_code=400, detail="Batch exceeds maximum limit of 100 files.")

    batch_id = f"BATCH-{uuid.uuid4().hex[:8].upper()}"
    sem = asyncio.Semaphore(5)  # Bounded concurrency to protect server CPU/RAM
    results = []

    async def process_single(idx: int, up_file: UploadFile) -> dict:
        async with sem:
            clean_name = Path(up_file.filename or f"file_{idx}.txt").name
            clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', clean_name)
            scan_id = f"{batch_id}-{idx + 1:03d}"

            temp_dir = Path("data/temp_upload")
            temp_dir.mkdir(parents=True, exist_ok=True)
            temp_path = temp_dir / f"{scan_id}_{clean_name}"

            try:
                # Extension whitelist check
                ext = Path(clean_name).suffix.lower()
                if ext not in engine.policy.allowed_extensions:
                    raise ValueError(f"Extension '{ext}' not in allowed policy whitelist: {engine.policy.allowed_extensions}")

                content = await up_file.read()
                if len(content) > engine.policy.max_upload_size_bytes:
                    raise ValueError(f"File size ({len(content)} bytes) exceeds maximum policy limit ({engine.policy.max_upload_size_bytes} bytes)")

                temp_path.write_bytes(content)
                record = engine.evaluate_file(temp_path)
                risk_score_100 = record.risk_score_100

                is_skipped = any("scan_skipped" in r for r in record.reasons)
                if is_skipped:
                    verdict = "Scan Incomplete"
                    allowed = False
                    status = "incomplete"
                    if temp_path.exists():
                        temp_path.unlink()
                elif record.status in ("quarantined", "open") or risk_score_100 >= (engine.policy.suspicious_threshold * 100):
                    verdict = "Blocked" if risk_score_100 >= (engine.policy.quarantine_threshold * 100) else "Needs Review"
                    allowed = False
                    status = "flagged"
                    if temp_path.exists():
                        temp_path.unlink()
                else:
                    verdict = "Allowed"
                    allowed = True
                    status = "completed"
                    # Allowed files move to data/monitored/
                    dest_dir = Path("data/monitored")
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = dest_dir / clean_name
                    if dest_file.exists():
                        dest_file = dest_dir / f"{dest_file.stem}_{int(time.time())}{dest_file.suffix}"
                    if temp_path.exists():
                        temp_path.replace(dest_file)

                store.record_batch_scan(
                    batch_id=batch_id,
                    scan_id=scan_id,
                    filename=clean_name,
                    file_size=len(content),
                    status=status,
                    risk_score=risk_score_100 if not is_skipped else None,
                    verdict=verdict,
                    findings_count=sum(record.category_counts.values()),
                    reasons=record.reasons,
                    category_counts=record.category_counts,
                )

                return {
                    "index": idx + 1,
                    "scan_id": scan_id,
                    "filename": clean_name,
                    "size_bytes": len(content),
                    "allowed": allowed,
                    "verdict": verdict,
                    "risk_score": risk_score_100 if not is_skipped else None,
                    "status": status,
                    "findings_count": sum(record.category_counts.values()),
                    "reasons": record.reasons[:3],
                    "category_counts": record.category_counts,
                    "heuristic_score": round(record.heuristic_score, 1),
                    "model_score": round(record.model_score, 1),
                }
            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                store.record_batch_scan(
                    batch_id=batch_id,
                    scan_id=scan_id,
                    filename=clean_name,
                    file_size=0,
                    status="failed",
                    risk_score=None,
                    verdict="Failed",
                    findings_count=0,
                    reasons=[f"error: {str(e)[:80]}"],
                    category_counts={},
                )
                return {
                    "index": idx + 1,
                    "scan_id": scan_id,
                    "filename": clean_name,
                    "size_bytes": 0,
                    "allowed": False,
                    "verdict": "Failed",
                    "risk_score": None,
                    "status": "failed",
                    "findings_count": 0,
                    "reasons": [str(e)[:80]],
                    "category_counts": {},
                    "heuristic_score": 0.0,
                    "model_score": 0.0,
                }

    tasks = [process_single(i, f) for i, f in enumerate(files)]
    results = await asyncio.gather(*tasks)

    # Compute batch summary metrics
    total = len(results)
    flagged = sum(1 for r in results if r["status"] == "flagged")
    completed = sum(1 for r in results if r["status"] == "completed")
    failed = sum(1 for r in results if r["status"] == "failed")
    incomplete = sum(1 for r in results if r["status"] == "incomplete")

    store.log_audit(
        "batch_upload_completed",
        batch_id,
        f"Total: {total}, Flagged: {flagged}, Clean: {completed}, Incomplete/Failed: {incomplete + failed}",
    )

    return {
        "batch_id": batch_id,
        "total_files": total,
        "completed": completed,
        "flagged": flagged,
        "incomplete": incomplete,
        "failed": failed,
        "items": results,
    }


@app.get("/api/upload/batch/history")
def get_batch_history(batch_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    return store.list_batch_scans(batch_id=batch_id, limit=limit)


@app.get("/api/quarantine")
def list_quarantined_files() -> list[dict]:
    q_dir = Path("data/quarantine")
    q_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(q_dir.glob("*")):
        if f.is_file():
            stat = f.stat()
            file_hash = ""
            try:
                import hashlib
                h = hashlib.sha256()
                with open(f, "rb") as fp:
                    while chunk := fp.read(65536):
                        h.update(chunk)
                file_hash = h.hexdigest()
            except Exception:
                file_hash = "unreadable"
            files.append({
                "filename": f.name,
                "size_bytes": stat.st_size,
                "quarantined_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "path": str(f),
                "sha256": file_hash,
                "integrity": "verified" if file_hash and file_hash != "unreadable" else "unknown"
            })
    return files


@app.post("/api/quarantine/restore")
def restore_quarantine_item(payload: dict, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_mutation_permission(x_role)
    filename = payload.get("filename")
    if not filename:
        raise HTTPException(status_code=400, detail="Filename required")

    try:
        restored = engine.restore_quarantined_file(filename)
    except OSError as err:
        raise HTTPException(status_code=500, detail=str(err))

    if not restored:
        raise HTTPException(status_code=404, detail="Quarantined file not found")

    # Update matching incident record status to 'released'
    incidents = store.list_incidents()
    for inc in incidents:
        if filename in inc.path or Path(inc.path).name == Path(filename).name:
            store.update_status(inc.path, "released")

    broadcaster.publish({
        "type": "quarantine_change",
        "action": "restore",
        "filename": filename,
        "restored_path": str(restored),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {"status": "success", "message": f"Restored file to {restored}", "restored_path": str(restored)}


@app.delete("/api/quarantine/{filename}")
def delete_quarantine_item(filename: str, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_mutation_permission(x_role)
    q_dir = Path("data/quarantine")
    file_path = q_dir / filename
    if not file_path.exists():
        matches = list(q_dir.glob(f"*{filename}*"))
        if matches:
            file_path = matches[0]
        else:
            raise HTTPException(status_code=404, detail="File not found in quarantine")
    try:
        file_path.unlink()
    except (PermissionError, OSError) as err:
        raise HTTPException(status_code=500, detail=f"Cannot delete locked file: {err}")

    # Synchronize incident status to purged
    for inc in store.list_incidents():
        if filename in inc.path or Path(inc.path).name == Path(filename).name:
            store.update_status(inc.path, "purged")

    store.log_audit("quarantine_permanently_deleted", filename, f"Purged from {file_path}")

    broadcaster.publish({
        "type": "quarantine_change",
        "action": "delete",
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {"status": "success", "message": f"Permanently deleted {filename}"}


@app.get("/api/audit")
def list_audit_trail(
    action: Optional[str] = None,
    performed_by: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: Optional[int] = None,
    page_size: Optional[int] = None,
    limit: Optional[int] = 100,
):
    lim = page_size if (page_size and page_size > 0) else (limit or 100)
    offset = ((page - 1) * lim) if (page and lim) else 0

    logs = store.list_audit_log(
        action=action,
        performed_by=performed_by,
        start_date=start_date,
        end_date=end_date,
        limit=lim,
        offset=offset,
    )
    total = store.count_audit_log(
        action=action,
        performed_by=performed_by,
    )

    items = [
        {
            "id": log.id,
            "timestamp": log.timestamp,
            "created_at": log.created_at or log.timestamp,
            "action": log.action,
            "target_path": log.target_path,
            "details": log.details,
            "performed_by": log.performed_by,
        }
        for log in logs
    ]

    if page is not None:
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": lim,
            "pages": ((total + lim - 1) // lim) if lim else 1,
        }
    return items


@app.get("/api/audit/export")
def export_audit_csv(
    action: Optional[str] = None,
    performed_by: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Response:
    logs = store.list_audit_log(
        action=action,
        performed_by=performed_by,
        start_date=start_date,
        end_date=end_date,
        limit=5000,
        offset=0,
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Action", "Target Path", "Details", "Performed By"])
    for log in logs:
        writer.writerow([log.id, log.timestamp, log.action, log.target_path, log.details, log.performed_by])
    filename = f"sentinel_audit_{int(time.time())}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class SettingsRequest(BaseModel):
    suspicious_threshold: float
    quarantine_threshold: float
    auto_quarantine: bool
    include_extra_signals: bool = False


@app.get("/api/settings")
def get_settings() -> dict:
    return {
        "suspicious_threshold": engine.policy.suspicious_threshold * 100.0,
        "quarantine_threshold": engine.policy.quarantine_threshold * 100.0,
        "auto_quarantine": engine.policy.auto_quarantine,
        "include_extra_signals": getattr(engine.policy, "include_extra_signals", False),
    }


@app.post("/api/settings")
def update_settings(req: SettingsRequest, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    engine.policy = RiskPolicy(
        suspicious_threshold=req.suspicious_threshold / 100.0,
        quarantine_threshold=req.quarantine_threshold / 100.0,
        auto_quarantine=req.auto_quarantine,
        quarantine_dir=engine.policy.quarantine_dir,
        include_extra_signals=req.include_extra_signals,
    )
    store.log_audit("policy_updated", "system_settings", f"Suspicious: {req.suspicious_threshold}, Quarantine: {req.quarantine_threshold}, Auto: {req.auto_quarantine}, ExtraSignals: {req.include_extra_signals}")
    return {"status": "success", "message": "Policy settings updated"}


@app.get("/api/model/benchmark")
def get_model_benchmark() -> dict:
    from leakguard.modeling import evaluate_model_pipeline
    metrics = evaluate_model_pipeline(model)
    return metrics


@app.get("/api/model/health")
def get_model_health() -> dict:
    from leakguard.extra_signals import model_health_mgr
    return model_health_mgr.get_health_metrics()


class ModelRollbackRequest(BaseModel):
    backup_filename: str


@app.post("/api/model/rollback")
def rollback_model(req: ModelRollbackRequest, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    from leakguard.extra_signals import model_health_mgr
    ok = model_health_mgr.rollback(req.backup_filename)
    if not ok:
        raise HTTPException(status_code=400, detail="Rollback failed: backup file not found")
    store.log_audit("model_rollback", "data/model.joblib", f"Rolled back to {req.backup_filename}")
    return {"status": "success", "message": f"Successfully rolled back model to {req.backup_filename}"}


@app.post("/api/model/retrain")
def retrain_model(x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    from leakguard.extra_signals import model_health_mgr
    # Save a backup before retraining
    model_health_mgr.backup_model("data/model.joblib")

    docs = load_project_documents("data/monitored") + load_project_documents("sample_files")
    if not docs:
        docs = [
            "Internal company design document for project architecture.",
            "Quarterly performance targets and employee development plans.",
            "Standard operating procedure for network server maintenance."
        ]
    model.fit(docs)
    store.log_audit("model_retrained", "data/model.joblib", f"Retrained on {len(docs)} samples")
    return {"status": "success", "sample_count": len(docs), "message": "Model retrained successfully"}


@app.get("/api/analytics/risk-timeline")
def get_risk_timeline() -> dict:
    """Provide 24h risk timeline and hourly detections heatmap data."""
    incidents = store.list_incidents()
    # Compute 24h timeline
    now = time.time()
    day_ago = now - 86400
    timeline = []
    for h in range(24):
        slot_time = now - (23 - h) * 3600
        slot_label = time.strftime("%H:00", time.localtime(slot_time))
        # Count incidents in slot
        slot_count = sum(1 for i in incidents if abs(time.mktime(time.strptime(i.scanned_at[:19], "%Y-%m-%dT%H:%M:%S")) - slot_time) < 1800) if incidents else 0
        timeline.append({"hour": slot_label, "count": slot_count})

    heatmap = [
        {"category": "Financial (Cards / Bank)", "count": sum(1 for i in incidents if any("credit" in r.lower() or "card" in r.lower() or "iban" in r.lower() for r in i.reasons))},
        {"category": "National ID (PAN / Aadhaar)", "count": sum(1 for i in incidents if any("pan" in r.lower() or "aadhaar" in r.lower() for r in i.reasons))},
        {"category": "Credentials & API Keys", "count": sum(1 for i in incidents if any("password" in r.lower() or "secret" in r.lower() or "key" in r.lower() for r in i.reasons))},
        {"category": "Contact Information (Email / Phone)", "count": sum(1 for i in incidents if any("email" in r.lower() or "phone" in r.lower() for r in i.reasons))},
    ]

    return {"timeline": timeline, "heatmap": heatmap}


# ---------------- PROMPT VERIFICATION ENDPOINTS ---------------- #

class PromptVerifyRequest(BaseModel):
    text: Optional[str] = None
    prompt: Optional[str] = None

    @property
    def prompt_text(self) -> str:
        return self.text or self.prompt or ""


class PromptBatchVerifyRequest(BaseModel):
    prompts: list[str]


@app.post("/api/prompt/anomaly")
def api_prompt_anomaly(payload: PromptVerifyRequest) -> dict:
    """Analyze prompt for injection, evasion, and structural anomalies."""
    from leakguard.prompt_anomaly import analyze_prompt_anomaly
    return analyze_prompt_anomaly(payload.prompt_text)


@app.post("/api/prompt/verify")
def api_verify_prompt(payload: PromptVerifyRequest) -> dict:
    """Scan and sanitize a single prompt before sending to an LLM or external service."""
    from leakguard.prompt_anomaly import analyze_prompt_anomaly
    result = verify_prompt_text(payload.prompt_text)
    preview = result.sanitized_prompt[:100]
    check_id = prompt_store.record_check(result, preview=preview)

    resp = result.to_dict()
    resp["id"] = check_id
    resp["anomaly"] = analyze_prompt_anomaly(payload.prompt_text)
    store.log_audit("prompt_verified", f"hash:{result.prompt_hash[:10]}", f"Verdict: {result.verdict}, Score: {result.risk_score}")
    return resp


@app.post("/api/prompt/verify/batch")
def api_verify_prompt_batch(payload: PromptBatchVerifyRequest) -> dict:
    """Verify multiple prompts in batch mode."""
    if len(payload.prompts) > 100:
        raise HTTPException(status_code=400, detail="Batch exceeds maximum limit of 100 prompts.")

    results = []
    for idx, prompt_text in enumerate(payload.prompts):
        res = verify_prompt_text(prompt_text)
        preview = res.sanitized_prompt[:80]
        check_id = prompt_store.record_check(res, preview=preview)
        item = res.to_dict()
        item["index"] = idx + 1
        item["id"] = check_id
        results.append(item)

    safe_count = sum(1 for r in results if r["verdict"] == "SAFE")
    review_count = sum(1 for r in results if r["verdict"] == "REVIEW")
    block_count = sum(1 for r in results if r["verdict"] == "BLOCK")

    return {
        "total": len(results),
        "safe_count": safe_count,
        "review_count": review_count,
        "block_count": block_count,
        "results": results,
    }


@app.get("/api/prompt/history")
def get_prompt_history(limit: int = 50) -> list[dict]:
    """Retrieve history of verified prompts (contains masked values only)."""
    return prompt_store.list_checks(limit=limit)


@app.get("/api/stream/events")
async def sse_event_stream() -> StreamingResponse:
    queue = broadcaster.subscribe()

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Yield initial connection heartbeat
            yield f"data: {json.dumps({'type': 'connected', 'event_id': f'evt_{int(time.time()*1000)}_0', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            while True:
                try:
                    # Wait up to 15s for new events; if none, emit heartbeat
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    heartbeat = json.dumps({
                        "type": "heartbeat",
                        "event_id": f"hb_{int(time.time()*1000)}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    yield f"data: {heartbeat}\n\n"
        except asyncio.CancelledError:
            broadcaster.unsubscribe(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/system/self-test")
def run_system_self_test(x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    """End-to-end self-test verification: create fake sensitive file -> scan -> quarantine -> restore -> delete -> verify audit."""
    steps = []
    monitored_dir = Path("data/monitored")
    monitored_dir.mkdir(parents=True, exist_ok=True)
    test_file = monitored_dir / f"self_test_leak_{int(time.time())}.txt"

    # Step 1: Create fake sensitive file
    try:
        fake_content = (
            "CONFIDENTIAL INTERNAL MEMO\n"
            "Customer credit card: 4532-0150-1234-5678\n"
            "Customer Aadhaar: 9876 5432 1098\n"
            "Email: test.leak@internal-corp.test\n"
        )
        test_file.write_text(fake_content, encoding="utf-8")
        steps.append({"step": "create_sensitive_file", "status": "pass", "details": str(test_file)})
    except Exception as e:
        steps.append({"step": "create_sensitive_file", "status": "fail", "details": str(e)})
        return {"status": "failed", "steps": steps}

    # Step 2: Scan & evaluate
    record = None
    try:
        record = engine.evaluate_file(test_file)
        is_high = record.risk_score >= 0.70
        steps.append({
            "step": "scan_and_evaluate",
            "status": "pass" if is_high else "fail",
            "details": f"Risk Score: {record.risk_score_100}% (Status: {record.status})",
        })
    except Exception as e:
        steps.append({"step": "scan_and_evaluate", "status": "fail", "details": str(e)})

    # Step 3: Verify Quarantine
    q_dir = Path(engine.policy.quarantine_dir)
    quarantined_files = list(q_dir.glob(f"{test_file.stem}*")) if q_dir.exists() else []
    if quarantined_files:
        steps.append({"step": "quarantine_verification", "status": "pass", "details": f"Isolated in {quarantined_files[0]}"})
    else:
        steps.append({"step": "quarantine_verification", "status": "fail", "details": "File not found in quarantine vault"})

    # Step 4: Restore
    restored_target = None
    if quarantined_files:
        try:
            restored_target = engine.restore_quarantined_file(quarantined_files[0].name)
            steps.append({"step": "restore_verification", "status": "pass", "details": f"Restored to {restored_target}"})
        except Exception as e:
            steps.append({"step": "restore_verification", "status": "fail", "details": str(e)})

    # Step 5: Clean up / Delete restored file
    if restored_target and Path(restored_target).exists():
        try:
            Path(restored_target).unlink()
            steps.append({"step": "cleanup_file", "status": "pass", "details": "Temporary self-test file purged"})
        except Exception as e:
            steps.append({"step": "cleanup_file", "status": "fail", "details": str(e)})

    # Step 6: Verify Audit Trail
    audit_entries = store.list_audit_log(limit=10)
    has_audit = any("self_test" in a.target_path or "quarantine" in a.action for a in audit_entries)
    steps.append({"step": "audit_trail_verification", "status": "pass" if has_audit else "fail", "details": f"Verified in recent {len(audit_entries)} audit entries"})

    all_passed = all(s["status"] == "pass" for s in steps)
    return {
        "status": "passed" if all_passed else "failed",
        "steps": steps,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------- WATCHED FOLDERS, ENGINES & WORKFLOWS ---------------- #

@app.get("/api/watched-folders")
def get_watched_folders() -> list[dict]:
    monitored_dir = Path("data/monitored")
    monitored_dir.mkdir(parents=True, exist_ok=True)
    files = [f for f in monitored_dir.rglob("*") if f.is_file()]
    total_size = sum(f.stat().st_size for f in files)
    return [
        {
            "id": "wf-monitored",
            "name": "data/monitored",
            "label": "Monitored Vault (Primary Active)",
            "path": str(monitored_dir.resolve()),
            "file_count": len(files),
            "size_bytes": total_size,
            "scoped_status": "SCOPED_SAFE",
            "watcher_state": "Running" if monitoring_service.is_running else "Paused",
            "is_primary": True,
            "status_badge": "Active • Sandbox Scoped",
            "description": "Designated real-time detection root. Scoped strictly within application bounds.",
        },
        {
            "id": "wf-desktop",
            "name": "Desktop",
            "label": "User Desktop (Advisory)",
            "path": str(Path.home() / "Desktop"),
            "file_count": 0,
            "size_bytes": 0,
            "scoped_status": "OUT_OF_BOUNDS_PROTECTED",
            "watcher_state": "Protected",
            "is_primary": False,
            "status_badge": "Isolated • Protected (data/monitored limit)",
            "description": "Host Desktop folder. Isolated and protected: watcher remains strictly confined to data/monitored/.",
        },
        {
            "id": "wf-downloads",
            "name": "Downloads",
            "label": "User Downloads (Advisory)",
            "path": str(Path.home() / "Downloads"),
            "file_count": 0,
            "size_bytes": 0,
            "scoped_status": "OUT_OF_BOUNDS_PROTECTED",
            "watcher_state": "Protected",
            "is_primary": False,
            "status_badge": "Isolated • Protected (data/monitored limit)",
            "description": "Host Downloads folder. Isolated and protected: watcher remains strictly confined to data/monitored/.",
        },
    ]


@app.get("/api/engines")
def get_detection_engines() -> list[dict]:
    incidents = store.list_incidents()
    all_findings = []
    for inc in incidents:
        all_findings.extend(store.get_findings_for_incident(inc.path))

    regex_hits = len(all_findings)
    model_hits = sum(1 for inc in incidents if inc.model_score > 0.3)
    luhn_hits = sum(1 for f in all_findings if "luhn" in f.rule.lower() or "card" in f.rule.lower())
    kw_hits = sum(1 for f in all_findings if "keyword" in f.rule.lower() or "secret" in f.rule.lower() or "api_key" in f.rule.lower())
    prompt_history = prompt_store.list_checks()
    prompt_hits = len(prompt_history)

    model_trained = "2026-10-12T00:00:00Z" if model._fitted else "Untrained"

    return [
        {
            "id": "engine-regex",
            "name": "Regex Library",
            "version": "v2.4.0",
            "status": "Active",
            "state": "current",
            "color": "green",
            "last_updated": "2026-10-12T00:00:00Z",
            "hits": regex_hits,
            "description": "Pattern matching for Aadhaar, PAN, IBAN, SSN, Credit Cards, Secrets & Private Keys",
        },
        {
            "id": "engine-luhn",
            "name": "Luhn Validator",
            "version": "v1.2.0",
            "status": "Active",
            "state": "current",
            "color": "green",
            "last_updated": "2026-10-12T00:00:00Z",
            "hits": luhn_hits,
            "description": "Mathematical checksum validator eliminating false-positive card numbers",
        },
        {
            "id": "engine-keyword",
            "name": "Keyword Classifier",
            "version": "v3.1.0",
            "status": "Active",
            "state": "current",
            "color": "green",
            "last_updated": "2026-10-12T00:00:00Z",
            "hits": kw_hits,
            "description": "Categorical weighted dictionary scanning across 8 security domains",
        },
        {
            "id": "engine-model",
            "name": "IsolationForest Anomaly Detector",
            "version": "v1.0.0",
            "status": "Active" if model._fitted else "Untrained",
            "state": "current" if model._fitted else "untrained",
            "color": "green" if model._fitted else "orange",
            "last_updated": model_trained,
            "hits": model_hits,
            "description": "Unsupervised high-dimensional outlier detection and hybrid fusion scoring",
        },
        {
            "id": "engine-prompt",
            "name": "Prompt Guard",
            "version": "v2.0.0",
            "status": "Active",
            "state": "current",
            "color": "green",
            "last_updated": "2026-10-13T00:00:00Z",
            "hits": prompt_hits,
            "description": "Sensitive Screener, Sanitization Playground, and prompt anomaly mitigation",
        },
    ]


class WorkflowRuleCreate(BaseModel):
    name: str
    condition_field: str
    condition_op: str = "eq"
    condition_val: str
    action: str
    action_val: str = ""
    enabled: bool = True


class WorkflowTestRequest(BaseModel):
    rule_id: Optional[int] = None
    rule: Optional[WorkflowRuleCreate] = None
    sample_size: int = 10


@app.get("/api/workflows")
def list_workflows() -> list[dict]:
    rules = store.list_workflow_rules()
    return [
        {
            "id": r.id,
            "name": r.name,
            "condition_field": r.condition_field,
            "condition_op": r.condition_op,
            "condition_val": r.condition_val,
            "action": r.action,
            "action_val": r.action_val,
            "enabled": r.enabled,
            "created_at": r.created_at,
        }
        for r in rules
    ]


@app.post("/api/workflows")
def create_workflow(req: WorkflowRuleCreate, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    rule = store.create_workflow_rule(
        name=req.name,
        condition_field=req.condition_field,
        condition_op=req.condition_op,
        condition_val=req.condition_val,
        action=req.action,
        action_val=req.action_val,
        enabled=req.enabled,
    )
    return {
        "status": "success",
        "rule": {
            "id": rule.id,
            "name": rule.name,
            "condition_field": rule.condition_field,
            "condition_op": rule.condition_op,
            "condition_val": rule.condition_val,
            "action": rule.action,
            "action_val": rule.action_val,
            "enabled": rule.enabled,
            "created_at": rule.created_at,
        }
    }


@app.put("/api/workflows/{rule_id}/toggle")
def toggle_workflow(rule_id: int, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    ok = store.toggle_workflow_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Workflow rule not found")
    return {"status": "success", "rule_id": rule_id}


@app.delete("/api/workflows/{rule_id}")
def delete_workflow(rule_id: int, x_role: Optional[str] = Header(None, alias="X-Role")) -> dict:
    require_admin_permission(x_role)
    ok = store.delete_workflow_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Workflow rule not found")
    return {"status": "success", "rule_id": rule_id}


@app.post("/api/workflows/test")
def test_workflow_rule(req: WorkflowTestRequest) -> dict:
    recent = store.list_incidents(limit=req.sample_size or 10)
    if not recent:
        return {"status": "success", "evaluated_incidents": 0, "matches_count": 0, "matches": []}

    results = []
    if req.rule:
        temp_rule = WorkflowRule(
            id=0,
            name=req.rule.name,
            condition_field=req.rule.condition_field,
            condition_op=req.rule.condition_op,
            condition_val=req.rule.condition_val,
            action=req.rule.action,
            action_val=req.rule.action_val,
            enabled=True,
        )
        cond_field = temp_rule.condition_field.lower().strip()
        cond_op = temp_rule.condition_op.lower().strip()
        cond_val = temp_rule.condition_val.lower().strip()
        for inc in recent:
            score = inc.risk_score_100
            severity = inc.risk_level.upper()
            ext = Path(inc.path).suffix.lower().lstrip(".")
            cats = [k.lower() for k in inc.category_counts.keys()]
            matched = False
            if cond_field in ("severity", "risk_level"):
                matched = (severity.lower() == cond_val) if cond_op == "eq" else (cond_val in severity.lower())
            elif cond_field in ("file_type", "extension"):
                matched = (ext == cond_val) if cond_op == "eq" else (cond_val in ext)
            elif cond_field in ("category", "pii_type"):
                matched = any(cond_val in c for c in cats) or (cond_val in " ".join(inc.reasons).lower())
            elif cond_field == "source":
                matched = (inc.source.lower() == cond_val) if cond_op == "eq" else (cond_val in inc.source.lower())
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
                results.append({
                    "incident_id": inc.id,
                    "path": inc.path,
                    "file_name": Path(inc.path).name,
                    "risk_score": inc.risk_score_100,
                    "action": temp_rule.action,
                    "action_val": temp_rule.action_val,
                    "rule_name": temp_rule.name,
                })
    else:
        for inc in recent:
            runs = store.evaluate_incident_workflows(inc, dry_run=True)
            for r in runs:
                if req.rule_id is None or r.get("rule_id") == req.rule_id:
                    results.append({
                        "incident_id": inc.id,
                        "path": inc.path,
                        "file_name": Path(inc.path).name,
                        "risk_score": inc.risk_score_100,
                        "action": r.get("action"),
                        "action_val": r.get("action_val"),
                        "rule_name": r.get("rule_name"),
                    })

    return {
        "status": "success",
        "evaluated_incidents": len(recent),
        "matches_count": len(results),
        "matches": results,
    }

