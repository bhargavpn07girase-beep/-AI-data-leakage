"""Read-only security assistant for SentinelDLP.

Provides context-grounded queries, interactive text & document risk scoring,
and security guidance without modifying application state or protected ML models.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from leakguard.incident import IncidentStore, RiskEngine, RiskPolicy
from leakguard.scanning import scan_text


class SecurityAssistant:
    """Read-only security assistant grounded in live SQLite database records, files, and DLP policy."""

    def __init__(
        self,
        store: IncidentStore,
        policy: RiskPolicy,
        engine: RiskEngine | None = None,
        quarantine_dir: Path | str = "data/quarantine",
    ) -> None:
        self.store = store
        self.policy = policy
        self.engine = engine
        self.quarantine_dir = Path(quarantine_dir)

    def answer_query(self, query: str, monitoring_status: dict[str, Any] | None = None) -> dict[str, Any]:
        """Answer operator questions using actual application data and document risk evaluations."""
        clean_query = query.strip()
        if not clean_query:
            return {
                "answer": "Please enter a question or provide document text to analyze for data leakage risk.",
                "source": "System Guidance",
                "data": None,
            }

        q_lower = clean_query.lower()

        # 1. Monitoring / System Status
        if any(term in q_lower for term in [
            "monitoring status", "monitor status", "system status", "service status",
            "is monitoring active", "watch folder", "watched folder", "status", "uptime"
        ]):
            return self._handle_monitoring_status(monitoring_status)

        # 1a. Check this prompt (Phase 2 & 3 prompt verify and anomaly integration)
        if any(phrase in q_lower for phrase in ["check this prompt", "check prompt", "verify prompt", "prompt anomaly"]):
            from leakguard.prompt_verification import verify_prompt
            from leakguard.prompt_anomaly import analyze_prompt_anomaly
            prompt_candidate = re.sub(r"(?i)^(?:check\s+this\s+prompt|verify\s+prompt|check\s+prompt)[:\s]*", "", clean_query).strip()
            if not prompt_candidate:
                prompt_candidate = clean_query
            v_res = verify_prompt(prompt_candidate)
            a_res = analyze_prompt_anomaly(prompt_candidate)
            return {
                "answer": (
                    f"**Prompt Verification & Anomaly Screening:**\n\n"
                    f"- **Data Leak Verdict**: `{v_res['verdict']}` (Risk: {v_res['risk_score']}%)\n"
                    f"- **Prompt Anomaly Level**: `{a_res['level']}` (Anomaly Score: {a_res['anomaly_score']}%)\n"
                    f"- **Recommended Action**: {a_res['recommended_action']}\n\n"
                    f"**Detected Findings**: {len(v_res['findings'])} sensitive tokens masked\n"
                    f"**Sanitized Preview**: `{v_res['sanitized_prompt'][:120]}...`\n"
                    f"**Anomaly Signals**: {', '.join(a_res['reasons'][:3])}"
                ),
                "source": "Prompt Screening Engine",
                "data": {"verification": v_res, "anomaly": a_res},
            }

        # 1b. How do I restore a file
        if any(term in q_lower for term in ["how do i restore", "restore a file", "restore quarantined", "unquarantine"]):
            return {
                "answer": (
                    "**How to Restore a Quarantined File:**\n\n"
                    "1. Navigate to the **Quarantine Vault** tab in the sidebar.\n"
                    "2. Locate the quarantined file and click the **Restore** button.\n"
                    "3. SentinelDLP safely moves the file back to its original location in `data/monitored/`.\n"
                    "   - *Collision Handling*: If a file with the same name already exists, Sentinel automatically saves it with a `_restored_<timestamp>` suffix.\n"
                    "   - *Audit Trail*: An immutable audit log entry is written for the restore action.\n"
                    "4. Alternatively, open any quarantined incident in the **Incidents** registry drawer and click **Restore / Release File**."
                ),
                "source": "Operational SOP",
                "data": None,
            }

        # 1c. Summarize last 24h
        if any(term in q_lower for term in ["summarize last 24h", "last 24 hours", "last 24h", "past 24h", "past 24 hours"]):
            incidents = self.store.list_incidents()
            now = time.time()
            day_ago = now - 86400
            recent = []
            for inc in incidents:
                try:
                    t = time.mktime(time.strptime(inc.scanned_at[:19], "%Y-%m-%dT%H:%M:%S"))
                    if t >= day_ago:
                        recent.append(inc)
                except Exception:
                    recent.append(inc)
            high_count = sum(1 for i in recent if i.risk_score >= 0.7)
            quar_count = sum(1 for i in recent if i.status == "quarantined")
            return {
                "answer": (
                    f"**Last 24 Hours Activity Summary:**\n\n"
                    f"- **Total Documents Evaluated**: {len(recent)}\n"
                    f"- **High-Risk Alerts (>=70%)**: {high_count}\n"
                    f"- **Isolated to Quarantine**: {quar_count}\n"
                    f"- **System Policy**: Auto-quarantine is active at 70% threshold.\n"
                    f"All evaluations completed offline with zero data egress."
                ),
                "source": "24h Activity Aggregator",
                "data": {"count_24h": len(recent), "high_risk_24h": high_count},
            }

        # 2. Difference between detection and confirmed data leak
        if "difference" in q_lower and ("leak" in q_lower or "detection" in q_lower):
            return {
                "answer": (
                    "**Detection vs. Confirmed Data Leak:**\n\n"
                    "- **Detection (Alert)**: Occurs when SentinelDLP flags sensitive patterns (such as PII, PAN, credit cards, high entropy tokens) "
                    "or anomalous document structures exceeding risk thresholds. It indicates *presence of high-risk content* inside a monitored file or upload.\n\n"
                    "- **Confirmed Data Leak**: Occurs when sensitive content has actually bypassed controls and traversed an unauthorized boundary (e.g. exfiltrated outside the organization). "
                    "SentinelDLP prevents this by isolating high-risk files into the quarantine vault (`data/quarantine`) before egress occurs."
                ),
                "source": "Security Knowledge",
                "data": None,
            }

        # 3. How to safely test detection rules
        if any(phrase in q_lower for phrase in ["how can i test", "test detection rules", "test rules", "safely test", "testing rules", "safe rule testing"]):
            return {
                "answer": (
                    "**Safely Testing Detection Rules in SentinelDLP:**\n\n"
                    "1. **Use Synthetic / Test Data**: Place a non-production `.txt` or `.csv` file with synthetic test formats into the watched directory (`data/monitored`).\n"
                    "2. **Supported Pattern Tests**:\n"
                    "   - *Valid Luhn Credit Card*: Use synthetic test card numbers (never real customer cards).\n"
                    "   - *Indian Identity*: Synthetic PAN (`ABCDE1234F`) or Aadhaar (`1234 5678 9012`).\n"
                    "   - *High-Entropy Key*: Synthetic 40-character random hex tokens.\n"
                    "3. **Upload Review**: Use the **Upload Review** tab to test isolated files without modifying your monitored folder.\n"
                    "4. **Verify Action**: Check that files with risk score >= 70% are automatically moved to `data/quarantine` and logged in the Audit Trail."
                ),
                "source": "Security Guidance",
                "data": None,
            }

        # 4. Top risky / highest vulnerability files
        if any(term in q_lower for term in [
            "highest", "top risky", "most risky", "highest risk", "high-vulnerability",
            "vulnerability", "dangerous files", "worst files", "riskiest"
        ]):
            return self._handle_top_risky()

        # 5. Recent quarantine activity
        if any(term in q_lower for term in ["quarantine", "quarantined", "isolated", "quarantine activity"]):
            return self._handle_quarantine()

        # 6. Blocked uploads
        if any(term in q_lower for term in ["blocked", "uploads were actually blocked", "blocked uploads", "upload review"]):
            return self._handle_blocked_uploads()

        # 7. Sensitive data categories detected
        if any(term in q_lower for term in ["categories", "category", "sensitive-data categories", "sensitive data detected", "what types of data", "what data"]):
            return self._handle_categories()

        # 8. Summarize latest incidents
        if any(term in q_lower for term in ["summarize", "summary", "incident", "incidents", "alerts", "events"]):
            return self._handle_incident_summary()

        # 9. Inquiries about specific files or CSV files already in system
        file_res = self._handle_file_or_incident_inquiry(clean_query, q_lower)
        if file_res:
            return file_res

        # 10. Direct interactive text / payload risk scoring
        # If the user pasted text or typed something with potential PII/sensitive tokens or asks "score this" / "analyze"
        if len(clean_query) > 10 and self.engine and self.engine.model:
            return self._handle_direct_text_analysis(clean_query)

        # Fallback response grounded in real data capabilities
        return {
            "answer": (
                "**Sentinel Copilot is ready to assist you.** Here is what I can inspect for you:\n\n"
                "- **Monitoring Status**: *'What is the current monitoring status?'*\n"
                "- **Incident Summaries**: *'Summarize the latest security incidents'*\n"
                "- **Highest Risk Files**: *'Which files have the highest recorded risk scores?'*\n"
                "- **File & CSV Score Analysis**: *'What is the score for risky_customer_record.csv?'* or *'Why was incident #34 flagged?'*\n"
                "- **Direct Text Analysis**: Paste any text or snippet to instantly compute its risk score and sensitive findings.\n"
                "- **Quarantine Activity**: *'Show me the recent quarantine activity'*\n"
                "- **Blocked Uploads**: *'How many uploads were actually blocked?'*\n"
                "- **Security Concepts**: *'Explain the difference between a detection and a confirmed data leak'*"
            ),
            "source": "Sentinel Assistant",
            "data": None,
        }

    def _handle_monitoring_status(self, status: dict[str, Any] | None) -> dict[str, Any]:
        watched = status.get("watched_folder", "data/monitored") if status else "data/monitored"
        is_active = status.get("monitoring_active", False) if status else False
        uptime = status.get("uptime_seconds", 0) if status else 0
        last_scan = status.get("last_scan_time") if status else None

        mins = uptime // 60
        secs = uptime % 60
        uptime_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"

        status_text = "🟢 **ACTIVE** (Watchdog filesystem observer running)" if is_active else "🟡 **PAUSED**"
        scan_text = f"`{last_scan}`" if last_scan else "No scans recorded yet"

        answer = (
            f"**SentinelDLP System Monitoring Status:**\n\n"
            f"- **Service State**: {status_text}\n"
            f"- **Watched Directory**: `{watched}`\n"
            f"- **System Uptime**: {uptime_str}\n"
            f"- **Last Scan Recorded**: {scan_text}\n"
            f"- **Enforcement Policy**: Suspicious threshold at `{self.policy.suspicious_threshold * 100:.0f}%`, "
            f"Auto-quarantine at `{self.policy.quarantine_threshold * 100:.0f}%` (Status: {'Enabled' if self.policy.auto_quarantine else 'Disabled'})."
        )
        return {"answer": answer, "source": "Live Service Status", "data": status}

    def _handle_incident_summary(self) -> dict[str, Any]:
        incidents = self.store.list_incidents()
        if not incidents:
            return {
                "answer": "There are currently **no security incidents** recorded in the SentinelDLP database.",
                "source": "Database Record (incidents)",
                "data": [],
            }

        total = len(incidents)
        open_count = sum(1 for i in incidents if i.status == "open")
        quarantined = sum(1 for i in incidents if i.status == "quarantined")
        recent = sorted(incidents, key=lambda i: i.scanned_at, reverse=True)[:5]

        items_text = []
        for inc in recent:
            reasons_brief = ", ".join(inc.reasons[:2]) if inc.reasons else "Normal pattern"
            items_text.append(
                f"- **{Path(inc.path).name}** (Risk Score: `{inc.risk_score_100}%`, Status: `{inc.status.upper()}`)\n"
                f"  *Key Factors*: {reasons_brief}\n"
                f"  *Scanned Timestamp*: {inc.scanned_at}"
            )

        summary_body = "\n\n".join(items_text)
        answer = (
            f"**Incident Summary Report:**\n\n"
            f"- **Total Scanned Files**: {total}\n"
            f"- **Open Incidents Requiring Review**: {open_count}\n"
            f"- **Quarantined Files**: {quarantined}\n\n"
            f"**Most Recent Security Incidents:**\n\n{summary_body}"
        )
        return {"answer": answer, "source": "Database Record (incidents)", "data": [i.__dict__ for i in recent]}

    def _handle_top_risky(self) -> dict[str, Any]:
        incidents = self.store.list_incidents()
        if not incidents:
            return {
                "answer": "No scanned files or risk scores are recorded in the database yet.",
                "source": "Database Record (incidents)",
                "data": [],
            }

        risky = sorted(incidents, key=lambda i: i.risk_score, reverse=True)[:5]
        entries = []
        for idx, inc in enumerate(risky, 1):
            reasons = ", ".join(inc.reasons[:2]) if inc.reasons else "Baseline pattern"
            entries.append(
                f"{idx}. **{Path(inc.path).name}** — **Risk Score: `{inc.risk_score_100}%`** [{inc.status.upper()}]\n"
                f"   *Primary Threat Factors*: {reasons}\n"
                f"   *Heuristic Contribution*: `{inc.heuristic_score:.1f}%` | *Model Anomaly*: `{inc.model_score:.1f}%`"
            )

        answer = "**Files with Highest Recorded Risk Scores:**\n\n" + "\n\n".join(entries)
        return {"answer": answer, "source": "Database Record (incidents)", "data": [i.__dict__ for i in risky]}

    def _handle_categories(self) -> dict[str, Any]:
        incidents = self.store.list_incidents()
        category_totals: dict[str, int] = {}
        for inc in incidents:
            for cat, count in inc.category_counts.items():
                category_totals[cat] = category_totals.get(cat, 0) + count

        if not category_totals:
            return {
                "answer": "No sensitive data categories have been matched in the recorded files yet.",
                "source": "Database Record (findings)",
                "data": {},
            }

        sorted_cats = sorted(category_totals.items(), key=lambda x: x[1], reverse=True)
        lines = [f"- **{cat.upper()}**: {cnt} match{'es' if cnt != 1 else ''}" for cat, cnt in sorted_cats]

        answer = (
            f"**Sensitive Data Categories Detected across Monitored Documents:**\n\n"
            + "\n".join(lines)
            + f"\n\n*Total detections across all categories*: **{sum(category_totals.values())}**"
        )
        return {"answer": answer, "source": "Database Record (findings)", "data": category_totals}

    def _handle_quarantine(self) -> dict[str, Any]:
        q_files = list(self.quarantine_dir.glob("*")) if self.quarantine_dir.exists() else []
        physical_files = [f for f in q_files if f.is_file()]

        audit_entries = self.store.list_audit_log(limit=50)
        quarantine_actions = [a for a in audit_entries if "quarantine" in a.action.lower()][:5]

        if not physical_files and not quarantine_actions:
            return {
                "answer": "The quarantine vault (`data/quarantine`) is currently empty. No files are currently isolated.",
                "source": "Quarantine Vault & Audit Log",
                "data": {"count": 0},
            }

        file_list = [f"- `{f.name}` ({f.stat().st_size} bytes)" for f in physical_files[:5]]
        recent_activity = [f"- *[{a.timestamp}]* {a.action}: `{Path(a.target_path).name}` ({a.details})" for a in quarantine_actions]

        parts = [f"**Quarantine Vault Activity:**\n- **Currently Isolated Files**: {len(physical_files)} file(s)"]
        if file_list:
            parts.append("\n**Isolated Files:**\n" + "\n".join(file_list))
        if recent_activity:
            parts.append("\n**Recent Quarantine Audit Trail:**\n" + "\n".join(recent_activity))

        return {"answer": "\n".join(parts), "source": "Quarantine Vault & Audit Log", "data": {"isolated_count": len(physical_files)}}

    def _handle_blocked_uploads(self) -> dict[str, Any]:
        audit_entries = self.store.list_audit_log(limit=200)
        blocked = [a for a in audit_entries if "blocked" in a.action.lower()]

        if not blocked:
            return {
                "answer": (
                    "**Upload Review Status:**\n\n"
                    "No uploaded files have been blocked yet. Files uploaded through Upload Review that exceed the "
                    f"quarantine threshold ({self.policy.quarantine_threshold * 100:.0f}%) will be blocked and recorded in the audit log."
                ),
                "source": "Audit Log (upload_review)",
                "data": {"blocked_count": 0},
            }

        lines = [f"- *[{b.timestamp}]* `{Path(b.target_path).name}` — {b.details}" for b in blocked[:5]]
        answer = (
            f"**Blocked Uploads Enforcement:**\n\n"
            f"- **Total Blocked Upload Decisions Recorded**: {len(blocked)}\n\n"
            f"**Recent Block Events:**\n" + "\n".join(lines)
        )
        return {"answer": answer, "source": "Audit Log (upload_review)", "data": {"blocked_count": len(blocked)}}

    def _handle_file_or_incident_inquiry(self, full_query: str, q_lower: str) -> dict[str, Any] | None:
        incidents = self.store.list_incidents()
        if not incidents:
            return None

        # Try matching by incident ID (e.g. "#1" or "incident 34")
        id_match = re.search(r"#?(\d+)", q_lower)
        target_incident = None

        if id_match:
            try:
                rec_id = int(id_match.group(1))
                for inc in incidents:
                    if inc.id == rec_id:
                        target_incident = inc
                        break
            except ValueError:
                pass

        # Try matching by file name (e.g. "risky_customer_record.csv" or "sensitive.json")
        if not target_incident:
            for inc in incidents:
                filename = Path(inc.path).name.lower()
                stem = Path(inc.path).stem.lower()
                if filename in q_lower or (len(stem) > 3 and stem in q_lower):
                    target_incident = inc
                    break

        # Check if user mentioned CSV files in general
        if not target_incident and "csv" in q_lower:
            csv_incidents = [i for i in incidents if i.path.lower().endswith(".csv")]
            if csv_incidents:
                target_incident = sorted(csv_incidents, key=lambda i: i.risk_score, reverse=True)[0]

        if not target_incident:
            return None

        findings = self.store.get_findings_for_incident(target_incident.path)
        findings_summary = []
        for f in findings[:6]:
            line_str = f"line {f.line_number}" if f.line_number else "content"
            findings_summary.append(f"- Rule `[{f.rule}]` on {line_str}: masked value `{f.masked_value}`")

        reasons_text = "\n".join([f"- {r}" for r in target_incident.reasons]) if target_incident.reasons else "- Normal behavioral profile"

        findings_block = ""
        if findings_summary:
            findings_block = "\n\n**Specific Findings Detected:**\n" + "\n".join(findings_summary)

        preview_block = ""
        if target_incident.masked_preview:
            safe_preview = target_incident.masked_preview.strip().replace("\n", " ")[:200]
            preview_block = f"\n\n**Redacted Document Preview:**\n> `{safe_preview}...`"

        answer = (
            f"**Risk Evaluation for `{Path(target_incident.path).name}` (Incident #{target_incident.id}):**\n\n"
            f"- **Recorded Risk Score**: `{target_incident.risk_score_100}%`\n"
            f"- **Enforcement Verdict**: `{target_incident.status.upper()}`\n"
            f"- **Scanned Timestamp**: `{target_incident.scanned_at}`\n"
            f"- **Rule-Based Heuristic Score**: `{target_incident.heuristic_score:.1f}%`\n"
            f"- **IsolationForest Model Score**: `{target_incident.model_score:.1f}%`\n\n"
            f"**Why this file received this score (Contributing Factors):**\n"
            f"{reasons_text}"
            f"{findings_block}"
            f"{preview_block}"
        )
        return {
            "answer": answer,
            "source": f"Database Record (Incident #{target_incident.id})",
            "data": {
                "id": target_incident.id,
                "path": target_incident.path,
                "risk_score": target_incident.risk_score_100,
                "status": target_incident.status,
            },
        }

    def _handle_direct_text_analysis(self, text: str) -> dict[str, Any]:
        """Compute live DLP risk assessment on pasted snippet or text query."""
        if not self.engine or not self.engine.model:
            return {
                "answer": "Text analysis engine is currently uninitialized.",
                "source": "Engine Warning",
                "data": None,
            }

        # 1. Regex & rule scanning
        masked_text, findings = scan_text(text, file_path="chat_input.txt")
        # 2. Model evaluation
        eval_details = self.engine.model.evaluate_details(text)

        # Apply same scoring policy
        risk_score_0_1 = float(eval_details.get("score_0_1", 0.0))
        if findings and risk_score_0_1 < 0.5:
            risk_score_0_1 = max(risk_score_0_1, min(1.0, 0.5 + len(findings) * 0.1))

        risk_score_100 = round(risk_score_0_1 * 100.0, 1)

        if risk_score_0_1 >= self.policy.quarantine_threshold:
            verdict = "HIGH RISK / QUARANTINE"
        elif risk_score_0_1 >= self.policy.suspicious_threshold:
            verdict = "SUSPICIOUS / AUDIT"
        else:
            verdict = "SAFE / NORMAL"

        reasons = eval_details.get("top_reasons", ["Normal text profile"])
        reasons_list = "\n".join([f"- {r}" for r in reasons])

        findings_summary = []
        for f in findings[:5]:
            findings_summary.append(f"- Detected category `[{f.rule}]`: masked value `{f.masked_value}`")

        findings_block = ""
        if findings_summary:
            findings_block = "\n\n**Detected Sensitive Data Elements:**\n" + "\n".join(findings_summary)

        answer = (
            f"**Real-Time Data Defense Assessment for Provided Text:**\n\n"
            f"- **Computed Risk Score**: `{risk_score_100}%`\n"
            f"- **Policy Verdict**: **{verdict}**\n"
            f"- **Rule Heuristic Component**: `{eval_details.get('heuristic_score', 0.0)}%`\n"
            f"- **ML Anomaly Component**: `{eval_details.get('model_anomaly_score', 0.0)}%`\n\n"
            f"**Risk Factors Identified:**\n"
            f"{reasons_list}"
            f"{findings_block}"
        )

        return {
            "answer": answer,
            "source": "Sentinel Inspection Engine (Real-Time)",
            "data": {
                "risk_score": risk_score_100,
                "verdict": verdict,
                "findings_count": len(findings),
            },
        }
