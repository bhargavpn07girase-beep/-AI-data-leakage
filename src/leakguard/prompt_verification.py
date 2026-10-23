"""Sensitive data detection and sanitization for prompts before sending to AI models.

100% offline, privacy-preserving detector that identifies PII, financial identifiers,
credentials, and confidential patterns, producing a sanitized prompt with typed
placeholders such as [CREDIT_CARD], [EMAIL], [AADHAAR], [API_KEY].
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from leakguard.scanning import (
    DEFAULT_RULES,
    is_luhn_valid,
    mask_sensitive_value,
    ContentFinding,
)

# Standard detection patterns aligned with SentinelDLP rules
PATTERNS = {
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "aadhaar": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "pan_card": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3}[-.\s]?\d{4}"),
}

KEYWORD_WEIGHTS = {
    "CONFIDENTIAL": 0.8,
    "RESTRICTED": 0.7,
    "INTERNAL ONLY": 0.6,
    "SECRET": 0.7,
    "PRIVATE KEY": 0.9,
    "PASSWORD": 0.8,
    "API KEY": 0.8,
}


# Extended credential & secret patterns specifically for prompt security
EXTRA_SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
    "api_key_assignment": re.compile(r"""(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.]{16,})['"]?"""),
    "password_assignment": re.compile(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?"""),
    "aws_access_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "jwt_token": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
}


@dataclass(frozen=True)
class PromptFinding:
    rule: str
    masked_value: str
    start: int
    end: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    reason: str


@dataclass(frozen=True)
class PromptVerificationResult:
    verdict: str  # SAFE, REVIEW, BLOCK
    risk_score: float  # 0 to 100
    sanitized_prompt: str
    findings: list[PromptFinding]
    prompt_hash: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        reasons: list[str] = []
        if self.findings:
            reasons = list(dict.fromkeys(f.reason for f in self.findings if f.reason))
        elif self.verdict == "SAFE":
            reasons = ["Clean prompt: no sensitive identifiers or confidential terms detected."]
        return {
            "verdict": self.verdict,
            "risk_score": round(self.risk_score, 1),
            "sanitized_prompt": self.sanitized_prompt,
            "reasons": reasons,
            "findings": [
                {
                    "rule": f.rule,
                    "masked_value": f.masked_value,
                    "start": f.start,
                    "end": f.end,
                    "severity": f.severity,
                    "reason": f.reason,
                }
                for f in self.findings
            ],
            "prompt_hash": self.prompt_hash,
            "timestamp": self.timestamp,
        }


RULE_PLACEHOLDERS = {
    "credit_card": "[CREDIT_CARD]",
    "aadhaar": "[AADHAAR]",
    "pan_card": "[PAN_CARD]",
    "iban": "[IBAN]",
    "email": "[EMAIL]",
    "phone": "[PHONE_NUMBER]",
    "private_key": "[PRIVATE_KEY_BLOCK]",
    "api_key_assignment": "[API_KEY]",
    "password_assignment": "[PASSWORD]",
    "aws_access_key": "[AWS_KEY]",
    "jwt_token": "[JWT_TOKEN]",
    "confidential_keyword": "[CONFIDENTIAL_TERM]",
}


def verify_prompt_text(text: str) -> PromptVerificationResult:
    """Scan prompt text, detect sensitive elements, compute score, and produce sanitized string."""
    if not text or not text.strip():
        h = hashlib.sha256(b"").hexdigest()
        return PromptVerificationResult(
            verdict="SAFE",
            risk_score=0.0,
            sanitized_prompt="",
            findings=[],
            prompt_hash=h,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    findings: list[PromptFinding] = []
    spans_to_replace: list[tuple[int, int, str]] = []

    # 1. Regex checks from standard pattern library
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            raw_val = match.group(0)
            if rule == "credit_card":
                clean_digits = re.sub(r"\D", "", raw_val)
                if not is_luhn_valid(clean_digits):
                    continue
                masked = mask_sensitive_value("credit_card", raw_val)
                findings.append(PromptFinding(
                    rule=rule,
                    masked_value=masked,
                    start=match.start(),
                    end=match.end(),
                    severity="CRITICAL",
                    reason="Valid credit card number validated with Luhn checksum",
                ))
                spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[REDACTED]")))
            elif rule == "aadhaar":
                masked = mask_sensitive_value("aadhaar", raw_val)
                findings.append(PromptFinding(
                    rule=rule,
                    masked_value=masked,
                    start=match.start(),
                    end=match.end(),
                    severity="HIGH",
                    reason="Indian Aadhaar 12-digit national identifier",
                ))
                spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[REDACTED]")))
            elif rule == "pan_card":
                masked = mask_sensitive_value("pan", raw_val)
                findings.append(PromptFinding(
                    rule=rule,
                    masked_value=masked,
                    start=match.start(),
                    end=match.end(),
                    severity="HIGH",
                    reason="Indian Permanent Account Number (PAN)",
                ))
                spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[REDACTED]")))
            elif rule == "iban":
                masked = mask_sensitive_value("iban", raw_val)
                findings.append(PromptFinding(
                    rule=rule,
                    masked_value=masked,
                    start=match.start(),
                    end=match.end(),
                    severity="HIGH",
                    reason="International Bank Account Number (IBAN)",
                ))
                spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[REDACTED]")))
            elif rule == "email":
                masked = mask_sensitive_value("email", raw_val)
                findings.append(PromptFinding(
                    rule=rule,
                    masked_value=masked,
                    start=match.start(),
                    end=match.end(),
                    severity="MEDIUM",
                    reason="Email address exposure",
                ))
                spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[REDACTED]")))
            elif rule == "phone":
                masked = mask_sensitive_value("phone", raw_val)
                findings.append(PromptFinding(
                    rule=rule,
                    masked_value=masked,
                    start=match.start(),
                    end=match.end(),
                    severity="LOW",
                    reason="Phone number contact pattern",
                ))
                spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[REDACTED]")))

    # 2. Extra secret & credential patterns
    for rule, pattern in EXTRA_SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            raw_val = match.group(0)
            masked = f"{raw_val[:4]}...[SECRET]...{raw_val[-3:]}" if len(raw_val) > 10 else "[MASKED_CREDENTIAL]"
            findings.append(PromptFinding(
                rule=rule,
                masked_value=masked,
                start=match.start(),
                end=match.end(),
                severity="CRITICAL",
                reason=f"Credential exposure ({rule.replace('_', ' ')})",
            ))
            spans_to_replace.append((match.start(), match.end(), RULE_PLACEHOLDERS.get(rule, "[SECRET]")))

    # 3. Confidential keyword detections
    upper_text = text.upper()
    for kw, weight in KEYWORD_WEIGHTS.items():
        pos = 0
        while True:
            idx = upper_text.find(kw, pos)
            if idx == -1:
                break
            # Boundary check
            is_start = idx == 0 or not upper_text[idx - 1].isalnum()
            is_end = (idx + len(kw) == len(upper_text)) or not upper_text[idx + len(kw)].isalnum()
            if is_start and is_end:
                findings.append(PromptFinding(
                    rule="confidential_keyword",
                    masked_value=kw,
                    start=idx,
                    end=idx + len(kw),
                    severity="MEDIUM" if weight >= 0.5 else "LOW",
                    reason=f"Restricted classification keyword '{kw}'",
                ))
                spans_to_replace.append((idx, idx + len(kw), RULE_PLACEHOLDERS["confidential_keyword"]))
            pos = idx + len(kw)

    # 4. Construct sanitized prompt by replacing spans from right to left
    # Deduplicate overlapping spans, prioritizing longer spans (e.g. credit card 16 digits over aadhaar 12 digits)
    spans_to_replace.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    non_overlapping = []
    last_end = -1
    for start, end, placeholder in spans_to_replace:
        if start >= last_end:
            non_overlapping.append((start, end, placeholder))
            last_end = end

    # Replace from back to keep index integrity
    sanitized_chars = list(text)
    for start, end, placeholder in reversed(non_overlapping):
        sanitized_chars[start:end] = list(placeholder)
    sanitized_prompt = "".join(sanitized_chars)

    # 5. Score calculation (0 to 100)
    score = 0.0
    for f in findings:
        if f.severity == "CRITICAL":
            score += 45.0
        elif f.severity == "HIGH":
            score += 30.0
        elif f.severity == "MEDIUM":
            score += 15.0
        elif f.severity == "LOW":
            score += 5.0
    risk_score = min(100.0, score)

    # Risk band mapping
    if risk_score >= 70.0:
        verdict = "BLOCK"
    elif risk_score >= 30.0:
        verdict = "REVIEW"
    else:
        verdict = "SAFE"

    prompt_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    return PromptVerificationResult(
        verdict=verdict,
        risk_score=risk_score,
        sanitized_prompt=sanitized_prompt,
        findings=findings,
        prompt_hash=prompt_hash,
        timestamp=timestamp,
    )


class PromptHistoryStore:
    """Store prompt verification audit entries locally in SQLite without storing raw text."""

    def __init__(self, db_path: str | Path = "data/leakguard.db") -> None:
        self.db_path = Path(db_path)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS prompt_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prompt_hash TEXT NOT NULL,
                    prompt_preview TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    findings_count INTEGER NOT NULL,
                    reasons TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prompt_checks_hash ON prompt_checks(prompt_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prompt_checks_time ON prompt_checks(created_at DESC)")
            conn.commit()

    def record_check(self, result: PromptVerificationResult, preview: str = "") -> int:
        reasons_list = [f.reason for f in result.findings[:4]]
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prompt_checks (prompt_hash, prompt_preview, verdict, risk_score, findings_count, reasons, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.prompt_hash,
                    preview[:120],
                    result.verdict,
                    result.risk_score,
                    len(result.findings),
                    "; ".join(reasons_list),
                    result.timestamp,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def list_checks(self, limit: int = 50) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, prompt_hash, prompt_preview, verdict, risk_score, findings_count, reasons, created_at FROM prompt_checks ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r[0],
                "prompt_hash": r[1],
                "prompt_preview": r[2],
                "verdict": r[3],
                "risk_score": r[4],
                "findings_count": r[5],
                "reasons": r[6],
                "created_at": r[7],
            }
            for r in rows
        ]


def verify_prompt(text: str) -> dict[str, Any]:
    """Helper alias returning a dictionary representation of prompt verification."""
    return verify_prompt_text(text).to_dict()

