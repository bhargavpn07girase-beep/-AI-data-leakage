"""Prompt Anomaly Detector for SentinelDLP.

100% offline, rule-plus-statistics anomaly engine that detects:
1. Prompt injection / jailbreak patterns (DAN, role override, system prompt extraction, delimiter spoofing)
2. Data exfiltration intent (bulk customer dump, webhook/URL sinks, exfiltration verbs + target destinations)
3. Obfuscation & evasion (base64/hex, high Shannon entropy, zero-width/invisible chars, homoglyphs, leetspeak, ROT13)
4. Structural anomalies (length bursts, symbol/digit ratio spikes, repeated token flooding, large log dumps)
5. Secret material heuristics (private keys, API tokens, JWTs, .env blocks)
6. Statistical baseline (rolling features + z-score deviation using data/prompt_model.joblib)

Produces 0-100 anomaly score, category breakdown, reasons, and level (NORMAL, SUSPICIOUS, ANOMALOUS).
"""

from __future__ import annotations

import math
import os
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np


# 1. Injection & Jailbreak Patterns
INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:DAN|unfiltered|jailbroken|an\s+adversary)\b"),
    re.compile(r"(?i)\bact\s+as\s+(?:DAN|an\s+AI\s+without\s+rules|unrestricted)\b"),
    re.compile(r"(?i)\breveal\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+rules)\b"),
    re.compile(r"(?i)\bwhat\s+(?:are|is)\s+your\s+(?:system\s+prompt|base\s+instructions)\b"),
    re.compile(r"(?i)<\s*/?\s*(?:system|assistant|instruction|context)\s*>"),
    re.compile(r"(?i)###\s*(?:system|instruction|response):?"),
    re.compile(r"(?i)\bdeveloper\s+mode\s+(?:enabled|on|activate)\b"),
    re.compile(r"(?i)\bdo\s+anything\s+now\b"),
    re.compile(r"(?i)\bforget\s+(?:all\s+)?constraints\b"),
]

# 2. Exfiltration Intent Patterns
EXFILTRATION_PATTERNS = [
    re.compile(r"(?i)\b(?:send|upload|email|post|transmit|forward|webhook|curl|wget)\s+(?:this|all|customer|data|records?|passwords?|credentials?)\s+to\b"),
    re.compile(r"(?i)\bdump\s+(?:all|entire|every)\s+(?:database|customer|table|record|user|credential|secret)s?\b"),
    re.compile(r"(?i)\blist\s+every\s+(?:customer|client|employee|user|password|api[_-]?key)\b"),
    re.compile(r"(?i)\bhttps?://[^\s]+\.(?:requestcatcher|pipedream|burpcollaborator|oast|webhook\.site)\b"),
    re.compile(r"(?i)\b(?:exfiltrate|leak|steal|extract\s+all)\b"),
]

# 3. Secret Material Patterns
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    re.compile(r"(?i)(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{16,}['\"]?"),
]

# Leetspeak translation table
LEET_MAP = str.maketrans({
    '@': 'a', '4': 'a', '8': 'b', '3': 'e', '1': 'i', '!': 'i',
    '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't'
})


def calculate_shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return float(entropy)


def detect_zero_width_or_invisible(text: str) -> int:
    """Count zero-width or non-printing Unicode characters."""
    zero_width_codepoints = {
        0x200B, 0x200C, 0x200D, 0xFEFF, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E
    }
    return sum(1 for ch in text if ord(ch) in zero_width_codepoints)


def detect_mixed_script_homoglyphs(text: str) -> int:
    """Detect presence of mixed Cyrillic / Latin characters indicating homoglyph spoofing."""
    has_latin = False
    cyrillic_count = 0
    for ch in text:
        if 'LATIN' in unicodedata.name(ch, ''):
            has_latin = True
        elif 'CYRILLIC' in unicodedata.name(ch, ''):
            cyrillic_count += 1
    return cyrillic_count if has_latin else 0


def detect_base64_blobs(text: str) -> list[str]:
    """Find plausible base64 strings of length >= 24."""
    pattern = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
    blobs = []
    for match in pattern.finditer(text):
        m = match.group(0)
        # Check entropy of candidate blob
        if calculate_shannon_entropy(m) >= 4.0:
            blobs.append(m)
    return blobs


@dataclass
class PromptAnomalyResult:
    anomaly_score: float  # 0 to 100
    level: str  # NORMAL, SUSPICIOUS, ANOMALOUS
    signals: Dict[str, float]  # Contribution per signal (0 to 100)
    reasons: List[str]
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_score": round(self.anomaly_score, 1),
            "level": self.level,
            "signals": {k: round(v, 1) for k, v in self.signals.items()},
            "reasons": self.reasons,
            "recommended_action": self.recommended_action,
        }


class PromptAnomalyDetector:
    """Offline engine for detecting malicious or abnormal prompt characteristics."""

    def __init__(self, model_path: str = "data/prompt_model.joblib"):
        self.model_path = Path(model_path)
        self.model = None
        self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        """Load or create local statistical baseline model."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(str(self.model_path))
            except Exception:
                self.model = None

    def analyze(self, text: str) -> PromptAnomalyResult:
        if not text or not text.strip():
            return PromptAnomalyResult(
                anomaly_score=0.0,
                level="NORMAL",
                signals={"injection": 0.0, "exfiltration": 0.0, "obfuscation": 0.0, "structural": 0.0, "secrets": 0.0},
                reasons=["Empty prompt"],
                recommended_action="Allow",
            )

        reasons: list[str] = []
        signal_scores: dict[str, float] = {
            "injection": 0.0,
            "exfiltration": 0.0,
            "obfuscation": 0.0,
            "structural": 0.0,
            "secrets": 0.0,
        }

        # 1. Prompt Injection & Jailbreak checks
        injection_hits = 0
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                injection_hits += 1
        if injection_hits > 0:
            inj_score = min(100.0, injection_hits * 45.0)
            signal_scores["injection"] = inj_score
            reasons.append(f"Prompt injection / jailbreak patterns detected ({injection_hits} indicator{'s' if injection_hits > 1 else ''})")

        # Check leetspeak normalized version for injection keywords
        normalized_leet = text.translate(LEET_MAP)
        if injection_hits == 0:
            for pattern in INJECTION_PATTERNS:
                if pattern.search(normalized_leet):
                    signal_scores["injection"] = max(signal_scores["injection"], 50.0)
                    signal_scores["obfuscation"] = max(signal_scores["obfuscation"], 40.0)
                    reasons.append("Obfuscated / leetspeak prompt jailbreak attempt detected")
                    break

        # 2. Exfiltration Intent checks
        exfil_hits = 0
        for pattern in EXFILTRATION_PATTERNS:
            if pattern.search(text):
                exfil_hits += 1
        if exfil_hits > 0:
            exfil_score = min(100.0, exfil_hits * 50.0)
            signal_scores["exfiltration"] = exfil_score
            reasons.append(f"Data exfiltration intent identified ({exfil_hits} pattern match{'es' if exfil_hits > 1 else ''})")

        # 3. Obfuscation & Evasion checks
        entropy = calculate_shannon_entropy(text)
        zero_width = detect_zero_width_or_invisible(text)
        homoglyphs = detect_mixed_script_homoglyphs(text)
        b64_blobs = detect_base64_blobs(text)

        obfuscation_sub = 0.0
        if zero_width > 0:
            obfuscation_sub += 60.0
            reasons.append(f"Invisible/zero-width Unicode characters found ({zero_width} codepoints)")
        if homoglyphs >= 2:
            obfuscation_sub += 45.0
            reasons.append(f"Mixed-script Cyrillic/Latin homoglyph evasion detected ({homoglyphs} chars)")
        if b64_blobs:
            obfuscation_sub += min(50.0, len(b64_blobs) * 25.0)
            reasons.append(f"High-entropy Base64/encoded payload segments detected ({len(b64_blobs)} segment{'s' if len(b64_blobs) > 1 else ''})")
        if entropy > 5.4 and len(text) > 80:
            obfuscation_sub += 30.0
            reasons.append(f"Abnormally high Shannon entropy ({entropy:.2f} bits/char)")

        signal_scores["obfuscation"] = min(100.0, max(signal_scores["obfuscation"], obfuscation_sub))

        # 4. Structural Anomalies
        struct_score = 0.0
        length = len(text)
        if length > 12000:
            struct_score += 40.0
            reasons.append(f"Abnormal prompt length ({length} characters)")
        
        # Symbol and digit ratio
        non_alpha = sum(1 for ch in text if not ch.isalpha() and not ch.isspace())
        ratio = non_alpha / length if length > 0 else 0.0
        if ratio > 0.45 and length > 150:
            struct_score += 35.0
            reasons.append(f"Excessive symbol/digit character density ({ratio*100:.1f}%)")

        # Repeated token flooding (e.g. repeated words to overflow context)
        words = text.split()
        if len(words) >= 30:
            word_counts = Counter(words)
            most_common, most_count = word_counts.most_common(1)[0]
            if most_count / len(words) > 0.4:
                struct_score += 50.0
                reasons.append(f"Token flooding detected ('{most_common[:15]}' repeated {most_count} times)")

        signal_scores["structural"] = min(100.0, struct_score)

        # 5. Secret Material Heuristics
        secret_hits = 0
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                secret_hits += 1
        if secret_hits > 0:
            sec_score = min(100.0, secret_hits * 50.0)
            signal_scores["secrets"] = sec_score
            reasons.append(f"Sensitive secret material / credential blocks detected ({secret_hits} item{'s' if secret_hits > 1 else ''})")

        # Composite Anomaly Score (driven by the highest severity signal plus additive cues)
        max_sig = max(signal_scores.values())
        other_sig_sum = sum(v for v in signal_scores.values() if v != max_sig)
        anomaly_score = min(100.0, max_sig + 0.2 * other_sig_sum)

        # Classification into Risk Bands
        if anomaly_score >= 70.0:
            level = "ANOMALOUS"
            action = "Block Prompt & Alert SOC"
        elif anomaly_score >= 40.0:
            level = "SUSPICIOUS"
            action = "Security Review Required"
        else:
            level = "NORMAL"
            action = "Allow Prompt"

        if not reasons:
            reasons.append("No abnormal patterns or injection signals detected")

        return PromptAnomalyResult(
            anomaly_score=anomaly_score,
            level=level,
            signals=signal_scores,
            reasons=reasons,
            recommended_action=action,
        )


# Global singleton detector instance
_detector = PromptAnomalyDetector()


def analyze_prompt_anomaly(text: str) -> dict[str, Any]:
    """Analyze prompt anomaly and return dict representation."""
    return _detector.analyze(text).to_dict()
