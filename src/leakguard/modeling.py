"""Real anomaly-scoring pipeline for sensitive-document detection with persistence and reason breakdown."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Dict, List, Tuple, Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from leakguard.scanning import DEFAULT_RULES, is_luhn_valid


EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_PATTERN = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3}[-.\s]?\d{4}")
URL_PATTERN = re.compile(r"https?://[^\s\"<>]+|www\.[^\s\"<>]+", re.IGNORECASE)
PLACEHOLDER_PATTERN = re.compile(r"<(?:ID_NUM|USERNAME|NAME|EMAIL|PHONE_NUM|ADDRESS|URL)>", re.IGNORECASE)
ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9.\- ]+\b(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Parkway|Pkwy|Court|Ct|Place)\b",
    re.IGNORECASE,
)

NAME_PATTERN = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b")
KEYWORD_PATTERN = re.compile(
    r"\b(confidential|restricted|internal\s+only|top\s+secret|password|secret|api[_\s]?key|private[_\s]?key|ssn|credit\s+card|payroll|patient\s+record)\b",
    re.IGNORECASE,
)

PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b")
AADHAAR_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def _calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _normalize_text(text: str) -> str:
    return " ".join(text.split())


def _extract_risk_features(text: str) -> dict[str, float]:
    normalized = _normalize_text(text)
    length = float(len(normalized))
    word_count = float(len(re.findall(r"\b\w+\b", normalized)))
    digit_count = float(sum(c.isdigit() for c in normalized))
    digit_ratio = (digit_count / length) if length > 0 else 0.0
    entropy = _calculate_entropy(text)

    email_count = float(len(EMAIL_PATTERN.findall(normalized)))
    phone_count = float(len(PHONE_PATTERN.findall(normalized)))
    url_count = float(len(URL_PATTERN.findall(normalized)))
    placeholder_count = float(len(PLACEHOLDER_PATTERN.findall(normalized)))
    address_count = float(len(ADDRESS_PATTERN.findall(normalized)))
    name_count = float(len(NAME_PATTERN.findall(normalized)))
    keyword_count = float(len(KEYWORD_PATTERN.findall(normalized)))
    pan_count = float(len(PAN_PATTERN.findall(normalized)))
    aadhaar_count = float(len(AADHAAR_PATTERN.findall(normalized)))
    iban_count = float(len(IBAN_PATTERN.findall(normalized)))

    # Credit card counts
    cc_count = 0.0
    for match in re.finditer(r'\b(?:\d[ -]*?){13,19}\b', text):
        digits = re.sub(r'\D', '', match.group(0))
        if 13 <= len(digits) <= 19 and is_luhn_valid(digits):
            cc_count += 1.0

    return {
        "email_count": email_count,
        "phone_count": phone_count,
        "url_count": url_count,
        "placeholder_count": placeholder_count,
        "address_count": address_count,
        "name_count": name_count,
        "keyword_count": keyword_count,
        "pan_count": pan_count,
        "aadhaar_count": aadhaar_count,
        "iban_count": iban_count,
        "cc_count": cc_count,
        "word_count": word_count,
        "text_length": length,
        "entropy": entropy,
        "digit_ratio": digit_ratio,
    }


def _feature_vector(features: dict[str, float]) -> np.ndarray:
    ordered = [
        features["email_count"],
        features["phone_count"],
        features["url_count"],
        features["placeholder_count"],
        features["address_count"],
        features["name_count"],
        features["keyword_count"],
        features["pan_count"],
        features["aadhaar_count"],
        features["iban_count"],
        features["cc_count"],
        features["word_count"],
        features["text_length"],
        features["entropy"],
        features["digit_ratio"],
    ]
    return np.asarray(ordered, dtype=float).reshape(1, -1)


def _parse_text_payload(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            items.extend(_parse_text_payload(item))
        return items
    if isinstance(value, dict):
        texts: list[str] = []
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in {"text", "content", "message", "prompt", "question", "body"}:
                texts.extend(_parse_text_payload(item))
            else:
                texts.extend(_parse_text_payload(item))
        return texts
    return []


def load_document_texts(path: str | Path, max_records: int = 50) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        return []

    if file_path.suffix.lower() == ".jsonl":
        records: list[str] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        records.append(line.strip())
                        continue
                    records.extend(_parse_text_payload(payload))
                    if len(records) >= max_records:
                        break
        except Exception:
            pass
        return records

    if file_path.suffix.lower() == ".json":
        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return [file_path.read_text(encoding="utf-8", errors="replace")[:10000]]
        return _parse_text_payload(payload)[:max_records]

    return [file_path.read_text(encoding="utf-8", errors="replace")[:10000]]


def load_project_documents(data_dir: str | Path) -> list[str]:
    root = Path(data_dir)
    if not root.exists():
        return []

    documents: list[str] = []
    for file_path in sorted(root.rglob("*")):
        if file_path.is_file() and file_path.suffix.lower() in {".json", ".jsonl", ".txt", ".csv", ".log", ".md"}:
            documents.extend(load_document_texts(file_path))
    return documents


class LeakRiskModel:
    """Detect risky or anomalous document content using Isolation Forest over document features."""

    def __init__(self, *, contamination: float = 0.1, random_state: int = 42, threshold: float = 0.5, model_path: str | Path = "data/model.joblib") -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.threshold = threshold
        self.model_path = Path(model_path)
        self.model = IsolationForest(contamination=contamination, random_state=random_state)
        self._fitted = False

        # Attempt to load saved model if present
        if self.model_path.exists():
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, IsolationForest):
                    self.model = loaded
                    self._fitted = True
            except Exception:
                pass

    def save(self) -> None:
        if self._fitted:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, self.model_path)

    def fit(self, texts: list[str]) -> "LeakRiskModel":
        if not texts:
            raise ValueError("At least one text sample is required for fitting")

        matrix = np.vstack([_feature_vector(_extract_risk_features(text)) for text in texts])
        self.model.fit(matrix)
        self._fitted = True
        self.save()
        return self

    def fit_project_data(self, data_dir: str | Path = "data/monitored/datasets") -> "LeakRiskModel":
        documents = load_project_documents(data_dir)
        if not documents:
            raise FileNotFoundError(f"No project dataset files found under: {data_dir}")
        return self.fit(documents)

    def evaluate_details(self, text: str) -> dict[str, Any]:
        """Compute comprehensive score, breakdown (heuristic vs model), and contributing reasons."""
        if not self._fitted:
            # Provide baseline fit if uninitialized
            self.fit([
                "Internal routine status update and sprint planning notes.",
                "Public documentation regarding API usage and configuration setup.",
                "Weekly team calendar for engineering design discussions."
            ])

        features = _extract_risk_features(text)
        vector = _feature_vector(features)
        decision = float(self.model.decision_function(vector)[0])

        reasons: list[dict[str, Any]] = []

        # Heuristic scoring components
        email_contrib = min(40.0, features["email_count"] * 35.0)
        phone_contrib = min(35.0, features["phone_count"] * 35.0)

        cc_contrib = min(50.0, features["cc_count"] * 50.0)
        pan_contrib = min(40.0, features["pan_count"] * 40.0)
        aadhaar_contrib = min(40.0, features["aadhaar_count"] * 40.0)
        iban_contrib = min(35.0, features["iban_count"] * 35.0)
        kw_contrib = min(30.0, features["keyword_count"] * 15.0)
        entropy_contrib = 15.0 if features["entropy"] > 4.5 else 0.0
        digit_contrib = 15.0 if features["digit_ratio"] > 0.35 else 0.0

        if features["email_count"] > 0:
            reasons.append({"factor": "Email addresses detected", "weight": round(email_contrib, 1)})
        if features["phone_count"] > 0:
            reasons.append({"factor": "Phone numbers detected", "weight": round(phone_contrib, 1)})
        if features["cc_count"] > 0:
            reasons.append({"factor": "Valid Credit Card (Luhn checked)", "weight": round(cc_contrib, 1)})
        if features["pan_count"] > 0:
            reasons.append({"factor": "PAN Card Number detected", "weight": round(pan_contrib, 1)})
        if features["aadhaar_count"] > 0:
            reasons.append({"factor": "Aadhaar Identity Number detected", "weight": round(aadhaar_contrib, 1)})
        if features["iban_count"] > 0:
            reasons.append({"factor": "IBAN Bank Account detected", "weight": round(iban_contrib, 1)})
        if features["keyword_count"] > 0:
            reasons.append({"factor": "Confidential / Restricted Keywords", "weight": round(kw_contrib, 1)})
        if features["entropy"] > 4.5:
            reasons.append({"factor": "High Text Entropy (potential secret/key)", "weight": round(entropy_contrib, 1)})

        raw_heuristic = email_contrib + phone_contrib + cc_contrib + pan_contrib + aadhaar_contrib + iban_contrib + kw_contrib + entropy_contrib + digit_contrib
        heuristic_score_0_1 = min(1.0, raw_heuristic / 100.0)

        # Scikit-Learn IsolationForest: decision > 0 is normal, decision < 0 is anomaly.
        # Calibrate anomaly risk: lower decision -> higher anomaly risk in [0, 1]
        model_risk_0_1 = max(0.0, min(1.0, 0.5 - (decision / 1.0)))
        if model_risk_0_1 > 0.65:
            reasons.append({"factor": "IsolationForest Anomaly Pattern", "weight": round(model_risk_0_1 * 25.0, 1)})

        if raw_heuristic == 0.0:
            final_score_0_1 = min(0.3, model_risk_0_1 * 0.4)
        else:
            final_score_0_1 = max(heuristic_score_0_1, model_risk_0_1)

        final_score_100 = round(final_score_0_1 * 100.0, 1)

        # Sort reasons by weight descending
        reasons.sort(key=lambda r: r["weight"], reverse=True)

        return {
            "score_0_1": float(final_score_0_1),
            "score_100": float(final_score_100),
            "heuristic_score": round(heuristic_score_0_1 * 100.0, 1),
            "model_anomaly_score": round(model_risk_0_1 * 100.0, 1),
            "raw_decision": round(decision, 4),
            "model_version": "IsolationForest_v1.2",
            "features": features,
            "reasons": reasons,
            "top_reasons": [f"{r['factor']} (+{r['weight']})" for r in reasons[:4]] or ["Normal text pattern"]
        }

    def score_text(self, text: str) -> float:
        details = self.evaluate_details(text)
        return details["score_0_1"]

    def predict_label(self, text: str) -> str:
        score = self.score_text(text)
        return "suspicious" if score >= self.threshold else "normal"

    def score_documents(self, texts: list[str]) -> list[float]:
        return [self.score_text(text) for text in texts]


def evaluate_model_pipeline(model: LeakRiskModel | None = None) -> dict[str, Any]:
    """Evaluate Isolation Forest pipeline on held-out synthetic test dataset and calculate metrics."""
    from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

    clf = model or LeakRiskModel()
    if not clf._fitted:
        clf.fit([
            "Quarterly strategic planning meeting notes and agenda for marketing.",
            "General office supplies invoice and vendor ordering procedure.",
            "Public product documentation explaining REST API parameters and return schemas.",
            "Engineering backlog sprint review and team velocity retrospective notes.",
        ])

    # Held-out synthetic test dataset with known ground-truth labels
    synthetic_eval_data = [
        # Normal samples (0)
        ("Weekly department sync notes regarding office calendar and team lunch.", 0),
        ("Documentation on how to connect your workstation to the guest Wi-Fi portal.", 0),
        ("Standard operating procedure for submitting travel reimbursements to accounting.", 0),
        ("Overview of project milestones and feature release dates for Q3 release.", 0),
        ("Guide for submitting pull requests and code review formatting guidelines.", 0),
        # Anomalous / Sensitive samples (1)
        ("Client sensitive record: email john.doe@bank.com, card: 4532 0151 8293 4128, PAN: ABCDE1234F.", 1),
        ("CONFIDENTIAL API private key: 98f4a3bc76d123e45a6b, internal admin password: SuperSecret987!", 1),
        ("Executive salary records with PAN card BKZPK1234L and Aadhaar 8921 4452 1198 restricted.", 1),
        ("Customer payment dump with IBAN GB82WEST12345698765432 and phone +1-555-901-2345.", 1),
        ("Top secret system credentials: username admin, password Passw0rd!1234 with high entropy hash.", 1),
    ]

    y_true = [item[1] for item in synthetic_eval_data]
    y_pred = []

    for text, _ in synthetic_eval_data:
        pred_label = clf.predict_label(text)
        y_pred.append(1 if pred_label == "suspicious" else 0)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "model_version": "IsolationForest_v1.2",
        "evaluation_samples": len(synthetic_eval_data),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }

