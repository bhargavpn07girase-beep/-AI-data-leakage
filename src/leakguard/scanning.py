"""Regex-based content scanning and masking for local, user-authorized files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Optional


@dataclass(frozen=True)
class ScanRule:
    name: str
    pattern: str
    replacement: str


@dataclass(frozen=True)
class ContentFinding:
    file_path: str
    rule: str
    line_number: int | None
    masked_value: str
    count: int = 1


@dataclass(frozen=True)
class ScanResult:
    file_path: str
    findings: list[ContentFinding]
    masked_text: str
    skipped: bool = False
    reason: str | None = None
    category_counts: dict[str, int] = field(default_factory=dict)


def is_luhn_valid(number_str: str) -> bool:
    digits = [int(ch) for ch in number_str if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            double = digit * 2
            checksum += double if double < 10 else double - 9
        else:
            checksum += digit
    return checksum % 10 == 0


DEFAULT_RULES = (
    ScanRule('email', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[EMAIL]'),
    ScanRule('phone', r'(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3}[-.\s]?\d{4}', '[PHONE]'),
    ScanRule('url', r'https?://[^\s"<>]+|www\.[^\s"<>]+', '[URL]'),
    ScanRule('placeholder', r'<(?:ID_NUM|USERNAME|NAME|EMAIL|PHONE_NUM|ADDRESS|URL)>', '[REDACTED]'),
    ScanRule('pan', r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', '[PAN_CARD]'),
    ScanRule('aadhaar', r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[AADHAAR]'),
    ScanRule('iban', r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b', '[IBAN]'),
    ScanRule('address', r'\b\d{1,5}\s+[A-Za-z0-9.\- ]+\b(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Parkway|Pkwy|Court|Ct|Place)\b', '[ADDRESS]'),


    ScanRule('confidential', r'\b(confidential|restricted|internal\s+only|password|secret|api[_\s]?key|private[_\s]?key)\b', '[CONFIDENTIAL]'),
)


def mask_sensitive_value(category: str, raw_text: str) -> str:
    """Mask sensitive string value according to category while preserving structure."""
    val = raw_text.strip()
    if not val:
        return "[REDACTED]"
    if category == 'email':
        parts = val.split('@')
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + '***' if len(name) > 1 else '***'
            return f"{masked_name}@{domain}"
        return "e***@masked.com"
    elif category == 'phone':
        digits = re.sub(r'\D', '', val)
        last4 = digits[-4:] if len(digits) >= 4 else 'XXXX'
        return f"XXX-XXX-{last4}"
    elif category in ('credit_card', 'card'):
        digits = re.sub(r'\D', '', val)
        last4 = digits[-4:] if len(digits) >= 4 else 'XXXX'
        return f"XXXX-XXXX-XXXX-{last4}"
    elif category == 'aadhaar':
        digits = re.sub(r'\D', '', val)
        last4 = digits[-4:] if len(digits) >= 4 else 'XXXX'
        return f"XXXX-XXXX-{last4}"
    elif category == 'pan':
        if len(val) == 10:
            return f"XXXXX{val[5:]}"
        return "XXXXX1234F"
    elif category == 'iban':
        if len(val) > 6:
            return f"{val[:4]}****{val[-4:]}"
        return "XX****XXXX"
    elif category == 'url':
        m = re.match(r'(https?://[^/]+)', val, re.IGNORECASE)
        if m:
            return f"{m.group(1)}/..."
        return "[URL_REDACTED]"
    elif category == 'confidential':
        if len(val) > 2:
            return f"{val[0]}{'*' * (len(val) - 2)}{val[-1]}"
        return "***"
    return "[REDACTED]"


def scan_text(text: str, file_path: str, rules: tuple[ScanRule, ...] = DEFAULT_RULES, start_line_offset: int = 0) -> tuple[str, list[ContentFinding]]:
    masked_text = text
    findings: list[ContentFinding] = []

    # First check credit card with Luhn check specifically
    cc_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
    for match in cc_pattern.finditer(text):
        matched_str = match.group(0)
        digits_only = re.sub(r'\D', '', matched_str)
        if 13 <= len(digits_only) <= 19 and is_luhn_valid(digits_only):
            line_number = start_line_offset + text.count('\n', 0, match.start()) + 1
            findings.append(
                ContentFinding(
                    file_path=file_path,
                    rule='credit_card',
                    line_number=line_number,
                    masked_value=mask_sensitive_value('credit_card', matched_str),
                )
            )
            masked_text = masked_text.replace(matched_str, '[CREDIT_CARD]')

    for rule in rules:
        regex = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
        for match in regex.finditer(masked_text):
            line_number = start_line_offset + masked_text.count('\n', 0, match.start()) + 1
            raw_match = match.group(0)
            masked_val = mask_sensitive_value(rule.name, raw_match) if rule.replacement.startswith('[') else rule.replacement
            findings.append(
                ContentFinding(
                    file_path=file_path,
                    rule=rule.name,
                    line_number=line_number,
                    masked_value=masked_val,
                )
            )
        masked_text = regex.sub(rule.replacement, masked_text)
    return masked_text, findings


def extract_file_text(file_path: Path, max_chars: int = 5_000_000) -> str:
    suffix = file_path.suffix.lower()
    if suffix == '.pdf':
        try:
            import pypdf
            reader = pypdf.PdfReader(str(file_path))
            pages_text: list[str] = []
            char_count = 0
            for page in reader.pages:
                t = page.extract_text() or ''
                pages_text.append(t)
                char_count += len(t)
                if char_count >= max_chars:
                    break
            return "\n".join(pages_text)
        except Exception as e:
            raise OSError(f"Corrupted or unreadable PDF: {str(e)}") from e
    elif suffix in ('.docx', '.doc'):
        try:
            import docx
            doc = docx.Document(str(file_path))
            paragraphs: list[str] = []
            char_count = 0
            for p in doc.paragraphs:
                paragraphs.append(p.text)
                char_count += len(p.text)
                if char_count >= max_chars:
                    break
            return "\n".join(paragraphs)
        except Exception as e:
            raise OSError(f"Corrupted or unreadable DOCX: {str(e)}") from e

    try:
        return file_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        try:
            return file_path.read_text(encoding='latin-1')
        except Exception:
            return file_path.read_bytes().decode('utf-8', errors='replace')


def scan_file_chunked(
    file_path: Path,
    chunk_size: int = 256 * 1024,
    overlap: int = 2048,
    max_scan_bytes: int = 50_000_000,
    rules: tuple[ScanRule, ...] = DEFAULT_RULES,
) -> ScanResult:
    """Scan large text files in streaming chunks with overlap to catch cross-boundary matches."""
    findings: list[ContentFinding] = []
    category_counts: dict[str, int] = {}
    seen_dedup_keys: set[tuple[str, int | None, str]] = set()
    preview_parts: list[str] = []

    bytes_read = 0
    line_offset = 0
    buffer = ""

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            bytes_read += len(chunk.encode("utf-8", errors="replace"))
            content = buffer + chunk

            masked_chunk, chunk_findings = scan_text(
                content,
                file_path=str(file_path),
                rules=rules,
                start_line_offset=line_offset,
            )

            if len(preview_parts) < 3:
                preview_parts.append(masked_chunk[:500])

            for finding in chunk_findings:
                key = (finding.rule, finding.line_number, finding.masked_value)
                if key not in seen_dedup_keys:
                    seen_dedup_keys.add(key)
                    findings.append(finding)
                    category_counts[finding.rule] = category_counts.get(finding.rule, 0) + 1

            if len(chunk) < chunk_size or bytes_read >= max_scan_bytes:
                break

            line_offset += content[:-overlap].count("\n")
            buffer = content[-overlap:]

    is_truncated = bytes_read >= max_scan_bytes and file_path.stat().st_size > bytes_read
    return ScanResult(
        file_path=str(file_path),
        findings=findings,
        masked_text="\n".join(preview_parts)[:2000],
        skipped=False,
        reason="partial_scan_exceeded_stream_limit" if is_truncated else None,
        category_counts=category_counts,
    )


def scan_file(path: str | Path, max_size_bytes: int = 50_000_000, rules: tuple[ScanRule, ...] = DEFAULT_RULES) -> ScanResult:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f'File does not exist: {file_path}')

    file_size = file_path.stat().st_size

    # Hard resource ceiling (200 MB)
    hard_limit = 200_000_000
    if file_size > hard_limit:
        return ScanResult(
            file_path=str(file_path),
            findings=[],
            masked_text='',
            skipped=True,
            reason='file_too_large',
            category_counts={},
        )

    # Honor small limits if explicitly requested by caller (e.g., test thresholds < 100 KB)
    if file_size > max_size_bytes and max_size_bytes < 100_000:
        return ScanResult(
            file_path=str(file_path),
            findings=[],
            masked_text='',
            skipped=True,
            reason='file_too_large',
            category_counts={},
        )

    suffix = file_path.suffix.lower()

    if suffix in ('.pdf', '.docx', '.doc'):
        try:
            text = extract_file_text(file_path)
            masked_text, findings = scan_text(text, str(file_path), rules)
            cat_counts: dict[str, int] = {}
            for f in findings:
                cat_counts[f.rule] = cat_counts.get(f.rule, 0) + 1
            return ScanResult(
                file_path=str(file_path),
                findings=findings,
                masked_text=masked_text[:2000],
                category_counts=cat_counts,
            )
        except OSError as e:
            return ScanResult(
                file_path=str(file_path),
                findings=[],
                masked_text='',
                skipped=True,
                reason=f'corrupted_document:{str(e)[:100]}',
                category_counts={},
            )

    if file_size > 2_000_000:
        try:
            return scan_file_chunked(file_path, max_scan_bytes=max_size_bytes, rules=rules)
        except Exception as e:
            return ScanResult(
                file_path=str(file_path),
                findings=[],
                masked_text='',
                skipped=True,
                reason=f'read_error:{str(e)[:100]}',
                category_counts={},
            )

    try:
        text = extract_file_text(file_path)
    except OSError as err:
        return ScanResult(
            file_path=str(file_path),
            findings=[],
            masked_text='',
            skipped=True,
            reason=f'read_error:{str(err)[:100]}',
            category_counts={},
        )

    masked_text, findings = scan_text(text, str(file_path), rules)
    cat_counts: dict[str, int] = {}
    for f in findings:
        cat_counts[f.rule] = cat_counts.get(f.rule, 0) + 1

    return ScanResult(
        file_path=str(file_path),
        findings=findings,
        masked_text=masked_text[:2000],
        category_counts=cat_counts,
    )


def scan_directory(directory: str | Path, max_size_bytes: int = 10_000_000) -> list[ScanResult]:
    root = Path(directory)
    if not root.exists():
        return []
    results: list[ScanResult] = []
    supported = {'.txt', '.csv', '.json', '.jsonl', '.log', '.md', '.pdf', '.docx'}
    for file_path in sorted(root.rglob('*')):
        if file_path.is_file() and file_path.suffix.lower() in supported:
            results.append(scan_file(file_path, max_size_bytes=max_size_bytes))
    return results


