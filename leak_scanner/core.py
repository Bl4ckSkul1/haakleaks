"""
HaakLeaks — Core Engine
Shared types, base scanner class, and utility functions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# SecretFinding
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    severity:    str   # critical | high | medium | low | info
    category:    str   # credential | api_key | token | cloud | pii | crypto | config
    type:        str   # aws_access_key | github_token | password | ...
    value:       str   # the raw secret (masked in reports)
    source:      str   # git | docker | apk | binary | config | pcap | cloud
    location:    str   # file path, "commit abc123:path/file.py", docker layer id, etc.
    context:     str   # surrounding content snippet (truncated, ≤256 chars)
    line_number: int   # 0 if not applicable
    description: str   # human-readable description of the finding type
    confidence:  str   # high | medium | low
    metadata:    dict  = field(default_factory=dict)
    timestamp:   str   = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )

    # ------------------------------------------------------------------
    def masked_value(self, show_chars: int = 8) -> str:
        """Return first N chars + *** + last 4 chars."""
        v = self.value
        if not v:
            return "***"
        show_end = 4
        if len(v) <= show_chars + show_end + 3:
            # Short secret — show only first N chars
            return v[:show_chars] + "***"
        return v[:show_chars] + "***" + v[-show_end:]

    def to_dict(self) -> dict:
        return {
            "severity":    self.severity,
            "category":    self.category,
            "type":        self.type,
            "value":       self.masked_value(),
            "source":      self.source,
            "location":    self.location,
            "context":     self.context[:256] if self.context else "",
            "line_number": self.line_number,
            "description": self.description,
            "confidence":  self.confidence,
            "metadata":    self.metadata,
            "timestamp":   self.timestamp,
        }


# ---------------------------------------------------------------------------
# BaseScanner
# ---------------------------------------------------------------------------

class BaseScanner:
    """Abstract base class for all HaakLeaks source scanners."""

    NAME        = "base"
    DESCRIPTION = "Base scanner (do not use directly)"

    def __init__(self, target: str, options: Optional[dict] = None):
        self.target        = target
        self.options       = options or {}
        self.findings:     list[SecretFinding] = []
        self.files_scanned = 0
        self.bytes_scanned = 0

    # ------------------------------------------------------------------
    def scan(self) -> list[SecretFinding]:
        """
        Execute the scan.  Must be overridden by subclasses.
        Should populate self.findings and update self.files_scanned /
        self.bytes_scanned, then return self.findings.
        """
        raise NotImplementedError(
            f"Scanner '{self.NAME}' must implement scan()"
        )

    # ------------------------------------------------------------------
    def add_finding(
        self,
        severity:    str,
        category:    str,
        type_:       str,
        value:       str,
        location:    str,
        context:     str  = "",
        line_number: int  = 0,
        description: str  = "",
        confidence:  str  = "high",
        metadata:    Optional[dict] = None,
    ) -> SecretFinding:
        """Convenience method — create a SecretFinding and append it."""
        finding = SecretFinding(
            severity    = severity,
            category    = category,
            type        = type_,
            value       = value,
            source      = self.NAME,
            location    = location,
            context     = context[:256] if context else "",
            line_number = line_number,
            description = description,
            confidence  = confidence,
            metadata    = metadata or {},
        )
        self.findings.append(finding)
        return finding

    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        """Return a summary dict for this scanner's run."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_cat: dict[str, int] = {}

        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1

        return {
            "scanner":        self.NAME,
            "target":         self.target,
            "total_findings": len(self.findings),
            "files_scanned":  self.files_scanned,
            "bytes_scanned":  self.bytes_scanned,
            "by_severity":    counts,
            "by_category":    by_cat,
        }

    # ------------------------------------------------------------------
    def _opt(self, key: str, default=None):
        """Safe option accessor."""
        return self.options.get(key, default)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def mask_secret(value: str, show_start: int = 8, show_end: int = 4) -> str:
    """
    Mask a secret value for safe display / logging.

    Examples:
      AKIAIOSFODNN7EXAMPLE  →  AKIAIOSFODNN***MPLE
      supersecret           →  supersec***
    """
    if not value:
        return "***"
    if len(value) <= show_start + show_end + 3:
        return value[:show_start] + "***"
    return value[:show_start] + "***" + value[-show_end:]


def truncate(text: str, max_len: int = 256) -> str:
    """Truncate text to max_len with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def normalize_line(line: str, max_len: int = 512) -> str:
    """Strip and truncate a line for context storage."""
    return line.strip()[:max_len]


def is_binary_file(path: str, sample_size: int = 8192) -> bool:
    """
    Heuristic: is this file binary?
    Reads a sample and checks for null bytes.
    """
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sample_size)
        if b"\x00" in chunk:
            return True
        # Check ratio of non-printable bytes
        non_printable = sum(
            1 for b in chunk if b < 9 or (14 <= b <= 31)
        )
        return non_printable / len(chunk) > 0.30 if chunk else False
    except OSError:
        return False


def human_size(n: int) -> str:
    """Convert bytes to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def severity_rank(sev: str) -> int:
    """Return a sortable integer for severity (higher = more severe)."""
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        sev.lower(), 0
    )


def sort_findings(findings: list[SecretFinding]) -> list[SecretFinding]:
    """Sort findings by severity descending, then by source + location."""
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.source, f.location),
    )
