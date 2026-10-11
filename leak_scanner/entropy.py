"""
HaakLeaks — Shannon Entropy Analysis
Detect high-entropy strings that may be secrets even when regex doesn't match.
"""
import re
import math
import string
from typing import Iterator


# ---------------------------------------------------------------------------
# Character sets for entropy classification
# ---------------------------------------------------------------------------

_CHARSET_HEX         = set(string.hexdigits)
_CHARSET_BASE64      = set(string.ascii_letters + string.digits + "+/=")
_CHARSET_BASE64URL   = set(string.ascii_letters + string.digits + "-_=")
_CHARSET_ALPHANUM    = set(string.ascii_letters + string.digits)
_CHARSET_PRINTABLE   = set(string.printable)

# Minimum lengths per charset for entropy checks
_MIN_LEN = {
    "hex":       16,   # 64-bit key minimum
    "base64":    20,
    "base64url": 20,
    "alphanum":  18,
    "mixed":     16,
}

# Entropy thresholds (bits per character)
_THRESHOLD = {
    "hex":       3.0,   # max for hex is 4.0 (16 symbols)
    "base64":    4.5,   # max for base64 is ~6.0
    "base64url": 4.5,
    "alphanum":  4.0,   # max for alphanum is ~5.95
    "mixed":     3.8,
}


# ---------------------------------------------------------------------------
# Core entropy function
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy (bits per character) for a string.

    Perfect random base64  → ~6.0
    Random hex string      → ~4.0
    English text           → ~4.5
    Repeated chars         → 0.0
    """
    if not data:
        return 0.0

    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Charset detection
# ---------------------------------------------------------------------------

def _detect_charset(s: str) -> str:
    """Return the best-fit charset name for a candidate string."""
    chars = set(s)
    if chars <= _CHARSET_HEX:
        return "hex"
    if chars <= _CHARSET_BASE64:
        return "base64"
    if chars <= _CHARSET_BASE64URL:
        return "base64url"
    if chars <= _CHARSET_ALPHANUM:
        return "alphanum"
    return "mixed"


# ---------------------------------------------------------------------------
# is_high_entropy
# ---------------------------------------------------------------------------

def is_high_entropy(
    value: str,
    threshold: float = 3.5,
    min_length: int = 16,
) -> bool:
    """
    Return True if a string appears to be a high-entropy secret.

    Args:
        value      : the string to test
        threshold  : entropy threshold (default 3.5 bits/char)
        min_length : minimum length to consider (default 16)

    Returns True when:
      - len >= min_length
      - entropy >= threshold for the detected charset
      - not a known low-entropy false positive (repeated pattern, etc.)
    """
    if not value or len(value) < min_length:
        return False

    charset = _detect_charset(value)
    actual_threshold = max(threshold, _THRESHOLD.get(charset, threshold))
    min_len = max(min_length, _MIN_LEN.get(charset, min_length))

    if len(value) < min_len:
        return False

    ent = shannon_entropy(value)

    # Additional heuristics to reduce false positives
    if _is_likely_fp(value):
        return False

    return ent >= actual_threshold


def _is_likely_fp(value: str) -> bool:
    """Cheap false-positive checks based on string structure."""
    # All same character
    if len(set(value)) <= 2:
        return True
    # Looks like a version string (1.2.3.4)
    if re.fullmatch(r"[\d.]+", value):
        return True
    # UUID without dashes
    if re.fullmatch(r"[0-9a-f]{32}", value, re.IGNORECASE):
        # Could be a real MD5-format key — don't reject it
        return False
    # Long repeated pattern
    half = value[: len(value) // 2]
    if half * 2 == value or (half + half[:1]) == value:
        return True
    # Looks like a file path
    if value.startswith(("/", "C:\\", "./", "../")):
        return True
    # Looks like a URL
    if value.startswith(("http://", "https://", "ftp://")):
        return True
    return False


# ---------------------------------------------------------------------------
# String extraction helpers
# ---------------------------------------------------------------------------

# Patterns for extracting candidate high-entropy strings from different contexts

# Quoted strings (JS, Python, Java, etc.)
_RE_DOUBLE_QUOTED = re.compile(r'"([^"\\]{16,256})"')
_RE_SINGLE_QUOTED = re.compile(r"'([^'\\]{16,256})'")
_RE_BACKTICK      = re.compile(r"`([^`\\]{16,256})`")

# Assignment patterns (VAR = VALUE)
_RE_ASSIGNMENT    = re.compile(
    r"""(?:^|[;,\s])(?:[A-Z_]{3,}|[a-z_]{3,})\s*[:=]+\s*['""]?([A-Za-z0-9+/=_\-]{16,256})['""]?""",
    re.MULTILINE,
)

# Raw tokens (consecutive non-whitespace, non-special chars of sufficient length)
_RE_RAW_TOKEN     = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def extract_quoted_strings(
    text: str,
    min_length: int = 16,
    max_length: int = 512,
) -> Iterator[tuple[str, int]]:
    """
    Yield (value, start_pos) for all quoted strings in text
    that are within [min_length, max_length] characters.

    Covers double-quoted, single-quoted, and backtick strings.
    For use in config files, YAML, TOML, JSON, etc.
    """
    for pattern in (_RE_DOUBLE_QUOTED, _RE_SINGLE_QUOTED, _RE_BACKTICK):
        for m in pattern.finditer(text):
            val = m.group(1)
            if min_length <= len(val) <= max_length:
                yield val, m.start()


def extract_string_literals(
    text: str,
    min_length: int = 16,
    max_length: int = 256,
) -> Iterator[tuple[str, int]]:
    """
    Yield (value, start_pos) for assignment values and quoted strings.
    Designed for source code (JS, TS, Python, Java, Go, etc.).

    This is the primary extractor for entropy scanning.
    """
    seen: set[str] = set()

    # Assignment values
    for m in _RE_ASSIGNMENT.finditer(text):
        val = m.group(1).strip("\"'` \t")
        if min_length <= len(val) <= max_length and val not in seen:
            seen.add(val)
            yield val, m.start()

    # Quoted strings
    for val, pos in extract_quoted_strings(text, min_length, max_length):
        if val not in seen:
            seen.add(val)
            yield val, pos


def extract_raw_tokens(
    text: str,
    min_length: int = 20,
    max_length: int = 512,
) -> Iterator[tuple[str, int]]:
    """
    Yield raw token-like strings that could be secrets.
    Used for binary scanning where structure is absent.
    """
    for m in _RE_RAW_TOKEN.finditer(text):
        val = m.group(0)
        if min_length <= len(val) <= max_length:
            yield val, m.start()


# ---------------------------------------------------------------------------
# Scan a text block for high-entropy strings
# ---------------------------------------------------------------------------

def find_high_entropy_strings(
    text: str,
    threshold: float = 3.8,
    min_length: int = 16,
    max_length: int = 512,
    source: str = "generic",
) -> list[dict]:
    """
    Scan text for high-entropy strings and return a list of candidates.

    Each result dict:
        {
            "value":    str,
            "entropy":  float,
            "charset":  str,
            "position": int,
            "context":  str,   # ±40 chars around the match
        }
    """
    results = []

    extractor = extract_raw_tokens if source == "binary" else extract_string_literals

    for val, pos in extractor(text, min_length, max_length):
        if is_high_entropy(val, threshold=threshold, min_length=min_length):
            ent     = shannon_entropy(val)
            charset = _detect_charset(val)
            ctx_start = max(0, pos - 40)
            ctx_end   = min(len(text), pos + len(val) + 40)
            context   = text[ctx_start:ctx_end].replace("\n", " ").replace("\r", "")

            results.append({
                "value":    val,
                "entropy":  ent,
                "charset":  charset,
                "position": pos,
                "context":  context[:120],
            })

    return results


# ---------------------------------------------------------------------------
# Convenience — classify entropy level
# ---------------------------------------------------------------------------

def entropy_level(ent: float) -> str:
    """Classify an entropy value as a human-readable level."""
    if ent >= 5.5:
        return "very_high"
    if ent >= 4.5:
        return "high"
    if ent >= 3.5:
        return "medium"
    if ent >= 2.5:
        return "low"
    return "very_low"


def entropy_severity(ent: float, min_length: int = 16) -> str:
    """Map entropy level + length to a finding severity."""
    if min_length >= 40 and ent >= 5.0:
        return "high"
    if ent >= 4.5:
        return "medium"
    if ent >= 3.8:
        return "low"
    return "info"
