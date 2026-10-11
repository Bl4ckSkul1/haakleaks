"""
HaakLeaks — Binary File Scanner
Extracts printable strings from binary files (EXE, DLL, SO, firmware, JARs, WARs)
and scans for embedded secrets, connection strings, and private keys.
By Adrian Martinez | HAAK Cybersecurity
"""

import io
import os
import re
import struct
import zipfile

from leak_scanner.core import BaseScanner, SecretFinding
from leak_scanner.patterns import scan_content, SECRET_PATTERNS
from leak_scanner.entropy import shannon_entropy, is_high_entropy, extract_quoted_strings
from leak_scanner.colors import (
    msg_info, msg_ok, msg_warn, msg_secret, section, progress_bar
)


# Minimum string length to extract
STRINGS_MIN_LEN = 8
ENTROPY_MIN_LEN = 20

# Chunk size for streaming large files
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB

# Maximum file size to scan (default 500 MB)
MAX_FILE_SIZE = 500 * 1024 * 1024

# Regex patterns for things we care about specifically in binary context
_URL_RE = re.compile(
    rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,256}",
    re.IGNORECASE,
)
_IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_EMAIL_RE = re.compile(
    rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)
_WIN_PATH_RE = re.compile(
    rb"[A-Za-z]:\\(?:[A-Za-z0-9 _\-\.]+\\){1,8}[A-Za-z0-9 _\-\.]*"
)
_UNIX_PATH_RE = re.compile(
    rb"(?:/etc/|/home/|/root/|/var/|/tmp/|/opt/|/usr/)[A-Za-z0-9/_.\-]{4,120}"
)
_CONN_STRING_RE = re.compile(
    rb"(?:server|host|data source|initial catalog|user id|password|uid|pwd)\s*=\s*[^\x00;]{1,80}",
    re.IGNORECASE,
)
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_JDBC_RE = re.compile(
    rb"jdbc:[a-z]+://[A-Za-z0-9\-._:/@?&=;]{8,200}",
    re.IGNORECASE,
)
_MONGO_RE = re.compile(
    rb"mongodb(?:\+srv)?://[A-Za-z0-9\-._:@/?&=]{8,200}",
    re.IGNORECASE,
)
_REDIS_RE = re.compile(
    rb"redis://[A-Za-z0-9\-._:@/?&=]{4,120}",
    re.IGNORECASE,
)

# Java archive types — extract as ZIP and scan internals as text + binary
JAVA_ARCHIVE_EXTS = {".jar", ".war", ".ear", ".aar"}

# Text-scannable extensions when found inside a Java archive
JAVA_ARCHIVE_TEXT_EXTS = {
    ".properties", ".xml", ".yml", ".yaml", ".json", ".conf", ".ini",
    ".toml", ".cfg", ".txt", ".env", ".sh",
}


def _extract_ascii_strings(data: bytes, min_len: int = STRINGS_MIN_LEN) -> list:
    """Extract printable ASCII strings from a byte buffer."""
    pattern = re.compile(b"[\\x20-\\x7E]{" + str(min_len).encode() + b",}")
    return [(m.start(), m.group().decode("ascii", errors="replace")) for m in pattern.finditer(data)]


def _extract_utf16le_strings(data: bytes, min_len: int = STRINGS_MIN_LEN) -> list:
    """Extract UTF-16LE strings from a byte buffer (Windows binaries)."""
    results = []
    pattern = re.compile(b"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + b",}")
    for m in pattern.finditer(data):
        raw = m.group()
        try:
            decoded = raw.decode("utf-16-le", errors="replace")
            decoded = decoded.replace("\x00", "")
            if len(decoded) >= min_len:
                results.append((m.start(), decoded))
        except Exception:
            pass
    return results


def _is_pe(data: bytes) -> bool:
    """Quick check: is this a PE (Windows EXE/DLL)?"""
    return len(data) > 4 and data[:2] == b"MZ"


def _is_elf(data: bytes) -> bool:
    """Quick check: is this an ELF binary?"""
    return len(data) > 4 and data[:4] == b"\x7fELF"


def _is_macho(data: bytes) -> bool:
    """Quick check: is this a Mach-O binary?"""
    if len(data) < 4:
        return False
    magic = struct.unpack(">I", data[:4])[0]
    return magic in {0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE}


def _is_java_archive(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in JAVA_ARCHIVE_EXTS


def _safe_read_binary(path: str, max_size: int = MAX_FILE_SIZE) -> bytes | None:
    try:
        size = os.path.getsize(path)
        if size > max_size:
            msg_warn(f"File too large ({size / 1024 / 1024:.1f} MB), capping at {max_size // 1024 // 1024} MB: {path}")
            size = max_size
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError as ex:
        msg_warn(f"Cannot read {path}: {ex}")
        return None


class BinaryScanner(BaseScanner):
    NAME = "binary"
    DESCRIPTION = "Extract strings from binaries and scan for embedded secrets"

    def scan(self) -> list:
        section("Binary Scanner", "⚙")
        findings = []
        target = self.target.strip()

        if not os.path.isfile(target):
            msg_warn(f"File not found: {target}")
            return findings

        msg_info(f"Scanning binary: {os.path.basename(target)}")

        # Java archives — special handling
        if _is_java_archive(target):
            findings.extend(self._scan_java_archive(target))
        else:
            findings.extend(self._scan_binary_file(target, label=os.path.basename(target)))

        msg_ok(
            f"Binary scan complete: {self.files_scanned} file(s), "
            f"{self.bytes_scanned // 1024} KB processed, {len(findings)} findings"
        )
        self.findings = findings
        return findings

    # ---------------------------------------------------------------------- #
    # Core binary file scanner
    # ---------------------------------------------------------------------- #
    def _scan_binary_file(self, path: str, label: str = "") -> list:
        findings = []
        label = label or os.path.basename(path)

        data = _safe_read_binary(path)
        if data is None:
            return findings

        self.files_scanned += 1
        self.bytes_scanned += len(data)

        file_size = len(data)
        msg_info(f"  {label}: {file_size // 1024} KB  ({self._detect_format(data)})")

        # -------------------------------------------------- #
        # Direct regex searches on raw bytes (fast paths)
        # -------------------------------------------------- #
        raw_findings = []

        for m in _PRIVATE_KEY_RE.finditer(data):
            raw_findings.append((m.start(), "critical", "private_key",
                                 "private_key_in_binary",
                                 m.group().decode("ascii", errors="replace"),
                                 "Private key header found in binary",
                                 "high"))

        for m in _JDBC_RE.finditer(data):
            val = m.group().decode("ascii", errors="replace")
            raw_findings.append((m.start(), "high", "connection_string",
                                 "jdbc_connection_string", val,
                                 "JDBC connection string in binary", "high"))

        for m in _MONGO_RE.finditer(data):
            val = m.group().decode("ascii", errors="replace")
            raw_findings.append((m.start(), "high", "connection_string",
                                 "mongodb_connection_string", val,
                                 "MongoDB connection URI in binary", "high"))

        for m in _REDIS_RE.finditer(data):
            val = m.group().decode("ascii", errors="replace")
            raw_findings.append((m.start(), "medium", "connection_string",
                                 "redis_connection_string", val,
                                 "Redis connection URI in binary", "high"))

        for m in _CONN_STRING_RE.finditer(data):
            val = m.group().decode("ascii", errors="replace")
            if any(kw in val.lower() for kw in ("password=", "pwd=", "passwd=")):
                raw_findings.append((m.start(), "high", "connection_string",
                                     "sql_connection_string", val,
                                     "Connection string with credential in binary", "medium"))

        for m in _URL_RE.finditer(data):
            url = m.group().decode("ascii", errors="replace")
            # Only report URLs that look interesting (with creds or tokens)
            if "@" in url or any(kw in url.lower() for kw in ("key=", "token=", "secret=", "password=")):
                raw_findings.append((m.start(), "medium", "url",
                                     "url_with_credentials", url,
                                     "URL with embedded credentials in binary", "medium"))

        for offset, severity, category, type_, value, description, confidence in raw_findings:
            self.add_finding(
                severity=severity,
                category=category,
                type_=type_,
                value=value,
                location=f"{label}+0x{offset:x}",
                context=data[max(0, offset - 32): offset + 128].decode("ascii", errors="replace")[:200],
                line_number=0,
                description=description,
                confidence=confidence,
                metadata={"offset": hex(offset), "file": label, "encoding": "binary"},
            )
            findings.append(self.findings[-1])

        # -------------------------------------------------- #
        # Extract strings → run pattern scanner
        # -------------------------------------------------- #
        ascii_strings = _extract_ascii_strings(data)
        utf16_strings = _extract_utf16le_strings(data)

        all_strings = ascii_strings + utf16_strings
        total_strings = len(all_strings)
        msg_info(f"  Extracted strings: {total_strings} (ASCII: {len(ascii_strings)}, UTF-16LE: {len(utf16_strings)})")

        # Build text blob for scan_content
        text_blob = "\n".join(s for _, s in all_strings)
        self.bytes_scanned += len(text_blob.encode("utf-8", errors="replace"))

        matches = scan_content(text_blob, filename=label)
        for (
            pattern_name, match_value, severity, category,
            description, confidence, m_start, m_end
        ) in matches:
            # Try to find approximate byte offset
            approx_offset = 0
            chars_so_far = 0
            for offset, s in all_strings:
                chars_so_far += len(s) + 1
                if chars_so_far >= m_start:
                    approx_offset = offset
                    break

            self.add_finding(
                severity=severity,
                category=category,
                type_=pattern_name,
                value=match_value,
                location=f"{label}+0x{approx_offset:x}",
                context=text_blob[max(0, m_start - 60): m_end + 60].strip()[:200],
                line_number=0,
                description=f"{description} (extracted from binary)",
                confidence=confidence,
                metadata={"offset": hex(approx_offset), "file": label, "encoding": "extracted_string"},
            )
            findings.append(self.findings[-1])

        # -------------------------------------------------- #
        # Entropy analysis on extracted strings
        # -------------------------------------------------- #
        for offset, s in all_strings:
            if len(s) >= ENTROPY_MIN_LEN and is_high_entropy(s):
                self.add_finding(
                    severity="low",
                    category="entropy",
                    type_="binary_high_entropy_string",
                    value=s,
                    location=f"{label}+0x{offset:x}",
                    context=s[:120],
                    line_number=0,
                    description="High-entropy string extracted from binary — possible hardcoded secret",
                    confidence="low",
                    metadata={
                        "offset": hex(offset),
                        "file": label,
                        "entropy": round(shannon_entropy(s), 3),
                    },
                )
                findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # Java archive (.jar / .war / .ear / .aar) scanner
    # ---------------------------------------------------------------------- #
    def _scan_java_archive(self, path: str) -> list:
        findings = []
        label = os.path.basename(path)

        if not zipfile.is_zipfile(path):
            msg_warn(f"Not a valid ZIP/JAR: {path}")
            return findings

        msg_info(f"Scanning Java archive: {label}")

        try:
            with zipfile.ZipFile(path, "r") as zf:
                namelist = zf.namelist()
                total = len(namelist)

                for idx, name in enumerate(namelist):
                    progress_bar(idx + 1, total, label=name[:50], width=30)

                    fname = os.path.basename(name)
                    _, ext = os.path.splitext(fname.lower())

                    try:
                        data = zf.read(name)
                    except Exception:
                        continue

                    self.bytes_scanned += len(data)

                    if ext in JAVA_ARCHIVE_TEXT_EXTS:
                        # Scan as text
                        try:
                            text = data.decode("utf-8", errors="replace")
                            self.files_scanned += 1
                            matches = scan_content(text, filename=fname)
                            for (
                                pattern_name, match_value, severity, category,
                                description, confidence, m_start, m_end
                            ) in matches:
                                line_no = text[:m_start].count("\n") + 1
                                self.add_finding(
                                    severity=severity,
                                    category=category,
                                    type_=pattern_name,
                                    value=match_value,
                                    location=f"{label}!{name}:{line_no}",
                                    context=text[max(0, m_start - 60): m_end + 60].strip()[:200],
                                    line_number=line_no,
                                    description=description,
                                    confidence=confidence,
                                    metadata={"archive": label, "entry": name},
                                )
                                findings.append(self.findings[-1])

                            for qs in extract_quoted_strings(text):
                                if len(qs) >= ENTROPY_MIN_LEN and is_high_entropy(qs):
                                    self.add_finding(
                                        severity="low",
                                        category="entropy",
                                        type_="jar_high_entropy_string",
                                        value=qs,
                                        location=f"{label}!{name}",
                                        context=qs[:120],
                                        line_number=0,
                                        description="High-entropy string in Java archive text file",
                                        confidence="low",
                                        metadata={
                                            "archive": label,
                                            "entry": name,
                                            "entropy": round(shannon_entropy(qs), 3),
                                        },
                                    )
                                    findings.append(self.findings[-1])
                        except Exception:
                            pass

                    elif ext == ".class":
                        # .class file — extract strings from bytecode
                        self.files_scanned += 1
                        ascii_strings = _extract_ascii_strings(data, min_len=STRINGS_MIN_LEN)
                        text_blob = "\n".join(s for _, s in ascii_strings)
                        matches = scan_content(text_blob, filename=fname)
                        for (
                            pattern_name, match_value, severity, category,
                            description, confidence, m_start, m_end
                        ) in matches:
                            self.add_finding(
                                severity=severity,
                                category=category,
                                type_=pattern_name,
                                value=match_value,
                                location=f"{label}!{name}",
                                context=text_blob[max(0, m_start - 60): m_end + 60].strip()[:200],
                                line_number=0,
                                description=f"{description} (extracted from .class bytecode)",
                                confidence=confidence,
                                metadata={"archive": label, "entry": name},
                            )
                            findings.append(self.findings[-1])

                    elif ext in {".jar", ".war", ".ear"}:
                        # Nested archive — recurse via a temp buffer
                        try:
                            inner = zipfile.ZipFile(io.BytesIO(data), "r")
                            for inner_name in inner.namelist():
                                inner_data = inner.read(inner_name)
                                inner_fname = os.path.basename(inner_name)
                                _, inner_ext = os.path.splitext(inner_fname.lower())
                                if inner_ext in JAVA_ARCHIVE_TEXT_EXTS:
                                    text = inner_data.decode("utf-8", errors="replace")
                                    matches = scan_content(text, filename=inner_fname)
                                    for (
                                        pn, mv, sv, cat, desc, conf, ms, me
                                    ) in matches:
                                        ln = text[:ms].count("\n") + 1
                                        self.add_finding(
                                            severity=sv,
                                            category=cat,
                                            type_=pn,
                                            value=mv,
                                            location=f"{label}!{name}!{inner_name}:{ln}",
                                            context=text[max(0, ms - 60): me + 60].strip()[:200],
                                            line_number=ln,
                                            description=desc,
                                            confidence=conf,
                                            metadata={"archive": label, "entry": f"{name}!{inner_name}"},
                                        )
                                        findings.append(self.findings[-1])
                            inner.close()
                        except Exception:
                            pass

        except zipfile.BadZipFile as ex:
            msg_warn(f"Bad ZIP/JAR: {ex}")
        except Exception as ex:
            msg_warn(f"Error reading Java archive: {ex}")

        progress_bar(1, 1, label="Done", width=30)
        return findings

    # ---------------------------------------------------------------------- #
    # Helper: detect file format
    # ---------------------------------------------------------------------- #
    @staticmethod
    def _detect_format(data: bytes) -> str:
        if len(data) < 4:
            return "unknown"
        if data[:2] == b"MZ":
            return "PE (Windows EXE/DLL)"
        if data[:4] == b"\x7fELF":
            return "ELF (Linux binary)"
        if data[:4] in {b"PK\x03\x04", b"PK\x05\x06"}:
            return "ZIP/JAR archive"
        if data[:4] == b"\xca\xfe\xba\xbe":
            return "Mach-O fat binary / Java .class"
        if data[:2] == b"\xfe\xed":
            return "Mach-O binary"
        return "binary (unknown format)"
