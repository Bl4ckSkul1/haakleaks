"""
HaakLeaks — Android APK Scanner
Extracts and scans APK files for API keys, tokens, Firebase configs,
and other embedded secrets.
By Adrian Martinez | HAAK Cybersecurity
"""

import json
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


# Minimum printable-string length to extract from .dex / .so
STRINGS_MIN_LEN = 10

# File paths of particular interest inside an APK
HIGH_VALUE_FILES = {
    "google-services.json",
    "GoogleService-Info.plist",
    "amplifyconfiguration.json",
    "awsconfiguration.json",
    "agconnect-services.json",
    "fabric.properties",
    "crashlytics.properties",
    "firebase.json",
    "appsflyer.properties",
    "branch.json",
    "onesignal.json",
    "mapbox.properties",
}

# Text extensions that are scannable
TEXT_EXTENSIONS = {
    ".js", ".json", ".xml", ".yml", ".yaml", ".properties",
    ".txt", ".conf", ".cfg", ".ini", ".toml",
    ".html", ".htm",
    ".ts",
    ".kt", ".java",  # rare, but some deobfuscated APKs contain these
}

# Binary extensions that need strings extraction
BINARY_EXTENSIONS = {".dex", ".so", ".dll"}

# Regex for extracting printable ASCII strings from binary data
_ASCII_STRINGS_RE = re.compile(rb"[\x20-\x7E]{" + str(STRINGS_MIN_LEN).encode() + rb",}")

# AndroidManifest patterns (works on both binary and decoded XML)
_MANIFEST_API_KEY_RE = re.compile(
    rb'(?:com\.google\.[a-z.]+\.API_KEY|api[_\-]?key|MAPS_API_KEY)[^>]*?'
    rb'android:value\s*=\s*["\']?([A-Za-z0-9_\-]{20,})',
    re.IGNORECASE,
)
_MANIFEST_FIREBASE_RE = re.compile(
    rb"https://[a-z0-9\-]+\.firebaseio\.com",
    re.IGNORECASE,
)
_MANIFEST_DEBUGGABLE_RE = re.compile(
    rb'android:debuggable\s*=\s*["\']?true',
    re.IGNORECASE,
)
_MANIFEST_BACKUP_RE = re.compile(
    rb'android:allowBackup\s*=\s*["\']?true',
    re.IGNORECASE,
)
_MANIFEST_GCM_RE = re.compile(
    rb'com\.google\.android\.c2dm\.permission\.RECEIVE|gcm_defaultSenderId[^>]*?(\d{10,15})',
    re.IGNORECASE,
)
_MANIFEST_EXPORTED_RE = re.compile(
    rb'android:exported\s*=\s*["\']?true',
    re.IGNORECASE,
)


def _extract_printable_strings(data: bytes, min_len: int = STRINGS_MIN_LEN) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(b"[\\x20-\\x7E]{" + str(min_len).encode() + b",}")
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


def _extract_utf16le_strings(data: bytes, min_len: int = STRINGS_MIN_LEN) -> list:
    """Extract UTF-16LE encoded strings (common in Windows / some Android resources)."""
    results = []
    # Match sequences of printable chars in UTF-16LE (ascii char + null byte)
    pattern = re.compile(b"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + b",}")
    for m in pattern.finditer(data):
        raw = m.group()
        try:
            decoded = raw.decode("utf-16-le", errors="replace").replace("\x00", "")
            if len(decoded) >= min_len:
                results.append(decoded)
        except Exception:
            pass
    return results


def _is_text_file(name: str) -> bool:
    _, ext = os.path.splitext(name.lower())
    return ext in TEXT_EXTENSIONS


def _is_binary_scannable(name: str) -> bool:
    _, ext = os.path.splitext(name.lower())
    return ext in BINARY_EXTENSIONS


class APKScanner(BaseScanner):
    NAME = "apk"
    DESCRIPTION = "Scan Android APK files for embedded API keys, tokens, and secrets"

    def scan(self) -> list:
        section("APK Scanner", "📱")
        findings = []
        target = self.target.strip()

        if not os.path.isfile(target):
            msg_warn(f"APK file not found: {target}")
            return findings

        if not zipfile.is_zipfile(target):
            msg_warn(f"File is not a valid ZIP/APK: {target}")
            return findings

        msg_info(f"Scanning APK: {os.path.basename(target)}")

        try:
            with zipfile.ZipFile(target, "r") as zf:
                namelist = zf.namelist()
                total_files = len(namelist)
                msg_info(f"APK entries: {total_files}")

                for idx, name in enumerate(namelist):
                    progress_bar(idx + 1, total_files, label=name[:50], width=30)

                    findings.extend(self._scan_apk_entry(zf, name))

        except zipfile.BadZipFile as ex:
            msg_warn(f"Bad ZIP/APK file: {ex}")
        except Exception as ex:
            msg_warn(f"Unexpected error reading APK: {ex}")

        progress_bar(1, 1, label="Done", width=30)
        msg_ok(f"APK scan complete: {self.files_scanned} files, {len(findings)} findings")
        self.findings = findings
        return findings

    # ---------------------------------------------------------------------- #
    # Per-entry dispatcher
    # ---------------------------------------------------------------------- #
    def _scan_apk_entry(self, zf: zipfile.ZipFile, name: str) -> list:
        findings = []
        fname = os.path.basename(name).lower()
        _, ext = os.path.splitext(fname)

        try:
            data = zf.read(name)
        except Exception:
            return findings

        self.bytes_scanned += len(data)

        # -------------------------------------------------- AndroidManifest
        if name == "AndroidManifest.xml":
            findings.extend(self._scan_manifest(data, name))
            self.files_scanned += 1
            return findings

        # -------------------------------------------------- High-value JSON
        if fname in HIGH_VALUE_FILES or fname == os.path.basename(fname) and ext == ".json":
            try:
                text = data.decode("utf-8", errors="replace")
                findings.extend(self._scan_text(text, name, "json_config"))
                self.files_scanned += 1
            except Exception:
                pass
            return findings

        # -------------------------------------------------- Text-based files
        if _is_text_file(name):
            try:
                text = data.decode("utf-8", errors="replace")
                findings.extend(self._scan_text(text, name, "text_file"))
                self.files_scanned += 1
            except Exception:
                pass
            return findings

        # -------------------------------------------------- .dex / .so binary
        if _is_binary_scannable(name):
            findings.extend(self._scan_binary_strings(data, name))
            self.files_scanned += 1
            return findings

        # -------------------------------------------------- Nested APKs / ZIPs (split APK)
        if ext in {".apk", ".zip", ".jar"} and len(data) > 4:
            if data[:4] == b"PK\x03\x04":
                try:
                    import io
                    inner_zf = zipfile.ZipFile(io.BytesIO(data), "r")
                    for inner_name in inner_zf.namelist():
                        inner_findings = self._scan_apk_entry(
                            inner_zf, inner_name
                        )
                        # Prefix location with outer name
                        for f in inner_findings:
                            f.location = f"{name}!{f.location}"
                        findings.extend(inner_findings)
                    inner_zf.close()
                except Exception:
                    pass

        return findings

    # ---------------------------------------------------------------------- #
    # AndroidManifest.xml scanner
    # ---------------------------------------------------------------------- #
    def _scan_manifest(self, data: bytes, name: str) -> list:
        findings = []

        # Binary XML detection: starts with 0x00080000 (AXML magic)
        is_binary_xml = len(data) > 4 and data[:2] == b"\x03\x00"

        # Regardless of binary/text, scan raw bytes for string patterns
        # The binary format still stores strings in a string pool we can grep
        text_repr = data.decode("utf-8", errors="replace")

        # Pattern scan on the decoded bytes
        matches = scan_content(text_repr, filename="AndroidManifest.xml")
        for (
            pattern_name, match_value, severity, category,
            description, confidence, m_start, m_end
        ) in matches:
            self.add_finding(
                severity=severity,
                category=category,
                type_=pattern_name,
                value=match_value,
                location=f"{name}",
                context=text_repr[max(0, m_start - 60): m_end + 60].strip()[:200],
                line_number=0,
                description=description,
                confidence=confidence,
                metadata={"apk_component": "AndroidManifest.xml"},
            )
            findings.append(self.findings[-1])

        # Specific manifest checks on raw bytes
        # Google Maps / Firebase API keys
        for m in _MANIFEST_API_KEY_RE.finditer(data):
            key_val = m.group(1).decode("utf-8", errors="replace")
            self.add_finding(
                severity="critical",
                category="api_key",
                type_="android_manifest_api_key",
                value=key_val,
                location=name,
                context=m.group().decode("utf-8", errors="replace")[:200],
                line_number=0,
                description="API key found in AndroidManifest.xml metadata",
                confidence="high",
                metadata={"apk_component": "AndroidManifest.xml", "key_type": "google_api_key"},
            )
            findings.append(self.findings[-1])

        # Firebase URL
        for m in _MANIFEST_FIREBASE_RE.finditer(data):
            url = m.group().decode("utf-8", errors="replace")
            self.add_finding(
                severity="medium",
                category="url",
                type_="android_firebase_url",
                value=url,
                location=name,
                context=url,
                line_number=0,
                description="Firebase Realtime Database URL found in AndroidManifest.xml",
                confidence="high",
                metadata={"apk_component": "AndroidManifest.xml"},
            )
            findings.append(self.findings[-1])

        # Debuggable flag
        if _MANIFEST_DEBUGGABLE_RE.search(data):
            self.add_finding(
                severity="medium",
                category="misconfiguration",
                type_="android_debuggable",
                value="android:debuggable=true",
                location=name,
                context="android:debuggable=true",
                line_number=0,
                description="Application is marked as debuggable — enables ADB debugging on production builds",
                confidence="high",
                metadata={"apk_component": "AndroidManifest.xml"},
            )
            findings.append(self.findings[-1])

        # AllowBackup flag
        if _MANIFEST_BACKUP_RE.search(data):
            self.add_finding(
                severity="low",
                category="misconfiguration",
                type_="android_allow_backup",
                value="android:allowBackup=true",
                location=name,
                context="android:allowBackup=true",
                line_number=0,
                description="Application allows ADB backup — app data can be extracted without root",
                confidence="high",
                metadata={"apk_component": "AndroidManifest.xml"},
            )
            findings.append(self.findings[-1])

        # Exported components count (info)
        exported_count = len(_MANIFEST_EXPORTED_RE.findall(data))
        if exported_count > 3:
            self.add_finding(
                severity="info",
                category="misconfiguration",
                type_="android_exported_components",
                value=str(exported_count),
                location=name,
                context=f"{exported_count} exported components found",
                line_number=0,
                description=f"{exported_count} exported components detected — review for unauthorized access",
                confidence="medium",
                metadata={"apk_component": "AndroidManifest.xml", "count": exported_count},
            )
            findings.append(self.findings[-1])

        self.files_scanned += 1
        return findings

    # ---------------------------------------------------------------------- #
    # Text file scanner
    # ---------------------------------------------------------------------- #
    def _scan_text(self, text: str, name: str, component_type: str) -> list:
        findings = []
        self.bytes_scanned += len(text.encode("utf-8", errors="replace"))

        matches = scan_content(text, filename=os.path.basename(name))
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
                location=f"{name}:{line_no}",
                context=text[max(0, m_start - 60): m_end + 60].strip()[:200],
                line_number=line_no,
                description=description,
                confidence=confidence,
                metadata={"apk_component": component_type, "file": name},
            )
            findings.append(self.findings[-1])

        # Special handling for google-services.json
        if os.path.basename(name) == "google-services.json":
            try:
                obj = json.loads(text)
                project_info = obj.get("project_info", {})
                firebase_url = project_info.get("firebase_url", "")
                if firebase_url:
                    self.add_finding(
                        severity="medium",
                        category="url",
                        type_="firebase_db_url",
                        value=firebase_url,
                        location=name,
                        context=f"firebase_url: {firebase_url}",
                        line_number=0,
                        description="Firebase Realtime Database URL in google-services.json",
                        confidence="high",
                        metadata={"apk_component": "google-services.json"},
                    )
                    findings.append(self.findings[-1])

                # current_key inside oauth_client
                for client in obj.get("client", []):
                    for oauth in client.get("oauth_client", []):
                        pass  # oauth_client just has client_id — not a secret per se
                    services = client.get("services", {})
                    appinvite = services.get("appinvite_service", {})
                    # api_key
                    for api_entry in client.get("api_key", []):
                        current_key = api_entry.get("current_key", "")
                        if current_key:
                            self.add_finding(
                                severity="critical",
                                category="api_key",
                                type_="google_services_api_key",
                                value=current_key,
                                location=name,
                                context=f"api_key.current_key: {current_key}",
                                line_number=0,
                                description="Google API key found in google-services.json",
                                confidence="high",
                                metadata={"apk_component": "google-services.json"},
                            )
                            findings.append(self.findings[-1])
            except json.JSONDecodeError:
                pass

        # Entropy check on quoted strings
        for qs in extract_quoted_strings(text):
            if len(qs) >= 20 and is_high_entropy(qs):
                self.add_finding(
                    severity="medium",
                    category="entropy",
                    type_="high_entropy_string",
                    value=qs,
                    location=name,
                    context=qs[:120],
                    line_number=0,
                    description="High-entropy quoted string — possible embedded secret",
                    confidence="low",
                    metadata={
                        "apk_component": component_type,
                        "entropy": round(shannon_entropy(qs), 3),
                    },
                )
                findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # Binary strings extraction (.dex / .so)
    # ---------------------------------------------------------------------- #
    def _scan_binary_strings(self, data: bytes, name: str) -> list:
        findings = []

        ascii_strings = _extract_printable_strings(data)
        utf16_strings = _extract_utf16le_strings(data)
        all_strings = ascii_strings + utf16_strings

        # Combine into a pseudo-text blob with newlines
        text_blob = "\n".join(all_strings)

        matches = scan_content(text_blob, filename=os.path.basename(name))
        for (
            pattern_name, match_value, severity, category,
            description, confidence, m_start, m_end
        ) in matches:
            self.add_finding(
                severity=severity,
                category=category,
                type_=pattern_name,
                value=match_value,
                location=name,
                context=text_blob[max(0, m_start - 60): m_end + 60].strip()[:200],
                line_number=0,
                description=f"{description} (extracted from binary {os.path.basename(name)})",
                confidence=confidence,
                metadata={"apk_component": "binary", "file": name},
            )
            findings.append(self.findings[-1])

        # Entropy on long strings from binary
        for s in all_strings:
            if len(s) >= 20 and is_high_entropy(s):
                self.add_finding(
                    severity="low",
                    category="entropy",
                    type_="binary_high_entropy_string",
                    value=s,
                    location=name,
                    context=s[:120],
                    line_number=0,
                    description="High-entropy string extracted from binary — possible hardcoded secret",
                    confidence="low",
                    metadata={
                        "apk_component": "binary",
                        "file": name,
                        "entropy": round(shannon_entropy(s), 3),
                    },
                )
                findings.append(self.findings[-1])

        return findings
