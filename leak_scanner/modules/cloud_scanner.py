"""
HaakLeaks — Cloud Storage Scanner
Checks for publicly accessible S3 buckets, Azure Blob containers,
and GCP Storage buckets, then scans any exposed files for secrets.
By Adrian Martinez | HAAK Cybersecurity
"""

import json
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
from io import BytesIO

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from leak_scanner.core import BaseScanner, SecretFinding
from leak_scanner.patterns import scan_content, SECRET_PATTERNS
from leak_scanner.entropy import shannon_entropy, is_high_entropy, extract_quoted_strings
from leak_scanner.colors import (
    msg_info, msg_ok, msg_warn, msg_secret, section, progress_bar
)


# Max size of a single cloud file to download and scan (default 2 MB)
DEFAULT_MAX_OBJECT_SIZE = 2 * 1024 * 1024

# Request timeout (seconds)
REQUEST_TIMEOUT = 15

# Files that are high-value to scan when found in cloud storage
HIGH_VALUE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials", "credentials.json", "service-account.json",
    "secrets.yml", "secrets.yaml", "config.json", "config.yml",
    "database.yml", "settings.py", "wp-config.php",
    "terraform.tfvars", ".npmrc", ".netrc",
    "id_rsa", "id_ed25519",
    "google-services.json", "amplifyconfiguration.json",
}

HIGH_VALUE_EXTENSIONS = {
    ".env", ".pem", ".key", ".p12", ".pfx",
    ".sql", ".bak", ".dump",
    ".csv",   # data dumps
    ".log",
}

SCANNABLE_CONTENT_TYPES = {
    "text/plain", "text/html", "application/json", "application/xml",
    "text/xml", "application/x-yaml", "text/yaml", "text/csv",
    "application/javascript", "text/javascript",
    "application/x-www-form-urlencoded",
    "application/toml", "text/x-properties",
}


# ---------------------------------------------------------------------------
# Cloud provider detection
# ---------------------------------------------------------------------------

def _detect_provider(target: str) -> tuple:
    """
    Returns (provider, bucket_name, container_name, account_name, prefix).
    provider: 's3' | 'azure' | 'gcp' | 'unknown'
    """
    target = target.strip().rstrip("/")

    # s3://bucket-name
    m = re.match(r"^s3://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]?)(/.*)?$", target, re.IGNORECASE)
    if m:
        return ("s3", m.group(1), "", "", m.group(2) or "")

    # https://bucket.s3.amazonaws.com or https://s3.amazonaws.com/bucket
    m = re.match(r"^https?://([a-z0-9\-\.]+)\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com(/.*)?$",
                 target, re.IGNORECASE)
    if m:
        return ("s3", m.group(1), "", "", m.group(2) or "")

    m = re.match(r"^https?://s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9\-\.]+)(/.*)?$",
                 target, re.IGNORECASE)
    if m:
        return ("s3", m.group(1), "", "", m.group(2) or "")

    # https://account.blob.core.windows.net/container
    m = re.match(
        r"^https?://([a-z0-9]+)\.blob\.core\.windows\.net/([a-z0-9\-]+)(/.*)?$",
        target, re.IGNORECASE,
    )
    if m:
        return ("azure", "", m.group(2), m.group(1), m.group(3) or "")

    # https://storage.googleapis.com/bucket or gs://bucket
    m = re.match(r"^gs://([a-z0-9][a-z0-9\-_\.]{1,61})(/.*)?$", target, re.IGNORECASE)
    if m:
        return ("gcp", m.group(1), "", "", m.group(2) or "")

    m = re.match(
        r"^https?://storage\.googleapis\.com/([a-z0-9\-_\.]+)(/.*)?$",
        target, re.IGNORECASE,
    )
    if m:
        return ("gcp", m.group(1), "", "", m.group(2) or "")

    m = re.match(
        r"^https?://([a-z0-9\-_\.]+)\.storage\.googleapis\.com(/.*)?$",
        target, re.IGNORECASE,
    )
    if m:
        return ("gcp", m.group(1), "", "", m.group(2) or "")

    # Bare bucket name → assume S3 for convenience
    if re.match(r"^[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]?$", target, re.IGNORECASE):
        return ("s3", target, "", "", "")

    return ("unknown", target, "", "", "")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str, timeout: int = REQUEST_TIMEOUT, stream: bool = False,
         max_size: int = DEFAULT_MAX_OBJECT_SIZE) -> requests.Response | None:
    try:
        resp = requests.get(
            url, timeout=timeout, stream=stream,
            headers={"User-Agent": "Mozilla/5.0 HaakLeaks/1.0"},
            allow_redirects=True,
        )
        return resp
    except requests.exceptions.RequestException as ex:
        return None


def _fetch_object_text(url: str, max_size: int = DEFAULT_MAX_OBJECT_SIZE) -> str | None:
    """Download an object and return text content if scannable."""
    resp = _get(url, stream=True)
    if resp is None or resp.status_code != 200:
        return None

    content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()

    # Check if binary content type
    binary_types = {"image/", "video/", "audio/", "application/octet-stream",
                    "application/zip", "application/gzip"}
    if any(content_type.startswith(bt) for bt in binary_types):
        return None

    # Stream up to max_size
    chunks = []
    total = 0
    for chunk in resp.iter_content(chunk_size=8192):
        total += len(chunk)
        chunks.append(chunk)
        if total >= max_size:
            break

    raw = b"".join(chunks)

    # Try to detect if binary
    null_count = raw[:512].count(b"\x00")
    if null_count > 20:
        return None

    return raw.decode("utf-8", errors="replace")


def _is_interesting_object(key: str) -> bool:
    """Return True if this object key is worth scanning."""
    fname = os.path.basename(key.rstrip("/")).lower()
    _, ext = os.path.splitext(fname)

    if fname in HIGH_VALUE_FILENAMES:
        return True
    if ext in HIGH_VALUE_EXTENSIONS:
        return True
    # Text-based config extensions
    if ext in {".yml", ".yaml", ".json", ".env", ".properties", ".toml",
               ".ini", ".cfg", ".conf", ".xml", ".txt", ".sh", ".log",
               ".tf", ".tfvars", ".py", ".rb", ".php"}:
        return True
    return False


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class CloudScanner(BaseScanner):
    NAME = "cloud"
    DESCRIPTION = "Scan cloud storage (S3/Azure/GCP) for exposed files and secrets"

    def scan(self) -> list:
        section("Cloud Storage Scanner", "☁")
        findings = []

        if not REQUESTS_AVAILABLE:
            msg_warn("'requests' library not installed. Install with: pip install requests")
            return findings

        target = self.target.strip()
        provider, bucket, container, account, prefix = _detect_provider(target)

        msg_info(f"Provider: {provider.upper()}  |  Target: {target}")

        if provider == "s3":
            findings.extend(self._scan_s3(bucket, prefix))
        elif provider == "azure":
            findings.extend(self._scan_azure(account, container, prefix))
        elif provider == "gcp":
            findings.extend(self._scan_gcp(bucket, prefix))
        else:
            msg_warn(f"Cannot determine cloud provider for: {target}")
            msg_info("Supported formats: s3://bucket, bucket.s3.amazonaws.com, "
                     "account.blob.core.windows.net/container, gs://bucket, "
                     "storage.googleapis.com/bucket")

        msg_ok(f"Cloud scan complete: {self.files_scanned} objects, {len(findings)} findings")
        self.findings = findings
        return findings

    # ------------------------------------------------------------------ #
    # AWS S3
    # ------------------------------------------------------------------ #
    def _scan_s3(self, bucket: str, prefix: str = "") -> list:
        findings = []
        base_url = f"https://{bucket}.s3.amazonaws.com"

        # ----- Check if bucket is listable ---------------------------------
        list_url = base_url + "/"
        if prefix:
            list_url += f"?prefix={urllib.parse.quote(prefix.lstrip('/'))}"

        msg_info(f"Testing S3 bucket listing: {list_url}")
        resp = _get(list_url)

        if resp is None:
            msg_warn("No response from S3 endpoint")
            return findings

        if resp.status_code == 403:
            self.add_finding(
                severity="info",
                category="cloud_access",
                type_="s3_bucket_listing_forbidden",
                value=bucket,
                location=list_url,
                context="HTTP 403 — bucket exists but listing is forbidden",
                line_number=0,
                description=f"S3 bucket '{bucket}' exists but public listing is disabled (403)",
                confidence="high",
                metadata={"provider": "s3", "bucket": bucket, "url": list_url},
            )
            findings.append(self.findings[-1])
            # Still try known sensitive file paths
            findings.extend(self._s3_probe_known_files(base_url, bucket))
            return findings

        if resp.status_code == 404:
            msg_warn(f"S3 bucket does not exist or is inaccessible: {bucket}")
            return findings

        if resp.status_code == 200:
            self.add_finding(
                severity="medium",
                category="cloud_access",
                type_="s3_bucket_public_listing",
                value=bucket,
                location=list_url,
                context="HTTP 200 — bucket listing is publicly accessible",
                line_number=0,
                description=f"S3 bucket '{bucket}' is publicly listable — all objects are enumerable",
                confidence="high",
                metadata={"provider": "s3", "bucket": bucket, "url": list_url},
            )
            findings.append(self.findings[-1])

            # Parse XML listing
            try:
                root = ET.fromstring(resp.text)
                ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
                contents = root.findall(".//s3:Contents", ns) or root.findall(".//Contents")

                keys = []
                for obj in contents:
                    key_el = obj.find("s3:Key", ns) or obj.find("Key")
                    size_el = obj.find("s3:Size", ns) or obj.find("Size")
                    if key_el is not None:
                        key = key_el.text or ""
                        size = int(size_el.text or "0") if size_el is not None else 0
                        keys.append((key, size))

                msg_info(f"Objects found: {len(keys)}")
                interesting = [(k, s) for k, s in keys if _is_interesting_object(k)]
                msg_info(f"Interesting objects: {len(interesting)}")

                for idx, (key, size) in enumerate(interesting):
                    progress_bar(idx + 1, len(interesting), label=key[:50], width=30)
                    obj_url = f"{base_url}/{urllib.parse.quote(key)}"
                    findings.extend(
                        self._scan_cloud_object(obj_url, key, size, "s3", bucket)
                    )

                if interesting:
                    progress_bar(len(interesting), len(interesting), label="Done", width=30)

            except ET.ParseError as ex:
                msg_warn(f"Failed to parse S3 listing XML: {ex}")

        # ----- Check bucket policy & ACL -----------------------------------
        for check_type, param in [("policy", "?policy"), ("acl", "?acl")]:
            check_url = base_url + "/" + param
            cr = _get(check_url)
            if cr and cr.status_code == 200:
                self.add_finding(
                    severity="high",
                    category="cloud_access",
                    type_=f"s3_bucket_{check_type}_exposed",
                    value=bucket,
                    location=check_url,
                    context=cr.text[:200] if cr.text else "",
                    line_number=0,
                    description=f"S3 bucket {check_type} is publicly readable — may expose access controls",
                    confidence="high",
                    metadata={"provider": "s3", "bucket": bucket, "url": check_url, "check": check_type},
                )
                findings.append(self.findings[-1])

                # Scan policy text for leaked credentials or overly permissive rules
                if check_type == "policy" and cr.text:
                    findings.extend(
                        self._scan_policy_text(cr.text, check_url, "s3", bucket)
                    )

        return findings

    def _s3_probe_known_files(self, base_url: str, bucket: str) -> list:
        """When listing is forbidden, try well-known sensitive file paths."""
        findings = []
        probe_paths = list(HIGH_VALUE_FILENAMES) + [
            "backup.sql", "dump.sql", "database.sql",
            "data.csv", "users.csv", "emails.csv",
            "config/database.yml", "config/secrets.yml",
            ".git/config",
        ]
        for path in probe_paths:
            url = f"{base_url}/{path}"
            resp = _get(url)
            if resp and resp.status_code == 200:
                findings.extend(
                    self._scan_cloud_object(url, path, 0, "s3", bucket)
                )
        return findings

    # ------------------------------------------------------------------ #
    # Azure Blob Storage
    # ------------------------------------------------------------------ #
    def _scan_azure(self, account: str, container: str, prefix: str = "") -> list:
        findings = []
        base_url = f"https://{account}.blob.core.windows.net"
        list_url = (
            f"{base_url}/{container}"
            f"?restype=container&comp=list"
        )
        if prefix:
            list_url += f"&prefix={urllib.parse.quote(prefix.lstrip('/'))}"

        msg_info(f"Testing Azure container listing: {list_url}")
        resp = _get(list_url)

        if resp is None:
            msg_warn("No response from Azure endpoint")
            return findings

        if resp.status_code == 403 or resp.status_code == 401:
            self.add_finding(
                severity="info",
                category="cloud_access",
                type_="azure_container_listing_forbidden",
                value=f"{account}/{container}",
                location=list_url,
                context=f"HTTP {resp.status_code} — container exists but listing forbidden",
                line_number=0,
                description=f"Azure container '{container}' exists but is not publicly listable",
                confidence="high",
                metadata={"provider": "azure", "account": account, "container": container},
            )
            findings.append(self.findings[-1])
            return findings

        if resp.status_code == 404:
            msg_warn(f"Azure container not found: {account}/{container}")
            return findings

        if resp.status_code == 200:
            self.add_finding(
                severity="medium",
                category="cloud_access",
                type_="azure_container_public_listing",
                value=f"{account}/{container}",
                location=list_url,
                context="HTTP 200 — Azure container listing is publicly accessible",
                line_number=0,
                description=f"Azure Blob container '{container}' in account '{account}' is publicly listable",
                confidence="high",
                metadata={"provider": "azure", "account": account, "container": container},
            )
            findings.append(self.findings[-1])

            # Parse XML listing
            try:
                root = ET.fromstring(resp.text)
                blobs = root.findall(".//Blob")

                keys = []
                for blob in blobs:
                    name_el = blob.find("Name")
                    props = blob.find("Properties")
                    size_el = props.find("Content-Length") if props is not None else None
                    if name_el is not None:
                        key = name_el.text or ""
                        size = int(size_el.text or "0") if size_el is not None else 0
                        keys.append((key, size))

                msg_info(f"Blobs found: {len(keys)}")
                interesting = [(k, s) for k, s in keys if _is_interesting_object(k)]

                for idx, (key, size) in enumerate(interesting):
                    progress_bar(idx + 1, len(interesting), label=key[:50], width=30)
                    obj_url = f"{base_url}/{container}/{urllib.parse.quote(key)}"
                    findings.extend(
                        self._scan_cloud_object(obj_url, key, size, "azure",
                                                f"{account}/{container}")
                    )

                if interesting:
                    progress_bar(len(interesting), len(interesting), label="Done", width=30)

            except ET.ParseError as ex:
                msg_warn(f"Failed to parse Azure listing XML: {ex}")

        return findings

    # ------------------------------------------------------------------ #
    # GCP Storage
    # ------------------------------------------------------------------ #
    def _scan_gcp(self, bucket: str, prefix: str = "") -> list:
        findings = []
        api_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o"
        params = {"maxResults": 1000}
        if prefix:
            params["prefix"] = prefix.lstrip("/")

        query_string = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
        list_url = f"{api_url}?{query_string}"

        msg_info(f"Testing GCP bucket listing: {list_url}")
        resp = _get(list_url)

        if resp is None:
            msg_warn("No response from GCP endpoint")
            return findings

        if resp.status_code in {401, 403}:
            self.add_finding(
                severity="info",
                category="cloud_access",
                type_="gcp_bucket_listing_forbidden",
                value=bucket,
                location=list_url,
                context=f"HTTP {resp.status_code} — bucket exists but listing forbidden",
                line_number=0,
                description=f"GCP bucket '{bucket}' exists but public listing is disabled",
                confidence="high",
                metadata={"provider": "gcp", "bucket": bucket},
            )
            findings.append(self.findings[-1])
            return findings

        if resp.status_code == 404:
            msg_warn(f"GCP bucket not found: {bucket}")
            return findings

        if resp.status_code == 200:
            self.add_finding(
                severity="medium",
                category="cloud_access",
                type_="gcp_bucket_public_listing",
                value=bucket,
                location=list_url,
                context="HTTP 200 — GCP bucket listing is publicly accessible",
                line_number=0,
                description=f"GCP Storage bucket '{bucket}' is publicly listable",
                confidence="high",
                metadata={"provider": "gcp", "bucket": bucket},
            )
            findings.append(self.findings[-1])

            try:
                data = resp.json()
                items = data.get("items", [])
                msg_info(f"Objects found: {len(items)}")

                interesting = [
                    item for item in items if _is_interesting_object(item.get("name", ""))
                ]

                for idx, item in enumerate(interesting):
                    key = item.get("name", "")
                    size = int(item.get("size", 0))
                    media_link = item.get("mediaLink", "")
                    obj_url = (
                        media_link or
                        f"https://storage.googleapis.com/{bucket}/{urllib.parse.quote(key)}"
                    )
                    progress_bar(idx + 1, len(interesting), label=key[:50], width=30)
                    findings.extend(
                        self._scan_cloud_object(obj_url, key, size, "gcp", bucket)
                    )

                if interesting:
                    progress_bar(len(interesting), len(interesting), label="Done", width=30)

            except (json.JSONDecodeError, ValueError) as ex:
                msg_warn(f"Failed to parse GCP listing JSON: {ex}")

        return findings

    # ------------------------------------------------------------------ #
    # Common: scan a single cloud object
    # ------------------------------------------------------------------ #
    def _scan_cloud_object(
        self,
        url: str,
        key: str,
        size: int,
        provider: str,
        bucket: str,
    ) -> list:
        findings = []
        fname = os.path.basename(key.rstrip("/"))
        fname_lower = fname.lower()
        _, ext = os.path.splitext(fname_lower)

        max_size = self.options.get("max_object_size", DEFAULT_MAX_OBJECT_SIZE)

        # Private key files — just report existence
        if ext in {".pem", ".key", ".p12", ".pfx", ".ppk"} or \
           fname_lower in {"id_rsa", "id_ed25519"}:
            self.add_finding(
                severity="critical",
                category="cloud_secret_file",
                type_="cloud_private_key_exposed",
                value=url,
                location=url,
                context=f"Private key/cert file publicly accessible at {url}",
                line_number=0,
                description=f"Private key/certificate file '{fname}' is publicly accessible in cloud storage",
                confidence="high",
                metadata={"provider": provider, "bucket": bucket, "key": key, "url": url},
            )
            findings.append(self.findings[-1])

        if size > max_size:
            return findings

        text = _fetch_object_text(url, max_size=max_size)
        if text is None:
            return findings

        self.files_scanned += 1
        self.bytes_scanned += len(text.encode("utf-8", errors="replace"))

        # Pattern scan
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
                location=f"{url}:{line_no}",
                context=text[max(0, m_start - 60): m_end + 60].strip()[:200],
                line_number=line_no,
                description=f"{description} (in publicly exposed cloud object)",
                confidence=confidence,
                metadata={
                    "provider": provider,
                    "bucket": bucket,
                    "key": key,
                    "url": url,
                },
            )
            findings.append(self.findings[-1])

        # Entropy analysis
        for qs in extract_quoted_strings(text):
            if len(qs) >= 20 and is_high_entropy(qs):
                self.add_finding(
                    severity="medium",
                    category="entropy",
                    type_="cloud_high_entropy_value",
                    value=qs,
                    location=url,
                    context=qs[:120],
                    line_number=0,
                    description="High-entropy value in publicly exposed cloud object",
                    confidence="low",
                    metadata={
                        "provider": provider,
                        "bucket": bucket,
                        "key": key,
                        "entropy": round(shannon_entropy(qs), 3),
                    },
                )
                findings.append(self.findings[-1])

        return findings

    # ------------------------------------------------------------------ #
    # Scan IAM policy text for overly permissive rules or leaked creds
    # ------------------------------------------------------------------ #
    def _scan_policy_text(
        self, text: str, url: str, provider: str, bucket: str
    ) -> list:
        findings = []

        # Public "Allow *" patterns in S3 bucket policy
        public_allow_re = re.compile(
            r'"Principal"\s*:\s*(?:"\*"|\{"AWS"\s*:\s*"\*"\})',
            re.IGNORECASE,
        )
        if public_allow_re.search(text):
            self.add_finding(
                severity="critical",
                category="cloud_access",
                type_="s3_bucket_policy_public_allow",
                value=bucket,
                location=url,
                context=text[:300],
                line_number=0,
                description=f"S3 bucket policy allows public access (* principal) — bucket is fully public",
                confidence="high",
                metadata={"provider": provider, "bucket": bucket},
            )
            findings.append(self.findings[-1])

        # Pattern scan on policy for embedded keys
        matches = scan_content(text, filename="bucket-policy.json")
        for (
            pattern_name, match_value, severity, category,
            description, confidence, m_start, m_end
        ) in matches:
            self.add_finding(
                severity=severity,
                category=category,
                type_=pattern_name,
                value=match_value,
                location=url,
                context=text[max(0, m_start - 40): m_end + 40].strip()[:200],
                line_number=0,
                description=f"{description} (found in bucket policy)",
                confidence=confidence,
                metadata={"provider": provider, "bucket": bucket},
            )
            findings.append(self.findings[-1])

        return findings
