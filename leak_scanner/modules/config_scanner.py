"""
HaakLeaks — Configuration File Scanner
Walks directory trees looking for config files containing secrets:
.env, YAML, JSON, TOML, INI, private keys, cloud credentials, and more.
By Adrian Martinez | HAAK Cybersecurity
"""

import fnmatch
import json
import os
import re

from leak_scanner.core import BaseScanner, SecretFinding
from leak_scanner.patterns import scan_content, SECRET_PATTERNS
from leak_scanner.entropy import shannon_entropy, is_high_entropy, extract_quoted_strings
from leak_scanner.colors import (
    msg_info, msg_ok, msg_warn, msg_secret, section, progress_bar
)


# Default max file size (5 MB)
DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024

# Directories to always skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "vendor", "dist", "build", ".idea", ".vscode", ".next",
    ".nuxt", "coverage", ".tox", ".mypy_cache", ".pytest_cache",
    "target",           # Java/Maven
    "obj", "bin",       # .NET
    ".terraform",       # Terraform cache
    "bower_components",
}

# File extensions that are definitively text config files
CONFIG_EXTENSIONS = {
    ".env", ".conf", ".cfg", ".ini", ".properties",
    ".yml", ".yaml", ".json", ".toml", ".xml", ".plist",
    ".tf", ".tfvars", ".hcl",
    ".sh", ".bash", ".zsh", ".fish",
    ".php", ".py", ".rb", ".go", ".java", ".kt", ".js", ".ts",
    ".htpasswd", ".htaccess",
    ".txt",
}

# Exact filenames to always include regardless of extension
CONFIG_FILENAMES = {
    # .env variants
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test", ".env.example", ".env.sample",
    # Shell config
    ".bashrc", ".bash_profile", ".zshrc", ".profile", ".bash_history",
    ".zsh_history",
    # Tool configs
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".my.cnf", ".mycnf",
    ".boto", ".s3cfg",
    # Docker
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.override.yml", "docker-compose.override.yaml",
    "Dockerfile",
    # Terraform
    "terraform.tfvars", "terraform.tfvars.json",
    # Kubernetes
    "kubeconfig",
    # CI/CD
    ".travis.yml", "circle.yml", ".circleci",
    "Jenkinsfile", ".gitlab-ci.yml",
    "Makefile",
    # CMS / frameworks
    "wp-config.php", "settings.py", "config.php", "database.yml",
    "secrets.yml", "secrets.yaml", "application.properties",
    "application.yml", "application.yaml",
    # .NET
    "appsettings.json", "appsettings.Development.json",
    "appsettings.Production.json", "web.config",
    # Cloud credentials
    "credentials", "credentials.json", "service-account.json",
    "client_secret.json",
    # Spring Boot
    "bootstrap.yml", "bootstrap.properties",
    # Misc
    "config.json", "config.yml", "config.yaml", "config.toml",
    "settings.json", "secrets.json",
    ".htpasswd",
}

# Private key / certificate files — just their existence is a finding
KEY_FILENAMES = {
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "id_rsa.pub", "id_ed25519.pub",
}
KEY_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".jks", ".cer", ".crt", ".ppk", ".pub"}

# Keys in config files that are likely secret values
SECRET_KEY_WORDS = re.compile(
    r"(password|passwd|secret|token|api[_\-]?key|auth[_\-]?key|"
    r"access[_\-]?key|private[_\-]?key|client[_\-]?secret|"
    r"client[_\-]?id|connectionstring|conn[_\-]?str|"
    r"bearer|credentials|jwt[_\-]?secret|salt|encryption[_\-]?key|"
    r"signing[_\-]?key|webhook[_\-]?secret|database[_\-]?url|"
    r"db[_\-]?password|db[_\-]?pass|smtp[_\-]?pass|ftp[_\-]?pass)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Env-file (KEY=VALUE) parser
# ---------------------------------------------------------------------------

_ENV_LINE_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$"
)


def _parse_env_file(text: str) -> list:
    """Parse a .env file and yield (key, value, line_number) tuples."""
    results = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(stripped)
        if m:
            key, value = m.group(1), m.group(2)
            # Strip surrounding quotes
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            results.append((key, value, line_no))
    return results


def _is_sensitive_key(key: str) -> bool:
    return bool(SECRET_KEY_WORDS.search(key))


def _looks_like_secret_value(value: str) -> bool:
    """Quick heuristic: is this value likely a real secret?"""
    if not value or len(value) < 8:
        return False
    # Placeholder values to ignore
    placeholders = {
        "changeme", "change_me", "placeholder", "your_password",
        "your_secret", "xxx", "yyy", "todo", "fixme", "tbd",
        "example", "test", "demo", "dev", "prod", "none", "null",
        "false", "true", "0", "1", "localhost",
    }
    if value.lower() in placeholders:
        return False
    if value.startswith("<") and value.endswith(">"):
        return False
    if value.startswith("${") and value.endswith("}"):
        return False
    # High entropy is a strong signal
    if is_high_entropy(value):
        return True
    # Looks like a base64/hex blob
    if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", value):
        return True
    return True  # If the key is sensitive and value isn't a placeholder, report it


class ConfigScanner(BaseScanner):
    NAME = "config"
    DESCRIPTION = "Scan directories for configuration files containing secrets"

    def scan(self) -> list:
        section("Config File Scanner", "⚙")
        findings = []
        target = os.path.abspath(self.target)

        max_file_size  = self.options.get("max_file_size", DEFAULT_MAX_FILE_SIZE)
        include_globs  = self.options.get("include", [])   # e.g. ["*.env", "*.yml"]
        exclude_globs  = self.options.get("exclude", [])   # e.g. ["test/*"]
        recursive      = self.options.get("recursive", True)

        # Target can be a single file or a directory
        if os.path.isfile(target):
            msg_info(f"Scanning single file: {target}")
            findings.extend(
                self._scan_file(target, max_file_size=max_file_size)
            )
        elif os.path.isdir(target):
            msg_info(f"Scanning directory: {target}")
            # Collect all candidate files first for progress bar
            candidates = self._collect_files(
                target, recursive, include_globs, exclude_globs, max_file_size
            )
            total = len(candidates)
            msg_info(f"Config files to scan: {total}")

            for idx, fpath in enumerate(candidates):
                rel = os.path.relpath(fpath, target)
                progress_bar(idx + 1, total, label=rel[:50], width=30)
                findings.extend(self._scan_file(fpath, max_file_size=max_file_size))

            progress_bar(total, total, label="Done", width=30)
        else:
            msg_warn(f"Target not found: {target}")
            return findings

        msg_ok(
            f"Config scan complete: {self.files_scanned} files, "
            f"{self.bytes_scanned // 1024} KB, {len(findings)} findings"
        )
        self.findings = findings
        return findings

    # ---------------------------------------------------------------------- #
    # File collection
    # ---------------------------------------------------------------------- #
    def _collect_files(
        self,
        root: str,
        recursive: bool,
        include_globs: list,
        exclude_globs: list,
        max_file_size: int,
    ) -> list:
        candidates = []

        walker = os.walk(root) if recursive else [(root, [], os.listdir(root))]

        for dirpath, dirnames, filenames in walker:
            # Prune skipped directories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS and not d.startswith(".")
                   or d in {".env"}  # keep .env dirs if any
            ]
            # Also remove hidden dirs except known-useful ones
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                # Size check
                try:
                    if os.path.getsize(fpath) > max_file_size:
                        continue
                except OSError:
                    continue

                if self._is_candidate(fname, fpath, include_globs, exclude_globs):
                    candidates.append(fpath)

        return candidates

    def _is_candidate(
        self, fname: str, fpath: str,
        include_globs: list, exclude_globs: list
    ) -> bool:
        fname_lower = fname.lower()
        _, ext = os.path.splitext(fname_lower)

        # Explicit include overrides everything
        if include_globs:
            return any(fnmatch.fnmatch(fname_lower, g) for g in include_globs)

        # Explicit exclude
        if exclude_globs:
            if any(fnmatch.fnmatch(fpath, g) or fnmatch.fnmatch(fname_lower, g)
                   for g in exclude_globs):
                return False

        # Exact filename match
        if fname_lower in CONFIG_FILENAMES or fname in CONFIG_FILENAMES:
            return True

        # Key file match
        if fname_lower in KEY_FILENAMES or ext in KEY_EXTENSIONS:
            return True

        # Extension match
        if ext in CONFIG_EXTENSIONS:
            return True

        # .env.* variants (e.g., .env.local)
        if fname_lower.startswith(".env"):
            return True

        return False

    # ---------------------------------------------------------------------- #
    # Single file scanner
    # ---------------------------------------------------------------------- #
    def _scan_file(self, fpath: str, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> list:
        findings = []
        fname = os.path.basename(fpath)
        fname_lower = fname.lower()
        _, ext = os.path.splitext(fname_lower)

        # -------------------------------------------------- Key/cert files
        if fname_lower in KEY_FILENAMES or ext in KEY_EXTENSIONS:
            findings.extend(self._report_key_file(fpath, fname))
            # Still try to read and pattern-match .pem files
            if ext == ".pem":
                text = self._read_text(fpath, max_file_size)
                if text:
                    findings.extend(self._scan_text(text, fpath, "pem_file"))
            return findings

        # -------------------------------------------------- Read as text
        text = self._read_text(fpath, max_file_size)
        if text is None:
            return findings

        self.files_scanned += 1
        self.bytes_scanned += len(text.encode("utf-8", errors="replace"))

        # -------------------------------------------------- .env files
        if fname_lower.startswith(".env") or fname_lower == ".env":
            findings.extend(self._scan_env_file(text, fpath))

        # -------------------------------------------------- Pattern scan on full text
        findings.extend(self._scan_text(text, fpath, ext.lstrip(".") or fname_lower))

        # -------------------------------------------------- YAML/JSON structured scan
        if ext in {".yml", ".yaml"}:
            findings.extend(self._scan_yaml_keys(text, fpath))
        elif ext == ".json":
            findings.extend(self._scan_json_keys(text, fpath))

        # -------------------------------------------------- shell history files
        if "history" in fname_lower:
            findings.extend(self._scan_shell_history(text, fpath))

        return findings

    # ---------------------------------------------------------------------- #
    # Private key / certificate file reporting
    # ---------------------------------------------------------------------- #
    def _report_key_file(self, fpath: str, fname: str) -> list:
        findings = []
        _, ext = os.path.splitext(fname.lower())

        key_types = {
            ".pem": ("RSA/EC/DH key or certificate (PEM)", "critical"),
            ".key": ("Private key file", "critical"),
            ".p12": ("PKCS#12 certificate bundle (likely contains private key)", "critical"),
            ".pfx": ("PFX certificate bundle (likely contains private key)", "critical"),
            ".jks": ("Java KeyStore (may contain private keys)", "high"),
            ".ppk": ("PuTTY private key file", "critical"),
            ".cer": ("Certificate file (public — verify no private key included)", "low"),
            ".crt": ("Certificate file", "low"),
        }

        if fname.lower() in {"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"}:
            key_type, severity = "SSH private key", "critical"
        elif fname.lower().endswith(".pub"):
            key_type, severity = "SSH public key (low risk — but verify)", "info"
        else:
            key_type, severity = key_types.get(ext, ("Key/certificate file", "high"))

        self.add_finding(
            severity=severity,
            category="private_key",
            type_="private_key_file",
            value=fpath,
            location=fpath,
            context=f"File exists: {fpath}",
            line_number=0,
            description=f"{key_type} found at {fpath}",
            confidence="high",
            metadata={"file_type": key_type, "path": fpath},
        )
        findings.append(self.findings[-1])
        self.files_scanned += 1
        return findings

    # ---------------------------------------------------------------------- #
    # .env file parser
    # ---------------------------------------------------------------------- #
    def _scan_env_file(self, text: str, fpath: str) -> list:
        findings = []

        for key, value, line_no in _parse_env_file(text):
            if not value:
                continue

            if _is_sensitive_key(key) and _looks_like_secret_value(value):
                self.add_finding(
                    severity="high",
                    category="env_secret",
                    type_="env_key_value_secret",
                    value=value,
                    location=f"{fpath}:{line_no}",
                    context=f"{key}={value}",
                    line_number=line_no,
                    description=f"Secret value assigned to '{key}' in .env file",
                    confidence="high",
                    metadata={"key_name": key, "file": fpath},
                )
                findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # Pattern scan on raw text
    # ---------------------------------------------------------------------- #
    def _scan_text(self, text: str, fpath: str, file_type: str) -> list:
        findings = []
        fname = os.path.basename(fpath)

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
                location=f"{fpath}:{line_no}",
                context=text[max(0, m_start - 60): m_end + 60].strip()[:200],
                line_number=line_no,
                description=description,
                confidence=confidence,
                metadata={"file_type": file_type, "file": fpath},
            )
            findings.append(self.findings[-1])

        # Entropy on quoted strings
        for qs in extract_quoted_strings(text):
            if len(qs) >= 20 and is_high_entropy(qs):
                self.add_finding(
                    severity="medium",
                    category="entropy",
                    type_="high_entropy_config_value",
                    value=qs,
                    location=fpath,
                    context=qs[:120],
                    line_number=0,
                    description="High-entropy value in config file — possible secret",
                    confidence="low",
                    metadata={"file": fpath, "entropy": round(shannon_entropy(qs), 3)},
                )
                findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # YAML structured key scanner
    # ---------------------------------------------------------------------- #
    def _scan_yaml_keys(self, text: str, fpath: str) -> list:
        """
        Simple regex-based YAML key scanner — avoids needing PyYAML.
        Looks for   key: value   lines where key is secret-sounding.
        """
        findings = []
        line_re = re.compile(
            r"^\s*([A-Za-z_\-][A-Za-z0-9_\-]*):\s+['\"]?(.+?)['\"]?\s*$",
            re.MULTILINE,
        )
        for m in line_re.finditer(text):
            key, value = m.group(1), m.group(2).strip()
            if not value or value in {"null", "~", "[]", "{}"}:
                continue
            if _is_sensitive_key(key) and _looks_like_secret_value(value):
                line_no = text[:m.start()].count("\n") + 1
                self.add_finding(
                    severity="high",
                    category="yaml_secret",
                    type_="yaml_key_value_secret",
                    value=value,
                    location=f"{fpath}:{line_no}",
                    context=m.group().strip()[:200],
                    line_number=line_no,
                    description=f"Secret-looking value for YAML key '{key}'",
                    confidence="medium",
                    metadata={"key_name": key, "file": fpath},
                )
                findings.append(self.findings[-1])
        return findings

    # ---------------------------------------------------------------------- #
    # JSON structured key scanner
    # ---------------------------------------------------------------------- #
    def _scan_json_keys(self, text: str, fpath: str) -> list:
        """Recursively walk a JSON object and flag secret-sounding keys."""
        findings = []

        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return findings

        def walk(node, path=""):
            if isinstance(node, dict):
                for k, v in node.items():
                    current_path = f"{path}.{k}" if path else k
                    if isinstance(v, str) and _is_sensitive_key(k) and _looks_like_secret_value(v):
                        # Find line number by searching for the key in text
                        key_re = re.compile(re.escape(f'"{k}"'))
                        m = key_re.search(text)
                        line_no = text[:m.start()].count("\n") + 1 if m else 0
                        self.add_finding(
                            severity="high",
                            category="json_secret",
                            type_="json_key_value_secret",
                            value=v,
                            location=f"{fpath}:{line_no}",
                            context=f"{current_path}: {v[:60]}",
                            line_number=line_no,
                            description=f"Secret-looking value for JSON key '{k}'",
                            confidence="medium",
                            metadata={"key_path": current_path, "file": fpath},
                        )
                        findings.append(self.findings[-1])
                    elif isinstance(v, (dict, list)):
                        walk(v, current_path)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{path}[{i}]")

        walk(obj)
        return findings

    # ---------------------------------------------------------------------- #
    # Shell history scanner
    # ---------------------------------------------------------------------- #
    def _scan_shell_history(self, text: str, fpath: str) -> list:
        """Look for secrets passed as CLI arguments in shell history."""
        findings = []
        secret_flag_re = re.compile(
            r"(?:--?(?:password|passwd|secret|token|key|api[_\-]?key|auth))[=\s]+([^\s;|&]{6,})",
            re.IGNORECASE,
        )
        env_inline_re = re.compile(
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|AUTH_KEY|CLIENT_SECRET)\s*=\s*([^\s;|&]{6,})",
            re.IGNORECASE,
        )
        curl_auth_re = re.compile(
            r"curl\s+.*?(?:-u|--user)\s+([^\s@]+:[^\s@]+)",
            re.IGNORECASE,
        )

        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for pattern, type_, desc in [
                (secret_flag_re, "shell_cli_secret", "Secret value passed as CLI argument in shell history"),
                (env_inline_re, "shell_env_inline", "Secret in inline environment variable in shell history"),
                (curl_auth_re, "shell_curl_creds", "curl credentials found in shell history"),
            ]:
                for m in pattern.finditer(line):
                    value = m.group(1)
                    self.add_finding(
                        severity="high",
                        category="shell_history",
                        type_=type_,
                        value=value,
                        location=f"{fpath}:{line_no}",
                        context=line[:200],
                        line_number=line_no,
                        description=desc,
                        confidence="medium",
                        metadata={"file": fpath, "command": line[:200]},
                    )
                    findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # Helpers
    # ---------------------------------------------------------------------- #
    @staticmethod
    def _read_text(fpath: str, max_size: int = DEFAULT_MAX_FILE_SIZE) -> str | None:
        try:
            size = os.path.getsize(fpath)
            if size > max_size:
                return None
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
