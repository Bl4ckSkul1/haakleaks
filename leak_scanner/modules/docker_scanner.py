"""
HaakLeaks — Docker Image Scanner
Scans Docker image layers for secrets embedded in the filesystem or build history.
By Adrian Martinez | HAAK Cybersecurity
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from leak_scanner.core import BaseScanner, SecretFinding
from leak_scanner.patterns import scan_content, SECRET_PATTERNS
from leak_scanner.entropy import shannon_entropy, is_high_entropy, extract_quoted_strings
from leak_scanner.colors import (
    msg_info, msg_ok, msg_warn, msg_secret, section, progress_bar
)


# Text-based file extensions worth scanning inside layers
TEXT_EXTENSIONS = {
    ".env", ".conf", ".cfg", ".ini", ".properties",
    ".json", ".yml", ".yaml", ".xml", ".toml",
    ".sh", ".bash", ".zsh", ".fish",
    ".py", ".rb", ".php", ".js", ".ts", ".go", ".java",
    ".tf", ".tfvars", ".hcl",
    ".txt", ".log",
    ".htpasswd", ".htaccess",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".my.cnf",
}

SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials", "credentials.json", "service-account.json",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".my.cnf",
    "docker-compose.yml", "secrets.yml", "secrets.yaml",
    "terraform.tfvars",
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "Dockerfile",
}

SENSITIVE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".jks", ".cer", ".crt", ".ppk"}

MAX_TEXT_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file in layer


def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


def _run_docker(args: list, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="replace",
    )


def _is_text_file(path: str) -> bool:
    fname = os.path.basename(path).lower()
    _, ext = os.path.splitext(fname)
    if fname in SENSITIVE_FILENAMES or ext in TEXT_EXTENSIONS:
        return True
    # Try reading first 512 bytes to detect binary
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(512)
        null_count = chunk.count(b"\x00")
        return null_count < (len(chunk) * 0.10) if chunk else False
    except OSError:
        return False


def _safe_read_text(path: str, max_bytes: int = MAX_TEXT_FILE_SIZE) -> str | None:
    """Read a file as text, returning None on error or if it exceeds max_bytes."""
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


class DockerScanner(BaseScanner):
    NAME = "docker"
    DESCRIPTION = "Scan Docker image layers and history for embedded secrets"

    def scan(self) -> list:
        section("Docker Image Scanner", "🐳")
        findings = []
        target = self.target.strip()

        # ------------------------------------------------------------------ #
        # Determine: docker image name vs .tar file
        # ------------------------------------------------------------------ #
        is_tar = target.endswith(".tar") and os.path.isfile(target)

        if is_tar:
            msg_info(f"Scanning Docker tar archive: {target}")
            findings = self._scan_tar(target, image_name=target)
        elif _docker_available():
            msg_info(f"Docker available. Scanning image: {target}")
            findings = self._scan_via_docker(target)
        else:
            msg_warn("Docker is not available. If the target is a .tar file, rename it or pass as absolute path ending in .tar")
            return findings

        self.findings = findings
        return findings

    # ---------------------------------------------------------------------- #
    # Docker CLI path
    # ---------------------------------------------------------------------- #
    def _scan_via_docker(self, image: str) -> list:
        findings = []
        tmpdir = tempfile.mkdtemp(prefix="haakleaks_docker_")

        try:
            # ---------------------------------------------------------- #
            # 1. Pull image if not present (optional, skip if unavailable)
            # ---------------------------------------------------------- #
            # Check locally first
            inspect = _run_docker(["inspect", "--type=image", image], timeout=15)
            if inspect.returncode != 0:
                msg_info(f"Image not found locally, pulling {image}…")
                pull = _run_docker(["pull", image], timeout=300)
                if pull.returncode != 0:
                    msg_warn(f"Could not pull image: {pull.stderr[:200]}")
                    return findings

            # ---------------------------------------------------------- #
            # 2. Save to tar
            # ---------------------------------------------------------- #
            img_hash = hashlib.md5(image.encode()).hexdigest()[:8]
            tar_path = os.path.join(tmpdir, f"image_{img_hash}.tar")
            msg_info(f"Saving image to {tar_path}…")
            save_result = _run_docker(["save", image, "-o", tar_path], timeout=300)
            if save_result.returncode != 0:
                msg_warn(f"docker save failed: {save_result.stderr[:200]}")
                return findings

            # ---------------------------------------------------------- #
            # 3. Scan the tar
            # ---------------------------------------------------------- #
            findings.extend(self._scan_tar(tar_path, image_name=image))

            # ---------------------------------------------------------- #
            # 4. Scan image history for leaked build args / ENV secrets
            # ---------------------------------------------------------- #
            history_result = _run_docker(
                ["history", "--no-trunc", "--format", "{{.CreatedBy}}", image],
                timeout=30,
            )
            if history_result.returncode == 0:
                findings.extend(
                    self._scan_dockerfile_commands(
                        history_result.stdout.splitlines(),
                        source_label="docker history",
                    )
                )

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return findings

    # ---------------------------------------------------------------------- #
    # Tar-based scanning (works for both docker save and direct .tar files)
    # ---------------------------------------------------------------------- #
    def _scan_tar(self, tar_path: str, image_name: str) -> list:
        findings = []
        extract_dir = tempfile.mkdtemp(prefix="haakleaks_layers_")

        try:
            # ---------------------------------------------------------- #
            # Extract outer tar
            # ---------------------------------------------------------- #
            try:
                with tarfile.open(tar_path, "r") as tf:
                    tf.extractall(path=extract_dir)
            except Exception as ex:
                msg_warn(f"Failed to extract image tar: {ex}")
                return findings

            # ---------------------------------------------------------- #
            # Parse manifest.json for layer order
            # ---------------------------------------------------------- #
            manifest_path = os.path.join(extract_dir, "manifest.json")
            layers_ordered = []
            config_file = None

            if os.path.isfile(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as fh:
                        manifest = json.load(fh)
                    if manifest and isinstance(manifest, list):
                        entry = manifest[0]
                        layers_ordered = entry.get("Layers", [])
                        config_file = entry.get("Config", "")
                except Exception as ex:
                    msg_warn(f"Could not parse manifest.json: {ex}")

            if not layers_ordered:
                # Fallback: find all layer.tar files
                for root, dirs, files in os.walk(extract_dir):
                    for fn in files:
                        if fn == "layer.tar":
                            rel = os.path.relpath(os.path.join(root, fn), extract_dir)
                            layers_ordered.append(rel)

            # ---------------------------------------------------------- #
            # Scan config / Dockerfile commands baked into config JSON
            # ---------------------------------------------------------- #
            if config_file:
                cfg_path = os.path.join(extract_dir, config_file)
                if os.path.isfile(cfg_path):
                    cfg_text = _safe_read_text(cfg_path)
                    if cfg_text:
                        try:
                            cfg = json.loads(cfg_text)
                            history = cfg.get("history", [])
                            cmds = [h.get("created_by", "") for h in history if h.get("created_by")]
                            findings.extend(
                                self._scan_dockerfile_commands(cmds, source_label="image config")
                            )
                        except json.JSONDecodeError:
                            pass

            # ---------------------------------------------------------- #
            # Scan each layer
            # ---------------------------------------------------------- #
            total_layers = len(layers_ordered)
            msg_info(f"Layers to scan: {total_layers}")

            for layer_idx, layer_rel in enumerate(layers_ordered):
                layer_tar = os.path.join(extract_dir, layer_rel)
                progress_bar(
                    layer_idx + 1, total_layers,
                    label=f"Layer {layer_idx + 1}/{total_layers}",
                    width=30,
                )

                if not os.path.isfile(layer_tar):
                    continue

                layer_dir = tempfile.mkdtemp(prefix=f"haakleaks_layer{layer_idx}_")
                try:
                    try:
                        with tarfile.open(layer_tar, "r") as ltf:
                            ltf.extractall(path=layer_dir)
                    except Exception as ex:
                        msg_warn(f"Failed to extract layer {layer_idx}: {ex}")
                        continue

                    findings.extend(
                        self._scan_layer_directory(
                            layer_dir,
                            layer_id=layer_rel,
                            image_name=image_name,
                        )
                    )
                finally:
                    shutil.rmtree(layer_dir, ignore_errors=True)

            progress_bar(total_layers, total_layers, label="Done", width=30)

        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

        return findings

    # ---------------------------------------------------------------------- #
    # Scan extracted layer filesystem directory
    # ---------------------------------------------------------------------- #
    def _scan_layer_directory(
        self, layer_dir: str, layer_id: str, image_name: str
    ) -> list:
        findings = []

        for root, dirs, files in os.walk(layer_dir):
            # Skip opaque whiteout dirs and procfs artifacts
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".wh.") and d not in {"proc", "sys", "dev"}
            ]

            for filename in files:
                if filename.startswith(".wh."):
                    continue  # whiteout file — deleted in this layer

                abs_path = os.path.join(root, filename)
                container_path = os.path.relpath(abs_path, layer_dir)
                container_path = "/" + container_path.replace("\\", "/")

                fname = filename.lower()
                _, ext = os.path.splitext(fname)

                # Always flag private key / certificate files
                if ext in SENSITIVE_EXTENSIONS or filename in SENSITIVE_FILENAMES:
                    self.add_finding(
                        severity="high",
                        category="sensitive_file",
                        type_="sensitive_file_in_layer",
                        value=container_path,
                        location=container_path,
                        context=f"Layer: {layer_id[:24]}",
                        line_number=0,
                        description=f"Sensitive file '{filename}' found inside Docker layer",
                        confidence="high",
                        metadata={
                            "image": image_name,
                            "layer": layer_id,
                            "container_path": container_path,
                        },
                    )
                    findings.append(self.findings[-1])

                # Scan text files for secrets
                if not _is_text_file(abs_path):
                    continue

                text = _safe_read_text(abs_path)
                if not text:
                    continue

                self.files_scanned += 1
                self.bytes_scanned += len(text.encode("utf-8", errors="replace"))

                matches = scan_content(text, filename=filename)
                for (
                    pattern_name, match_value, severity, category,
                    description, confidence, m_start, m_end
                ) in matches:
                    # Estimate line number
                    line_no = text[:m_start].count("\n") + 1
                    self.add_finding(
                        severity=severity,
                        category=category,
                        type_=pattern_name,
                        value=match_value,
                        location=f"{container_path}:{line_no}",
                        context=text[max(0, m_start - 60): m_end + 60].strip()[:200],
                        line_number=line_no,
                        description=description,
                        confidence=confidence,
                        metadata={
                            "image": image_name,
                            "layer": layer_id,
                            "container_path": container_path,
                        },
                    )
                    findings.append(self.findings[-1])

                # Entropy analysis
                for qs in extract_quoted_strings(text):
                    if len(qs) >= 20 and is_high_entropy(qs):
                        self.add_finding(
                            severity="medium",
                            category="entropy",
                            type_="high_entropy_string",
                            value=qs,
                            location=container_path,
                            context=qs[:120],
                            line_number=0,
                            description="High-entropy string in Docker layer file",
                            confidence="low",
                            metadata={
                                "image": image_name,
                                "layer": layer_id,
                                "container_path": container_path,
                                "entropy": round(shannon_entropy(qs), 3),
                            },
                        )
                        findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # Parse Dockerfile-style commands (from history or config)
    # ---------------------------------------------------------------------- #
    def _scan_dockerfile_commands(
        self, commands: list, source_label: str
    ) -> list:
        findings = []

        env_re = re.compile(
            r"ENV\s+([A-Z_][A-Z0-9_]*)=([^\s\\]+)",
            re.IGNORECASE,
        )
        arg_re = re.compile(
            r"ARG\s+([A-Z_][A-Z0-9_]*)=([^\s\\]+)",
            re.IGNORECASE,
        )
        secret_key_words = re.compile(
            r"(password|passwd|secret|token|api_?key|auth|credential|private_?key|access_?key|"
            r"client_?secret|client_?id|jwt|bearer|connectionstring)",
            re.IGNORECASE,
        )
        curl_secret_re = re.compile(
            r"(curl|wget)\s+.*?(http[s]?://[^\s]+)",
            re.IGNORECASE,
        )

        for cmd in commands:
            if not cmd.strip():
                continue

            cmd_text = cmd.strip()

            # ENV and ARG with potential defaults
            for pattern, cmd_type in [(env_re, "ENV"), (arg_re, "ARG")]:
                for m in pattern.finditer(cmd_text):
                    key_name, value = m.group(1), m.group(2)
                    if secret_key_words.search(key_name):
                        self.add_finding(
                            severity="high",
                            category="dockerfile",
                            type_=f"dockerfile_{cmd_type.lower()}_secret",
                            value=value,
                            location=source_label,
                            context=cmd_text[:200],
                            line_number=0,
                            description=(
                                f"Secret-looking {cmd_type} directive '{key_name}' in Dockerfile/history. "
                                "Build-time secrets baked into image layers persist forever."
                            ),
                            confidence="high",
                            metadata={
                                "command": cmd_text[:200],
                                "directive": cmd_type,
                                "key_name": key_name,
                                "source": source_label,
                            },
                        )
                        findings.append(self.findings[-1])
                    elif is_high_entropy(value) and len(value) >= 16:
                        self.add_finding(
                            severity="medium",
                            category="dockerfile",
                            type_=f"dockerfile_{cmd_type.lower()}_entropy",
                            value=value,
                            location=source_label,
                            context=cmd_text[:200],
                            line_number=0,
                            description=f"High-entropy default value in {cmd_type} '{key_name}'",
                            confidence="medium",
                            metadata={
                                "command": cmd_text[:200],
                                "directive": cmd_type,
                                "key_name": key_name,
                                "entropy": round(shannon_entropy(value), 3),
                            },
                        )
                        findings.append(self.findings[-1])

            # RUN curl/wget that fetches secret files
            for m in curl_secret_re.finditer(cmd_text):
                url = m.group(2)
                if any(kw in url.lower() for kw in ("secret", "credential", "key", "token", "password")):
                    self.add_finding(
                        severity="medium",
                        category="dockerfile",
                        type_="dockerfile_fetching_secret",
                        value=url,
                        location=source_label,
                        context=cmd_text[:200],
                        line_number=0,
                        description="RUN command fetches a URL that looks like it may contain secrets",
                        confidence="medium",
                        metadata={"command": cmd_text[:200]},
                    )
                    findings.append(self.findings[-1])

            # Pattern scan on the raw command text
            matches = scan_content(cmd_text, filename="Dockerfile")
            for (
                pattern_name, match_value, severity, category,
                description, confidence, m_start, m_end
            ) in matches:
                self.add_finding(
                    severity=severity,
                    category=category,
                    type_=pattern_name,
                    value=match_value,
                    location=source_label,
                    context=cmd_text[:200],
                    line_number=0,
                    description=description,
                    confidence=confidence,
                    metadata={"command": cmd_text[:200], "source": source_label},
                )
                findings.append(self.findings[-1])

        return findings
