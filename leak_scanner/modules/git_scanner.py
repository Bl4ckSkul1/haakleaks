"""
HaakLeaks — Git Repository History Scanner
Scans all commits in a git repository for leaked secrets.
By Adrian Martinez | HAAK Cybersecurity
"""

import os
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from leak_scanner.core import BaseScanner, SecretFinding
from leak_scanner.patterns import scan_content, SECRET_PATTERNS
from leak_scanner.entropy import shannon_entropy, is_high_entropy, extract_quoted_strings
from leak_scanner.colors import (
    msg_info, msg_ok, msg_warn, msg_secret, section, progress_bar
)


# Files that commonly contain secrets — flag when touched in any commit
SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    "credentials.json", "credentials", "service-account.json",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".my.cnf",
    "docker-compose.yml", "docker-compose.override.yml",
    "terraform.tfvars", "secrets.yml", "secrets.yaml",
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
}

SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".cer", ".crt",
    ".ppk",  # PuTTY private key
}

# Regex to parse git log --all --format="%H %ae %ai %s"
_LOG_RE = re.compile(
    r"^([0-9a-f]{40})\s+(\S+)\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}|\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s[+-]\d{4})\s+(.*)$"
)

# diff-tree header: diff --git a/path b/path
_DIFF_FILE_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
_HUNK_HEADER_RE = re.compile(r"^@@ .+ @@")


def _run_git(args: list, cwd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a git command, returning CompletedProcess. Raises on timeout."""
    cmd = ["git"] + args
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="replace",
    )


def _parse_diff_chunks(diff_text: str):
    """
    Parse a git diff output and yield (file_path, line_number, added_line) tuples
    for every added line (starts with '+', not '+++').
    """
    current_file = None
    current_line = 0  # line number in the new file

    for raw_line in diff_text.splitlines():
        m = _DIFF_FILE_RE.match(raw_line)
        if m:
            current_file = m.group(2)  # b-side path
            current_line = 0
            continue

        hunk_m = _HUNK_HEADER_RE.match(raw_line)
        if hunk_m:
            # Extract new-file start: @@ -a,b +c,d @@
            hunk_match = re.search(r"\+(\d+)", raw_line)
            if hunk_match:
                current_line = int(hunk_match.group(1)) - 1
            continue

        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue

        if raw_line.startswith("+"):
            current_line += 1
            yield current_file, current_line, raw_line[1:]
        elif raw_line.startswith("-"):
            pass  # removed line, skip
        else:
            current_line += 1  # context line


class GitScanner(BaseScanner):
    NAME = "git"
    DESCRIPTION = "Scan git repository history for leaked secrets in all commits"

    def scan(self) -> list:
        section("Git History Scanner", "⎇")
        findings = []

        # ------------------------------------------------------------------ #
        # 1. Verify target is a git repository
        # ------------------------------------------------------------------ #
        target = os.path.abspath(self.target)
        if not os.path.isdir(target):
            msg_warn(f"Target is not a directory: {target}")
            return findings

        result = _run_git(["rev-parse", "--git-dir"], cwd=target)
        if result.returncode != 0:
            msg_warn(f"Not a git repository: {target}")
            return findings

        msg_info(f"Repository: {target}")

        # ------------------------------------------------------------------ #
        # 2. Gather commits
        # ------------------------------------------------------------------ #
        depth       = self.options.get("git_depth", 0)       # 0 = unlimited
        branch      = self.options.get("git_branch", "--all")
        skip_merges = self.options.get("skip_merges", True)
        max_age_days= self.options.get("max_age_days", 0)     # 0 = no limit

        log_args = ["log", branch, "--format=%H %ae %ai %s"]
        if skip_merges:
            log_args.append("--no-merges")
        if depth and depth > 0:
            log_args.extend(["-n", str(depth)])

        log_result = _run_git(log_args, cwd=target, timeout=120)
        if log_result.returncode != 0:
            msg_warn(f"git log failed: {log_result.stderr[:200]}")
            return findings

        raw_commits = []
        for line in log_result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 3)
            if len(parts) < 2:
                continue
            commit_hash = parts[0]
            author_email = parts[1] if len(parts) > 1 else ""
            commit_date = parts[2] if len(parts) > 2 else ""
            commit_msg = parts[3] if len(parts) > 3 else ""
            raw_commits.append((commit_hash, author_email, commit_date, commit_msg))

        if not raw_commits:
            msg_info("No commits found.")
            return findings

        # Filter by age
        if max_age_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
            filtered = []
            for h, ae, cd, cm in raw_commits:
                try:
                    # cd looks like: 2023-10-01T14:22:00+05:30  or  2023-10-01 14:22:00 +0530
                    cd_clean = cd.replace(" ", "T", 1) if " " in cd else cd
                    dt = datetime.fromisoformat(cd_clean)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if dt >= cutoff:
                        filtered.append((h, ae, cd, cm))
                except ValueError:
                    filtered.append((h, ae, cd, cm))
            raw_commits = filtered

        total_commits = len(raw_commits)
        msg_info(f"Commits to scan: {total_commits}")

        # ------------------------------------------------------------------ #
        # 3. Deduplification map: secret_value -> (finding, count)
        # ------------------------------------------------------------------ #
        seen_secrets: dict = {}   # value -> (first_commit_hash, finding_idx, count)

        # ------------------------------------------------------------------ #
        # 4. Scan each commit
        # ------------------------------------------------------------------ #
        for idx, (commit_hash, author_email, commit_date, commit_msg) in enumerate(raw_commits):
            progress_bar(
                idx + 1,
                total_commits,
                label=f"{commit_hash[:8]} ({author_email})",
                width=30,
            )

            # Get diff
            diff_result = _run_git(
                ["diff-tree", "-p", "--no-commit-id", "-r", commit_hash],
                cwd=target,
                timeout=60,
            )
            if diff_result.returncode != 0:
                continue

            diff_text = diff_result.stdout
            if not diff_text.strip():
                continue

            self.bytes_scanned += len(diff_text.encode("utf-8", errors="replace"))

            # Collect added lines per file
            lines_per_file: dict = defaultdict(list)
            for file_path, line_no, added_line in _parse_diff_chunks(diff_text):
                if file_path:
                    lines_per_file[file_path].append((line_no, added_line))

            for file_path, lines in lines_per_file.items():
                self.files_scanned += 1

                # Flag sensitive filenames
                fname = os.path.basename(file_path)
                _, ext = os.path.splitext(fname)
                if fname in SENSITIVE_FILENAMES or ext in SENSITIVE_EXTENSIONS:
                    key = f"__sensitive_file__{commit_hash}_{file_path}"
                    if key not in seen_secrets:
                        seen_secrets[key] = True
                        f = self._make_finding(
                            severity="medium",
                            category="sensitive_file",
                            type_="sensitive_file_in_history",
                            value=file_path,
                            location=f"{file_path}",
                            context=f"commit {commit_hash[:8]} by {author_email}: {commit_msg[:80]}",
                            line_number=0,
                            description=f"Sensitive file '{fname}' was committed to git history",
                            confidence="medium",
                            metadata={
                                "commit": commit_hash,
                                "author": author_email,
                                "date": commit_date,
                                "message": commit_msg[:120],
                                "file": file_path,
                            },
                        )
                        findings.append(f)

                # Run pattern matching on added content
                full_content = "\n".join(line for _, line in lines)
                matches = scan_content(full_content, filename=file_path)

                for (
                    pattern_name, match_value, severity, category,
                    description, confidence, m_start, m_end
                ) in matches:
                    # Deduplicate by value
                    secret_key = match_value.strip()
                    if secret_key in seen_secrets:
                        seen_secrets[secret_key]["count"] += 1
                        # Update metadata on the original finding
                        orig_f = findings[seen_secrets[secret_key]["finding_idx"]]
                        if orig_f.metadata:
                            orig_f.metadata["also_in_commits"] = seen_secrets[secret_key]["count"]
                        continue

                    # Find line number for this match
                    # Approximate: walk lines until we cover m_start chars
                    approx_line = 0
                    chars = 0
                    for ln, ln_text in lines:
                        chars += len(ln_text) + 1
                        if chars >= m_start:
                            approx_line = ln
                            break

                    f = self._make_finding(
                        severity=severity,
                        category=category,
                        type_=pattern_name,
                        value=match_value,
                        location=f"{file_path}:{approx_line}",
                        context=f"commit {commit_hash[:8]} | {author_email} | {commit_date[:10]}: {commit_msg[:60]}",
                        line_number=approx_line,
                        description=description,
                        confidence=confidence,
                        metadata={
                            "commit": commit_hash,
                            "author": author_email,
                            "date": commit_date,
                            "message": commit_msg[:120],
                            "file": file_path,
                            "also_in_commits": 0,
                        },
                    )
                    seen_secrets[secret_key] = {
                        "count": 1,
                        "finding_idx": len(findings),
                    }
                    findings.append(f)

                # Entropy analysis on quoted strings in added lines
                for _, line_text in lines:
                    for qs in extract_quoted_strings(line_text):
                        if len(qs) >= 20 and is_high_entropy(qs):
                            qs_key = qs.strip()
                            if qs_key not in seen_secrets:
                                seen_secrets[qs_key] = {"count": 1, "finding_idx": len(findings)}
                                f = self._make_finding(
                                    severity="medium",
                                    category="entropy",
                                    type_="high_entropy_string",
                                    value=qs,
                                    location=file_path,
                                    context=f"commit {commit_hash[:8]} | {author_email}: {line_text[:80]}",
                                    line_number=0,
                                    description="High-entropy quoted string found in git diff — possible secret",
                                    confidence="low",
                                    metadata={
                                        "commit": commit_hash,
                                        "author": author_email,
                                        "date": commit_date,
                                        "message": commit_msg[:120],
                                        "file": file_path,
                                        "entropy": round(shannon_entropy(qs), 3),
                                    },
                                )
                                findings.append(f)

        # Final progress bar flush
        progress_bar(total_commits, total_commits, label="Done", width=30)

        # ------------------------------------------------------------------ #
        # 5. Scan deleted sensitive files list
        # ------------------------------------------------------------------ #
        msg_info("Checking deleted file history…")
        deleted_result = _run_git(
            ["log", "--all", "--diff-filter=D", "--name-only", "--format=%H"],
            cwd=target,
            timeout=60,
        )
        if deleted_result.returncode == 0:
            current_commit = None
            for line in deleted_result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if re.match(r"^[0-9a-f]{40}$", line):
                    current_commit = line
                    continue
                fname = os.path.basename(line)
                _, ext = os.path.splitext(fname)
                if fname in SENSITIVE_FILENAMES or ext in SENSITIVE_EXTENSIONS:
                    key = f"__deleted_{current_commit}_{line}"
                    if key not in seen_secrets:
                        seen_secrets[key] = True
                        f = self._make_finding(
                            severity="medium",
                            category="sensitive_file",
                            type_="deleted_sensitive_file",
                            value=line,
                            location=line,
                            context=f"Deleted in commit {current_commit[:8] if current_commit else 'unknown'}",
                            line_number=0,
                            description=f"Sensitive file '{fname}' was deleted — content may still be in history",
                            confidence="medium",
                            metadata={
                                "commit": current_commit or "",
                                "file": line,
                                "event": "deleted",
                            },
                        )
                        findings.append(f)

        # ------------------------------------------------------------------ #
        # 6. Summary
        # ------------------------------------------------------------------ #
        msg_ok(
            f"Git scan complete: {total_commits} commits, "
            f"{self.files_scanned} files, {len(findings)} findings"
        )

        self.findings = findings
        return findings

    # ---------------------------------------------------------------------- #
    # Helper
    # ---------------------------------------------------------------------- #
    def _make_finding(
        self,
        severity, category, type_, value, location,
        context="", line_number=0, description="",
        confidence="high", metadata=None,
    ) -> SecretFinding:
        self.add_finding(
            severity=severity,
            category=category,
            type_=type_,
            value=value,
            location=location,
            context=context,
            line_number=line_number,
            description=description,
            confidence=confidence,
            metadata=metadata,
        )
        return self.findings[-1]
