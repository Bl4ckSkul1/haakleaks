"""
HaakLeaks — CLI Orchestrator
Parses arguments, dispatches scanners, collects findings, and outputs reports.
By Adrian Martinez | HAAK Cybersecurity
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

from leak_scanner import __version__
from leak_scanner.core import sort_findings, SecretFinding
from leak_scanner.patterns import PATTERN_COUNT
from leak_scanner.colors import (
    print_banner, msg_info, msg_ok, msg_fail, msg_warn, msg_scan,
    msg_finding_detail, section, subsection, summary_box,
)


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haakleaks",
        description="HaakLeaks — Multi-Source Secret Scanner by Adrian Martinez / HAAK Cybersecurity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  haakleaks.py --git /path/to/repo
  haakleaks.py --docker nginx:latest
  haakleaks.py --apk com.example.apk
  haakleaks.py --binary firmware.bin
  haakleaks.py --config /var/www/html
  haakleaks.py --pcap capture.pcap
  haakleaks.py --cloud s3://my-bucket
  haakleaks.py --all /path/to/project -o report.json --html report.html
        """,
    )

    # --- Source modes ---
    src = parser.add_argument_group("Source modes (at least one required)")
    src.add_argument("--git",    metavar="PATH",  help="Scan git repository history")
    src.add_argument("--docker", metavar="IMAGE", help="Scan Docker image layers")
    src.add_argument("--apk",    metavar="FILE",  help="Scan Android APK file")
    src.add_argument("--binary", metavar="FILE",  help="Scan binary file (strings extraction)")
    src.add_argument("--config", metavar="PATH",  help="Scan directory/file for config secrets")
    src.add_argument("--pcap",   metavar="FILE",  help="Scan PCAP network capture")
    src.add_argument("--cloud",  metavar="URL",   help="Scan cloud storage (s3://bucket, gs://, az://, do://)")
    src.add_argument("--all",    metavar="PATH",  help="Auto-detect and scan everything in path")

    # --- Scan options ---
    opts = parser.add_argument_group("Scan options")
    opts.add_argument(
        "--min-entropy", type=float, default=4.0, metavar="N",
        help="Minimum Shannon entropy threshold (default: 4.0)",
    )
    opts.add_argument(
        "--no-entropy", action="store_true",
        help="Disable entropy analysis (faster, fewer low-confidence findings)",
    )
    opts.add_argument(
        "--max-file-size", type=int, default=50, metavar="MB",
        help="Maximum file size in MB to scan (default: 50)",
    )
    opts.add_argument(
        "--git-depth", type=int, default=0, metavar="N",
        help="Git history depth (0 = all commits, default: all)",
    )
    opts.add_argument(
        "--git-branch", metavar="BRANCH",
        help="Specific git branch to scan (default: --all branches)",
    )
    opts.add_argument(
        "--include", metavar="PATTERNS",
        help="Comma-separated file patterns to include (e.g. '*.py,*.env')",
    )
    opts.add_argument(
        "--exclude", metavar="PATTERNS",
        help="Comma-separated file patterns to exclude",
    )
    opts.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="info",
        help="Minimum severity to report (default: info)",
    )

    # --- Output ---
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output",     metavar="FILE", help="JSON report output file")
    out.add_argument("--html",             metavar="FILE", help="HTML report output file")
    out.add_argument("--engagement",       metavar="ID",   help="Engagement ID (embedded in report)")
    out.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress output (only show findings and summary)",
    )
    out.add_argument(
        "--no-print-findings", action="store_true",
        help="Don't print individual findings to stdout",
    )

    # --- Network / connection ---
    net = parser.add_argument_group("Network (for --cloud)")
    net.add_argument("--proxy",   metavar="URL",  help="HTTP/HTTPS proxy URL")
    net.add_argument("--timeout", type=int, default=15, metavar="SEC",
                     help="HTTP request timeout in seconds (default: 15)")

    # --- Meta ---
    parser.add_argument("--version", action="version", version=f"HaakLeaks {__version__}")

    return parser


# ---------------------------------------------------------------------------
# --all auto-detect
# ---------------------------------------------------------------------------

def _auto_detect_sources(path: str) -> list[tuple[str, str]]:
    """
    Inspect a path and return a list of (source_type, target) pairs.
    For --all mode.
    """
    sources = []
    path = os.path.abspath(path)

    if not os.path.exists(path):
        msg_fail(f"Path does not exist: {path}")
        return sources

    # Is it a git repo?
    if os.path.isdir(os.path.join(path, ".git")):
        sources.append(("git", path))
        msg_info(f"Detected: git repository at {path}")

    # Walk for interesting files
    apk_files     = []
    pcap_files    = []
    binary_files  = []
    has_config    = False

    binary_exts = {".bin", ".elf", ".exe", ".dll", ".so", ".dylib", ".dex",
                   ".ko", ".efi", ".img", ".rom", ".fw", ".firmware"}
    pcap_exts   = {".pcap", ".pcapng", ".cap"}
    config_exts = {
        ".env", ".conf", ".cfg", ".ini", ".properties", ".yml", ".yaml",
        ".json", ".toml", ".tf", ".tfvars", ".hcl",
    }
    config_fnames = {
        ".env", ".netrc", ".pgpass", "credentials.json",
        "service-account.json", "terraform.tfvars",
    }

    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", "__pycache__", ".tox", "venv", ".venv"}
        ]
        for fname in files:
            fpath = os.path.join(root, fname)
            _, ext = os.path.splitext(fname.lower())

            if ext == ".apk":
                apk_files.append(fpath)
            elif ext in pcap_exts:
                pcap_files.append(fpath)
            elif ext in binary_exts:
                binary_files.append(fpath)
            elif ext in config_exts or fname in config_fnames:
                has_config = True

    # Config scan of the whole dir (if no git — avoid double-scanning)
    if has_config:
        sources.append(("config", path))
        msg_info(f"Detected: config files in {path}")

    for f in apk_files:
        sources.append(("apk", f))
        msg_info(f"Detected: APK file {f}")

    for f in pcap_files:
        sources.append(("pcap", f))
        msg_info(f"Detected: PCAP capture {f}")

    for f in binary_files[:10]:  # cap at 10 to avoid scanning huge dirs
        sources.append(("binary", f))
        msg_info(f"Detected: binary {f}")

    if not sources:
        # Fallback: just do a config scan
        sources.append(("config", path))
        msg_info(f"No specific source type detected — running config scan on {path}")

    return sources


# ---------------------------------------------------------------------------
# Scanner dispatch
# ---------------------------------------------------------------------------

def _run_scanner(
    source_type: str,
    target: str,
    options: dict,
    quiet: bool,
) -> list[SecretFinding]:
    """Instantiate and run the appropriate scanner."""
    from leak_scanner.modules import ALL_SCANNERS

    scanner_class = ALL_SCANNERS.get(source_type)
    if not scanner_class:
        msg_fail(f"Unknown scanner type: {source_type}")
        return []

    if not quiet:
        msg_scan(f"Starting {source_type} scan: {target}")

    scanner  = scanner_class(target=target, options=options)
    findings = scanner.scan()
    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _filter_by_severity(
    findings: list[SecretFinding], min_severity: str
) -> list[SecretFinding]:
    min_rank = _SEVERITY_RANK.get(min_severity.lower(), 1)
    return [f for f in findings if _SEVERITY_RANK.get(f.severity.lower(), 0) >= min_rank]


def _build_report(
    findings: list[SecretFinding],
    sources_scanned: list[str],
    target: str,
    engagement: str,
    duration: float,
    files_scanned: int,
    bytes_scanned: int,
) -> dict:
    by_source:   dict[str, int] = {}
    by_category: dict[str, int] = {}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        by_source[f.source]    = by_source.get(f.source, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        counts[f.severity]     = counts.get(f.severity, 0) + 1

    return {
        "meta": {
            "tool":             "HaakLeaks",
            "version":          __version__,
            "date":             datetime.now().isoformat(timespec="seconds"),
            "target":           target,
            "duration_seconds": round(duration, 2),
            "engagement":       engagement or "",
            "sources_scanned":  sources_scanned,
            "pattern_count":    PATTERN_COUNT,
        },
        "stats": {
            "total_findings":   len(findings),
            "files_scanned":    files_scanned,
            "bytes_scanned":    bytes_scanned,
            "findings_critical": counts["critical"],
            "findings_high":     counts["high"],
            "findings_medium":   counts["medium"],
            "findings_low":      counts["low"],
            "findings_info":     counts["info"],
            "by_source":         by_source,
            "by_category":       by_category,
        },
        "findings": [f.to_dict() for f in findings],
    }


def _save_json(report: dict, path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        msg_ok(f"JSON report saved: {path}")
    except OSError as ex:
        msg_fail(f"Cannot write JSON report to {path}: {ex}")


def _save_html(report: dict, path: str) -> None:
    """Generate a minimal self-contained HTML report."""
    findings = report["findings"]
    stats    = report["stats"]
    meta     = report["meta"]

    _SEV_COLOR = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#2563eb",
        "info":     "#6b7280",
    }

    rows_html = ""
    for idx, f in enumerate(findings, 1):
        sev   = f.get("severity", "info")
        color = _SEV_COLOR.get(sev, "#6b7280")
        rows_html += f"""
        <tr>
            <td>{idx}</td>
            <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
            <td>{_esc(f.get('category',''))}</td>
            <td>{_esc(f.get('type',''))}</td>
            <td><code>{_esc(f.get('value',''))}</code></td>
            <td>{_esc(f.get('source',''))}</td>
            <td title="{_esc(f.get('location',''))}">{_esc(f.get('location','')[:60])}</td>
            <td>{_esc(f.get('confidence',''))}</td>
        </tr>
        <tr class="ctx-row">
            <td colspan="8">
                <small><b>Description:</b> {_esc(f.get('description',''))}<br>
                <b>Context:</b> <code>{_esc(f.get('context','')[:200])}</code></small>
            </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HaakLeaks Report — {_esc(meta.get('target',''))}</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:0}}
  .header{{background:linear-gradient(135deg,#1e1b4b,#0f172a);padding:2rem 3rem;border-bottom:2px solid #7c3aed}}
  .header h1{{margin:0;font-size:2rem;color:#a78bfa}}
  .header p{{margin:0.3rem 0;color:#94a3b8;font-size:0.9rem}}
  .container{{padding:2rem 3rem;max-width:1400px}}
  .stats{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
  .stat-card{{background:#1e293b;border:1px solid #334155;border-radius:0.75rem;padding:1rem 1.5rem;min-width:120px;text-align:center}}
  .stat-card .num{{font-size:2rem;font-weight:700}}
  .stat-card .lbl{{font-size:0.75rem;color:#94a3b8;text-transform:uppercase}}
  .crit{{color:#dc2626}}.high{{color:#ea580c}}.med{{color:#d97706}}.low{{color:#2563eb}}.info{{color:#6b7280}}
  table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:0.75rem;overflow:hidden}}
  th{{background:#334155;padding:0.75rem 1rem;text-align:left;font-size:0.8rem;text-transform:uppercase;color:#94a3b8}}
  td{{padding:0.6rem 1rem;border-bottom:1px solid #334155;font-size:0.85rem}}
  tr:hover td{{background:#263349}}
  .ctx-row td{{background:#192133;padding:0.4rem 1rem 0.8rem;font-size:0.78rem;color:#94a3b8}}
  .badge{{padding:0.2rem 0.5rem;border-radius:9999px;font-size:0.7rem;font-weight:700;color:#fff}}
  code{{background:#0f172a;padding:0.1rem 0.4rem;border-radius:4px;font-size:0.8rem;color:#a78bfa}}
  h2{{color:#a78bfa;margin-top:2rem}}
</style>
</head>
<body>
<div class="header">
  <h1>HaakLeaks — Secret Scanner Report</h1>
  <p>Target: <b>{_esc(meta.get('target',''))}</b> &nbsp;|&nbsp;
     Date: {_esc(meta.get('date',''))} &nbsp;|&nbsp;
     Duration: {meta.get('duration_seconds',0):.1f}s &nbsp;|&nbsp;
     Patterns: {meta.get('pattern_count',0)} &nbsp;|&nbsp;
     Engagement: {_esc(meta.get('engagement','—'))}
  </p>
</div>
<div class="container">
  <h2>Summary</h2>
  <div class="stats">
    <div class="stat-card"><div class="num">{stats['total_findings']}</div><div class="lbl">Total</div></div>
    <div class="stat-card"><div class="num crit">{stats['findings_critical']}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num high">{stats['findings_high']}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num med">{stats['findings_medium']}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num low">{stats['findings_low']}</div><div class="lbl">Low</div></div>
    <div class="stat-card"><div class="num info">{stats['findings_info']}</div><div class="lbl">Info</div></div>
    <div class="stat-card"><div class="num">{stats['files_scanned']}</div><div class="lbl">Files</div></div>
  </div>

  <h2>Findings ({len(findings)})</h2>
  <table>
  <thead><tr>
    <th>#</th><th>Severity</th><th>Category</th><th>Type</th>
    <th>Value (masked)</th><th>Source</th><th>Location</th><th>Confidence</th>
  </tr></thead>
  <tbody>{rows_html}</tbody>
  </table>

  <p style="margin-top:2rem;color:#475569;font-size:0.75rem">
    Generated by HaakLeaks v{_esc(meta.get('version',''))} &nbsp;|&nbsp; Adrian Martinez / HAAK Cybersecurity
  </p>
</div>
</body>
</html>"""

    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        msg_ok(f"HTML report saved: {path}")
    except OSError as ex:
        msg_fail(f"Cannot write HTML report to {path}: {ex}")


def _esc(s: str) -> str:
    """HTML escape."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    parser  = _build_parser()
    args    = parser.parse_args()

    # Determine which sources to run
    source_pairs: list[tuple[str, str]] = []

    if args.all:
        source_pairs = _auto_detect_sources(args.all)
    else:
        if args.git:    source_pairs.append(("git",    args.git))
        if args.docker: source_pairs.append(("docker", args.docker))
        if args.apk:    source_pairs.append(("apk",    args.apk))
        if args.binary: source_pairs.append(("binary", args.binary))
        if args.config: source_pairs.append(("config", args.config))
        if args.pcap:   source_pairs.append(("pcap",   args.pcap))
        if args.cloud:  source_pairs.append(("cloud",  args.cloud))

    if not source_pairs:
        print_banner(quiet=False)
        parser.print_help()
        sys.exit(0)

    if not args.quiet:
        print_banner(quiet=False)

    # Build shared options dict
    options = {
        "min_entropy":   args.min_entropy,
        "no_entropy":    args.no_entropy,
        "max_file_size": args.max_file_size,
        "git_depth":     args.git_depth,
        "git_branch":    args.git_branch,
        "include":       args.include,
        "exclude":       args.exclude,
        "proxy":         args.proxy,
        "timeout":       args.timeout,
        "verbose":       not args.quiet,
    }

    # --- Run all requested scanners ---
    all_findings:    list[SecretFinding] = []
    sources_scanned: list[str]           = []
    total_files   = 0
    total_bytes   = 0

    t0 = time.time()

    for source_type, target in source_pairs:
        findings = _run_scanner(source_type, target, options, args.quiet)
        all_findings.extend(findings)
        sources_scanned.append(source_type)

        # Accumulate stats from scanner
        from leak_scanner.modules import ALL_SCANNERS
        # (stats were already accumulated inside each scanner object)

    duration = time.time() - t0

    # --- Filter by minimum severity ---
    filtered = _filter_by_severity(all_findings, args.min_severity)
    sorted_findings = sort_findings(filtered)

    # --- Print findings ---
    if not args.no_print_findings and sorted_findings:
        section("Findings", ">>")
        for f in sorted_findings:
            msg_finding_detail(f)

    # --- Summary stats (approximate) ---
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_source:   dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in sorted_findings:
        counts[f.severity]     = counts.get(f.severity, 0) + 1
        by_source[f.source]    = by_source.get(f.source, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    stats = {
        "total_findings":    len(sorted_findings),
        "files_scanned":     total_files,
        "bytes_scanned":     total_bytes,
        "duration_seconds":  duration,
        "findings_critical": counts["critical"],
        "findings_high":     counts["high"],
        "findings_medium":   counts["medium"],
        "findings_low":      counts["low"],
        "findings_info":     counts["info"],
        "by_source":         by_source,
        "by_category":       by_category,
    }

    if not args.quiet:
        summary_box(stats, title="Scan Complete")

    # --- Reports ---
    target_str = (
        args.all or args.git or args.docker or args.apk or
        args.binary or args.config or args.pcap or args.cloud or "unknown"
    )

    report = _build_report(
        findings        = sorted_findings,
        sources_scanned = sources_scanned,
        target          = target_str,
        engagement      = args.engagement or "",
        duration        = duration,
        files_scanned   = total_files,
        bytes_scanned   = total_bytes,
    )

    if args.output:
        _save_json(report, args.output)

    if args.html:
        _save_html(report, args.html)

    # Exit code: 1 if critical/high findings, 0 otherwise
    if counts["critical"] + counts["high"] > 0:
        sys.exit(1)
    sys.exit(0)
