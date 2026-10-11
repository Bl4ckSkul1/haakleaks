#!/usr/bin/env python3
"""
HaakLeaks — Multi-Source Secret Scanner
HTML Report Generator
Adrian Martinez / HAAK Cybersecurity Consulting
Usage: python3 haakleaks_report.py scan_results.json output.html
"""

import json
import sys
import os
import html
from datetime import datetime

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mask_secret(value: str) -> str:
    if not value:
        return ""
    v = str(value)
    if len(v) <= 12:
        return v[:2] + "***" + v[-2:]
    return v[:8] + "***" + v[-4:]


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def sev_color(sev: str) -> str:
    return {
        "critical": "#ff0040",
        "high":     "#ff6b00",
        "medium":   "#ffaa00",
        "low":      "#22c55e",
        "info":     "#3b82f6",
    }.get(sev.lower(), "#64748b")


def sev_bg(sev: str) -> str:
    return {
        "critical": "rgba(255,0,64,0.12)",
        "high":     "rgba(255,107,0,0.12)",
        "medium":   "rgba(255,170,0,0.12)",
        "low":      "rgba(34,197,94,0.12)",
        "info":     "rgba(59,130,246,0.12)",
    }.get(sev.lower(), "rgba(100,116,139,0.12)")


def source_color(src: str) -> str:
    return {
        "git":    "#00c8ff",
        "docker": "#3b82f6",
        "config": "#22c55e",
        "binary": "#8b5cf6",
        "apk":    "#ff6b00",
        "pcap":   "#ffaa00",
        "cloud":  "#ff0040",
    }.get(src.lower(), "#64748b")


def source_icon(src: str) -> str:
    return {
        "git":    "⬡",
        "docker": "🐳",
        "config": "⚙",
        "binary": "⬢",
        "apk":    "📱",
        "pcap":   "📡",
        "cloud":  "☁",
    }.get(src.lower(), "📄")


def cat_color(cat: str) -> str:
    return {
        "api_key":    "#00c8ff",
        "credential": "#ff6b00",
        "token":      "#8b5cf6",
        "cloud":      "#ff0040",
        "pii":        "#ffaa00",
        "crypto":     "#22c55e",
        "config":     "#64748b",
    }.get(cat.lower(), "#64748b")


def escape(s) -> str:
    return html.escape(str(s)) if s is not None else ""

# ---------------------------------------------------------------------------
# Build timeline rows (git only)
# ---------------------------------------------------------------------------

def build_git_timeline(findings):
    commits = {}
    for f in findings:
        if f.get("source", "").lower() != "git":
            continue
        meta = f.get("metadata", {})
        commit = meta.get("commit", "")[:7] or "unknown"
        key = commit
        if key not in commits:
            commits[key] = {
                "commit": commit,
                "author": meta.get("author", "unknown"),
                "date":   meta.get("date", ""),
                "message": meta.get("message", ""),
                "count": 0,
                "severities": []
            }
        commits[key]["count"] += 1
        commits[key]["severities"].append(f.get("severity", "info"))
    return sorted(commits.values(), key=lambda x: x["date"], reverse=True)


# ---------------------------------------------------------------------------
# Render HTML
# ---------------------------------------------------------------------------

def render_html(data: dict) -> str:
    meta    = data.get("meta", {})
    stats   = data.get("stats", {})
    findings = data.get("findings", [])

    tool_name    = escape(meta.get("tool", "HaakLeaks"))
    version      = escape(meta.get("version", "1.0.0"))
    scan_date    = escape(meta.get("date", datetime.now().strftime("%Y-%m-%d")))
    target       = escape(meta.get("target", "N/A"))
    duration_s   = meta.get("duration_seconds", 0)
    engagement   = escape(meta.get("engagement", ""))
    sources_list = meta.get("sources_scanned", [])

    total        = stats.get("total_findings", len(findings))
    files_s      = stats.get("files_scanned", 0)
    bytes_s      = stats.get("bytes_scanned", 0)
    cnt_crit     = stats.get("findings_critical", 0)
    cnt_high     = stats.get("findings_high", 0)
    cnt_med      = stats.get("findings_medium", 0)
    cnt_low      = stats.get("findings_low", 0)
    cnt_info     = stats.get("findings_info", 0)
    by_source    = stats.get("by_source", {})
    by_category  = stats.get("by_category", {})

    duration_str = f"{duration_s}s" if duration_s < 60 else f"{duration_s//60}m {duration_s%60}s"

    # ---- source pills ----
    src_pills = "".join(
        f'<span class="pill" style="background:rgba(0,200,255,0.08);border:1px solid rgba(0,200,255,0.25);color:#00c8ff">{source_icon(s)} {escape(s)}</span>'
        for s in sources_list
    )

    # ---- bar chart data ----
    max_src_count = max(by_source.values(), default=1)
    bar_rows = ""
    for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
        pct = int(cnt / max_src_count * 100)
        col = source_color(src)
        bar_rows += f"""
        <div class="bar-row">
          <div class="bar-label">{source_icon(src)} <span>{escape(src)}</span></div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{col}" data-count="{cnt}"></div>
          </div>
          <div class="bar-count" style="color:{col}">{cnt}</div>
        </div>"""

    # ---- category pills ----
    cat_pills = ""
    for cat, cnt in sorted(by_category.items(), key=lambda x: -x[1]):
        col = cat_color(cat)
        cat_pills += f'<div class="cat-pill" style="border:1px solid {col};color:{col};background:rgba(0,0,0,0.3)">' \
                     f'<span class="cat-name">{escape(cat.replace("_"," "))}</span>' \
                     f'<span class="cat-count" style="background:{col};color:#060a14">{cnt}</span></div>'

    # ---- severity stacked bar ----
    sev_total = max(cnt_crit + cnt_high + cnt_med + cnt_low + cnt_info, 1)
    sev_stacks = ""
    for sev, cnt in [("critical", cnt_crit), ("high", cnt_high), ("medium", cnt_med), ("low", cnt_low), ("info", cnt_info)]:
        if cnt:
            pct = cnt / sev_total * 100
            sev_stacks += f'<div class="sev-stack" style="width:{pct:.1f}%;background:{sev_color(sev)}" title="{sev}: {cnt}"></div>'

    # ---- findings cards ----
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity","info").lower(), 5))

    finding_cards = ""
    for idx, f in enumerate(sorted_findings):
        sev      = f.get("severity", "info").lower()
        cat      = f.get("category", "")
        ftype    = f.get("type", "")
        value    = str(f.get("value", ""))
        source   = f.get("source", "")
        location = f.get("location", "")
        context  = f.get("context", "")
        line_no  = f.get("line_number")
        desc     = f.get("description", "")
        conf     = f.get("confidence", "")
        ts       = f.get("timestamp", "")
        meta_d   = f.get("metadata", {})

        masked   = mask_secret(value)
        full_esc = escape(value)
        sev_col  = sev_color(sev)
        sev_bg_  = sev_bg(sev)
        src_col  = source_color(source)

        # metadata rows
        meta_rows = ""
        for k, v in meta_d.items():
            meta_rows += f'<div class="meta-row"><span class="meta-key">{escape(k)}</span><span class="meta-val">{escape(v)}</span></div>'

        line_html = f'<span class="line-badge">line {line_no}</span>' if line_no else ""
        conf_html = f'<span class="conf-badge conf-{escape(conf)}">{escape(conf)}</span>' if conf else ""

        finding_cards += f"""
<div class="finding-card" data-sev="{sev}" data-source="{escape(source)}" data-cat="{escape(cat)}">
  <div class="card-left-border" style="background:{sev_col}"></div>
  <div class="card-body">
    <div class="card-header">
      <div class="card-badges">
        <span class="badge sev-badge" style="background:{sev_bg_};color:{sev_col};border:1px solid {sev_col}40">{sev.upper()}</span>
        <span class="badge src-badge" style="background:rgba(0,0,0,0.3);color:{src_col};border:1px solid {src_col}40">{source_icon(source)} {escape(source)}</span>
        <span class="badge cat-badge" style="background:rgba(0,0,0,0.3);color:{cat_color(cat)};border:1px solid {cat_color(cat)}40">{escape(cat)}</span>
        {conf_html}
      </div>
      <div class="card-type">{escape(ftype)}</div>
    </div>

    <div class="card-desc">{escape(desc)}</div>

    <div class="secret-row">
      <span class="secret-label">Value</span>
      <code class="secret-masked" id="val-{idx}">{escape(masked)}</code>
      <button class="reveal-btn" onclick="revealSecret({idx}, '{full_esc}')" title="This will show the full secret value">
        👁 Reveal
      </button>
      <button class="copy-btn" onclick="copySecret('{full_esc}')" title="Copy to clipboard">
        ⧉ Copy
      </button>
    </div>

    <div class="location-row">
      <span class="location-icon">📍</span>
      <code class="location-text">{escape(location)}</code>
      {line_html}
    </div>

    {"<div class='context-block'><pre class='context-code'>" + escape(context) + "</pre></div>" if context else ""}

    {"<details class='meta-details'><summary>Metadata ▸</summary><div class='meta-grid'>" + meta_rows + "</div></details>" if meta_rows else ""}

    {"<div class='ts-row'>" + escape(ts) + "</div>" if ts else ""}
  </div>
</div>"""

    # ---- git timeline ----
    timeline_section = ""
    git_commits = build_git_timeline(findings)
    if git_commits:
        timeline_rows = ""
        for c in git_commits:
            dot_col = "#ff0040" if "critical" in c["severities"] else \
                      "#ff6b00" if "high" in c["severities"] else \
                      "#ffaa00" if "medium" in c["severities"] else "#22c55e"
            timeline_rows += f"""
            <div class="tl-row">
              <div class="tl-dot" style="border-color:{dot_col}"></div>
              <div class="tl-content">
                <span class="tl-hash" style="color:#00c8ff">{escape(c['commit'])}</span>
                <span class="tl-author">{escape(c['author'])}</span>
                <span class="tl-date">{escape(c['date'])}</span>
                <span class="tl-count" style="background:{dot_col}20;color:{dot_col};border:1px solid {dot_col}50">{c['count']} secret{"s" if c["count"]!=1 else ""}</span>
                <div class="tl-msg">{escape(c['message'])}</div>
              </div>
            </div>"""
        timeline_section = f"""
<section id="timeline" class="section">
  <h2 class="section-title">⬡ Git Commit Timeline</h2>
  <div class="timeline-container">
    <div class="tl-line"></div>
    {timeline_rows}
  </div>
</section>"""

    # ---- severity summary cards ----
    sev_cards = ""
    for sev, cnt, icon in [
        ("critical", cnt_crit, "🔴"),
        ("high",     cnt_high, "🟠"),
        ("medium",   cnt_med,  "🟡"),
        ("low",      cnt_low,  "🟢"),
        ("info",     cnt_info, "🔵"),
    ]:
        col = sev_color(sev)
        sev_cards += f"""
        <div class="sev-card" style="border:1px solid {col}30;background:rgba(0,0,0,0.3)">
          <div class="sev-icon">{icon}</div>
          <div class="sev-label" style="color:{col}">{sev.upper()}</div>
          <div class="sev-num counter" style="color:{col}" data-target="{cnt}">{cnt}</div>
        </div>"""

    # ---- nav items ----
    nav_items = """
      <li><a href="#header" class="nav-link active">Overview</a></li>
      <li><a href="#dashboard" class="nav-link">Dashboard</a></li>
      <li><a href="#sources" class="nav-link">By Source</a></li>
      <li><a href="#categories" class="nav-link">Categories</a></li>
      <li><a href="#severity" class="nav-link">Severity</a></li>
      <li><a href="#findings" class="nav-link">Findings</a></li>"""
    if git_commits:
        nav_items += '<li><a href="#timeline" class="nav-link">Timeline</a></li>'
    nav_items += """
      <li><a href="#methodology" class="nav-link">Methodology</a></li>"""

    # ---- full HTML ----
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HaakLeaks Report — {target}</title>
<style>
/* ===== RESET & BASE ===== */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg-primary:#060a14;
  --bg-card:#0d1321;
  --border:rgba(0,200,255,0.08);
  --accent:#00c8ff;
  --accent-purple:#8b5cf6;
  --critical:#ff0040;
  --high:#ff6b00;
  --medium:#ffaa00;
  --low:#22c55e;
  --info:#3b82f6;
  --text:#e2e8f0;
  --text-muted:#64748b;
}}
html{{scroll-behavior:smooth}}
body{{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:var(--bg-primary);
  color:var(--text);
  min-height:100vh;
  display:flex;
}}

/* ===== SIDEBAR ===== */
.sidebar{{
  position:fixed;top:0;left:0;height:100vh;width:200px;
  background:#080d1a;
  border-right:1px solid var(--border);
  padding:24px 0;
  z-index:100;
  overflow-y:auto;
}}
.sidebar-logo{{
  padding:0 20px 20px;
  border-bottom:1px solid var(--border);
  margin-bottom:16px;
}}
.sidebar-logo .logo-text{{
  font-size:18px;font-weight:900;
  background:linear-gradient(135deg,var(--accent),var(--accent-purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  letter-spacing:3px;
}}
.sidebar-logo .logo-sub{{font-size:9px;color:var(--text-muted);letter-spacing:1px}}
.nav-list{{list-style:none}}
.nav-link{{
  display:block;padding:9px 20px;
  color:var(--text-muted);font-size:13px;
  text-decoration:none;border-left:2px solid transparent;
  transition:.2s;
}}
.nav-link:hover,.nav-link.active{{
  color:var(--accent);border-left-color:var(--accent);
  background:rgba(0,200,255,0.04);
}}

/* ===== MAIN ===== */
.main{{margin-left:200px;flex:1;padding:32px 40px;max-width:1100px}}

/* ===== HEADER ===== */
#header{{margin-bottom:40px;padding-bottom:28px;border-bottom:1px solid var(--border)}}
.header-badge{{
  display:inline-block;padding:3px 10px;border-radius:4px;
  background:rgba(0,200,255,0.1);border:1px solid rgba(0,200,255,0.3);
  color:var(--accent);font-size:11px;letter-spacing:2px;font-weight:700;
  margin-bottom:12px;
}}
.header-title{{
  font-size:42px;font-weight:900;letter-spacing:4px;
  background:linear-gradient(135deg,var(--accent),var(--accent-purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  line-height:1.1;margin-bottom:4px;
}}
.header-sub{{color:var(--text-muted);font-size:14px;letter-spacing:1px;margin-bottom:20px}}
.header-meta{{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:16px;font-size:13px;color:var(--text-muted)}}
.header-meta span strong{{color:var(--text)}}
.pills-row{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.pill{{padding:4px 12px;border-radius:20px;font-size:12px}}

/* ===== SECTION ===== */
.section{{margin-bottom:48px}}
.section-title{{
  font-size:16px;font-weight:700;letter-spacing:2px;
  color:var(--accent);margin-bottom:20px;
  padding-bottom:8px;border-bottom:1px solid var(--border);
}}

/* ===== METRIC CARDS ===== */
.metrics-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px}}
.metric-card{{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:10px;padding:20px 16px;text-align:center;
  transition:.2s;
}}
.metric-card:hover{{border-color:rgba(0,200,255,0.2)}}
.metric-label{{font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-bottom:6px;text-transform:uppercase}}
.metric-value{{font-size:28px;font-weight:800;color:var(--accent)}}
.metric-value.critical{{color:var(--critical)}}
.metric-value.high{{color:var(--high)}}

/* ===== BAR CHART ===== */
.bar-chart{{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:24px}}
.bar-row{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}
.bar-label{{width:110px;font-size:13px;color:var(--text-muted);display:flex;align-items:center;gap:6px}}
.bar-track{{flex:1;background:rgba(255,255,255,0.04);border-radius:4px;height:20px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;transition:width 1s ease;min-width:4px}}
.bar-count{{width:30px;font-size:13px;font-weight:700;text-align:right}}

/* ===== CATEGORIES ===== */
.cat-grid{{display:flex;flex-wrap:wrap;gap:12px}}
.cat-pill{{
  padding:8px 16px;border-radius:8px;display:flex;align-items:center;gap:8px;
  font-size:13px;cursor:default;
}}
.cat-name{{text-transform:capitalize}}
.cat-count{{
  padding:2px 8px;border-radius:12px;font-size:12px;font-weight:700;
}}

/* ===== SEVERITY SECTION ===== */
.sev-cards{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}}
.sev-card{{
  flex:1;min-width:80px;padding:16px 12px;border-radius:8px;text-align:center;
}}
.sev-icon{{font-size:20px;margin-bottom:4px}}
.sev-label{{font-size:10px;letter-spacing:1px;font-weight:700;margin-bottom:4px}}
.sev-num{{font-size:24px;font-weight:800}}
.stacked-bar{{
  display:flex;height:12px;border-radius:6px;overflow:hidden;background:rgba(255,255,255,0.04);
  margin-top:8px;
}}
.sev-stack{{height:100%;min-width:2px}}

/* ===== FILTERS ===== */
.filter-bar{{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:10px;padding:16px 20px;margin-bottom:20px;
  display:flex;flex-wrap:wrap;gap:12px;align-items:center;
}}
.filter-group{{display:flex;flex-wrap:wrap;gap:6px;align-items:center}}
.filter-label{{font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-right:4px}}
.filter-btn{{
  padding:5px 12px;border-radius:20px;border:1px solid var(--border);
  background:transparent;color:var(--text-muted);font-size:12px;
  cursor:pointer;transition:.15s;
}}
.filter-btn:hover{{color:var(--text);border-color:rgba(0,200,255,0.3)}}
.filter-btn.active{{
  background:rgba(0,200,255,0.1);color:var(--accent);
  border-color:rgba(0,200,255,0.4);
}}
.search-input{{
  flex:1;min-width:200px;padding:7px 14px;
  background:rgba(0,0,0,0.4);border:1px solid var(--border);
  border-radius:20px;color:var(--text);font-size:13px;outline:none;
}}
.search-input:focus{{border-color:rgba(0,200,255,0.4)}}
.search-input::placeholder{{color:var(--text-muted)}}

/* ===== FINDING CARDS ===== */
.finding-card{{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:10px;margin-bottom:12px;display:flex;
  overflow:hidden;transition:.15s;
}}
.finding-card:hover{{border-color:rgba(0,200,255,0.15)}}
.finding-card.hidden{{display:none}}
.card-left-border{{width:4px;flex-shrink:0}}
.card-body{{flex:1;padding:16px 20px}}
.card-header{{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}}
.card-badges{{display:flex;flex-wrap:wrap;gap:6px}}
.badge{{
  padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;
  letter-spacing:.5px;white-space:nowrap;
}}
.card-type{{font-size:12px;color:var(--text-muted);white-space:nowrap}}
.card-desc{{font-size:13px;color:var(--text-muted);margin-bottom:12px}}

.secret-row{{
  display:flex;align-items:center;gap:8px;margin-bottom:10px;
  background:rgba(0,0,0,0.3);border-radius:6px;padding:8px 12px;
}}
.secret-label{{font-size:11px;color:var(--text-muted);min-width:40px}}
.secret-masked{{
  font-family:'Courier New',monospace;font-size:13px;color:#ffaa00;flex:1;word-break:break-all;
}}
.reveal-btn,.copy-btn{{
  padding:4px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.1);
  background:rgba(255,255,255,0.05);color:var(--text-muted);
  font-size:11px;cursor:pointer;transition:.15s;white-space:nowrap;
}}
.reveal-btn:hover{{background:rgba(255,170,0,0.15);color:#ffaa00;border-color:#ffaa0040}}
.copy-btn:hover{{background:rgba(0,200,255,0.1);color:var(--accent);border-color:rgba(0,200,255,0.3)}}

.location-row{{
  display:flex;align-items:center;gap:8px;margin-bottom:10px;font-size:12px;
}}
.location-icon{{color:var(--text-muted)}}
.location-text{{
  font-family:'Courier New',monospace;color:var(--text-muted);flex:1;word-break:break-all;
}}
.line-badge{{
  padding:2px 8px;border-radius:4px;background:rgba(139,92,246,0.1);
  color:var(--accent-purple);font-size:11px;white-space:nowrap;
}}
.conf-badge{{
  padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;
}}
.conf-high{{background:rgba(34,197,94,0.12);color:#22c55e;border:1px solid #22c55e40}}
.conf-medium{{background:rgba(255,170,0,0.12);color:#ffaa00;border:1px solid #ffaa0040}}
.conf-low{{background:rgba(100,116,139,0.12);color:#64748b;border:1px solid #64748b40}}

.context-block{{
  background:#060a14;border:1px solid var(--border);
  border-radius:6px;margin-bottom:10px;overflow:auto;max-height:120px;
}}
.context-code{{
  font-family:'Courier New',monospace;font-size:12px;
  color:#94a3b8;padding:10px 14px;white-space:pre-wrap;word-break:break-all;
}}

.meta-details{{margin-top:8px}}
.meta-details summary{{
  cursor:pointer;font-size:12px;color:var(--text-muted);
  padding:4px 0;user-select:none;
}}
.meta-details summary:hover{{color:var(--accent)}}
.meta-grid{{padding:10px 0 0}}
.meta-row{{display:flex;gap:12px;font-size:12px;margin-bottom:4px}}
.meta-key{{color:var(--text-muted);min-width:80px;text-transform:capitalize}}
.meta-val{{color:var(--text);word-break:break-all}}
.ts-row{{font-size:11px;color:var(--text-muted);margin-top:6px;text-align:right}}

/* ===== PAGINATION ===== */
.pagination{{display:flex;gap:8px;align-items:center;justify-content:center;margin-top:20px}}
.page-btn{{
  padding:6px 14px;border-radius:6px;border:1px solid var(--border);
  background:transparent;color:var(--text-muted);font-size:13px;cursor:pointer;
}}
.page-btn:hover,.page-btn.active{{background:rgba(0,200,255,0.1);color:var(--accent);border-color:rgba(0,200,255,0.3)}}
.page-info{{font-size:12px;color:var(--text-muted)}}
.findings-count{{font-size:13px;color:var(--text-muted);margin-bottom:12px}}

/* ===== TIMELINE ===== */
.timeline-container{{position:relative;padding-left:28px}}
.tl-line{{
  position:absolute;left:8px;top:0;bottom:0;
  width:2px;background:linear-gradient(180deg,var(--accent),var(--accent-purple));
  opacity:.3;
}}
.tl-row{{display:flex;align-items:flex-start;gap:16px;margin-bottom:20px;position:relative}}
.tl-dot{{
  position:absolute;left:-24px;top:4px;
  width:12px;height:12px;border-radius:50%;
  border:2px solid var(--accent);background:var(--bg-primary);
  flex-shrink:0;
}}
.tl-content{{flex:1;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px 16px}}
.tl-hash{{font-family:'Courier New',monospace;font-size:13px;font-weight:700;margin-right:10px}}
.tl-author{{font-size:12px;color:var(--text-muted);margin-right:10px}}
.tl-date{{font-size:12px;color:var(--text-muted);margin-right:10px}}
.tl-count{{padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700}}
.tl-msg{{font-size:12px;color:var(--text-muted);margin-top:6px;font-style:italic}}

/* ===== METHODOLOGY ===== */
.method-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}}
.method-card{{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:8px;padding:16px;
}}
.method-key{{font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-bottom:4px}}
.method-val{{font-size:14px;font-weight:600;color:var(--text)}}

/* ===== FOOTER ===== */
footer{{
  margin-top:48px;padding-top:24px;border-top:1px solid var(--border);
  font-size:12px;color:var(--text-muted);text-align:center;
}}
footer strong{{color:var(--accent)}}
.disclaimer{{
  margin-top:8px;padding:10px 16px;border-radius:6px;
  background:rgba(255,0,64,0.06);border:1px solid rgba(255,0,64,0.15);
  color:#94a3b8;font-size:11px;
}}

/* ===== PRINT ===== */
@media print{{
  .sidebar{{display:none}}
  .main{{margin-left:0}}
  .reveal-btn,.copy-btn,.filter-bar{{display:none}}
  .finding-card{{break-inside:avoid}}
}}
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-text">HAAK</div>
    <div class="logo-sub">LEAKS REPORT</div>
  </div>
  <ul class="nav-list">
    {nav_items}
  </ul>
</nav>

<!-- MAIN -->
<main class="main">

<!-- HEADER -->
<section id="header">
  <div class="header-badge">SECRET SCANNER</div>
  <div class="header-title">HAAKLEAKS</div>
  <div class="header-sub">Multi-Source Secret Scanner Report</div>
  <div class="header-meta">
    <span>🎯 <strong>Target:</strong> {target}</span>
    <span>📅 <strong>Date:</strong> {scan_date}</span>
    {"<span>🔖 <strong>Engagement:</strong> " + engagement + "</span>" if engagement else ""}
    <span>⏱ <strong>Duration:</strong> {duration_str}</span>
    <span>🛠 <strong>Tool:</strong> {tool_name} v{version}</span>
  </div>
  <div class="pills-row">{src_pills}</div>
</section>

<!-- DASHBOARD -->
<section id="dashboard" class="section">
  <h2 class="section-title">📊 Executive Dashboard</h2>
  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-label">Total Findings</div>
      <div class="metric-value counter" data-target="{total}">{total}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Files Scanned</div>
      <div class="metric-value counter" data-target="{files_s}">{files_s}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Data Analyzed</div>
      <div class="metric-value">{human_bytes(bytes_s)}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Critical</div>
      <div class="metric-value critical counter" data-target="{cnt_crit}">{cnt_crit}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">High</div>
      <div class="metric-value high counter" data-target="{cnt_high}">{cnt_high}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Sources Scanned</div>
      <div class="metric-value counter" data-target="{len(sources_list)}">{len(sources_list)}</div>
    </div>
  </div>
</section>

<!-- BY SOURCE -->
<section id="sources" class="section">
  <h2 class="section-title">📦 Findings by Source</h2>
  <div class="bar-chart">
    {bar_rows if bar_rows else '<p style="color:var(--text-muted);font-size:13px">No source data available.</p>'}
  </div>
</section>

<!-- BY CATEGORY -->
<section id="categories" class="section">
  <h2 class="section-title">🏷 Findings by Category</h2>
  <div class="cat-grid">
    {cat_pills if cat_pills else '<p style="color:var(--text-muted);font-size:13px">No category data available.</p>'}
  </div>
</section>

<!-- SEVERITY BREAKDOWN -->
<section id="severity" class="section">
  <h2 class="section-title">⚠ Severity Breakdown</h2>
  <div class="sev-cards">
    {sev_cards}
  </div>
  <div class="stacked-bar">{sev_stacks}</div>
</section>

<!-- FINDINGS TABLE -->
<section id="findings" class="section">
  <h2 class="section-title">🔍 Findings</h2>

  <!-- Filters -->
  <div class="filter-bar">
    <input class="search-input" type="text" id="search-input" placeholder="🔍 Search findings..." oninput="applyFilters()">
    <div class="filter-group">
      <span class="filter-label">SEV</span>
      <button class="filter-btn active" data-filter="sev" data-val="all" onclick="toggleFilter(this,'sev')">All</button>
      <button class="filter-btn" data-filter="sev" data-val="critical" onclick="toggleFilter(this,'sev')" style="color:#ff0040">Critical</button>
      <button class="filter-btn" data-filter="sev" data-val="high" onclick="toggleFilter(this,'sev')" style="color:#ff6b00">High</button>
      <button class="filter-btn" data-filter="sev" data-val="medium" onclick="toggleFilter(this,'sev')" style="color:#ffaa00">Medium</button>
      <button class="filter-btn" data-filter="sev" data-val="low" onclick="toggleFilter(this,'sev')" style="color:#22c55e">Low</button>
      <button class="filter-btn" data-filter="sev" data-val="info" onclick="toggleFilter(this,'sev')" style="color:#3b82f6">Info</button>
    </div>
  </div>

  <div class="findings-count" id="findings-count"></div>
  <div id="findings-container">
    {finding_cards if finding_cards else '<p style="color:var(--text-muted);font-size:13px;padding:20px">No findings recorded.</p>'}
  </div>
  <div class="pagination" id="pagination"></div>
</section>

{timeline_section}

<!-- METHODOLOGY -->
<section id="methodology" class="section">
  <h2 class="section-title">📋 Methodology</h2>
  <div class="method-grid">
    <div class="method-card"><div class="method-key">Tool</div><div class="method-val">{tool_name} v{version}</div></div>
    <div class="method-card"><div class="method-key">Scan Date</div><div class="method-val">{scan_date}</div></div>
    <div class="method-card"><div class="method-key">Duration</div><div class="method-val">{duration_str}</div></div>
    <div class="method-card"><div class="method-key">Files Scanned</div><div class="method-val">{files_s:,}</div></div>
    <div class="method-card"><div class="method-key">Bytes Processed</div><div class="method-val">{human_bytes(bytes_s)}</div></div>
    <div class="method-card"><div class="method-key">Sources</div><div class="method-val">{", ".join(sources_list) or "N/A"}</div></div>
    <div class="method-card"><div class="method-key">Total Findings</div><div class="method-val">{total}</div></div>
    <div class="method-card"><div class="method-key">Engagement</div><div class="method-val">{engagement or "N/A"}</div></div>
  </div>
</section>

<!-- FOOTER -->
<footer>
  <div>Generated by <strong>HAAK Cybersecurity Consulting</strong> · Adrian Martinez · {scan_date}</div>
  <div class="disclaimer">
    CONFIDENTIAL — This report contains sensitive security findings. Distribution is restricted to authorized personnel only.
    Secrets shown in this report must be rotated immediately. HAAK Cybersecurity assumes no liability for unauthorized disclosure.
  </div>
</footer>

</main>

<script>
// ===== COUNT-UP ANIMATION =====
(function() {{
  const els = document.querySelectorAll('.counter[data-target]');
  els.forEach(el => {{
    const target = parseInt(el.getAttribute('data-target'), 10);
    if (!target) return;
    let current = 0;
    const step = Math.max(1, Math.floor(target / 40));
    const timer = setInterval(() => {{
      current = Math.min(current + step, target);
      el.textContent = current.toLocaleString();
      if (current >= target) clearInterval(timer);
    }}, 25);
  }});
}})();

// ===== REVEAL SECRET =====
function revealSecret(idx, fullVal) {{
  const el = document.getElementById('val-' + idx);
  if (!el) return;
  if (el.dataset.revealed === '1') {{
    el.textContent = el.dataset.masked;
    el.dataset.revealed = '0';
    el.style.color = '#ffaa00';
  }} else {{
    el.dataset.masked = el.textContent;
    el.textContent = fullVal;
    el.dataset.revealed = '1';
    el.style.color = '#ff6b00';
  }}
}}

// ===== COPY TO CLIPBOARD =====
function copySecret(val) {{
  navigator.clipboard.writeText(val).then(() => {{
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copied';
    btn.style.color = '#22c55e';
    setTimeout(() => {{ btn.textContent = orig; btn.style.color = ''; }}, 1500);
  }}).catch(() => {{
    const ta = document.createElement('textarea');
    ta.value = val; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  }});
}}

// ===== FILTERS =====
const activeFilters = {{ sev: 'all' }};
const PAGE_SIZE = 50;
let currentPage = 1;

function toggleFilter(btn, group) {{
  document.querySelectorAll(`.filter-btn[data-filter="${{group}}"]`).forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeFilters[group] = btn.getAttribute('data-val');
  currentPage = 1;
  applyFilters();
}}

function applyFilters() {{
  const query = document.getElementById('search-input').value.toLowerCase();
  const cards = document.querySelectorAll('.finding-card');
  let visible = [];
  cards.forEach(card => {{
    const sev = card.getAttribute('data-sev') || '';
    const src = card.getAttribute('data-source') || '';
    const cat = card.getAttribute('data-cat') || '';
    const text = card.textContent.toLowerCase();
    const sevMatch = activeFilters.sev === 'all' || sev === activeFilters.sev;
    const searchMatch = !query || text.includes(query);
    if (sevMatch && searchMatch) {{
      visible.push(card);
      card.classList.remove('hidden');
    }} else {{
      card.classList.add('hidden');
    }}
  }});
  paginate(visible);
}}

function paginate(visible) {{
  const total = visible.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  currentPage = Math.min(currentPage, totalPages);
  const start = (currentPage - 1) * PAGE_SIZE;
  const end = start + PAGE_SIZE;
  visible.forEach((card, i) => {{
    card.style.display = (i >= start && i < end) ? '' : 'none';
  }});
  // count
  const countEl = document.getElementById('findings-count');
  if (countEl) countEl.textContent = total + ' finding' + (total !== 1 ? 's' : '') + (total !== visible.length ? '' : '');
  // pagination
  const pgEl = document.getElementById('pagination');
  if (!pgEl) return;
  pgEl.innerHTML = '';
  if (totalPages <= 1) return;
  const prevBtn = document.createElement('button');
  prevBtn.className = 'page-btn';
  prevBtn.textContent = '← Prev';
  prevBtn.disabled = currentPage === 1;
  prevBtn.onclick = () => {{ currentPage--; applyFilters(); }};
  pgEl.appendChild(prevBtn);
  const info = document.createElement('span');
  info.className = 'page-info';
  info.textContent = 'Page ' + currentPage + ' / ' + totalPages;
  pgEl.appendChild(info);
  const nextBtn = document.createElement('button');
  nextBtn.className = 'page-btn';
  nextBtn.textContent = 'Next →';
  nextBtn.disabled = currentPage === totalPages;
  nextBtn.onclick = () => {{ currentPage++; applyFilters(); }};
  pgEl.appendChild(nextBtn);
}}

// ===== SCROLL SPY =====
(function() {{
  const sections = document.querySelectorAll('section[id]');
  const links = document.querySelectorAll('.nav-link');
  const observer = new IntersectionObserver(entries => {{
    entries.forEach(entry => {{
      if (entry.isIntersecting) {{
        links.forEach(l => {{
          l.classList.toggle('active', l.getAttribute('href') === '#' + entry.target.id);
        }});
      }}
    }});
  }}, {{ threshold: 0.25 }});
  sections.forEach(s => observer.observe(s));
}})();

// initial render
applyFilters();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 haakleaks_report.py scan_results.json output.html", file=sys.stderr)
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.isfile(input_path):
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON: {e}", file=sys.stderr)
            sys.exit(1)

    report_html = render_html(data)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report_html)

    findings_count = len(data.get("findings", []))
    print(f"[OK] Report generated: {output_path} ({findings_count} findings, {len(report_html):,} bytes)")


if __name__ == "__main__":
    main()
