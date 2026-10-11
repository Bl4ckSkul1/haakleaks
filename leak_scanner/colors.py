"""
HaakLeaks — Terminal Colors & Output Formatting
HAAK Cybersecurity style
"""
import sys
import os
import shutil

# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
ITALIC  = "\033[3m"

# Foreground
BLACK   = "\033[30m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"

# Bright foreground
BRED    = "\033[91m"
BGREEN  = "\033[92m"
BYELLOW = "\033[93m"
BBLUE   = "\033[94m"
BMAGENTA= "\033[95m"
BCYAN   = "\033[96m"
BWHITE  = "\033[97m"

# Background
BG_RED    = "\033[41m"
BG_GREEN  = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE   = "\033[44m"
BG_MAGENTA= "\033[45m"
BG_CYAN   = "\033[46m"
BG_BLACK  = "\033[40m"
BG_WHITE  = "\033[47m"

# ---------------------------------------------------------------------------
# Windows / no-tty fallback
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    """Check if the terminal supports ANSI color codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    # Windows: enable VT100 if possible
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR_ENABLED = _supports_color()


def c(code: str, text: str) -> str:
    """Apply ANSI code to text, stripping it when colors are disabled."""
    if _COLOR_ENABLED:
        return f"{code}{text}{RESET}"
    return text


# ---------------------------------------------------------------------------
# ASCII Art Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ██╗  ██╗ █████╗  █████╗ ██╗  ██╗██╗     ███████╗ █████╗ ██╗  ██╗███████╗
  ██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██║     ██╔════╝██╔══██╗██║ ██╔╝██╔════╝
  ███████║███████║███████║█████╔╝ ██║     █████╗  ███████║█████╔╝ ███████╗
  ██╔══██║██╔══██║██╔══██║██╔═██╗ ██║     ██╔══╝  ██╔══██║██╔═██╗ ╚════██║
  ██║  ██║██║  ██║██║  ██║██║  ██╗███████╗███████╗██║  ██║██║  ██╗███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
"""

SUBTITLE = "  Multi-Source Secret Scanner"
AUTHOR   = "  By Adrian Martinez | HAAK Cybersecurity"
VERSION_LINE = "  v1.0.0  |  git · docker · apk · binary · config · pcap · cloud"

SEPARATOR = "─" * 72


def print_banner(quiet: bool = False) -> None:
    """Print the full HaakLeaks banner."""
    if quiet:
        return
    print()
    if _COLOR_ENABLED:
        # Gradient-ish: cyan → blue banner
        lines = BANNER.split("\n")
        colors = [BCYAN, BCYAN, BBLUE, BBLUE, BLUE, BLUE]
        for i, line in enumerate(lines):
            col = colors[i % len(colors)] if line.strip() else ""
            print(f"{BOLD}{col}{line}{RESET}")
    else:
        print(BANNER)

    print(c(BWHITE + BOLD, SUBTITLE))
    print(c(DIM + CYAN, AUTHOR))
    print(c(DIM, VERSION_LINE))
    print()
    print(c(DIM + CYAN, "  " + SEPARATOR))
    print()


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

_ICONS = {
    "ok":      ("✔", BG_GREEN + BLACK + BOLD),
    "fail":    ("✘", BG_RED   + BWHITE + BOLD),
    "info":    ("●", BCYAN),
    "warn":    ("⚠", BYELLOW),
    "secret":  ("⚑", BRED + BOLD),
    "debug":   ("·", DIM),
    "scan":    ("⟳", BBLUE),
    "done":    ("✔", BGREEN + BOLD),
}

# Fallback icons for terminals that don't render Unicode well
_ICONS_ASCII = {
    "ok":      ("+", BG_GREEN + BLACK + BOLD),
    "fail":    ("!", BG_RED   + BWHITE + BOLD),
    "info":    ("*", BCYAN),
    "warn":    ("!", BYELLOW),
    "secret":  ("$", BRED + BOLD),
    "debug":   (".", DIM),
    "scan":    ("~", BBLUE),
    "done":    ("+", BGREEN + BOLD),
}


def _icon(key: str) -> tuple:
    try:
        # Quick Unicode probe
        "✔".encode(sys.stdout.encoding or "utf-8")
        return _ICONS.get(key, ("·", DIM))
    except (UnicodeEncodeError, LookupError):
        return _ICONS_ASCII.get(key, (".", DIM))


def msg_ok(text: str) -> None:
    sym, col = _icon("ok")
    tag = c(col, f" {sym} ")
    print(f"{tag} {c(BGREEN, text)}")


def msg_fail(text: str) -> None:
    sym, col = _icon("fail")
    tag = c(col, f" {sym} ")
    print(f"{tag} {c(BRED, text)}", file=sys.stderr)


def msg_info(text: str) -> None:
    sym, col = _icon("info")
    tag = c(col, f"[{sym}]")
    print(f"{tag} {text}")


def msg_warn(text: str) -> None:
    sym, col = _icon("warn")
    tag = c(col, f"[{sym}]")
    print(f"{tag} {c(BYELLOW, text)}")


def msg_scan(text: str) -> None:
    sym, col = _icon("scan")
    tag = c(col, f"[{sym}]")
    print(f"{tag} {c(BBLUE, text)}")


def msg_done(text: str) -> None:
    sym, col = _icon("done")
    tag = c(col, f"[{sym}]")
    print(f"{tag} {c(BGREEN, BOLD + text + RESET)}")


def msg_debug(text: str) -> None:
    sym, col = _icon("debug")
    tag = c(col, f"[{sym}]")
    print(f"{tag} {c(DIM, text)}")


# ---------------------------------------------------------------------------
# Secret finding display
# ---------------------------------------------------------------------------

_SEVERITY_STYLE = {
    "critical": (BG_RED    + BWHITE + BOLD, "CRITICAL"),
    "high":     (BRED      + BOLD,           "HIGH    "),
    "medium":   (BYELLOW   + BOLD,           "MEDIUM  "),
    "low":      (BBLUE     + BOLD,           "LOW     "),
    "info":     (DIM       + WHITE,          "INFO    "),
}


def msg_secret(severity: str, text: str, source: str = "", location: str = "") -> None:
    """Display a secret finding with severity badge."""
    sym, _ = _icon("secret")
    style, label = _SEVERITY_STYLE.get(
        severity.lower(), (BWHITE, severity.upper().ljust(8))
    )
    badge = c(style, f" {label} ")
    src_tag = c(DIM + CYAN, f"[{source}]") if source else ""
    loc_tag = c(DIM, f" {location}") if location else ""
    print(f"  {sym} {badge} {src_tag}{loc_tag}")
    print(f"      {c(BWHITE, text)}")


def msg_finding_detail(finding) -> None:
    """Pretty-print a SecretFinding object."""
    style, label = _SEVERITY_STYLE.get(
        finding.severity.lower(), (BWHITE, finding.severity.upper().ljust(8))
    )
    badge  = c(style, f" {label} ")
    cat    = c(DIM + MAGENTA, f"[{finding.category}]")
    typ    = c(BMAGENTA, finding.type)
    src    = c(BCYAN, finding.source)
    conf   = c(DIM, f"conf:{finding.confidence}")
    loc    = c(DIM + WHITE, finding.location)
    val    = c(BYELLOW, finding.masked_value())

    sym, _ = _icon("secret")
    print(f"\n  {sym} {badge} {cat} {typ}  {conf}")
    print(f"      {c(DIM,'src:')} {src}  {c(DIM,'loc:')} {loc}")
    print(f"      {c(DIM,'val:')} {val}")
    if finding.context:
        ctx = finding.context[:120].replace("\n", " ").strip()
        print(f"      {c(DIM,'ctx:')} {c(DIM + WHITE, ctx)}")
    if finding.metadata:
        meta_parts = []
        for k, v in finding.metadata.items():
            if v:
                meta_parts.append(f"{k}={str(v)[:40]}")
        if meta_parts:
            print(f"      {c(DIM,'meta:')} {c(DIM, '  '.join(meta_parts))}")


# ---------------------------------------------------------------------------
# Section / structural helpers
# ---------------------------------------------------------------------------

def section(title: str, icon: str = "") -> None:
    """Print a section header."""
    term_width = shutil.get_terminal_size((80, 20)).columns
    sep = "─" * min(term_width - 2, 72)
    print()
    print(c(DIM + CYAN, "  " + sep))
    prefix = f"  {icon} " if icon else "  "
    print(f"{prefix}{c(BOLD + BWHITE, title)}")
    print(c(DIM + CYAN, "  " + sep))


def subsection(title: str) -> None:
    """Print a subsection header."""
    print(f"\n  {c(BOLD + CYAN, '»')} {c(BOLD + WHITE, title)}")


def progress_bar(
    current: int,
    total: int,
    label: str = "",
    width: int = 30,
    prefix: str = "  ",
) -> None:
    """
    Print an in-place progress bar.
    Call with current==total for the final newline.
    """
    if total == 0:
        pct = 100.0
    else:
        pct = min(100.0, current / total * 100)

    filled = int(width * pct / 100)
    bar    = "█" * filled + "░" * (width - filled)

    if _COLOR_ENABLED:
        bar_str = f"{BBLUE}{bar}{RESET}"
    else:
        bar_str = bar

    line = f"\r{prefix}[{bar_str}] {pct:5.1f}%  {label[:40]:<40}"
    sys.stdout.write(line)
    sys.stdout.flush()

    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Table renderer
# ---------------------------------------------------------------------------

def table(
    headers: list,
    rows: list,
    col_colors: list = None,
    title: str = "",
    indent: str = "  ",
) -> None:
    """
    Render a simple fixed-width table.

    headers   : list of str
    rows      : list of list/tuple (each row = one record)
    col_colors: optional list of ANSI codes per column
    title     : optional table title
    indent    : left indent string
    """
    if not rows:
        msg_info("No data to display.")
        return

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    def fmt_row(cells, colors=None, bold=False):
        parts = []
        for i, cell in enumerate(cells):
            w   = col_widths[i] if i < len(col_widths) else 10
            txt = str(cell).ljust(w)
            if colors and i < len(colors) and colors[i]:
                txt = c(colors[i] + (BOLD if bold else ""), txt)
            elif bold:
                txt = c(BOLD, txt)
            parts.append(txt)
        return f"{indent}  " + "   ".join(parts)

    sep = indent + "  " + "─" * (sum(col_widths) + 3 * len(col_widths))

    if title:
        print(f"\n{indent}{c(BOLD + BWHITE, title)}")

    print(sep)
    print(fmt_row(headers, bold=True))
    print(sep)
    for row in rows:
        print(fmt_row(row, colors=col_colors))
    print(sep)


# ---------------------------------------------------------------------------
# Summary box
# ---------------------------------------------------------------------------

def summary_box(stats: dict, title: str = "Scan Summary") -> None:
    """Print a findings summary box."""
    section(title, "▶")

    severity_colors = {
        "critical": BRED + BOLD,
        "high":     BYELLOW + BOLD,
        "medium":   BYELLOW,
        "low":      BBLUE,
        "info":     DIM + WHITE,
    }

    total = stats.get("total_findings", 0)
    print(f"\n  {c(BOLD, 'Total findings:')} {c(BRED + BOLD if total else BGREEN, str(total))}")
    print()

    for sev in ("critical", "high", "medium", "low", "info"):
        key  = f"findings_{sev}"
        cnt  = stats.get(key, 0)
        col  = severity_colors.get(sev, WHITE)
        bar  = "■" * min(cnt, 40)
        sev_label = c(col, sev.upper().ljust(8))
        cnt_label = c(col, str(cnt).rjust(4))
        bar_label = c(DIM + col.split("\033")[1] if "\033" in col else DIM, bar[:40])
        print(f"    {sev_label}  {cnt_label}  {bar_label}")

    print()

    # By source
    by_source = stats.get("by_source", {})
    if by_source:
        print(f"  {c(BOLD + BWHITE, 'By source:')}")
        for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
            print(f"    {c(CYAN, src.ljust(12))}  {c(BWHITE, str(cnt))}")
        print()

    # By category
    by_cat = stats.get("by_category", {})
    if by_cat:
        print(f"  {c(BOLD + BWHITE, 'By category:')}")
        for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
            print(f"    {c(MAGENTA, cat.ljust(16))}  {c(BWHITE, str(cnt))}")
        print()

    files  = stats.get("files_scanned", 0)
    bscann = stats.get("bytes_scanned", 0)
    dur    = stats.get("duration_seconds", 0)

    def human_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    print(f"  {c(DIM, 'Files scanned:')} {files}    "
          f"{c(DIM, 'Data:')} {human_bytes(bscann)}    "
          f"{c(DIM, 'Duration:')} {dur:.1f}s")
