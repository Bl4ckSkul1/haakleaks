"""
HaakLeaks — PCAP Network Capture Scanner
Parses pcap files for credentials transmitted in cleartext:
HTTP Basic/Bearer, FTP, SMTP AUTH, form POST bodies, and more.
Uses stdlib-only PCAP parsing with optional tshark fallback.
By Adrian Martinez | HAAK Cybersecurity
"""

import base64
import os
import re
import struct
import subprocess
import urllib.parse

from leak_scanner.core import BaseScanner, SecretFinding
from leak_scanner.patterns import scan_content, SECRET_PATTERNS
from leak_scanner.entropy import shannon_entropy, is_high_entropy
from leak_scanner.colors import (
    msg_info, msg_ok, msg_warn, msg_secret, section, progress_bar
)


# ---------------------------------------------------------------------------
# PCAP format constants
# ---------------------------------------------------------------------------
PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

PCAP_MAGIC_LE = 0xa1b2c3d4   # little-endian, microseconds
PCAP_MAGIC_BE = 0xd4c3b2a1   # big-endian, microseconds
PCAP_MAGIC_LE_NS = 0xa1b23c4d  # little-endian, nanoseconds
PCAP_MAGIC_BE_NS = 0x4d3cb2a1  # big-endian, nanoseconds

# Ethernet + IP minimum header sizes
ETH_HEADER_SIZE = 14
IP_MIN_HEADER_SIZE = 20
TCP_MIN_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8

# EtherType
ETHERTYPE_IP   = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# IP Protocol numbers
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# Max payload size to analyze per packet
MAX_PAYLOAD = 64 * 1024  # 64 KB


# ---------------------------------------------------------------------------
# Credential-in-cleartext patterns
# ---------------------------------------------------------------------------

# HTTP Authorization header
_HTTP_AUTH_BASIC_RE = re.compile(
    rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)
_HTTP_AUTH_BEARER_RE = re.compile(
    rb"Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/=]+)",
    re.IGNORECASE,
)
_HTTP_API_KEY_HEADER_RE = re.compile(
    rb"(?:X-API-Key|X-Auth-Token|X-Access-Token|Authorization):\s*([A-Za-z0-9\-._~+/=]{20,})",
    re.IGNORECASE,
)
# HTTP Cookie
_HTTP_COOKIE_RE = re.compile(
    rb"Cookie:\s*([^\r\n]{8,512})",
    re.IGNORECASE,
)
# HTTP POST body — form-encoded
_POST_BODY_PASSWORD_RE = re.compile(
    rb"(?:password|passwd|pwd|pass|secret|token|api_key|apikey|api-key)"
    rb"=([^&\r\n\s]{1,256})",
    re.IGNORECASE,
)
# HTTP POST body — JSON body snippet
_JSON_BODY_SECRET_RE = re.compile(
    rb'"(?:password|passwd|secret|token|api_key|apikey|client_secret|access_token)"'
    rb'\s*:\s*"([^"]{1,256})"',
    re.IGNORECASE,
)
# HTTP request line with credentials in URL
_HTTP_REQUEST_LINE_RE = re.compile(
    rb"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+([^\s]+)\s+HTTP/",
    re.IGNORECASE,
)
_URL_CRED_RE = re.compile(
    r"(?:password|passwd|token|secret|api[_\-]?key)=([^&\s#]{4,128})",
    re.IGNORECASE,
)

# FTP
_FTP_USER_RE = re.compile(rb"^USER\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_FTP_PASS_RE = re.compile(rb"^PASS\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)

# SMTP AUTH
_SMTP_AUTH_LOGIN_RE = re.compile(rb"^AUTH\s+LOGIN", re.IGNORECASE | re.MULTILINE)
_SMTP_AUTH_PLAIN_RE = re.compile(
    rb"^AUTH\s+PLAIN\s+([A-Za-z0-9+/=]{4,})",
    re.IGNORECASE | re.MULTILINE,
)
_SMTP_BASE64_RE = re.compile(rb"^([A-Za-z0-9+/=]{8,})\r?\n", re.MULTILINE)

# LDAP (basic: simple bind request magic)
_LDAP_BIND_RE = re.compile(
    rb"\x60.{1,3}\x02\x01.{1,3}\x04.{1,64}\x80.{1,64}"
)

# Database connection strings in raw payloads
_DB_CONN_RE = re.compile(
    rb"(?:jdbc:|mongodb(?:\+srv)?://|postgres://|mysql://|redis://|mssql://)"
    rb"[A-Za-z0-9\-._:@/?&=]{8,200}",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# tshark availability check
# ---------------------------------------------------------------------------

def _tshark_available() -> bool:
    try:
        r = subprocess.run(
            ["tshark", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _run_tshark(pcap_file: str, fields: list, display_filter: str = "") -> list:
    """
    Run tshark to extract specific fields.
    Returns list of tab-separated line strings.
    """
    args = ["tshark", "-r", pcap_file, "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    if display_filter:
        args += ["-Y", display_filter]
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=120, errors="replace"
        )
        if r.returncode == 0:
            return [line for line in r.stdout.splitlines() if line.strip()]
    except Exception as ex:
        msg_warn(f"tshark error: {ex}")
    return []


# ---------------------------------------------------------------------------
# PCAP binary parser
# ---------------------------------------------------------------------------

class PCAPParser:
    """
    Minimal PCAP file parser (no pcapng support).
    Yields (pkt_no, src_ip, dst_ip, src_port, dst_port, proto, payload_bytes)
    """

    def __init__(self, path: str):
        self.path = path
        self.big_endian = False
        self.valid = False
        self._data = b""
        self._offset = 0
        self._load()

    def _load(self):
        try:
            with open(self.path, "rb") as fh:
                self._data = fh.read()
        except OSError as ex:
            msg_warn(f"Cannot read PCAP: {ex}")
            return

        if len(self._data) < PCAP_GLOBAL_HEADER_SIZE:
            msg_warn("File too small to be a PCAP")
            return

        magic = struct.unpack("<I", self._data[:4])[0]
        if magic in {PCAP_MAGIC_LE, PCAP_MAGIC_LE_NS}:
            self.big_endian = False
        elif magic in {PCAP_MAGIC_BE, PCAP_MAGIC_BE_NS}:
            self.big_endian = True
        else:
            msg_warn(f"Unrecognized PCAP magic: {magic:#010x} — not a standard PCAP file")
            return

        self._offset = PCAP_GLOBAL_HEADER_SIZE
        self.valid = True

    def _u16(self, data: bytes, offset: int) -> int:
        fmt = ">H" if self.big_endian else "<H"
        return struct.unpack_from(fmt, data, offset)[0]

    def _u32(self, data: bytes, offset: int) -> int:
        fmt = ">I" if self.big_endian else "<I"
        return struct.unpack_from(fmt, data, offset)[0]

    def packets(self):
        """Yield parsed packets as (pkt_no, src_ip, dst_ip, sport, dport, proto, payload)."""
        pkt_no = 0
        offset = self._offset
        data = self._data

        while offset + PCAP_PACKET_HEADER_SIZE <= len(data):
            pkt_no += 1

            # Packet header: ts_sec, ts_usec, incl_len, orig_len
            incl_len = self._u32(data, offset + 8)
            offset += PCAP_PACKET_HEADER_SIZE

            if offset + incl_len > len(data):
                break

            raw_pkt = data[offset: offset + incl_len]
            offset += incl_len

            parsed = self._parse_packet(raw_pkt)
            if parsed:
                yield (pkt_no,) + parsed

    def _parse_packet(self, raw: bytes):
        """Parse Ethernet→IP→TCP/UDP, return (src_ip, dst_ip, sport, dport, proto_str, payload)."""
        if len(raw) < ETH_HEADER_SIZE:
            return None

        ethertype = struct.unpack_from(">H", raw, 12)[0]

        # VLAN tag
        vlan_offset = 0
        if ethertype == ETHERTYPE_VLAN:
            if len(raw) < ETH_HEADER_SIZE + 4:
                return None
            ethertype = struct.unpack_from(">H", raw, 16)[0]
            vlan_offset = 4

        if ethertype not in {ETHERTYPE_IP, ETHERTYPE_IPV6}:
            return None

        ip_offset = ETH_HEADER_SIZE + vlan_offset

        if ethertype == ETHERTYPE_IP:
            return self._parse_ipv4(raw, ip_offset)
        # IPv6 not fully parsed (too complex without deps); skip payload extraction
        return None

    def _parse_ipv4(self, raw: bytes, ip_offset: int):
        if len(raw) < ip_offset + IP_MIN_HEADER_SIZE:
            return None

        ihl = (raw[ip_offset] & 0x0F) * 4
        if ihl < IP_MIN_HEADER_SIZE:
            return None

        proto = raw[ip_offset + 9]
        src_ip = ".".join(str(b) for b in raw[ip_offset + 12: ip_offset + 16])
        dst_ip = ".".join(str(b) for b in raw[ip_offset + 16: ip_offset + 20])

        transport_offset = ip_offset + ihl

        if proto == IP_PROTO_TCP:
            return self._parse_tcp(raw, transport_offset, src_ip, dst_ip)
        elif proto == IP_PROTO_UDP:
            return self._parse_udp(raw, transport_offset, src_ip, dst_ip)

        return None

    def _parse_tcp(self, raw: bytes, offset: int, src_ip: str, dst_ip: str):
        if len(raw) < offset + TCP_MIN_HEADER_SIZE:
            return None
        sport = struct.unpack_from(">H", raw, offset)[0]
        dport = struct.unpack_from(">H", raw, offset + 2)[0]
        data_offset = ((raw[offset + 12] >> 4) & 0xF) * 4
        if data_offset < TCP_MIN_HEADER_SIZE:
            data_offset = TCP_MIN_HEADER_SIZE
        payload_start = offset + data_offset
        payload = raw[payload_start: payload_start + MAX_PAYLOAD]
        if not payload:
            return None
        return src_ip, dst_ip, sport, dport, "TCP", payload

    def _parse_udp(self, raw: bytes, offset: int, src_ip: str, dst_ip: str):
        if len(raw) < offset + UDP_HEADER_SIZE:
            return None
        sport = struct.unpack_from(">H", raw, offset)[0]
        dport = struct.unpack_from(">H", raw, offset + 2)[0]
        payload = raw[offset + UDP_HEADER_SIZE: offset + UDP_HEADER_SIZE + MAX_PAYLOAD]
        if not payload:
            return None
        return src_ip, dst_ip, sport, dport, "UDP", payload


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class PCAPScanner(BaseScanner):
    NAME = "pcap"
    DESCRIPTION = "Scan network captures for credentials transmitted in cleartext"

    def scan(self) -> list:
        section("PCAP Network Capture Scanner", "📡")
        findings = []
        target = self.target.strip()

        if not os.path.isfile(target):
            msg_warn(f"PCAP file not found: {target}")
            return findings

        file_size = os.path.getsize(target)
        msg_info(f"Scanning: {os.path.basename(target)} ({file_size // 1024} KB)")

        use_tshark = _tshark_available()
        if use_tshark:
            msg_info("tshark detected — using enhanced parsing")
            findings.extend(self._scan_with_tshark(target))
        else:
            msg_info("tshark not available — using built-in PCAP parser")

        # Always run the built-in parser for raw payload scanning
        findings.extend(self._scan_builtin(target))

        # Deduplicate (same value from both parsers)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.type, f.value[:64])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        msg_ok(f"PCAP scan complete: {self.files_scanned} packets processed, {len(deduped)} findings")
        self.findings = deduped
        return deduped

    # ---------------------------------------------------------------------- #
    # tshark-based extraction
    # ---------------------------------------------------------------------- #
    def _scan_with_tshark(self, pcap_file: str) -> list:
        findings = []

        # HTTP Authorization / Cookie
        http_rows = _run_tshark(
            pcap_file,
            ["http.authorization", "http.cookie", "http.request.uri",
             "http.request.method", "http.file_data"],
            display_filter="http",
        )
        for row in http_rows:
            parts = row.split("\t")
            auth_val = parts[0].strip() if len(parts) > 0 else ""
            cookie_val = parts[1].strip() if len(parts) > 1 else ""
            uri_val = parts[2].strip() if len(parts) > 2 else ""
            method_val = parts[3].strip() if len(parts) > 3 else ""
            body_val = parts[4].strip() if len(parts) > 4 else ""

            if auth_val:
                findings.extend(self._classify_auth_header(
                    auth_val, "tshark-http", "HTTP Authorization (tshark)"
                ))

            if cookie_val and len(cookie_val) > 20:
                findings.extend(self._analyze_cookie(cookie_val, "tshark-http"))

            if uri_val:
                findings.extend(self._analyze_url(uri_val, "tshark-http"))

            if body_val:
                findings.extend(self._analyze_post_body(
                    body_val.encode("utf-8", errors="replace"), "tshark-http", 0, "", ""
                ))

        # FTP
        ftp_rows = _run_tshark(
            pcap_file,
            ["ftp.request.command", "ftp.request.arg"],
            display_filter="ftp",
        )
        ftp_user = None
        for row in ftp_rows:
            parts = row.split("\t")
            cmd = parts[0].strip() if parts else ""
            arg = parts[1].strip() if len(parts) > 1 else ""
            if cmd.upper() == "USER":
                ftp_user = arg
            elif cmd.upper() == "PASS" and arg:
                self.add_finding(
                    severity="critical",
                    category="cleartext_credential",
                    type_="ftp_cleartext_password",
                    value=arg,
                    location="tshark-ftp",
                    context=f"FTP login — user: {ftp_user or '?'}, pass: {arg}",
                    line_number=0,
                    description="FTP password transmitted in cleartext",
                    confidence="high",
                    metadata={"protocol": "FTP", "username": ftp_user or ""},
                )
                findings.append(self.findings[-1])
                ftp_user = None

        return findings

    # ---------------------------------------------------------------------- #
    # Built-in PCAP parser
    # ---------------------------------------------------------------------- #
    def _scan_builtin(self, pcap_file: str) -> list:
        findings = []

        parser = PCAPParser(pcap_file)
        if not parser.valid:
            return findings

        # Count packets for progress bar
        total_packets = sum(1 for _ in parser.packets())
        msg_info(f"Total packets: {total_packets}")

        # Re-create parser (iterator consumed)
        parser = PCAPParser(pcap_file)

        for pkt_no, src_ip, dst_ip, sport, dport, proto, payload in parser.packets():
            if pkt_no % 1000 == 0 or pkt_no == total_packets:
                progress_bar(pkt_no, total_packets, label=f"pkt {pkt_no}", width=30)

            self.files_scanned += 1
            self.bytes_scanned += len(payload)

            loc = f"pkt#{pkt_no} {src_ip}:{sport}→{dst_ip}:{dport}"

            # --------------------------------------------- HTTP
            if b"HTTP/" in payload or payload.startswith(b"GET ") or \
               payload.startswith(b"POST ") or payload.startswith(b"PUT "):
                findings.extend(
                    self._scan_http_payload(payload, pkt_no, src_ip, dst_ip)
                )

            # --------------------------------------------- FTP
            elif dport == 21 or sport == 21:
                findings.extend(
                    self._scan_ftp_payload(payload, pkt_no, src_ip, dst_ip)
                )

            # --------------------------------------------- SMTP
            elif dport in {25, 587, 465} or sport in {25, 587, 465}:
                findings.extend(
                    self._scan_smtp_payload(payload, pkt_no, src_ip, dst_ip)
                )

            # --------------------------------------------- Database ports
            elif dport in {5432, 3306, 1433, 27017, 6379} or \
                 sport in {5432, 3306, 1433, 27017, 6379}:
                findings.extend(
                    self._scan_db_payload(payload, pkt_no, src_ip, dst_ip, dport or sport)
                )

            # --------------------------------------------- Generic payload scan
            # Extract printable strings and run patterns
            printable = re.sub(rb"[^\x20-\x7E\r\n\t]", b" ", payload)
            text = printable.decode("ascii", errors="replace")
            matches = scan_content(text, filename=f"packet_{pkt_no}")
            for (
                pattern_name, match_value, severity, category,
                description, confidence, m_start, m_end
            ) in matches:
                self.add_finding(
                    severity=severity,
                    category=category,
                    type_=pattern_name,
                    value=match_value,
                    location=loc,
                    context=text[max(0, m_start - 40): m_end + 40].strip()[:200],
                    line_number=pkt_no,
                    description=f"{description} (in raw packet payload)",
                    confidence=confidence,
                    metadata={
                        "protocol": proto,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": sport,
                        "dst_port": dport,
                        "packet": pkt_no,
                    },
                )
                findings.append(self.findings[-1])

        progress_bar(total_packets, total_packets, label="Done", width=30)
        return findings

    # ---------------------------------------------------------------------- #
    # Protocol-specific payload scanners
    # ---------------------------------------------------------------------- #
    def _scan_http_payload(self, payload: bytes, pkt_no: int, src_ip: str, dst_ip: str) -> list:
        findings = []
        loc = f"pkt#{pkt_no} {src_ip}→{dst_ip} HTTP"

        # Authorization: Basic
        for m in _HTTP_AUTH_BASIC_RE.finditer(payload):
            b64 = m.group(1).decode("ascii", errors="replace").strip()
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
            except Exception:
                decoded = b64
            self.add_finding(
                severity="critical",
                category="cleartext_credential",
                type_="http_basic_auth",
                value=decoded,
                location=loc,
                context=f"Authorization: Basic {b64[:40]}",
                line_number=pkt_no,
                description="HTTP Basic Authentication credentials in cleartext",
                confidence="high",
                metadata={
                    "protocol": "HTTP",
                    "auth_type": "Basic",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet": pkt_no,
                },
            )
            findings.append(self.findings[-1])

        # Authorization: Bearer
        for m in _HTTP_AUTH_BEARER_RE.finditer(payload):
            token = m.group(1).decode("ascii", errors="replace").strip()
            self.add_finding(
                severity="high",
                category="token",
                type_="http_bearer_token",
                value=token,
                location=loc,
                context=f"Authorization: Bearer {token[:40]}",
                line_number=pkt_no,
                description="HTTP Bearer token captured in cleartext",
                confidence="high",
                metadata={
                    "protocol": "HTTP",
                    "auth_type": "Bearer",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet": pkt_no,
                },
            )
            findings.append(self.findings[-1])

        # Cookie header
        for m in _HTTP_COOKIE_RE.finditer(payload):
            cookie_val = m.group(1).decode("ascii", errors="replace").strip()
            if any(kw in cookie_val.lower() for kw in
                   ("session", "token", "auth", "jwt", "sid", "user_id")):
                self.add_finding(
                    severity="high",
                    category="session_token",
                    type_="http_session_cookie",
                    value=cookie_val[:200],
                    location=loc,
                    context=f"Cookie: {cookie_val[:80]}",
                    line_number=pkt_no,
                    description="Session/auth cookie captured in cleartext",
                    confidence="medium",
                    metadata={
                        "protocol": "HTTP",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packet": pkt_no,
                    },
                )
                findings.append(self.findings[-1])

        # POST body — form-encoded credentials
        findings.extend(self._analyze_post_body(payload, loc, pkt_no, src_ip, dst_ip))

        # URL with credentials in query string
        for m in _HTTP_REQUEST_LINE_RE.finditer(payload):
            url_raw = m.group(1).decode("ascii", errors="replace")
            findings.extend(self._analyze_url(url_raw, loc))

        # DB connection strings in payload
        for m in _DB_CONN_RE.finditer(payload):
            val = m.group().decode("ascii", errors="replace")
            self.add_finding(
                severity="high",
                category="connection_string",
                type_="db_connection_in_http",
                value=val,
                location=loc,
                context=val[:200],
                line_number=pkt_no,
                description="Database connection string in HTTP payload",
                confidence="medium",
                metadata={"protocol": "HTTP", "src_ip": src_ip, "dst_ip": dst_ip, "packet": pkt_no},
            )
            findings.append(self.findings[-1])

        return findings

    def _scan_ftp_payload(self, payload: bytes, pkt_no: int, src_ip: str, dst_ip: str) -> list:
        findings = []
        loc = f"pkt#{pkt_no} {src_ip}→{dst_ip} FTP"

        users = _FTP_USER_RE.findall(payload)
        passwords = _FTP_PASS_RE.findall(payload)

        if passwords:
            for pwd_bytes in passwords:
                pwd = pwd_bytes.decode("ascii", errors="replace").strip()
                user = users[0].decode("ascii", errors="replace").strip() if users else "unknown"
                self.add_finding(
                    severity="critical",
                    category="cleartext_credential",
                    type_="ftp_cleartext_password",
                    value=pwd,
                    location=loc,
                    context=f"FTP: USER {user} / PASS {pwd}",
                    line_number=pkt_no,
                    description="FTP credentials transmitted in cleartext",
                    confidence="high",
                    metadata={
                        "protocol": "FTP",
                        "username": user,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packet": pkt_no,
                    },
                )
                findings.append(self.findings[-1])

        return findings

    def _scan_smtp_payload(self, payload: bytes, pkt_no: int, src_ip: str, dst_ip: str) -> list:
        findings = []
        loc = f"pkt#{pkt_no} {src_ip}→{dst_ip} SMTP"

        # AUTH PLAIN — base64 encoded credentials
        for m in _SMTP_AUTH_PLAIN_RE.finditer(payload):
            b64 = m.group(1).decode("ascii", errors="replace").strip()
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                # Format: \x00username\x00password
                parts = [p for p in decoded.split("\x00") if p]
                readable = " | ".join(parts) if parts else decoded
            except Exception:
                readable = b64

            self.add_finding(
                severity="critical",
                category="cleartext_credential",
                type_="smtp_auth_plain",
                value=readable,
                location=loc,
                context=f"SMTP AUTH PLAIN: {b64[:40]}",
                line_number=pkt_no,
                description="SMTP AUTH PLAIN credentials in cleartext",
                confidence="high",
                metadata={
                    "protocol": "SMTP",
                    "auth_type": "PLAIN",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet": pkt_no,
                },
            )
            findings.append(self.findings[-1])

        # AUTH LOGIN — next packets contain base64 username then password
        if _SMTP_AUTH_LOGIN_RE.search(payload):
            # Extract any base64 blobs that follow AUTH LOGIN
            for m in _SMTP_BASE64_RE.finditer(payload):
                b64 = m.group(1).decode("ascii", errors="replace").strip()
                if len(b64) >= 8:
                    try:
                        decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="replace")
                        if decoded.isprintable() and len(decoded) >= 3:
                            self.add_finding(
                                severity="critical",
                                category="cleartext_credential",
                                type_="smtp_auth_login",
                                value=decoded,
                                location=loc,
                                context=f"SMTP AUTH LOGIN: {b64[:40]} → {decoded}",
                                line_number=pkt_no,
                                description="SMTP AUTH LOGIN credential (base64) in cleartext",
                                confidence="medium",
                                metadata={
                                    "protocol": "SMTP",
                                    "auth_type": "LOGIN",
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "packet": pkt_no,
                                },
                            )
                            findings.append(self.findings[-1])
                    except Exception:
                        pass

        return findings

    def _scan_db_payload(
        self, payload: bytes, pkt_no: int,
        src_ip: str, dst_ip: str, port: int
    ) -> list:
        findings = []
        loc = f"pkt#{pkt_no} {src_ip}→{dst_ip} port:{port}"

        for m in _DB_CONN_RE.finditer(payload):
            val = m.group().decode("ascii", errors="replace")
            self.add_finding(
                severity="high",
                category="connection_string",
                type_="db_connection_string_in_traffic",
                value=val,
                location=loc,
                context=val[:200],
                line_number=pkt_no,
                description=f"Database connection URI in network traffic (port {port})",
                confidence="medium",
                metadata={
                    "protocol": "DB",
                    "port": port,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet": pkt_no,
                },
            )
            findings.append(self.findings[-1])

        return findings

    # ---------------------------------------------------------------------- #
    # Helpers
    # ---------------------------------------------------------------------- #
    def _classify_auth_header(self, auth_val: str, source: str, context: str) -> list:
        findings = []
        if auth_val.lower().startswith("basic "):
            b64 = auth_val[6:].strip()
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
            except Exception:
                decoded = b64
            self.add_finding(
                severity="critical",
                category="cleartext_credential",
                type_="http_basic_auth",
                value=decoded,
                location=source,
                context=context,
                line_number=0,
                description="HTTP Basic Authentication credentials",
                confidence="high",
                metadata={"auth_type": "Basic", "source": source},
            )
            findings.append(self.findings[-1])
        elif auth_val.lower().startswith("bearer "):
            token = auth_val[7:].strip()
            self.add_finding(
                severity="high",
                category="token",
                type_="http_bearer_token",
                value=token,
                location=source,
                context=context,
                line_number=0,
                description="HTTP Bearer token",
                confidence="high",
                metadata={"auth_type": "Bearer", "source": source},
            )
            findings.append(self.findings[-1])
        return findings

    def _analyze_cookie(self, cookie_val: str, source: str) -> list:
        findings = []
        if any(kw in cookie_val.lower() for kw in
               ("session", "token", "auth", "jwt", "sid")):
            self.add_finding(
                severity="high",
                category="session_token",
                type_="http_session_cookie",
                value=cookie_val[:200],
                location=source,
                context=f"Cookie: {cookie_val[:80]}",
                line_number=0,
                description="Session/auth cookie",
                confidence="medium",
                metadata={"source": source},
            )
            findings.append(self.findings[-1])
        return findings

    def _analyze_url(self, url: str, source: str) -> list:
        findings = []
        for m in _URL_CRED_RE.finditer(url):
            val = m.group(1)
            self.add_finding(
                severity="high",
                category="url_credential",
                type_="url_query_secret",
                value=val,
                location=source,
                context=f"URL: {url[:200]}",
                line_number=0,
                description="Secret/credential found in URL query parameter",
                confidence="medium",
                metadata={"url": url[:200], "source": source},
            )
            findings.append(self.findings[-1])
        return findings

    def _analyze_post_body(
        self, payload: bytes, loc: str, pkt_no: int, src_ip: str, dst_ip: str
    ) -> list:
        findings = []

        for m in _POST_BODY_PASSWORD_RE.finditer(payload):
            raw_val = m.group(1).decode("ascii", errors="replace")
            value = urllib.parse.unquote_plus(raw_val)
            self.add_finding(
                severity="critical",
                category="cleartext_credential",
                type_="http_post_password",
                value=value,
                location=loc,
                context=payload[max(0, m.start() - 30): m.end() + 30].decode("ascii", errors="replace")[:200],
                line_number=pkt_no,
                description="Password/secret submitted via HTTP POST body",
                confidence="high",
                metadata={
                    "protocol": "HTTP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet": pkt_no,
                },
            )
            findings.append(self.findings[-1])

        for m in _JSON_BODY_SECRET_RE.finditer(payload):
            value = m.group(1).decode("utf-8", errors="replace")
            self.add_finding(
                severity="critical",
                category="cleartext_credential",
                type_="http_post_json_secret",
                value=value,
                location=loc,
                context=payload[max(0, m.start() - 30): m.end() + 30].decode("ascii", errors="replace")[:200],
                line_number=pkt_no,
                description="Secret/password submitted via JSON POST body",
                confidence="high",
                metadata={
                    "protocol": "HTTP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet": pkt_no,
                },
            )
            findings.append(self.findings[-1])

        return findings
