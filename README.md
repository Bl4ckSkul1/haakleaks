# HaakLeaks

```
██╗  ██╗ █████╗  █████╗ ██╗  ██╗██╗     ███████╗ █████╗ ██╗  ██╗███████╗
██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██║     ██╔════╝██╔══██╗██║ ██╔╝██╔════╝
███████║███████║███████║█████╔╝ ██║     █████╗  ███████║█████╔╝ ███████╗
██╔══██║██╔══██║██╔══██║██╔═██╗ ██║     ██╔══╝  ██╔══██║██╔═██╗ ╚════██║
██║  ██║██║  ██║██║  ██║██║  ██╗███████╗███████╗██║  ██║██║  ██╗███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

  Multi-Source Secret Scanner
  By Adrian Martinez | HAAK Cybersecurity
```

**The Swiss army knife of secret finding. Scans everything: git history, Docker images, APKs, binaries, configs, network captures, and cloud storage.**

HaakLeaks hunts for leaked secrets across 7 source types using 127+ regex patterns and Shannon entropy analysis. One tool to find API keys, tokens, passwords, and credentials wherever they hide.

---

## Sources

| Source | What it scans | Key features |
|--------|--------------|--------------|
| **Git** | Repository commit history | Diffs, deleted files, blame, dedup across commits |
| **Docker** | Container image layers | ENV/ARG in history, filesystem scanning, tar fallback |
| **APK** | Android applications | DEX strings, AndroidManifest, google-services.json, React Native bundles |
| **Binary** | Executables & firmware | ASCII/UTF-16 strings, JAR/WAR extraction, PE/ELF detection |
| **Config** | Directories & files | .env, YAML, JSON, Terraform, K8s secrets, shell history, private keys |
| **PCAP** | Network captures | HTTP Basic/Bearer, cookies, FTP, SMTP, POST credentials |
| **Cloud** | Public buckets | S3, Azure Blob, GCP Storage, DigitalOcean Spaces |

---

## Quick Start

```bash
git clone https://github.com/Bl4ckSkul1/haakleaks.git
cd haakleaks
pip install requests
```

### Usage

```bash
# Scan git repository history
python haakleaks.py --git /path/to/repo

# Scan Docker image
python haakleaks.py --docker myapp:latest

# Scan Android APK
python haakleaks.py --apk app-release.apk

# Scan binary/firmware
python haakleaks.py --binary firmware.bin

# Scan directory for config files with secrets
python haakleaks.py --config /var/www/app/

# Scan network capture
python haakleaks.py --pcap traffic.pcapng

# Scan public S3 bucket
python haakleaks.py --cloud s3://company-backups

# Auto-detect and scan everything in a path
python haakleaks.py --all /path/to/target

# Multiple sources at once
python haakleaks.py --git /repo --config /repo --binary /repo/dist/app.exe
```

### Reports

```bash
python haakleaks.py --git /repo -o results.json --html report.html --engagement HAAK-2026-006
```

---

## All Options

```
python haakleaks.py [source options] [scan options] [output options]

SOURCES (at least one required):
  --git PATH            Scan git repository history
  --docker IMAGE        Scan Docker image layers
  --apk FILE            Scan Android APK
  --binary FILE         Scan binary file
  --config PATH         Scan directory for config files
  --pcap FILE           Scan network capture
  --cloud URL           Scan cloud storage (s3://bucket)
  --all PATH            Auto-detect and scan everything

SCAN OPTIONS:
  --min-entropy N       Min entropy threshold (default: 4.0)
  --no-entropy          Skip entropy analysis
  --max-file-size N     Max file size in MB (default: 50)
  --git-depth N         Git history depth (0=all)
  --git-branch NAME     Specific git branch
  --include PATTERNS    File patterns to include (e.g., "*.py,*.js")
  --exclude PATTERNS    File patterns to exclude

OUTPUT:
  -o, --output FILE     JSON report
  --html FILE           HTML report
  --engagement ID       Engagement ID
  -q, --quiet           Minimal output
  --proxy URL           HTTP proxy (for cloud scanner)
  --timeout N           Request timeout
```

---

## Detection Patterns (127+)

### API Keys & Tokens
AWS, Google, Azure, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, OpenAI, Anthropic, npm, Shopify, Discord, Telegram, Mailgun, Square, PayPal, Heroku, DigitalOcean, Cloudflare, Datadog, Sentry, New Relic, Auth0, Okta, and more.

### Credentials
Passwords in code/config, Basic Auth, Bearer tokens, MongoDB/PostgreSQL/MySQL/Redis/AMQP/SMTP connection strings, private keys (RSA, EC, DSA, PGP, SSH), .netrc/.pgpass credentials.

### Cloud Resources
S3 buckets, Azure Blob/Vault, GCP Storage, Firebase, DigitalOcean Spaces.

### Configuration Secrets
.env files, Terraform variables, Kubernetes secrets (base64), Docker Compose env vars, CI/CD tokens, Spring Boot properties, .NET appsettings.

---

## HTML Report

- **Executive Dashboard** with animated metric cards
- **Findings by Source** horizontal bar chart with source-colored bars
- **Findings by Category** with colored pills
- **Severity Breakdown** with stacked proportional bar
- **Findings Table** with filter (severity/source/category), search, pagination
- **Git Timeline** (auto-shown for git findings) with commit-level visualization
- **Click-to-reveal secrets** (masked by default, warns before showing)
- Dark HAAK theme, self-contained HTML, print-friendly

---

## Pipeline Integration

```bash
# AttackMap → HaakLeaks: scan discovered infrastructure
python haakleaks.py --config /path/to/discovered/configs

# HaakJS → HaakLeaks: scan git history where JS secrets were found
python haakleaks.py --git /repo -o git_secrets.json

# HaakLeaks → HaakAuth: test discovered credentials
python haakauth.py -u https://api.target.com -t "Bearer <found_token>" --all

# Full engagement pipeline
python haakleaks.py --all /target --git /target -o leaks.json --html leaks.html
```

---

## Project Structure

```
haakleaks/
├── haakleaks.py                       # Entry point
├── haakleaks_report.py                # HTML report generator
├── README.md
├── requirements.txt
├── setup.py
├── LICENSE
└── leak_scanner/
    ├── __init__.py
    ├── main.py                        # CLI orchestrator
    ├── core.py                        # BaseScanner, SecretFinding
    ├── colors.py                      # Terminal output
    ├── patterns.py                    # 127+ regex patterns
    ├── entropy.py                     # Shannon entropy analysis
    ├── data/
    │   └── __init__.py
    └── modules/
        ├── __init__.py
        ├── git_scanner.py             # Git history
        ├── docker_scanner.py          # Docker images
        ├── apk_scanner.py             # Android APKs
        ├── binary_scanner.py          # Binaries & firmware
        ├── config_scanner.py          # Config files & directories
        ├── pcap_scanner.py            # Network captures
        └── cloud_scanner.py           # Cloud storage
```

---

## Requirements

- Python 3.10+
- `requests` (only external dependency)
- Optional: `git` CLI (for git scanner), `docker` CLI (for docker scanner), `tshark` (for enhanced PCAP parsing)

---

## Author

**Adrian Martinez** — Pentester & COO at HAAK Cybersecurity Consulting

- me@adrianmartinez.lat
- [@adrian.offsec](https://instagram.com/adrian.offsec)
- [@haakconsulting](https://instagram.com/haakconsulting)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is for **authorized security testing only**. Only use against systems where you have explicit written permission. Unauthorized use may be illegal. The authors are not responsible for misuse of this tool.
