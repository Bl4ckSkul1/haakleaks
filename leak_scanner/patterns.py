"""
HaakLeaks — Secret Detection Patterns
100+ regex patterns covering API keys, credentials, cloud resources, PII,
config secrets, and CI/CD tokens.

Each entry is a tuple:
  (name, compiled_regex, severity, category, description, confidence)
"""
import re

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _p(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | flags)


# ---------------------------------------------------------------------------
# FALSE POSITIVE FILTERS
# ---------------------------------------------------------------------------
# Values matching any of these patterns are silently discarded.

FALSE_POSITIVE_PATTERNS = [
    re.compile(r"^example", re.IGNORECASE),
    re.compile(r"^your[_-]", re.IGNORECASE),
    re.compile(r"^my[_-]", re.IGNORECASE),
    re.compile(r"^<[^>]+>$"),                   # <placeholder>
    re.compile(r"^\$\{[^}]+\}$"),               # ${env_var}
    re.compile(r"^\{\{[^}]+\}\}$"),             # {{template}}
    re.compile(r"^%[A-Z_]+%$"),                 # %WINDOWS_ENV%
    re.compile(r"^xxx+$", re.IGNORECASE),
    re.compile(r"^test", re.IGNORECASE),
    re.compile(r"^dummy", re.IGNORECASE),
    re.compile(r"^fake", re.IGNORECASE),
    re.compile(r"^sample", re.IGNORECASE),
    re.compile(r"^placeholder", re.IGNORECASE),
    re.compile(r"^changeme$", re.IGNORECASE),
    re.compile(r"^change_me$", re.IGNORECASE),
    re.compile(r"^replace_?me$", re.IGNORECASE),
    re.compile(r"^todo$", re.IGNORECASE),
    re.compile(r"^none$", re.IGNORECASE),
    re.compile(r"^null$", re.IGNORECASE),
    re.compile(r"^undefined$", re.IGNORECASE),
    re.compile(r"^n/a$", re.IGNORECASE),
    re.compile(r"^xxxxxxxxxxxxxxxx$", re.IGNORECASE),
    re.compile(r"^1234567890$"),
    re.compile(r"^0{8,}$"),
    re.compile(r"^AKIAIOSFODNN7EXAMPLE"),         # AWS docs example key
    re.compile(r"^wJalrXUtnFEMI/K7MDENG"),        # AWS docs example secret
    re.compile(r"INSERT_"),
    re.compile(r"_HERE$"),
    re.compile(r"^sk-[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$"),  # UUIDs disguised
]

# Known-safe entropy strings (common in base64-encoded public certs, etc.)
FALSE_POSITIVE_EXACT = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "credential", "credentials", "authorization", "auth", "bearer",
    "access_token", "refresh_token", "client_secret",
}


def is_false_positive(value: str) -> bool:
    """Return True if the value is a known false positive."""
    if not value or len(value) < 4:
        return True
    stripped = value.strip("\"'` \t\r\n")
    if stripped.lower() in FALSE_POSITIVE_EXACT:
        return True
    for pat in FALSE_POSITIVE_PATTERNS:
        if pat.search(stripped):
            return True
    return False


# ---------------------------------------------------------------------------
# PATTERN REGISTRY
# Each tuple: (name, regex, severity, category, description, confidence)
# ---------------------------------------------------------------------------

PATTERNS = []

def _add(name, pattern, severity, category, description, confidence="high"):
    PATTERNS.append((name, _p(pattern), severity, category, description, confidence))


# ===========================================================================
# 1. AWS
# ===========================================================================

_add("aws_access_key",
     r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
     "critical", "api_key",
     "AWS Access Key ID (AKIA prefix — permanent key)")

_add("aws_access_key_assumed",
     r"(?<![A-Z0-9])(ASIA[0-9A-Z]{16})(?![A-Z0-9])",
     "critical", "api_key",
     "AWS Access Key ID (ASIA prefix — assumed-role temporary key)")

_add("aws_secret_key",
     r"""(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
     "critical", "credential",
     "AWS Secret Access Key")

_add("aws_session_token",
     r"""(?:aws[_\-]?session[_\-]?token|AWS_SESSION_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?""",
     "critical", "token",
     "AWS Session Token (temporary credentials)")

_add("aws_mws_key",
     r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
     "high", "api_key",
     "Amazon MWS (Marketplace Web Service) key")

_add("aws_s3_bucket_url",
     r"https?://([a-z0-9][a-z0-9.\-]{2,62})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com",
     "info", "cloud",
     "AWS S3 bucket URL")

_add("aws_s3_url_alt",
     r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{2,62})",
     "info", "cloud",
     "AWS S3 bucket URL (path style)", "medium")

# ===========================================================================
# 2. Google / GCP
# ===========================================================================

_add("google_api_key",
     r"AIza[0-9A-Za-z\-_]{35}",
     "high", "api_key",
     "Google API Key (AIza prefix)")

_add("google_oauth_client",
     r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
     "medium", "credential",
     "Google OAuth 2.0 Client ID")

_add("google_oauth_secret",
     r"""(?:client[_-]?secret|GOOGLE_CLIENT_SECRET)\s*[=:]\s*['"]?(GOCSPX-[A-Za-z0-9_\-]{28,})['"]?""",
     "critical", "credential",
     "Google OAuth Client Secret")

_add("google_service_account",
     r'"type"\s*:\s*"service_account"',
     "high", "credential",
     "Google Service Account JSON key file", "high")

_add("firebase_url",
     r"https://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com",
     "medium", "cloud",
     "Firebase Realtime Database URL")

_add("firebase_server_key",
     r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
     "critical", "api_key",
     "Firebase Cloud Messaging (FCM) Server Key")

_add("gcp_storage_url",
     r"https?://storage\.googleapis\.com/[a-z0-9][a-z0-9.\-_]{1,61}",
     "info", "cloud",
     "GCP Cloud Storage bucket URL")

# ===========================================================================
# 3. Azure
# ===========================================================================

_add("azure_storage_key",
     r"""(?:AccountKey|DefaultEndpointsProtocol)[=;][^;'"\n]{10,}""",
     "critical", "credential",
     "Azure Storage Account connection string")

_add("azure_sas_token",
     r"[?&]sig=[A-Za-z0-9%+/]{43,}={0,2}",
     "high", "token",
     "Azure SAS (Shared Access Signature) token")

_add("azure_client_secret",
     r"""(?:client[_-]?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9~.\-_]{34,40})['"]?""",
     "critical", "credential",
     "Azure AD App Client Secret")

_add("azure_subscription_key",
     r"""(?:Ocp-Apim-Subscription-Key|subscription[_-]?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""",
     "high", "api_key",
     "Azure API Management Subscription Key")

_add("azure_blob_url",
     r"https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net",
     "info", "cloud",
     "Azure Blob Storage URL")

_add("azure_keyvault_url",
     r"https?://[a-z0-9-]{3,24}\.vault\.azure\.net",
     "info", "cloud",
     "Azure Key Vault URL")

# ===========================================================================
# 4. GitHub
# ===========================================================================

_add("github_token_classic",
     r"ghp_[A-Za-z0-9]{36}",
     "critical", "token",
     "GitHub Personal Access Token (classic, ghp_ prefix)")

_add("github_oauth_token",
     r"gho_[A-Za-z0-9]{36}",
     "critical", "token",
     "GitHub OAuth Token (gho_ prefix)")

_add("github_user_to_server",
     r"ghu_[A-Za-z0-9]{36}",
     "critical", "token",
     "GitHub User-to-Server Token (ghu_ prefix)")

_add("github_server_to_server",
     r"ghs_[A-Za-z0-9]{36}",
     "critical", "token",
     "GitHub Server-to-Server Token (ghs_ prefix)")

_add("github_refresh_token",
     r"ghr_[A-Za-z0-9]{76}",
     "critical", "token",
     "GitHub Refresh Token (ghr_ prefix)")

_add("github_actions_token",
     r"""GITHUB_TOKEN\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?""",
     "high", "token",
     "GitHub Actions GITHUB_TOKEN", "medium")

# ===========================================================================
# 5. GitLab
# ===========================================================================

_add("gitlab_pat",
     r"glpat-[A-Za-z0-9_\-]{20}",
     "critical", "token",
     "GitLab Personal Access Token (glpat- prefix)")

_add("gitlab_ci_token",
     r"""CI_(?:JOB_TOKEN|REGISTRY_PASSWORD|DEPLOY_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?""",
     "high", "token",
     "GitLab CI/CD Token variable")

_add("gitlab_runner_token",
     r"GR1348941[A-Za-z0-9_\-]{20}",
     "critical", "token",
     "GitLab Runner Registration Token")

# ===========================================================================
# 6. Stripe
# ===========================================================================

_add("stripe_live_secret",
     r"sk_live_[A-Za-z0-9]{24,}",
     "critical", "api_key",
     "Stripe Live Secret Key — PRODUCTION payments at risk")

_add("stripe_live_public",
     r"pk_live_[A-Za-z0-9]{24,}",
     "medium", "api_key",
     "Stripe Live Publishable Key (lower risk but signals prod environment)")

_add("stripe_test_secret",
     r"sk_test_[A-Za-z0-9]{24,}",
     "medium", "api_key",
     "Stripe Test Secret Key")

_add("stripe_restricted_key",
     r"rk_(?:live|test)_[A-Za-z0-9]{24,}",
     "high", "api_key",
     "Stripe Restricted API Key")

_add("stripe_webhook_secret",
     r"whsec_[A-Za-z0-9]{32,}",
     "high", "api_key",
     "Stripe Webhook Signing Secret")

# ===========================================================================
# 7. Slack
# ===========================================================================

_add("slack_bot_token",
     r"xoxb-[0-9]{11}-[0-9]{11,13}-[A-Za-z0-9]{24}",
     "critical", "token",
     "Slack Bot Token (xoxb-)")

_add("slack_user_token",
     r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11,13}-[A-Za-z0-9]{32}",
     "critical", "token",
     "Slack User Token (xoxp-)")

_add("slack_workspace_token",
     r"xoxa-2-[0-9]{11}-[0-9]{11}-[0-9]{11,13}-[A-Za-z0-9]{64}",
     "critical", "token",
     "Slack Workspace Access Token (xoxa-)")

_add("slack_legacy_bot",
     r"xoxb-[0-9]+-[A-Za-z0-9]+",
     "high", "token",
     "Slack Legacy Bot Token", "medium")

_add("slack_webhook",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
     "high", "token",
     "Slack Incoming Webhook URL")

# ===========================================================================
# 8. Twilio
# ===========================================================================

_add("twilio_api_key",
     r"SK[a-f0-9]{32}",
     "high", "api_key",
     "Twilio API Key SID")

_add("twilio_account_sid",
     r"AC[a-f0-9]{32}",
     "medium", "credential",
     "Twilio Account SID", "medium")

_add("twilio_auth_token",
     r"""(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""",
     "critical", "credential",
     "Twilio Auth Token")

# ===========================================================================
# 9. SendGrid
# ===========================================================================

_add("sendgrid_api_key",
     r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
     "critical", "api_key",
     "SendGrid API Key (SG. prefix)")

# ===========================================================================
# 10. OpenAI / Anthropic
# ===========================================================================

_add("openai_api_key",
     r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
     "critical", "api_key",
     "OpenAI API Key (legacy format)")

_add("openai_api_key_v2",
     r"sk-proj-[A-Za-z0-9_\-]{48,}",
     "critical", "api_key",
     "OpenAI API Key (project key, sk-proj- prefix)")

_add("openai_api_key_v3",
     r"sk-svcacct-[A-Za-z0-9_\-]{48,}",
     "critical", "api_key",
     "OpenAI Service Account Key")

_add("anthropic_api_key",
     r"sk-ant-(?:api03-)?[A-Za-z0-9_\-]{80,}",
     "critical", "api_key",
     "Anthropic Claude API Key")

# ===========================================================================
# 11. npm
# ===========================================================================

_add("npm_token",
     r"npm_[A-Za-z0-9]{36}",
     "critical", "token",
     "npm Access Token (npm_ prefix)")

_add("npmrc_token",
     r"""//registry\.npmjs\.org/:_authToken\s*=\s*['"]?([A-Za-z0-9_\-]{36,})['"]?""",
     "critical", "token",
     "npm registry authToken in .npmrc")

# ===========================================================================
# 12. Shopify
# ===========================================================================

_add("shopify_private_app",
     r"shppa_[A-Za-z0-9]{32}",
     "critical", "api_key",
     "Shopify Private App Access Token")

_add("shopify_shared_secret",
     r"shpss_[A-Za-z0-9]{32}",
     "high", "api_key",
     "Shopify Shared Secret")

_add("shopify_custom_app",
     r"shpca_[A-Za-z0-9]{32}",
     "critical", "api_key",
     "Shopify Custom App Access Token")

_add("shopify_access_token",
     r"shpat_[A-Za-z0-9]{32}",
     "critical", "api_key",
     "Shopify Admin API Access Token")

# ===========================================================================
# 13. Discord
# ===========================================================================

_add("discord_bot_token",
     r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}",
     "critical", "token",
     "Discord Bot Token")

_add("discord_webhook",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}",
     "high", "token",
     "Discord Webhook URL")

_add("discord_client_secret",
     r"""discord[_-]?(?:client[_-]?)?secret\s*[=:]\s*['"]?([A-Za-z0-9_\-]{32,})['"]?""",
     "critical", "credential",
     "Discord Client Secret")

# ===========================================================================
# 14. Telegram
# ===========================================================================

_add("telegram_bot_token",
     r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
     "critical", "token",
     "Telegram Bot API Token")

# ===========================================================================
# 15. Mailgun
# ===========================================================================

_add("mailgun_api_key",
     r"key-[0-9a-f]{32}",
     "critical", "api_key",
     "Mailgun API Key")

_add("mailgun_domain_key",
     r"""(?:mailgun[_-]?(?:api[_-]?)?key|MAILGUN_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9\-]{32,})['"]?""",
     "critical", "api_key",
     "Mailgun domain-specific API key")

# ===========================================================================
# 16. Square / PayPal
# ===========================================================================

_add("square_access_token",
     r"sq0atp-[A-Za-z0-9_\-]{22}",
     "critical", "token",
     "Square Access Token")

_add("square_oauth_secret",
     r"sq0csp-[A-Za-z0-9_\-]{43}",
     "critical", "credential",
     "Square OAuth Client Secret")

_add("paypal_braintree_token",
     r"""access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}""",
     "critical", "token",
     "PayPal/Braintree Production Access Token")

# ===========================================================================
# 17. Heroku
# ===========================================================================

_add("heroku_api_key",
     r"""(?:heroku[_\-]?(?:api[_\-]?)?key|HEROKU_API_KEY)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?""",
     "critical", "api_key",
     "Heroku API Key (UUID format)")

# ===========================================================================
# 18. DigitalOcean
# ===========================================================================

_add("digitalocean_pat",
     r"dop_v1_[A-Za-z0-9]{64}",
     "critical", "token",
     "DigitalOcean Personal Access Token (dop_v1_)")

_add("digitalocean_spaces_key",
     r"""(?:DO_SPACES_KEY|digitalocean[_-]?key)\s*[=:]\s*['"]?([A-Z0-9]{20})['"]?""",
     "high", "api_key",
     "DigitalOcean Spaces Access Key")

# ===========================================================================
# 19. Cloudflare
# ===========================================================================

_add("cloudflare_api_key",
     r"""(?:cloudflare[_-]?(?:api[_-]?)?key|CF_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{37})['"]?""",
     "critical", "api_key",
     "Cloudflare Global API Key")

_add("cloudflare_api_token",
     r"""(?:cloudflare[_-]?api[_-]?token|CF_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40})['"]?""",
     "critical", "api_key",
     "Cloudflare API Token (scoped)")

# ===========================================================================
# 20. Monitoring / APM
# ===========================================================================

_add("datadog_api_key",
     r"""(?:dd[_-]?api[_-]?key|DATADOG_API_KEY|DD_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""",
     "high", "api_key",
     "Datadog API Key")

_add("datadog_app_key",
     r"""(?:dd[_-]?app[_-]?key|DATADOG_APP_KEY|DD_APP_KEY)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?""",
     "high", "api_key",
     "Datadog Application Key")

_add("newrelic_api_key",
     r"NRAK-[A-Z0-9]{27}",
     "high", "api_key",
     "New Relic User API Key")

_add("newrelic_insert_key",
     r"""(?:new[_-]?relic[_-]?(?:insert[_-]?)?key|NEW_RELIC_INSERT_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?""",
     "high", "api_key",
     "New Relic Insights Insert Key")

_add("sentry_dsn",
     r"https://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest(?:\.us)?\.sentry\.io/[0-9]+",
     "medium", "credential",
     "Sentry DSN (Data Source Name)")

# ===========================================================================
# 21. Auth0 / Okta
# ===========================================================================

_add("auth0_client_secret",
     r"""(?:auth0[_-]?(?:client[_-]?)?secret|AUTH0_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,})['"]?""",
     "critical", "credential",
     "Auth0 Client Secret")

_add("auth0_management_token",
     r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
     "high", "token",
     "JWT token (Auth0 / any OIDC provider) — validate expiry", "medium")

_add("okta_api_token",
     r"""(?:okta[_-]?api[_-]?token|OKTA_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{42,})['"]?""",
     "critical", "token",
     "Okta API Token")

# ===========================================================================
# 22. Generic Credentials
# ===========================================================================

_add("generic_password_assignment",
     r"""(?:password|passwd|pwd|pass)\s*[:=]\s*['"]([^'"]{6,64})['"]""",
     "high", "credential",
     "Generic password assignment in code/config", "medium")

_add("generic_secret_assignment",
     r"""(?:secret|secret_key|client_secret|app_secret)\s*[:=]\s*['"]([^'"]{8,128})['"]""",
     "high", "credential",
     "Generic secret assignment", "medium")

_add("basic_auth_header",
     r"(?:Authorization|auth)\s*[=:]\s*[\"']?Basic\s+([A-Za-z0-9+/=]{8,})(?:[\"']|\s|$)",
     "high", "credential",
     "HTTP Basic Authentication header (base64 encoded)")

_add("bearer_token_header",
     r"(?:Authorization|auth)\s*[=:]\s*[\"']?Bearer\s+([A-Za-z0-9_\-\.]{20,})(?:[\"']|\s|$)",
     "medium", "token",
     "HTTP Bearer token in header", "medium")

# ===========================================================================
# 23. Database Connection Strings
# ===========================================================================

_add("mongodb_connection_string",
     r"mongodb(?:\+srv)?://[^:]+:([^@]{6,})@[^/\s\"']+",
     "critical", "credential",
     "MongoDB connection string with credentials")

_add("postgresql_connection_string",
     r"postgres(?:ql)?://[^:]+:([^@]{4,})@[^/\s\"']+",
     "critical", "credential",
     "PostgreSQL connection string with credentials")

_add("mysql_connection_string",
     r"mysql://[^:]+:([^@]{4,})@[^/\s\"']+",
     "critical", "credential",
     "MySQL connection string with credentials")

_add("redis_connection_string",
     r"redis://:([^@]{4,})@[^/\s\"']+",
     "high", "credential",
     "Redis connection string with password")

_add("amqp_connection_string",
     r"amqp(?:s)?://[^:]+:([^@]{4,})@[^/\s\"']+",
     "high", "credential",
     "AMQP/RabbitMQ connection string with credentials")

_add("smtp_connection_string",
     r"smtp(?:s)?://[^:]+:([^@]{4,})@[^/\s\"']+",
     "high", "credential",
     "SMTP connection string with credentials")

_add("jdbc_connection_string",
     r"""jdbc:[a-z]+://[^\s;'"]+password=([^;&\s'"]{4,})""",
     "critical", "credential",
     "JDBC connection string with password")

# ===========================================================================
# 24. Private Keys & Certificates
# ===========================================================================

_add("rsa_private_key",
     r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
     "critical", "crypto",
     "RSA Private Key block")

_add("ec_private_key",
     r"-----BEGIN EC PRIVATE KEY-----",
     "critical", "crypto",
     "EC (Elliptic Curve) Private Key block")

_add("dsa_private_key",
     r"-----BEGIN DSA PRIVATE KEY-----",
     "critical", "crypto",
     "DSA Private Key block")

_add("openssh_private_key",
     r"-----BEGIN OPENSSH PRIVATE KEY-----",
     "critical", "crypto",
     "OpenSSH Private Key block")

_add("pgp_private_key",
     r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     "critical", "crypto",
     "PGP Private Key block")

_add("pkcs8_private_key",
     r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
     "critical", "crypto",
     "PKCS#8 Encrypted Private Key block")

# ===========================================================================
# 25. Config Files — .env / Terraform / Kubernetes
# ===========================================================================

_add("dotenv_secret_value",
     r"""^(?:export\s+)?(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|PASSWORD|AUTH|APIKEY|ACCESS_KEY|CLIENT_SECRET|DATABASE_URL|DB_PASS(?:WORD)?|REDIS_PASS(?:WORD)?|MONGO_URI|POSTGRES_URI|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY|MASTER_KEY)\s*=\s*['"]?([^'"\n\r]{6,256})['"]?""",
     "high", "config",
     ".env file secret value", "medium")

_add("terraform_variable_sensitive",
     r"""(?:sensitive\s*=\s*true[\s\S]{0,200}?default\s*=\s*|default\s*=\s*)['"]([^'"]{8,128})['"]""",
     "high", "config",
     "Terraform variable with sensitive default value", "medium")

_add("kubernetes_secret_data",
     r"""kind:\s*Secret[\s\S]{0,500}?data:[\s\S]{0,500}?:\s+([A-Za-z0-9+/=]{16,})""",
     "high", "config",
     "Kubernetes Secret data (base64 encoded)")

_add("docker_compose_env_secret",
     r"""(?:environment:|env_file:)[\s\S]{0,300}(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIALS)\s*[=:]\s*['"]?([^'"\n]{6,128})['"]?""",
     "high", "config",
     "Docker Compose environment variable with secret", "medium")

_add("ci_github_secret",
     r"""secrets\.[A-Z_]+\s|env\.\s*GITHUB_TOKEN""",
     "info", "config",
     "GitHub Actions secrets reference (may indicate secret usage patterns)", "low")

# ===========================================================================
# 26. Cloud Storage (additional)
# ===========================================================================

_add("digitalocean_spaces_url",
     r"https?://[a-z0-9][a-z0-9\-]{1,62}\.(?:[a-z]{2,20}-[0-9]\.)?digitaloceanspaces\.com",
     "info", "cloud",
     "DigitalOcean Spaces URL")

_add("gcp_cloud_run_url",
     r"https?://[a-z0-9\-]+-[a-z0-9]+-[a-z]{2}\.a\.run\.app",
     "info", "cloud",
     "GCP Cloud Run service URL")

_add("azure_functions_url",
     r"https?://[a-z0-9\-]+\.azurewebsites\.net",
     "info", "cloud",
     "Azure App Service / Functions URL")

# ===========================================================================
# 27. PII (primarily for PCAP / config scanning)
# ===========================================================================

_add("credit_card_visa",
     r"""(?<!\d)4[0-9]{12}(?:[0-9]{3})?(?<!\d)""",
     "high", "pii",
     "Visa credit card number", "medium")

_add("credit_card_mastercard",
     r"""(?<!\d)5[1-5][0-9]{14}(?<!\d)""",
     "high", "pii",
     "Mastercard credit card number", "medium")

_add("credit_card_amex",
     r"""(?<!\d)3[47][0-9]{13}(?<!\d)""",
     "high", "pii",
     "American Express credit card number", "medium")

_add("credit_card_discover",
     r"""(?<!\d)6(?:011|5[0-9]{2})[0-9]{12}(?<!\d)""",
     "high", "pii",
     "Discover credit card number", "medium")

_add("us_ssn",
     r"""(?<!\d)(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)""",
     "high", "pii",
     "US Social Security Number (SSN)")

_add("email_with_password_context",
     r"""(?:email|username|user|login)\s*[=:]\s*['"]?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})['"]?""",
     "low", "pii",
     "Email address in credentials context", "low")

# ===========================================================================
# 28. Network capture specific
# ===========================================================================

_add("http_authorization_header",
     r"Authorization:\s*(Basic|Bearer|Token|Digest)\s+([A-Za-z0-9+/=_\-\.]{8,})",
     "high", "credential",
     "HTTP Authorization header in network traffic")

_add("http_set_cookie_session",
     r"Set-Cookie:\s*(?:session|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|auth_token|jwt|token)\s*=\s*([A-Za-z0-9+/=_\-\.%]{16,})",
     "medium", "token",
     "Session/auth cookie in HTTP response")

_add("http_post_password",
     r"(?:password|passwd|pwd|pass)=([^&\s\r\n]{4,64})",
     "critical", "credential",
     "Password in HTTP POST body (plaintext)")

_add("ftp_credentials",
     r"(?:USER|PASS)\s+([A-Za-z0-9_\-\.@+]{3,64})\r?\n",
     "critical", "credential",
     "FTP username or password in network traffic")

_add("smtp_auth",
     r"AUTH PLAIN ([A-Za-z0-9+/=]{8,})",
     "critical", "credential",
     "SMTP AUTH PLAIN credentials (base64)")

# ===========================================================================
# 29. Binary / APK extras
# ===========================================================================

_add("hardcoded_ip_port_credentials",
     r"""(?:user|username|pass|password)\s*[=:]\s*['"]([^'"\s]{4,32})['"][\s\S]{0,50}(?:host|server|addr)\s*[=:]\s*['"]?(\d{1,3}(?:\.\d{1,3}){3})['"]?""",
     "high", "credential",
     "Hardcoded credentials with IP address", "medium")

_add("android_api_key",
     r"""(?:google_api_key|GOOGLE_API_KEY|api_key)\s*[=:>]+\s*['"]?(AIza[0-9A-Za-z\-_]{35})['"]?""",
     "critical", "api_key",
     "Android Google API Key in resources/code")

_add("android_firebase_config",
     r"""(?:apiKey|projectId|storageBucket|messagingSenderId|appId)\s*[:=]\s*['"]([^'"]{8,})['"]""",
     "medium", "config",
     "Firebase app config in Android resources", "medium")

_add("ios_url_scheme_credentials",
     r"""(?:client[_-]?id|client[_-]?secret|api[_-]?key)\s*[=:>]+\s*['"]([A-Za-z0-9_\-\.]{8,64})['"]""",
     "high", "credential",
     "iOS embedded credentials in URL scheme / plist", "medium")

# ===========================================================================
# 30. Miscellaneous high-value patterns
# ===========================================================================

_add("jwt_secret_key",
     r"""(?:jwt[_-]?secret|JWT_SECRET|TOKEN_SECRET|SIGNING_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/=_\-!@#$%^&*]{16,})['"]?""",
     "critical", "crypto",
     "JWT signing secret")

_add("encryption_key",
     r"""(?:encryption[_-]?key|ENCRYPTION_KEY|AES_KEY|CIPHER_KEY|SECRET_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{16,64})['"]?""",
     "critical", "crypto",
     "Symmetric encryption key")

_add("master_password",
     r"""(?:master[_-]?(?:password|passwd|key|secret)|MASTER_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_\-!@#$%^&*]{6,64})['"]?""",
     "critical", "credential",
     "Master password or key")

_add("private_key_pem_inline",
     r"""-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]{10,3000}?-----END (?:[A-Z ]+)?PRIVATE KEY-----""",
     "critical", "crypto",
     "Full private key PEM block (inline)")

_add("kubernetes_service_account_token",
     r"eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_\-]+\.",
     "critical", "token",
     "Kubernetes Service Account JWT token")

_add("hashicorp_vault_token",
     r"""(?:vault[_-]?token|VAULT_TOKEN)\s*[=:]\s*['"]?(hvs\.[A-Za-z0-9]{24,}|s\.[A-Za-z0-9]{24,})['"]?""",
     "critical", "token",
     "HashiCorp Vault token")

_add("github_app_private_key",
     r"""-----BEGIN RSA PRIVATE KEY-----[\s\S]{100,3000}?-----END RSA PRIVATE KEY-----""",
     "critical", "crypto",
     "GitHub App RSA private key (full PEM block)")

_add("azure_devops_pat",
     r"""(?:azure[_-]?(?:devops[_-]?)?pat|AZURE_DEVOPS_PAT|TF_BUILD)\s*[=:]\s*['"]?([A-Za-z0-9]{52})['"]?""",
     "critical", "token",
     "Azure DevOps Personal Access Token")

_add("jfrog_api_key",
     r"""(?:jfrog[_-]?api[_-]?key|JFROG_API_KEY|ARTIFACTORY_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{73})['"]?""",
     "high", "api_key",
     "JFrog Artifactory API Key")

_add("docker_registry_credentials",
     r'''"auths"\s*:\s*\{[\s\S]{0,500}?"auth"\s*:\s*"([A-Za-z0-9+/=]{16,})"''',
     "critical", "credential",
     "Docker registry credentials in config.json")

_add("netrc_credentials",
     r"""machine\s+[^\s]+\s+login\s+([^\s]+)\s+password\s+([^\s]+)""",
     "critical", "credential",
     ".netrc credentials block")

_add("pgpass_credentials",
     r"""[A-Za-z0-9.\-]+:[0-9]+:[A-Za-z0-9*]+:[A-Za-z0-9]+:([^\s\r\n]{4,64})""",
     "critical", "credential",
     ".pgpass PostgreSQL credentials", "medium")


# ===========================================================================
# Convenience lookups
# ===========================================================================

# Index by name for fast lookup
PATTERN_INDEX: dict = {name: (regex, sev, cat, desc, conf)
                       for name, regex, sev, cat, desc, conf in PATTERNS}

# Patterns grouped by severity
PATTERNS_BY_SEVERITY: dict[str, list] = {}
for _name, _regex, _sev, _cat, _desc, _conf in PATTERNS:
    PATTERNS_BY_SEVERITY.setdefault(_sev, []).append(
        (_name, _regex, _sev, _cat, _desc, _conf)
    )

# Patterns grouped by category
PATTERNS_BY_CATEGORY: dict[str, list] = {}
for _name, _regex, _sev, _cat, _desc, _conf in PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(_cat, []).append(
        (_name, _regex, _sev, _cat, _desc, _conf)
    )

# Total count
PATTERN_COUNT = len(PATTERNS)

# Alias for backward-compat with older scanner modules
SECRET_PATTERNS = PATTERNS


# ===========================================================================
# scan_content() — convenience function used by all scanners
# ===========================================================================

def scan_content(
    text: str,
    filename: str = "",
) -> list[tuple]:
    """
    Scan a text string against all patterns.

    Returns a list of tuples:
        (pattern_name, value, severity, category, description, confidence, match_start, match_end)

    The caller is responsible for deduplication and false-positive filtering.
    """
    results = []
    for name, regex, severity, category, description, confidence in PATTERNS:
        for m in regex.finditer(text):
            # Prefer the first capturing group if present
            if m.lastindex and m.lastindex >= 1:
                value = m.group(1)
            else:
                value = m.group(0)

            if not value:
                continue

            value = value.strip("\"'` \t\r\n")

            if not value or is_false_positive(value):
                continue

            results.append((
                name,
                value,
                severity,
                category,
                description,
                confidence,
                m.start(),
                m.end(),
            ))

    return results
