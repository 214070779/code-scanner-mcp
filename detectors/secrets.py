'''
Secrets detector for the Code Security Scanner MCP Server.

Scans files for hardcoded secrets: API keys, tokens, passwords,
private keys, and other sensitive credentials.
'''

import re
from pathlib import Path
from typing import Dict, Tuple, List

from utils.scanner_helpers import (
    compile_patterns,
    scan_file_for_patterns,
    Finding,
)


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: Dict[str, Tuple[str, str, str]] = {
    'AWS Access Key ID': (
        r'AKIA[0-9A-Z]{16}',
        'Amazon Web Services access key ID exposed. This could allow unauthorized access to AWS resources.',
        'critical',
    ),
    'AWS Secret Access Key': (
        r'(?i)aws(.{0,20})?(?-i)[''"][0-9a-zA-Z\/+]{40}[''"]',
        'AWS secret access key detected. Combined with an access key ID, this grants full AWS API access.',
        'critical',
    ),
    'GitHub Personal Access Token': (
        r'(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}',
        'GitHub personal access token or OAuth access token exposed. Could grant access to repositories.',
        'critical',
    ),
    'GitHub App Token': (
        r'(?:gh[a-s])_[0-9a-zA-Z]{36}',
        'GitHub App token detected. Could provide API access to GitHub services.',
        'critical',
    ),
    'Generic API Key': (
        r'(?i)(?:api[_-]?key|apikey|api[_-]?secret|api_secret)\s*[:=]\s*[''"][0-9a-zA-Z_\-]{16,64}[''"]',
        'A generic API key or secret appears to be hardcoded. API keys should use environment variables.',
        'high',
    ),
    'Slack Bot Token': (
        r'xox[baprs]-[0-9a-zA-Z\-]{10,72}',
        'Slack token detected (bot, app, or user token). Could grant access to Slack workspaces.',
        'critical',
    ),
    'Slack Webhook URL': (
        r'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}',
        'Slack webhook URL exposed. Could allow sending messages to Slack channels.',
        'high',
    ),
    'Stripe API Key': (
        r'(?i)sk_live_[0-9a-zA-Z]{24,}',
        'Stripe live secret key detected. Could allow unauthorized payment operations.',
        'critical',
    ),
    'Stripe Publishable Key': (
        r'(?i)pk_(?:live|test)_[0-9a-zA-Z]{24,}',
        'Stripe publishable key detected. While less sensitive, it should not be hardcoded.',
        'medium',
    ),
    'Google OAuth / Service Account': (
        r'(?i)(?:google|gcp|firebase|gserviceaccount)?.{0,5}?(?:key|secret|token|password)\s*[:=]\s*[''"][0-9a-zA-Z_\-\.]{20,}[''"]',
        'Google Cloud Platform credential detected. Could grant access to GCP resources.',
        'critical',
    ),
    'Google API Key': (
        r'AIza[0-9A-Za-z\-_]{35}',
        'Google API key exposed. Could allow unauthorized access to Google APIs.',
        'high',
    ),
    'Heroku API Key': (
        r'(?i)heroku.{0,20}[''"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[''"]',
        'Heroku API key detected. Could grant access to Heroku applications and data.',
        'critical',
    ),
    'Twilio API Key': (
        r'SK[0-9a-fA-F]{32}',
        'Twilio API key or auth token detected. Could allow unauthorized SMS/voice operations.',
        'critical',
    ),
    'Docker Registry Credentials': (
        r'(?i)docker.{0,20}(?:password|pwd|secret)\s*[:=]\s*[''"][^''"]{6,}[''"]',
        'Docker registry credentials detected. Could allow unauthorized image access.',
        'high',
    ),
    'JWT Token': (
        r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        'JSON Web Token (JWT) detected. Could contain session or authentication claims.',
        'high',
    ),
    'RSA Private Key': (
        r'-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----',
        'Private key detected. This grants access to encrypted communications and should never be committed.',
        'critical',
    ),
    'Password Assignment': (
        r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[''"][^''"\s]{6,}[''"]',
        'A potential password or passphrase appears hardcoded. Use environment variables or a secrets manager.',
        'high',
    ),
    'Connection String': (
        r'(?i)(?:mongodb|postgresql|mysql|redis|rediss)://[^\s]{10,}',
        'Database connection string with embedded credentials detected. Could expose database access.',
        'critical',
    ),
    'npm Auth Token': (
        r'(?i)(?:npm|\.npmrc).{0,20}?_authToken\s*=\s*[0-9a-zA-Z\-_]{20,}',
        'npm authentication token detected. Could allow unauthorized package publishing.',
        'critical',
    ),
    'PEM Certificate': (
        r'-----BEGIN CERTIFICATE-----',
        'PEM-encoded certificate detected. Certificates should not be committed to version control.',
        'medium',
    ),
    'S3 Access Key Pattern': (
        r'(?i)(?:s3|bucket|storage).{0,20}(?:access|key|secret|token)\s*[:=]\s*[''"][^''"]{10,}[''"]',
        'Cloud storage credential pattern detected. Could indicate exposed S3 or object storage access.',
        'high',
    ),
    'SendGrid API Key': (
        r'SG\.[0-9a-zA-Z_\-]{22,68}',
        'SendGrid API key detected. Could allow unauthorized email sending.',
        'critical',
    ),
    'Mailchimp API Key': (
        r'(?i)[0-9a-f]{32}-us[0-9]{1,2}',
        'Mailchimp API key detected (when found in config context). Could expose mailing list data.',
        'high',
    ),
    'Telegram Bot Token': (
        r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
        'Telegram Bot API token detected. Could allow unauthorized bot control.',
        'critical',
    ),
}


def _build_pattern_list() -> List[dict]:
    patterns: List[dict] = []
    for name, (regex_str, desc, severity) in SECRET_PATTERNS.items():
        try:
            patterns.append({
                'name': name,
                'regex': re.compile(regex_str, re.MULTILINE),
                'description': desc,
                'severity': severity,
            })
        except re.error:
            continue
    return patterns


_SECRET_PATTERNS_COMPILED: List[dict] = _build_pattern_list()


def scan_file_for_secrets(
    file_path: Path,
    relative_to: Path,
) -> List[Finding]:
    '''Scan a single file for hardcoded secrets.

    Uses compiled regex patterns to detect API keys, tokens,
    passwords, private keys, and other sensitive credentials.

    Args:
        file_path: Absolute path to the file to scan.
        relative_to: Make paths relative to this root.

    Returns:
        List of Finding objects for detected secrets.
    '''
    findings: List[Finding] = []

    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except (OSError, LookupError):
        return findings

    lines = content.split('\n')

    # Skip common false-positive paths
    rel_path_str = str(file_path.relative_to(relative_to)) if relative_to else str(file_path)
    skip_extensions = {'.svg', '.lock', '.min.js', '.map'}
    if file_path.suffix.lower() in skip_extensions:
        return findings

    for pat in _SECRET_PATTERNS_COMPILED:
        for match in pat['regex'].finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            snippet_start = max(0, line_num - 2)
            snippet_end = min(len(lines), line_num + 1)
            snippet = '\n'.join(
                f'{i + 1}: {lines[i]}'
                for i in range(snippet_start, snippet_end)
            )

            findings.append(Finding(
                file_path=rel_path_str,
                line_number=line_num,
                severity=pat['severity'],
                finding_type='secret',
                title=pat['name'],
                description=pat['description'],
                snippet=snippet.strip(),
                recommendation='Move this secret to environment variables or a secrets manager (e.g., .env file, 1Password CLI, Vault). Never commit secrets to version control.',
            ))

    return findings
