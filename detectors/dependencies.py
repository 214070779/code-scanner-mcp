'''
Dependency vulnerability detector for the Code Security Scanner MCP Server.

Parses dependency manifests and checks against a built-in database
of known vulnerable package versions.
'''

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from utils.scanner_helpers import Finding


# ---------------------------------------------------------------------------
# Built-in vulnerability database
# ---------------------------------------------------------------------------
# This is a curated list of commonly vulnerable packages.
# For a production scanner, replace with an API-based lookup (OSV, NVD, etc).

VULNERABILITY_DB: List[Dict[str, Any]] = [
    # -- JavaScript/Node.js --
    {'package': 'lodash', 'version_range': '<4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'high', 'description': 'Prototype pollution in lodash allows attackers to modify object properties.'},
    {'package': 'axios', 'version_range': '<1.6.0', 'cve': 'CVE-2023-45857', 'severity': 'high', 'description': 'Axios Server-Side Request Forgery (SSRF) vulnerability.'},
    {'package': 'express', 'version_range': '<4.18.0', 'cve': 'CVE-2022-24999', 'severity': 'medium', 'description': 'Express.js open redirect vulnerability.'},
    {'package': 'minimist', 'version_range': '<1.2.6', 'cve': 'CVE-2021-44906', 'severity': 'high', 'description': 'Prototype pollution in minimist argument parser.'},
    {'package': 'json5', 'version_range': '<2.2.2', 'cve': 'CVE-2022-46175', 'severity': 'high', 'description': 'Prototype pollution in JSON5 parser.'},
    {'package': 'pathval', 'version_range': '<1.1.1', 'cve': 'CVE-2022-25918', 'severity': 'medium', 'description': 'Path traversal vulnerability in pathval.'},
    {'package': 'semver', 'version_range': '<7.5.2', 'cve': 'CVE-2022-25883', 'severity': 'medium', 'description': 'ReDoS vulnerability in semver package.'},
    {'package': 'request', 'version_range': '*', 'cve': 'Deprecated', 'severity': 'low', 'description': 'The `request` package is deprecated. Use `node-fetch`, `axios`, or built-in `fetch` instead.'},
    {'package': 'growl', 'version_range': '<1.10.0', 'cve': 'CVE-2017-16042', 'severity': 'medium', 'description': 'Command injection vulnerability in growl notifications.'},
    {'package': 'debug', 'version_range': '<2.6.9 || >=3.0.0 <3.1.0', 'cve': 'CVE-2017-16137', 'severity': 'medium', 'description': 'ReDoS vulnerability in debug package.'},
    {'package': 'moment', 'version_range': '<2.29.4', 'cve': 'CVE-2022-24785', 'severity': 'medium', 'description': 'Path traversal and ReDoS in moment.js.'},
    {'package': 'underscore', 'version_range': '<1.13.0', 'cve': 'CVE-2021-23358', 'severity': 'medium', 'description': 'Arbitrary code execution via template function.'},
    {'package': 'nth-check', 'version_range': '<2.0.1', 'cve': 'CVE-2021-3803', 'severity': 'high', 'description': 'ReDoS vulnerability in nth-check CSS parser.'},
    {'package': 'ansi-html', 'version_range': '<0.0.8', 'cve': 'CVE-2021-23424', 'severity': 'high', 'description': 'XSS vulnerability in ansi-html package.'},
    {'package': 'glob-parent', 'version_range': '<5.1.2', 'cve': 'CVE-2021-35065', 'severity': 'low', 'description': 'ReDoS vulnerability in glob-parent.'},
    {'package': 'trim-newlines', 'version_range': '<3.0.1', 'cve': 'CVE-2021-33623', 'severity': 'medium', 'description': 'ReDoS vulnerability in trim-newlines.'},
    {'package': 'shelljs', 'version_range': '<0.8.5', 'cve': 'CVE-2022-0144', 'severity': 'high', 'description': 'Insecure command execution in shelljs.'},

    # -- Python --
    {'package': 'django', 'version_range': '<4.2.10 || >=5.0.0 <5.0.4', 'cve': 'CVE-2024-27351', 'severity': 'high', 'description': 'Potential SQL injection in Django database models.'},
    {'package': 'flask', 'version_range': '<2.3.0', 'cve': 'CVE-2023-30861', 'severity': 'medium', 'description': 'Possible XSS vulnerability in Flask template handling.'},
    {'package': 'requests', 'version_range': '<2.32.0', 'cve': 'CVE-2024-35195', 'severity': 'medium', 'description': 'Requests library certificate verification bypass.'},
    {'package': 'cryptography', 'version_range': '<42.0.4', 'cve': 'CVE-2024-26130', 'severity': 'high', 'description': 'NULL pointer dereference in cryptography library.'},
    {'package': 'jinja2', 'version_range': '<3.1.3', 'cve': 'CVE-2024-22195', 'severity': 'medium', 'description': 'XSS vulnerability in Jinja2 template rendering.'},
    {'package': 'pillow', 'version_range': '<10.3.0', 'cve': 'CVE-2024-28219', 'severity': 'high', 'description': 'Buffer overflow in Pillow image processing library.'},
    {'package': 'setuptools', 'version_range': '<68.0.0', 'cve': 'CVE-2022-40897', 'severity': 'medium', 'description': 'ReDoS vulnerability in setuptools package listing.'},
    {'package': 'pyyaml', 'version_range': '<6.0', 'cve': 'CVE-2020-14343', 'severity': 'critical', 'description': 'Arbitrary code execution via unsafe yaml.load(). Use yaml.safe_load() instead.'},
    {'package': 'numpy', 'version_range': '<1.26.4', 'cve': 'CVE-2024-21503', 'severity': 'medium', 'description': 'Buffer overflow in numpy array deserialization.'},
    {'package': 'werkzeug', 'version_range': '<3.0.3', 'cve': 'CVE-2024-34069', 'severity': 'medium', 'description': 'Debugger console access vulnerability in Werkzeug.'},
    {'package': 'urllib3', 'version_range': '<2.0.7', 'cve': 'CVE-2023-45803', 'severity': 'medium', 'description': 'URL parsing vulnerability in urllib3.'},
    {'package': 'starlette', 'version_range': '<0.36.3', 'cve': 'CVE-2024-29042', 'severity': 'medium', 'description': 'Path traversal vulnerability in Starlette static files.'},

    # -- Java --
    {'package': 'log4j', 'version_range': '<2.17.1', 'cve': 'CVE-2021-44832', 'severity': 'critical', 'description': 'Log4Shell - Remote code execution via JNDI lookup in log4j.'},
    {'package': 'log4j-core', 'version_range': '<2.17.1', 'cve': 'CVE-2021-44832', 'severity': 'critical', 'description': 'Log4Shell - Remote code execution via JNDI lookup in log4j.'},
    {'package': 'spring-core', 'version_range': '<5.3.18 || >=6.0.0 <6.0.5', 'cve': 'CVE-2022-22965', 'severity': 'critical', 'description': 'Spring4Shell - Remote code execution via data binding.'},
    {'package': 'jackson-databind', 'version_range': '<2.13.4', 'cve': 'CVE-2022-42003', 'severity': 'high', 'description': 'Deserialization denial of service in Jackson.'},
    {'package': 'snakeyaml', 'version_range': '<2.0', 'cve': 'CVE-2022-1471', 'severity': 'critical', 'description': 'Arbitrary code execution via SnakeYAML deserialization.'},
    {'package': 'tomcat', 'version_range': '<10.1.19 || <9.0.86', 'cve': 'CVE-2024-23672', 'severity': 'high', 'description': 'Request smuggling vulnerability in Apache Tomcat.'},
    {'package': 'netty', 'version_range': '<4.1.100', 'cve': 'CVE-2023-34462', 'severity': 'medium', 'description': 'HTTP request smuggling in Netty.'},

    # -- Go --
    {'package': 'golang.org/x/crypto', 'version_range': '<0.17.0', 'cve': 'CVE-2023-48795', 'severity': 'high', 'description': 'Terrapin SSH protocol prefix truncation attack.'},
    {'package': 'github.com/gin-gonic/gin', 'version_range': '<1.9.1', 'cve': 'CVE-2023-26125', 'severity': 'medium', 'description': 'Request smuggling in Gin web framework.'},
    {'package': 'github.com/gorilla/websocket', 'version_range': '<1.5.1', 'cve': 'CVE-2023-39325', 'severity': 'high', 'description': 'Denial of service via crafted websocket frames.'},
    {'package': 'github.com/golang-jwt/jwt', 'version_range': '<5.0.0', 'cve': 'CVE-2023-47108', 'severity': 'high', 'description': 'Improper signature validation in JWT library.'},

    # -- Rust --
    {'package': 'openssl-sys', 'version_range': '<0.9.95', 'cve': 'CVE-2024-0727', 'severity': 'high', 'description': 'NULL pointer dereference in OpenSSL bindings.'},
    {'package': 'hyper', 'version_range': '<1.3.0', 'cve': 'CVE-2024-27308', 'severity': 'high', 'description': 'Request smuggling in hyper HTTP library.'},
    {'package': 'tokio', 'version_range': '<1.33.1', 'cve': 'CVE-2023-44487', 'severity': 'medium', 'description': 'HTTP/2 rapid reset attack affecting async runtime.'},
]

# Map dependency file names to their parser functions
DEPENDENCY_FILE_PATTERNS = {
    'package.json': 'npm',
    'yarn.lock': 'npm',
    'pnpm-lock.yaml': 'npm',
    'requirements.txt': 'pip',
    'Pipfile': 'pip',
    'pyproject.toml': 'pip',
    'pom.xml': 'maven',
    'build.gradle': 'gradle',
    'Cargo.toml': 'cargo',
    'Cargo.lock': 'cargo',
    'go.mod': 'go',
    'Gemfile': 'bundler',
    'Gemfile.lock': 'bundler',
    'composer.json': 'composer',
    'composer.lock': 'composer',
}


def _parse_version(version_str: str) -> tuple:
    '''Parse a semver version string into a comparable tuple of ints.'''
    cleaned = re.sub(r'[^0-9.]', '', version_str.split('-')[0].split('+')[0])
    parts = cleaned.split('.')
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result[:3])


def _version_in_range(version_str: str, range_str: str) -> bool:
    '''Check if a version string falls within a given range.

    Supports: '<X.Y.Z', '<=X.Y.Z', '>X.Y.Z', '>=X.Y.Z', 
    'X.Y.Z - A.B.C', '||' (or), '*' (all versions).
    '''
    version_str = version_str.strip()
    range_str = range_str.strip()

    if range_str == '*':
        return True

    # Handle OR conditions
    if '||' in range_str:
        parts = [p.strip() for p in range_str.split('||')]
        return any(_version_in_range(version_str, p) for p in parts)

    # Handle range with hyphen
    if ' - ' in range_str:
        low, high = range_str.split(' - ', 1)
        ver = _parse_version(version_str)
        return _parse_version(low) <= ver <= _parse_version(high)

    # Handle comparison operators
    ver = _parse_version(version_str)

    # Extract operator and target
    m = re.match(r'^(<=|>=|<|>|!=|=)?\s*([\d.]+)', range_str)
    if not m:
        return False

    operator = m.group(1) or '='
    target_str = m.group(2)
    target = _parse_version(target_str)

    if operator == '<':
        return ver < target
    elif operator == '<=':
        return ver <= target
    elif operator == '>':
        return ver > target
    elif operator == '>=':
        return ver >= target
    elif operator == '!=':
        return ver != target
    else:
        return ver == target


def _parse_npm_manifest(path: Path) -> List[Dict[str, str]]:
    '''Parse package.json and extract dependencies with versions.'''
    packages: List[Dict[str, str]] = []
    try:
        data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
    except (json.JSONDecodeError, OSError):
        return packages

    for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
        deps = data.get(section, {})
        for name, version in deps.items():
            # Strip semver prefixes
            clean_version = re.sub(r'^[\^~>=<]+\s*', '', str(version))
            if clean_version and clean_version != '*':
                packages.append({'name': name, 'version': clean_version, 'source': 'package.json'})

    return packages


def _parse_requirements_txt(path: Path) -> List[Dict[str, str]]:
    '''Parse requirements.txt and extract packages with versions.'''
    packages: List[Dict[str, str]] = []
    try:
        content = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return packages

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        # Handle package==version or package>=version etc
        m = re.match(r'([a-zA-Z0-9_.-]+)\s*([><=!]+)\s*([\d.*]+)', line)
        if m:
            packages.append({'name': m.group(1).lower(), 'version': m.group(3), 'source': 'requirements.txt'})
        elif line and not line.startswith('#'):
            packages.append({'name': line.split('=')[0].strip().split('>')[0].strip().split('<')[0].strip().lower(), 'version': '0.0.0', 'source': 'requirements.txt'})

    return packages


def _parse_pyproject_toml(path: Path) -> List[Dict[str, str]]:
    '''Parse pyproject.toml and extract dependencies with versions.'''
    packages: List[Dict[str, str]] = []
    try:
        content = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return packages

    # Simple TOML parsing for dependencies sections
    in_deps = False
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('[tool.poetry.dependencies]') or stripped.startswith('[project.dependencies]'):
            in_deps = True
            continue
        if stripped.startswith('['):
            in_deps = False
            continue
        if in_deps:
            m = re.match(r'([a-zA-Z0-9_.-]+)\s*=\s*["\']([^"\']+)["\']', stripped)
            if m:
                clean_ver = re.sub(r'^[\^~]', '', m.group(2))
                packages.append({'name': m.group(1).lower(), 'version': clean_ver, 'source': 'pyproject.toml'})

    return packages


def _parse_go_mod(path: Path) -> List[Dict[str, str]]:
    '''Parse go.mod and extract dependencies with versions.'''
    packages: List[Dict[str, str]] = []
    try:
        content = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return packages

    for line in content.split('\n'):
        stripped = line.strip()
        m = re.match(r'^\s+([a-zA-Z0-9_./-]+)\s+v?([\d.]+)', stripped)
        if m and not stripped.startswith('//'):
            packages.append({'name': m.group(1), 'version': m.group(2), 'source': 'go.mod'})

    return packages


def _parse_cargo_toml(path: Path) -> List[Dict[str, str]]:
    '''Parse Cargo.toml and extract dependencies with versions.'''
    packages: List[Dict[str, str]] = []
    try:
        content = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return packages

    in_deps = False
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('[dependencies]'):
            in_deps = True
            continue
        if stripped.startswith('[') and stripped.endswith(']'):
            in_deps = False
            continue
        if in_deps:
            m = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*["\']([^"\']+)["\']', stripped)
            if m:
                clean_ver = re.sub(r'^[\^~]', '', m.group(2))
                packages.append({'name': m.group(1).lower(), 'version': clean_ver, 'source': 'Cargo.toml'})

    return packages


_PARSERS = {
    'package.json': _parse_npm_manifest,
    'requirements.txt': _parse_requirements_txt,
    'pyproject.toml': _parse_pyproject_toml,
    'go.mod': _parse_go_mod,
    'Cargo.toml': _parse_cargo_toml,
}


def scan_dependency_files(
    scan_path: Path,
    relative_to: Path,
) -> List[Finding]:
    '''Scan dependency manifest files for known vulnerable packages.

    Discovers supported dependency files under scan_path, parses
    them, and checks each dependency against the built-in
    vulnerability database.

    Args:
        scan_path: Root path to scan recursively.
        relative_to: Make paths relative to this root.

    Returns:
        List of Finding objects for vulnerable dependencies.
    '''
    findings: List[Finding] = []
    all_packages: List[Dict[str, str]] = []

    for dep_file_name, ecosystem in DEPENDENCY_FILE_PATTERNS.items():
        # Search for the dependency file in the scan tree
        for found_path in scan_path.rglob(dep_file_name):
            # Skip node_modules etc
            if any(ignored in found_path.parts for ignored in ('node_modules', '.git', '__pycache__', '.venv', 'venv')):
                continue

            # Skip if it's a lock file in node_modules (already covered)
            if 'node_modules' in found_path.parts:
                continue

            parser = _PARSERS.get(dep_file_name)
            if parser:
                try:
                    deps = parser(found_path)
                    for dep in deps:
                        dep['manifest_path'] = str(found_path.relative_to(relative_to)) if relative_to else str(found_path)
                        dep['ecosystem'] = ecosystem
                    all_packages.extend(deps)
                except Exception:
                    pass

    for pkg in all_packages:
        pkg_name = pkg['name'].lower()
        pkg_version = pkg['version']

        for vuln in VULNERABILITY_DB:
            vuln_name = vuln['package'].lower()

            # Match package names (handle variations)
            if vuln_name == pkg_name or pkg_name.endswith('/' + vuln_name) or vuln_name.endswith(pkg_name):
                try:
                    if _version_in_range(pkg_version, vuln['version_range']):
                        findings.append(Finding(
                            file_path=pkg['manifest_path'],
                            line_number=1,
                            severity=vuln['severity'],
                            finding_type='vulnerable_dependency',
                            title=f'Vulnerable dependency: {pkg["name"]}',
                            description=vuln['description'],
                            package=pkg['name'],
                            cve=vuln.get('cve', ''),
                            recommendation=f'Update {pkg["name"]} to version {vuln["version_range"].replace("<", ">= ")} or later. Run the appropriate package manager update command.',
                        ))
                except (ValueError, IndexError):
                    pass

    return findings
