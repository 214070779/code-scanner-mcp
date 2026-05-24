'''
Shared scanning utilities for the Code Security Scanner MCP Server.

Provides file discovery, pattern matching, and report formatting
functions used across all detectors.
'''

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict


# ---------------------------------------------------------------------------
# Data models for scan findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    '''A single security finding discovered during scanning.'''
    file_path: str
    line_number: int
    severity: str            # 'critical' | 'high' | 'medium' | 'low'
    finding_type: str        # e.g. 'secret', 'vulnerable_dependency', 'insecure_pattern'
    title: str               # Short description
    description: str         # Detailed explanation
    snippet: str = ''        # Relevant code snippet
    recommendation: str = '' # How to fix
    cve: str = ''            # CVE identifier (for dependency vulns)
    package: str = ''        # Package name (for dependency vulns)
    matched_pattern: str = ''  # The regex pattern that matched


@dataclass
class ScanResult:
    '''Aggregated scan result from one or more detectors.'''
    scan_path: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def summary(self) -> Dict[str, int]:
        '''Return a count summary of findings by severity.'''
        counts: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_markdown(self) -> str:
        '''Format the full scan result as readable Markdown.'''
        lines: List[str] = []
        summary = self.summary
        lines.append(f'# Scan Report: `{self.scan_path}`')
        lines.append('')
        lines.append(f'- **Files scanned**: {self.files_scanned}')
        lines.append(f'- **Total findings**: {self.total_findings}')
        lines.append(f'- **Scan duration**: {self.scan_duration_ms}ms')
        lines.append('')
        lines.append('## Summary by Severity')
        lines.append('')
        lines.append(f'| Severity | Count |')
        lines.append(f'|----------|-------|')
        for sev in ['critical', 'high', 'medium', 'low']:
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}.get(sev, '')
            if summary[sev] > 0:
                lines.append(f'| {icon} **{sev.capitalize()}** | {summary[sev]} |')
        lines.append('')

        if not self.findings:
            lines.append('✅ **No issues found.**')
            lines.append('')
            return '\n'.join(lines)

        if self.errors:
            lines.append('## ⚠️ Scan Errors')
            lines.append('')
            for err in self.errors:
                lines.append(f'- `{err}`')
            lines.append('')

        lines.append('## Findings')
        lines.append('')

        for i, f in enumerate(self.findings, 1):
            sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}.get(f.severity.lower(), '')
            lines.append(f'### {i}. {sev_icon} {f.title}')
            lines.append('')
            lines.append(f'- **Severity**: {f.severity}')
            lines.append(f'- **Type**: {f.finding_type}')
            lines.append(f'- **File**: `{f.file_path}`')
            lines.append(f'- **Line**: {f.line_number}')
            if f.package:
                lines.append(f'- **Package**: {f.package}')
            if f.cve:
                lines.append(f'- **CVE**: {f.cve}')
            lines.append('')
            lines.append(f'{f.description}')
            if f.snippet:
                lines.append('')
                lines.append('```')
                lines.append(f.snippet)
                lines.append('```')
            if f.recommendation:
                lines.append('')
                lines.append(f'**Recommendation**: {f.recommendation}')
            lines.append('')
            lines.append('---')
            lines.append('')

        return '\n'.join(lines)

    def to_json(self) -> str:
        '''Format scan result as JSON.'''
        import json
        result = {
            'scan_path': self.scan_path,
            'files_scanned': self.files_scanned,
            'scan_duration_ms': self.scan_duration_ms,
            'total_findings': self.total_findings,
            'summary': self.summary,
            'findings': [asdict(f) for f in self.findings],
        }
        if self.errors:
            result['errors'] = self.errors
        return json.dumps(result, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# File discovery utilities
# ---------------------------------------------------------------------------

# Default file patterns to IGNORE during scanning
IGNORE_DIRS: set = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
    '.tox', '.eggs', 'dist', 'build', '.next', '.nuxt',
    '.cache', '.yarn', 'vendor', '.bundle', '.pytest_cache',
    '.mypy_cache', '.ruff_cache', '.vscode', '.idea',
}

IGNORE_EXTENSIONS: set = {
    '.pyc', '.pyo', '.so', '.dll', '.dylib', '.exe',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.mp4', '.mp3', '.avi', '.mov', '.wav', '.flac',
    '.min.js', '.min.css',
    '.lock', # except package-lock.json / yarn.lock handled specially
}


def is_binary_file(file_path: Path) -> bool:
    '''Quick check if a file is likely binary by looking at first bytes.'''
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        return True


def discover_files(
    scan_path: str,
    extensions: Optional[List[str]] = None,
    max_size_mb: int = 10,
) -> List[Path]:
    '''Recursively discover files under `scan_path` that should be scanned.

    Args:
        scan_path: Root path to scan.
        extensions: If provided, only include files with these extensions.
        max_size_mb: Skip files larger than this (default: 10 MB).

    Returns:
        Sorted list of file Paths.
    '''
    root = Path(scan_path).expanduser().resolve()
    if not root.exists():
        return []

    files: List[Path] = []
    for entry in root.rglob('*'):
        # Skip ignored directories
        if any(ignored in entry.parts for ignored in IGNORE_DIRS):
            continue
        if not entry.is_file():
            continue
        # Skip by extension
        if entry.suffix.lower() in IGNORE_EXTENSIONS:
            continue
        # Skip minified files
        if '.min.' in entry.name:
            continue
        # Skip binaries
        if is_binary_file(entry):
            continue
        # Skip large files
        try:
            if entry.stat().st_size > max_size_mb * 1024 * 1024:
                continue
        except OSError:
            continue
        # Filter by extension if requested
        if extensions:
            if entry.suffix.lower() not in extensions:
                continue
        files.append(entry)

    files.sort()
    return files


# ---------------------------------------------------------------------------
# Pattern matching utilities
# ---------------------------------------------------------------------------

def compile_patterns(patterns: Dict[str, Tuple[str, str]]) -> List[Dict[str, Any]]:
    '''Compile a dict of named patterns into compiled regex objects.

    Input format:
        {name: (regex, description)}

    Returns:
        List of dicts with 'name', 'regex', 'description', and 'compiled' keys.
    '''
    compiled: List[Dict[str, Any]] = []
    for name, (pattern_str, description) in patterns.items():
        try:
            compiled.append({
                'name': name,
                'regex': re.compile(pattern_str, re.MULTILINE),
                'description': description,
            })
        except re.error as e:
            # Should not happen with well-defined patterns
            continue
    return compiled


def scan_file_for_patterns(
    file_path: Path,
    patterns: List[Dict[str, Any]],
    relative_to: Optional[Path] = None,
) -> List[Finding]:
    '''Scan a single file against a list of compiled patterns.

    Args:
        file_path: The file to scan.
        patterns: List of compiled pattern dicts (from `compile_patterns`).
        relative_to: If set, make file_path relative to this root.

    Returns:
        List of Finding objects.
    '''
    findings: List[Finding] = []
    rel_path = str(file_path)
    if relative_to:
        try:
            rel_path = str(file_path.relative_to(relative_to))
        except ValueError:
            pass

    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except (OSError, LookupError):
        return findings

    lines = content.split('\n')

    for pat in patterns:
        for match in pat['regex'].finditer(content):
            # Calculate line number
            line_num = content[:match.start()].count('\n') + 1

            # Get snippet (surrounding lines)
            snippet_start = max(0, line_num - 2)
            snippet_end = min(len(lines), line_num + 1)
            snippet = '\n'.join(
                f'{i + 1}: {lines[i]}'
                for i in range(snippet_start, snippet_end)
            )

            findings.append(Finding(
                file_path=rel_path,
                line_number=line_num,
                severity='high',  # overridden per detector
                finding_type='pattern_match',
                title=pat['name'],
                description=pat['description'],
                snippet=snippet.strip(),
                matched_pattern=str(pat['regex'].pattern)[:200],
            ))

    return findings
