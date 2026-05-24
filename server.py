#!/usr/bin/env python3
'''
MCP Server for Code Security Scanning.

Provides tools to scan local codebases for hardcoded secrets,
vulnerable dependencies, and insecure coding patterns.

Tools:
  scan_secrets        - Scan files/directories for exposed secrets
  scan_dependencies   - Scan dependency manifests for known vulnerabilities
  scan_code_patterns   - Scan source files for insecure coding patterns
  scan_file           - Comprehensive scan of a single file (all checks)
  scan_directory      - Comprehensive scan of a directory (all checks)
'''

import time
import asyncio
import json
from pathlib import Path
from typing import Optional, List
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict, field_validator
from mcp.server.fastmcp import FastMCP

from utils.scanner_helpers import ScanResult, Finding, discover_files
from detectors.secrets import scan_file_for_secrets
from detectors.dependencies import scan_dependency_files
from detectors.insecure_code import scan_file_for_insecure_code

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

mcp = FastMCP("code_scanner_mcp")


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------

class ResponseFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"


class ScanPathInput(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid',
    )

    path: str = Field(
        ...,
        description="File or directory path to scan. Can be absolute or relative (e.g., '/home/user/project', './src').",
        min_length=1,
        max_length=4096,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable report, 'json' for machine-readable data.",
    )

    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Path cannot be empty")
        return v


class ScanDirectoryInput(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid',
    )

    path: str = Field(
        ...,
        description="Directory path to scan recursively (e.g., '/home/user/project', './src').",
        min_length=1,
        max_length=4096,
    )
    extensions: Optional[List[str]] = Field(
        default=None,
        description="Only scan files with these extensions (e.g., ['.py', '.js', '.ts']). Scans all supported files if not set.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable report, 'json' for machine-readable data.",
    )

    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Path cannot be empty")
        return v


class ScanFileInput(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid',
    )

    path: str = Field(
        ...,
        description="Single file path to scan (e.g., '/home/user/project/src/main.py', './config.js').",
        min_length=1,
        max_length=4096,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable report, 'json' for machine-readable data.",
    )

    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Path cannot be empty")
        return v


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def _resolve_path(path_str: str) -> Path:
    '''Resolve a path string to an absolute Path, handling ~ and relatives.'''
    resolved = Path(path_str).expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Path does not exist: {resolved}")
    return resolved


def _build_response(result: ScanResult, response_format: ResponseFormat) -> str:
    '''Format scan result as markdown or JSON.'''
    if response_format == ResponseFormat.JSON:
        return result.to_json()
    return result.to_markdown()


# ---------------------------------------------------------------------------
# Tool: scan_secrets
# ---------------------------------------------------------------------------

@mcp.tool(
    name="scan_secrets",
    annotations={
        "title": "Scan for Exposed Secrets",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def scan_secrets(params: ScanPathInput) -> str:
    '''Scan files for hardcoded API keys, tokens, passwords, and other secrets.

    This tool checks for 24+ types of secrets including AWS keys, GitHub tokens,
    Stripe keys, JWT tokens, private keys, database connection strings, and more.
    It recursively scans directories and reports findings with severity ratings.

    Args:
        params (ScanPathInput): Validated input containing:
            - path (str): File or directory path to scan
            - response_format (Optional[str]): 'markdown' (default) or 'json'

    Returns:
        str: Scan report in markdown or JSON format containing:
            - files_scanned count
            - Summary by severity (critical/high/medium/low)
            - Per-finding details with file, line, snippet, and fix recommendation

    Examples:
        - Use when: "Scan my project for API keys" -> params with path="./my-project"
        - Use when: "Check for secrets in config file" -> params with path="./.env.example"
        - Don't use when: You need to modify files (use editor tools instead)

    Error Handling:
        - Invalid path returns "Error: Path does not exist: {path}"
        - Unreadable files are skipped with a warning in errors list
    '''
    start = time.time()
    try:
        root_path = _resolve_path(params.path)
    except FileNotFoundError as e:
        return str(e)

    result = ScanResult(scan_path=str(root_path))

    if root_path.is_file():
        files_to_scan = [root_path]
    else:
        files_to_scan = discover_files(str(root_path))

    result.files_scanned = len(files_to_scan)

    for file_path in files_to_scan:
        try:
            findings = scan_file_for_secrets(file_path, root_path if root_path.is_dir() else root_path.parent)
            result.findings.extend(findings)
        except Exception as e:
            result.errors.append(f"Error scanning {file_path}: {e}")

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return _build_response(result, params.response_format)


# ---------------------------------------------------------------------------
# Tool: scan_dependencies
# ---------------------------------------------------------------------------

@mcp.tool(
    name="scan_dependencies",
    annotations={
        "title": "Scan Dependencies for Vulnerabilities",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def scan_dependencies(params: ScanPathInput) -> str:
    '''Scan dependency manifest files for known vulnerable packages.

    Detects and parses package.json, requirements.txt, pyproject.toml, go.mod,
    Cargo.toml, and more. Checks each dependency against a built-in database of
    45+ known vulnerabilities across Python, JavaScript, Java, Go, and Rust ecosystems.

    Args:
        params (ScanPathInput): Validated input containing:
            - path (str): Directory path to scan for dependency files
            - response_format (Optional[str]): 'markdown' (default) or 'json'

    Returns:
        str: Scan report in markdown or JSON format containing vulnerable
             dependencies with CVE identifiers, severity, and version ranges.

    Examples:
        - Use when: "Check my project for vulnerable packages" -> params with path="./my-project"
        - Use when: "Find outdated dependencies" -> params with path="/path/to/project"
        - Use when: "Is lodash safe to use?" -> params with path="./project/package.json"

    Notes:
        - Uses a built-in vulnerability database (not live API).
          Run the tool again to get updated results as the DB is updated.
    '''
    start = time.time()
    try:
        root_path = _resolve_path(params.path)
    except FileNotFoundError as e:
        return str(e)

    result = ScanResult(scan_path=str(root_path))

    # Always scan from the directory level for dependency files
    scan_dir = root_path if root_path.is_dir() else root_path.parent
    result.files_scanned = 1

    try:
        findings = scan_dependency_files(scan_dir, scan_dir)
        result.findings.extend(findings)
    except Exception as e:
        result.errors.append(f"Error scanning dependencies: {e}")

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return _build_response(result, params.response_format)


# ---------------------------------------------------------------------------
# Tool: scan_code_patterns
# ---------------------------------------------------------------------------

@mcp.tool(
    name="scan_code_patterns",
    annotations={
        "title": "Scan for Insecure Code Patterns",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def scan_code_patterns(params: ScanPathInput) -> str:
    '''Scan source files for insecure coding patterns.

    Detects SQL injection (string concatenation in queries), XSS (innerHTML,
    dangerouslySetInnerHTML, v-html), command injection (os.system, exec, shell=True),
    path traversal, insecure deserialization (pickle, yaml.load), hardcoded credentials,
    debug mode enabled, and more. Covers Python, JavaScript, TypeScript, PHP, Java,
    Ruby, Go, Rust, and other languages.

    Args:
        params (ScanPathInput): Validated input containing:
            - path (str): File or directory path to scan
            - response_format (Optional[str]): 'markdown' (default) or 'json'

    Returns:
        str: Scan report in markdown or JSON format with:
            - Total files scanned
            - Summary by severity
            - Per-finding details with exact line numbers and fix recommendations

    Examples:
        - Use when: "Find SQL injection risks in my codebase" -> params with path="./src"
        - Use when: "Check for XSS vulnerabilities" -> params with path="./src/components"
        - Use when: "Is there any insecure deserialization?" -> params with path="."
    '''
    start = time.time()
    try:
        root_path = _resolve_path(params.path)
    except FileNotFoundError as e:
        return str(e)

    result = ScanResult(scan_path=str(root_path))

    if root_path.is_file():
        files_to_scan = [root_path]
    else:
        files_to_scan = discover_files(str(root_path))

    result.files_scanned = len(files_to_scan)
    relative_root = root_path if root_path.is_dir() else root_path.parent

    for file_path in files_to_scan:
        try:
            findings = scan_file_for_insecure_code(file_path, relative_root)
            result.findings.extend(findings)
        except Exception as e:
            result.errors.append(f"Error scanning {file_path}: {e}")

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return _build_response(result, params.response_format)


# ---------------------------------------------------------------------------
# Tool: scan_file (comprehensive)
# ---------------------------------------------------------------------------

@mcp.tool(
    name="scan_file",
    annotations={
        "title": "Comprehensive File Scan",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def scan_file(params: ScanFileInput) -> str:
    '''Run ALL security checks on a single file (secrets + insecure code patterns).

    This is a comprehensive scan that runs both the secrets detector and
    the insecure code pattern detector on a single file. For directory-wide
    scans including dependency analysis, use scan_directory instead.

    Args:
        params (ScanFileInput): Validated input containing:
            - path (str): Path to a single file to scan
            - response_format (Optional[str]): 'markdown' (default) or 'json'

    Returns:
        str: Comprehensive scan report with all findings from all detectors.

    Examples:
        - Use when: "Scan this config file for secrets" -> params with path="./config.js"
        - Use when: "Check this Python file for security issues" -> params with path="./app.py"
        - Use when: "Is this file safe to commit?" -> params with path="./src/auth.ts"

    Notes:
        - Only runs on supported file types (source code, config, env files).
        - For full project scans including dependencies, use scan_directory.
    '''
    start = time.time()
    try:
        file_path = _resolve_path(params.path)
    except FileNotFoundError as e:
        return str(e)

    if not file_path.is_file():
        return f"Error: Path is not a file: {file_path}"

    result = ScanResult(scan_path=str(file_path))
    result.files_scanned = 1
    relative_root = file_path.parent

    try:
        secrets = scan_file_for_secrets(file_path, relative_root)
        result.findings.extend(secrets)
    except Exception as e:
        result.errors.append(f"Secrets scan error: {e}")

    try:
        code_patterns = scan_file_for_insecure_code(file_path, relative_root)
        result.findings.extend(code_patterns)
    except Exception as e:
        result.errors.append(f"Code pattern scan error: {e}")

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return _build_response(result, params.response_format)


# ---------------------------------------------------------------------------
# Tool: scan_directory (comprehensive)
# ---------------------------------------------------------------------------

@mcp.tool(
    name="scan_directory",
    annotations={
        "title": "Comprehensive Directory Scan",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def scan_directory(params: ScanDirectoryInput) -> str:
    '''Run ALL security checks on a directory (secrets + dependencies + code patterns).

    This is the most comprehensive scan. It recursively scans the directory and runs:
    1. Secrets detection (API keys, tokens, passwords)
    2. Dependency vulnerability scanning (package.json, requirements.txt, etc.)
    3. Insecure code pattern detection (SQLi, XSS, command injection, etc.)

    Args:
        params (ScanDirectoryInput): Validated input containing:
            - path (str): Directory path to scan recursively
            - extensions (Optional[List[str]]): Filter by file extensions (e.g., ['.py', '.js'])
            - response_format (Optional[str]): 'markdown' (default) or 'json'

    Returns:
        str: Comprehensive scan report with all findings organized by severity.

    Examples:
        - Use when: "Scan my entire project for security issues" -> params with path="."
        - Use when: "Audit the src directory before deployment" -> params with path="./src"
        - Use when: "Check if this project has any security vulnerabilities" -> params with path="/path/to/project"

    Notes:
        - This is a read-only operation. No files are modified.
        - Large directories may take some time to scan.
        - node_modules, .git, and other non-essential dirs are skipped.
    '''
    start = time.time()
    try:
        root_path = _resolve_path(params.path)
    except FileNotFoundError as e:
        return str(e)

    if not root_path.is_dir():
        return f"Error: Path is not a directory: {root_path}"

    result = ScanResult(scan_path=str(root_path))

    # Discover files to scan
    ext_list = params.extensions
    files_to_scan = discover_files(str(root_path), extensions=ext_list)
    result.files_scanned = len(files_to_scan)

    # 1. Secrets scanning
    for file_path in files_to_scan:
        try:
            findings = scan_file_for_secrets(file_path, root_path)
            result.findings.extend(findings)
        except Exception as e:
            result.errors.append(f"Secrets scan error on {file_path}: {e}")

    # 2. Dependency scanning
    try:
        dep_findings = scan_dependency_files(root_path, root_path)
        result.findings.extend(dep_findings)
    except Exception as e:
        result.errors.append(f"Dependency scan error: {e}")

    # 3. Insecure code pattern scanning
    for file_path in files_to_scan:
        try:
            findings = scan_file_for_insecure_code(file_path, root_path)
            result.findings.extend(findings)
        except Exception as e:
            result.errors.append(f"Code pattern scan error on {file_path}: {e}")

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return _build_response(result, params.response_format)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    mcp.run()


if __name__ == '__main__':
    main()
