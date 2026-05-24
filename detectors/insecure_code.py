'''
Insecure code pattern detector for the Code Security Scanner MCP Server.

Scans source files for common security anti-patterns: SQL injection,
cross-site scripting (XSS), command injection, path traversal,
insecure deserialization, and other dangerous coding practices.
'''

import re
from pathlib import Path
from typing import List, Dict, Any

from utils.scanner_helpers import Finding


# ---------------------------------------------------------------------------
# Insecure code patterns organized by vulnerability type
# ---------------------------------------------------------------------------

CODE_PATTERNS: List[Dict[str, Any]] = [
    # -- SQL Injection --
    {
        'name': 'SQL Injection - String Concatenation',
        'description': 'SQL query built using string concatenation or interpolation, which can lead to SQL injection. Use parameterized queries or an ORM instead.',
        'severity': 'critical',
        'recommendation': 'Use parameterized queries (e.g., cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])) or an ORM like SQLAlchemy.',
        'patterns': [
            # Python
            r'execute\(.*["\'].*\bSELECT\b.*["\']\s*[+%]',
            r'execute\(.*["\'].*\bINSERT\b.*["\']\s*[+%]',
            r'execute\(.*["\'].*\bUPDATE\b.*["\']\s*[+%]',
            r'execute\(.*["\'].*\bDELETE\b.*["\']\s*[+%]',
            r'cursor\(\)\.execute\(f["\']',
            r'\.execute\(f?["\'].*\{.*\}.*["\']',  # f-string in execute
            # JavaScript/Node.js
            r'\.query\(`[^`]*\$\{[^`]*`',
            r'\.execute\(`[^`]*\$\{[^`]*`',
            r'\.query\(["\'].*[+]\s*\w+',
            r'\.execute\(["\'].*[+]\s*\w+',
            # PHP
            r'mysqli_query\(.*["\'].*\$',
            r'->query\(["\'].*\$',
            # Java
            r'\.executeQuery\(["\'].*\+',
            r'Statement\.createQuery\(["\'].*\+',
            # Ruby
            r'\.execute\(["\'].*#\{',
            r'\.find_by_sql\(["\'].*#\{',
        ],
    },
    {
        'name': 'SQL Injection - Raw String Building',
        'description': 'Raw SQL query constructed without parameters. This is a SQL injection risk if any input is user-controlled.',
        'severity': 'critical',
        'recommendation': 'Use an ORM or parameterized queries. Never concatenate user input into SQL strings.',
        'patterns': [
            r'raw\(["\'].*SELECT',
            r'RawSQL\(["\']',
            r'raw_query\(["\']',
        ],
    },
    # -- Cross-Site Scripting (XSS) --
    {
        'name': 'XSS - innerHTML Assignment',
        'description': 'Setting innerHTML with potentially unsafe content. This can lead to cross-site scripting if the content contains user input.',
        'severity': 'high',
        'recommendation': 'Use textContent instead of innerHTML when setting text. If HTML is required, sanitize the input with DOMPurify or similar.',
        'patterns': [
            r'\.innerHTML\s*=\s*',
            r'\.innerHTML\s*\+=\s*',
            r'\.outerHTML\s*=\s*',
            r'\.insertAdjacentHTML\(',
        ],
    },
    {
        'name': 'XSS - dangerouslySetInnerHTML',
        'description': 'React dangerouslySetInnerHTML prop detected. This bypasses React XSS protection.',
        'severity': 'high',
        'recommendation': 'Use React components instead of raw HTML. If HTML is required, sanitize with DOMPurify first: __html: DOMPurify.sanitize(content).',
        'patterns': [
            r'dangerouslySetInnerHTML\s*=\s*\{{',
            r'dangerouslySetInnerHTML=',
        ],
    },
    {
        'name': 'XSS - v-html Directive',
        'description': 'Vue.js v-html directive detected. This renders raw HTML and can lead to XSS.',
        'severity': 'high',
        'recommendation': 'Use template expressions {{ }} instead of v-html when possible. If HTML is required, sanitize with DOMPurify.',
        'patterns': [
            r'v-html=',
        ],
    },
    {
        'name': 'XSS - Template Injection',
        'description': 'Server-side template injection risk. User input rendered in template engines without escaping.',
        'severity': 'high',
        'recommendation': 'Use auto-escaping template engines and avoid rendering raw user input in templates.',
        'patterns': [
            r'render\(.*["\'].*[+%]\s*\w+',
            r'render_template_string\(.*["\'].*\{',
            r'render_to_string\(.*["\'].*\+',
        ],
    },
    # -- Command Injection --
    {
        'name': 'Command Injection - os.system',
        'description': 'Using os.system() to execute shell commands. If the command string contains user input, this can lead to command injection.',
        'severity': 'critical',
        'recommendation': 'Use subprocess.run() with a list of arguments instead of a shell string: subprocess.run(["ls", "-la"], shell=False).',
        'patterns': [
            r'os\.system\(["\']',
            r'os\.popen\(["\']',
            r'commands\.getoutput\(',
            r'commands\.getstatusoutput\(',
        ],
    },
    {
        'name': 'Command Injection - subprocess shell=True',
        'description': 'Using subprocess with shell=True enables shell injection if the command includes user input.',
        'severity': 'critical',
        'recommendation': 'Use subprocess.run() with shell=False and pass arguments as a list: subprocess.run(["grep", pattern, filename], shell=False).',
        'patterns': [
            r'subprocess\.\w+\(.*shell\s*=\s*True',
            r'subprocess\.\w+\(.*shell=True',
            r'subprocess\.Popen\(.*shell\s*=\s*True',
            r'subprocess\.check_call\(.*shell\s*=\s*True',
            r'subprocess\.check_output\(.*shell\s*=\s*True',
        ],
    },
    {
        'name': 'Command Injection - exec/eval',
        'description': 'Using eval(), exec(), or similar functions that execute arbitrary code. Extremely dangerous with user input.',
        'severity': 'critical',
        'recommendation': 'Avoid eval() and exec() entirely. Use safer alternatives like AST literal evaluation (ast.literal_eval()).',
        'patterns': [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\bexecfile\s*\(',
            r'\bcompile\s*\(.*\beval\b',
        ],
    },
    {
        'name': 'Command Injection - child_process.exec',
        'description': 'Using Node.js child_process.exec() which runs commands in a shell. User input in the command string can lead to injection.',
        'severity': 'critical',
        'recommendation': 'Use child_process.execFile() or spawn() with arguments array instead of a shell command string.',
        'patterns': [
            r'child_process\.exec\(',
            r'require\(["\']child_process["\']\)\.exec\(',
            r'exec\(`.*\$\{',
            r'child_process\.execSync\(',
        ],
    },
    {
        'name': 'Command Injection - Shell Execution',
        'description': 'Shell command execution detected. Running shell commands with user-controlled input is dangerous.',
        'severity': 'high',
        'recommendation': 'Use language-native APIs instead of shell commands. If unavoidable, validate and sanitize all input.',
        'patterns': [
            r'shell_exec\(',
            r'`.*\$\(.*`',  # backtick with command substitution
            r'exec\(["\'].*[|;&`]',
        ],
    },
    # -- Path Traversal --
    {
        'name': 'Path Traversal - User Input in File Operations',
        'description': 'File path constructed from user input without validation. Can lead to path traversal attacks.',
        'severity': 'high',
        'recommendation': 'Validate file paths against an allowlist of permitted directories. Use os.path.realpath() and verify the resolved path starts with the allowed base directory.',
        'patterns': [
            r'open\(.*\{.*\}.*\)',   # f-string in open()
            r'open\(.*["\'].*\..*[\+\%].*\)',  # concatenation in open()
            r'Path\(.*f["\']',  # f-string path
            r'pathlib\.Path\(.*[+%]',
        ],
    },
    {
        'name': 'Path Traversal - send_file',
        'description': 'Using send_file() with a computed path. If the path includes user input, arbitrary file reads are possible.',
        'severity': 'high',
        'recommendation': 'Use send_from_directory() with a fixed base directory instead of send_file() with user-controlled paths.',
        'patterns': [
            r'send_file\(.*[+%]',
            r'send_from_directory\(.*[+%]',
        ],
    },
    # -- Insecure Deserialization --
    {
        'name': 'Insecure Deserialization - pickle',
        'description': 'Using pickle.loads() on untrusted data. Pickle deserialization can execute arbitrary code.',
        'severity': 'critical',
        'recommendation': 'Use a safer serialization format like JSON for untrusted data. If pickle is required, ensure the source is trusted and cryptographically verified.',
        'patterns': [
            r'pickle\.loads?\(',
            r'cPickle\.loads?\(',
            r'cloudpickle\.loads?\(',
            r'dill\.loads?\(',
        ],
    },
    {
        'name': 'Insecure Deserialization - yaml.load',
        'description': 'Using yaml.load() which can execute arbitrary code. Use yaml.safe_load() instead.',
        'severity': 'critical',
        'recommendation': 'Replace yaml.load() with yaml.safe_load() for untrusted YAML data.',
        'patterns': [
            r'yaml\.load\(',
            r'yaml\.load_all\(',
            r'YAML\(\)\.load\(',
        ],
    },
    {
        'name': 'Insecure Deserialization - Marshal/Serial',
        'description': 'Using marshal or other unsafe deserialization on potentially untrusted data.',
        'severity': 'high',
        'recommendation': 'Use JSON for untrusted data. Avoid deserializing from marshal, msgpack, or similar binary formats without validation.',
        'patterns': [
            r'marshal\.loads?\(',
            r'msgpack\.unpack\(',
            r'node-serialize\.unserialize\(',
            r'phpunserialize\(',
            r'JSON\.parse\(.*request|req\.body|req\.query',
        ],
    },
    # -- Hardcoded Secrets in Code --
    {
        'name': 'Hardcoded Database Password',
        'description': 'Database password appears hardcoded in source. This is a security risk if code is committed to version control.',
        'severity': 'critical',
        'recommendation': 'Use environment variables or a secrets manager. Never hardcode database credentials.',
        'patterns': [
            r'(?i)(?:db_?password|db_?pwd|database_password)\s*[:=]\s*[''"][^''"]{3,}[''"]',
        ],
    },
    {
        'name': 'Insecure Host Configuration',
        'description': 'Server configured to accept all hosts. This can lead to Host header attacks.',
        'severity': 'high',
        'recommendation': 'Set ALLOWED_HOSTS to a specific domain list. Never use "*" in production.',
        'patterns': [
            r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']\s*\]',
            r'ALLOWED_HOSTS\s*=\s*\["\*"\]',
        ],
    },
    {
        'name': 'Debug Mode Enabled',
        'description': 'Debug mode enabled in production framework config. This can leak sensitive information.',
        'severity': 'high',
        'recommendation': 'Set DEBUG=False and ensure debug/trace mode is disabled in production.',
        'patterns': [
            r'DEBUG\s*=\s*True',
            r'debug\s*=\s*True',
            r'app\.run\(.*debug\s*=\s*True',
        ],
    },
    {
        'name': 'CORS Wildcard',
        'description': 'CORS configured with wildcard origin, allowing any website to make cross-origin requests.',
        'severity': 'medium',
        'recommendation': 'Restrict CORS to specific origins instead of using "*". Only use wildcard for public APIs.',
        'patterns': [
            r'Access-Control-Allow-Origin:\s*\*',
            r'Access-Control-Allow-Origin\s*=\s*["\']\*["\']',
            r'origins?\s*=\s*\[\s*["\']\*["\']\s*\]',
            r'cors\(\s*\{\s*origin\s*:\s*["\']\*["\']',
        ],
    },
    {
        'name': 'Hardcoded JWT Secret',
        'description': 'JWT signing secret appears hardcoded. A leaked JWT secret allows forging authentication tokens.',
        'severity': 'critical',
        'recommendation': 'Use a strong, randomly generated secret stored in environment variables. Rotate secrets regularly.',
        'patterns': [
            r'(?i)jwt.?secret\s*[:=]\s*[''"][a-zA-Z0-9_\-]{5,}[''"]',
            r'(?i)jwt_secret_key\s*=\s*[''"][a-zA-Z0-9_\-]{5,}[''"]',
            r'(?i)secret_key\s*=\s*[''"][a-zA-Z0-9_\-]{10,}[''"]',
        ],
    },
    # -- Information Leakage --
    {
        'name': 'Stack Trace Exposure',
        'description': 'Application may expose stack traces to users. This leaks internal implementation details.',
        'severity': 'medium',
        'recommendation': 'Use custom error handlers that return generic error messages in production. Log full stack traces server-side only.',
        'patterns': [
            r'print_exc\(',
            r'format_exc\(',
            r'traceback\.print_exc',
            r'traceback\.format_exc',
        ],
    },
    {
        'name': 'Hardcoded Test Credentials',
        'description': 'Test credentials found in source code. Ensure these are not used in production.',
        'severity': 'medium',
        'recommendation': 'Use environment-specific configuration files. Never use test credentials in production.',
        'patterns': [
            r'(?i)(?:test_?password|test_?user|admin_?password)\s*[:=]\s*[''"][^''"]{3,}[''"]',
        ],
    },
    {
        'name': 'Directory Listing Enabled',
        'description': 'Directory listing appears to be enabled. This exposes the file structure of the application.',
        'severity': 'medium',
        'recommendation': 'Disable directory listing in production web server configuration.',
        'patterns': [
            r'Options\s*\+Indexes',
            r'DirectoryIndex\s+disabled',
            r'auto_index\s*=\s*True',
        ],
    },
]


def _compile_code_patterns() -> List[Dict[str, Any]]:
    compiled: List[Dict[str, Any]] = []
    for entry in CODE_PATTERNS:
        regexes = []
        for pattern in entry['patterns']:
            try:
                regexes.append(re.compile(pattern, re.MULTILINE))
            except re.error:
                continue
        compiled.append({
            'name': entry['name'],
            'description': entry['description'],
            'severity': entry['severity'],
            'recommendation': entry['recommendation'],
            'regexes': regexes,
        })
    return compiled


_CODE_PATTERNS_COMPILED: List[Dict[str, Any]] = _compile_code_patterns()


def scan_file_for_insecure_code(
    file_path: Path,
    relative_to: Path,
) -> List[Finding]:
    '''Scan a source file for insecure coding patterns.

    Checks for SQL injection, XSS, command injection, path traversal,
    insecure deserialization, and other security anti-patterns.

    Args:
        file_path: Absolute path to the file to scan.
        relative_to: Make paths relative to this root.

    Returns:
        List of Finding objects for insecure code patterns.
    '''
    findings: List[Finding] = []

    # Only scan source code files
    source_extensions = {
        '.py', '.js', '.ts', '.tsx', '.jsx', '.php', '.rb', '.java',
        '.kt', '.scala', '.go', '.rs', '.swift', '.c', '.cpp', '.h',
        '.vue', '.svelte', '.cs', '.fs', '.ex', '.exs',
    }
    if file_path.suffix.lower() not in source_extensions:
        return findings

    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except (OSError, LookupError):
        return findings

    lines = content.split('\n')
    rel_path_str = str(file_path.relative_to(relative_to)) if relative_to else str(file_path)

    for entry in _CODE_PATTERNS_COMPILED:
        for regex in entry['regexes']:
            for match in regex.finditer(content):
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
                    severity=entry['severity'],
                    finding_type='insecure_pattern',
                    title=entry['name'],
                    description=entry['description'],
                    snippet=snippet.strip(),
                    recommendation=entry['recommendation'],
                ))

    return findings
