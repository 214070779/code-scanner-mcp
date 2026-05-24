# Code Security Scanner MCP Server

Scan your local codebase for security vulnerabilities, hardcoded secrets, and insecure coding patterns — all from your AI assistant via MCP (Model Context Protocol).

## Features

### 🔑 Secrets Detection (24+ patterns)
- AWS Access Keys & Secret Keys
- GitHub tokens (personal, OAuth, app)
- Stripe API keys (live/test)
- Slack tokens & webhooks
- Google Cloud / Firebase credentials
- Database connection strings
- JWT tokens & private keys (RSA, DSA, EC)
- npm auth tokens, Telegram bot tokens, SendGrid API keys
- Generic API keys & password assignments

### 📦 Dependency Vulnerability Scanning
Automatically detects and parses:
- `package.json` (npm/yarn/pnpm)
- `requirements.txt`, `Pipfile`, `pyproject.toml` (Python)
- `go.mod` (Go)
- `Cargo.toml` (Rust)
- `pom.xml`, `build.gradle` (Java)

Checks against a built-in database of 45+ CVEs across JavaScript, Python, Java, Go, and Rust ecosystems.

### 🛡️ Insecure Code Pattern Detection
- **SQL Injection**: String concatenation in queries, raw SQL builders
- **XSS**: innerHTML, dangerouslySetInnerHTML, v-html
- **Command Injection**: os.system, subprocess shell=True, eval/exec, child_process.exec
- **Path Traversal**: Unsanitized file paths
- **Insecure Deserialization**: pickle, yaml.load, marshal
- **Configuration Issues**: Debug mode, CORS wildcard, hardcoded JWT secrets
- **Information Leakage**: Stack trace exposure, directory listing

## Tools

| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan for hardcoded API keys, tokens, and passwords |
| `scan_dependencies` | Check dependencies against known vulnerability database |
| `scan_code_patterns` | Detect SQLi, XSS, command injection, and other patterns |
| `scan_file` | Comprehensive scan of a single file (secrets + code patterns) |
| `scan_directory` | Full project audit (secrets + dependencies + code patterns) |

## Quick Start

### Prerequisites
- Python 3.11+
- `pip install mcp pydantic`

### Run with MCP Inspector
```bash
git clone https://github.com/214070779/code-scanner-mcp.git
cd code-scanner-mcp
pip install mcp pydantic
npx @modelcontextprotocol/inspector python3 server.py
```

### Configure in your AI Client

Add to your MCP settings:

```json
{
  "mcpServers": {
    "code-scanner": {
      "command": "python3",
      "args": ["/path/to/code-scanner-mcp/server.py"]
    }
  }
}
```

## Example Usage

**"Scan my project for security issues"**
→ AI calls `scan_directory(path="./my-project")`

**"Check this file for secrets before committing"**
→ AI calls `scan_file(path="./src/config.ts")`

**"Are there any vulnerable npm packages?"**
→ AI calls `scan_dependencies(path=".")`

## Supported Platforms

- [MCPize](https://mcpize.com)
- [Smithery](https://smithery.ai)
- [PulseMCP](https://pulsemcp.com)
- [MCP.so](https://mcp.so)
- All MCP-compatible AI clients

## Development

```bash
# Clone and install
git clone https://github.com/214070779/code-scanner-mcp.git
cd code-scanner-mcp
pip install mcp pydantic

# Run tests
python3 -c "from server import mcp; print('OK:', list(mcp._tool_manager._tools.keys()))"

# Run with inspector
npx @modelcontextprotocol/inspector python3 server.py
```

## License

MIT
