# Dev Community Posts

---

## dev.to Post Draft

**Title:** I Built an MCP Server That Gives AI Assistants Security Scanning Superpowers

**Tags:** security, mcp, opensource, python, devtools

**Body:**

If you've ever pushed a commit at 2 AM only to realize you accidentally committed an API key... this post is for you.

I got tired of manually grepping for secrets before every commit and checking `npm audit` output. So I built a Code Security Scanner as an MCP (Model Context Protocol) server.

**What it does**

It plugs into any MCP-compatible AI client (Claude, Cursor, etc.) and gives it 5 tools:

- **scan_secrets** — Find hardcoded API keys, tokens, and passwords (24+ patterns)
- **scan_dependencies** — Check dependency manifests against 45+ real CVEs
- **scan_code_patterns** — Detect SQL injection, XSS, command injection, and more
- **scan_file** — Pre-commit security check on individual files
- **scan_directory** — Full project audit in one command

**How it works**

Instead of learning a new CLI tool, you just ask your AI assistant:

> "Scan my project for security issues before I commit"

The AI calls the appropriate tool, and within seconds you get structured results with file paths, line numbers, severity levels, and fix suggestions.

**Why local-first matters**

Everything runs on your machine. Zero data leaves your environment. No cloud dependency, no signup, no API keys to manage.

**What it detects**

| Category | Coverage |
|----------|----------|
| Secrets | AWS keys, GitHub tokens, Stripe keys, Slack webhooks, DB URLs, JWT secrets, SSH keys — 24+ patterns |
| Dependencies | 45+ CVEs across npm, pip, Go, Rust, Java ecosystems |
| Code patterns | SQLi, XSS, command injection, path traversal, insecure deserialization — 20+ OWASP patterns |

**Stack**

Built with Python + FastMCP. Zero external API dependencies — all pattern matching is local.

**Get started**

- **GitHub:** github.com/214070779/code-scanner-mcp (MIT license)
- **MCPize:** mcpize.com/mcp/code-scanner
- **Free tier:** 50 scans/month — no credit card needed

What security checks would you add? Drop a comment below.

---

## Reddit r/programming Post Draft

**Title:** I built an open-source MCP server that detects secrets, CVEs, and insecure code in your projects — all from your AI assistant

**Text:**

I kept finding myself running `grep -r "API_KEY"` before every commit and manually checking `npm audit`. So I built a code security scanner as an MCP server.

It plugs into Claude, Cursor, or any MCP-compatible client and gives your AI assistant 5 security tools:
- scan_secrets (24+ patterns including AWS, GitHub, Stripe, JWT)
- scan_dependencies (45+ CVEs across Python, JS, Go, Rust, Java)
- scan_code_patterns (SQLi, XSS, cmd injection, OWASP Top 10)
- scan_file / scan_directory

Local-first — all scanning on your machine, no data leaves your environment.

MIT licensed, Python + FastMCP: github.com/214070779/code-scanner-mcp

Would love feedback from the community!

---

## Hacker News Post Draft

**Title:** Show HN: Code Security Scanner – An MCP Server That Finds Secrets and CVEs in Your Codebase

**URL:** https://github.com/214070779/code-scanner-mcp

**First comment:**

This is an MCP server that adds 5 security scanning tools to any AI coding assistant.

Key points:
- Local-only scanning (no data leaves your machine)
- 24 secret patterns, 45+ CVEs, 20+ insecure code patterns
- Multi-language: Python, JS/TS, Go, Rust, Java
- Python + FastMCP, MIT license
- Available on MCPize with free tier (50 scans/month)

Happy to answer questions about the architecture or how MCP tool integration works for security use cases.
