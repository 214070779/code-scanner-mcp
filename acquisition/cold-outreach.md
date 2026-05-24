# Cold Outreach Templates

---

## Dev Tool Newsletters

### Newsletter: TLDR InfoSec

**Subject:** MCP server for local code security scanning

**Body:**

Hi [Name],

I'm reaching out because I built an open-source Code Security Scanner as an MCP (Model Context Protocol) server, and I think your audience would find it useful.

It plugs into AI coding assistants (Claude, Cursor, etc.) and adds 5 tools:
- `scan_secrets` — 24+ patterns (AWS keys, GitHub tokens, Stripe, JWT)
- `scan_dependencies` — 45+ CVEs across Python, JS, Go, Rust, Java
- `scan_code_patterns` — SQLi, XSS, command injection, OWASP Top 10
- `scan_file` / `scan_directory` — targeted and full-project scanning

Key differentiator: It's local-first. All scanning runs on the developer's machine — zero data leaves their environment. No cloud dependency, no signup.

Tech stack: Python + FastMCP, MIT licensed.
GitHub: github.com/214070779/code-scanner-mcp
MCPize: mcpize.com/mcp/code-scanner

Would you consider featuring it in an upcoming issue? Happy to provide a short writeup or answer any questions.

Best,
[Your Name]

---

### Newsletter: Python Weekly

**Subject:** Python-based MCP server for code security scanning

**Body:**

Hi [Name],

I built a code security scanner as an MCP server using Python (FastMCP + pydantic), and I think your Python Weekly readers would find it interesting.

It gives AI coding assistants the ability to scan projects for:
- Hardcoded secrets (24+ patterns including cloud credentials, tokens)
- Vulnerable dependencies (45+ CVEs across Python, JS, Go, Rust, Java)
- Insecure code patterns (SQLi, XSS, command injection, OWASP Top 10)

All scanning is local — no external API calls, no data leaving the machine. This is particularly useful for Python developers using pyproject.toml/Pipfile for dependency auditing and detecting insecure patterns like `eval()`, `os.system()`, `pickle.load()`.

GitHub: github.com/214070779/code-scanner-mcp (MIT, Python)
MCPize: mcpize.com/mcp/code-scanner

Would love for it to be included in Python Weekly!

Best,
[Your Name]

---

### Newsletter: TLDR DevOps

**Subject:** Local-first MCP server for CI/CD security scanning

**Body:**

Hi [Name],

I built a code security scanner that integrates with AI coding assistants via MCP, designed for developers who want to catch security issues before they reach CI/CD pipelines.

It runs locally and detects:
- 24+ secret patterns (cloud credentials, tokens, keys)
- 45+ CVEs across 5 package ecosystems
- 20+ OWASP insecure code patterns

Since it's MCP-based, developers can scan their projects by simply asking their AI assistant — no context switching to a separate tool or dashboard.

GitHub: github.com/214070779/code-scanner-mcp
MCPize: mcpize.com/mcp/code-scanner

Would this be a good fit for your newsletter?

Best,
[Your Name]

---

### Newsletter: This Week in Rust

**Subject:** Rust-compatible MCP server for security scanning

**Body:**

Hi [Name],

I built a code security scanner as an MCP server that supports Rust projects — it can parse `Cargo.toml` for vulnerability checking and detect insecure patterns in `.rs` files.

The tool is local-first (all scanning on-device) and plugs into AI coding assistants. It detects:
- 24+ secret patterns across all languages
- 45+ CVEs (including Rust crates)
- 20+ insecure code patterns

GitHub: github.com/214070779/code-scanner-mcp
MCPize: mcpize.com/mcp/code-scanner

Would your readers find this useful?

Best,
[Your Name]

---

## Dev Tool Podcasts / YouTube Channels

### Pitch Template

**Subject:** Guest/show idea: MCP server for local code security scanning

**Body:**

Hi [Name],

I built an open-source Code Security Scanner as an MCP server that gives AI coding assistants security scanning abilities.

What makes it interesting:
- It's a concrete example of the MCP ecosystem creating real value for developers
- Local-first architecture (no cloud dependency, no data exfiltration)
- Shows how AI tools can go beyond code generation into code quality/security

The tech stack is Python + FastMCP, and it's MIT licensed.

GitHub: github.com/214070779/code-scanner-mcp

I'd be happy to come on the show to discuss:
- The MCP protocol and why it matters for developer tooling
- How to build local-first AI tools
- The state of open-source security tooling in 2026

Would this be a good fit?

Best,
[Your Name]
