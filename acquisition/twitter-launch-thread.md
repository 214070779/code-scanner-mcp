# Twitter/X Launch Thread

---

**Tweet 1 🧵**
I built an open-source MCP server that gives your AI coding assistant the ability to scan code for security vulnerabilities.

It detects:
• Hardcoded secrets (API keys, tokens, passwords)
• Vulnerable dependencies (45+ CVEs)
• Insecure code patterns (SQLi, XSS, injection)

Here's how it works 👇

---

**Tweet 2**
The problem: Every developer has pushed a secret to GitHub at 2 AM. We all do it. Security scanners exist but they're slow, cloud-dependent, and break your flow.

What if your AI assistant could scan for security issues as naturally as it writes code?

---

**Tweet 3**
Code Security Scanner plugs into any MCP-compatible AI client (Claude, Cursor, etc.) and adds 5 tools:

`scan_secrets` → Find hardcoded API keys and tokens
`scan_dependencies` → Check packages against known CVEs
`scan_code_patterns` → Detect SQLi, XSS, injection
`scan_file` → Pre-commit security check
`scan_directory` → Full project audit

---

**Tweet 4**
Real example:

You: "Scan my project for security issues before I commit"
AI: *calls scan_directory()*
Results in seconds:
🔴 Critical: AWS key in .env
🔴 Critical: Stripe secret in config
🟡 Medium: Debug mode enabled in production

All with file paths, line numbers, and fix suggestions.

---

**Tweet 5**
Why local-first matters:
• All scanning runs on your machine
• Zero data leaves your environment
• No signup, no cloud dependency
• Results in seconds, not minutes

Your code never touches a third-party server.

---

**Tweet 6**
What it scans:

🔑 24+ secret patterns (AWS, GitHub, Stripe, Slack, JWT, SSH keys, DB URLs)
📦 45+ CVEs across Python, JS, TS, Go, Rust, Java
🛡️ 20+ OWASP Top 10 patterns (SQLi, XSS, cmd injection, path traversal)

---

**Tweet 7**
Open source (MIT) on GitHub:
github.com/214070779/code-scanner-mcp

Available on MCPize with Free & Pro plans:
mcpize.com/mcp/code-scanner

Also listed on mcp.so, PulseMCP, awesome-mcp-servers.

Built with Python + FastMCP in a weekend. No external API dependencies.

---

**Tweet 8**
Why I built this:

I kept running `grep -r "API_KEY"` before every commit and manually checking `npm audit`. That's ridiculous in 2026.

Your AI assistant should handle this automatically. It already writes your code — it should check it too.

Try it out and let me know what security checks you'd add 👇
