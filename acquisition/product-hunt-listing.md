# Product Hunt Listing — Code Security Scanner (MCP)

## Listing Details

**Product Name:** Code Security Scanner
**Tagline (max 60 chars):** AI-powered code security scanner that finds secrets, CVEs, and insecure code
**Website:** https://mcpize.com/mcp/code-scanner
**Logo:** Use the AI-generated MCPize logo
**Category:** Developer Tools → Security | AI → Developer Tools
**Twitter Handle:** (optional)

---

## Headline Options

**Option A (direct):** Catch security bugs before they ship — right from your AI assistant
**Option B (problem-focused):** Push code with confidence. Real-time security scanning in your dev workflow.
**Option C (benefit-first):** Your AI assistant just got a security brain. No more shipping secrets to GitHub.

---

## Description

### Short Description (max 140 chars)
Scan your local codebase for hardcoded secrets, vulnerable dependencies, and insecure code patterns — all from your AI coding assistant via MCP.

### Long Description

**The Problem**
Every developer has pushed a secret to GitHub at 2 AM. Every team has shipped a dependency with a known CVE. Security scanners exist, but they're slow, cloud-dependent, and break your flow. You have to leave your editor, open a web dashboard, wait for a remote scan, then context-switch back to fix issues.

**The Solution**
Code Security Scanner brings security analysis directly into your AI coding assistant through MCP (Model Context Protocol). Tell your AI "scan this project for security issues" and get instant results with file paths, line numbers, and fix guidance — without leaving your editor.

**What It Scans For**

🔑 **Secrets (24+ patterns):** AWS keys, GitHub tokens, Stripe keys, Slack webhooks, database URLs, JWT secrets, SSH keys, and more

📦 **Dependencies (45+ CVEs):** Checks package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml, pom.xml against a built-in CVE database

🛡️ **Insecure Code (20+ patterns):** SQL injection, XSS, command injection, path traversal, insecure deserialization, hardcoded secrets in code

**5 MCP Tools**

| Tool | What It Does |
|------|-------------|
| `scan_secrets` | Find hardcoded API keys, tokens, passwords across your project |
| `scan_dependencies` | Audit package manifests against known CVEs |
| `scan_code_patterns` | Detect SQLi, XSS, command injection, and other OWASP Top 10 patterns |
| `scan_file` | Full security check on any single file before commit |
| `scan_directory` | Comprehensive project-wide security audit in one command |

**Why It's Different**

- **Local-first:** All scanning happens on your machine. Zero data leaves your environment.
- **AI-native:** No context switching. Your AI assistant calls the tools automatically.
- **Real-time:** Results in seconds, not minutes. Scan on every save if you want.
- **Multi-language:** Python, JavaScript, TypeScript, Go, Rust, Java — all supported out of the box.

**Pricing**
- **Free:** 50 scans/month, 10/min rate limit — enough for personal projects
- **Pro ($29/mo):** Unlimited scans, 60/min rate limit — for teams and daily use
- **Open Source:** MIT license. Self-host for free on GitHub.

---

## First Comment (Pinned)

> Hey Product Hunt! 👋
>
> I built Code Security Scanner because I kept finding myself running `grep -r "API_KEY"` before every commit and manually checking npm audit output. That's insane in 2026.
>
> This MCP server plugs directly into your AI coding assistant (Claude, Cursor, any MCP-compatible client) and gives it 5 security scanning superpowers:
>
> 1. Detect hardcoded secrets (AWS keys, tokens, DB passwords)
> 2. Check dependencies against 45+ real CVEs
> 3. Find SQL injection, XSS, and command injection patterns
> 4. Scan individual files before commit
> 5. Full project audit in one command
>
> **Why "local-first" matters:** It runs entirely on your machine. No data sent to the cloud, no signup required. Your code never leaves your laptop.
>
> **Why "AI-native" matters:** Instead of learning yet another CLI tool, you just ask your AI assistant. "Check this file for secrets." "Are my npm packages safe?" "Scan the whole project."
>
> **Free tier:** 50 scans/month, no credit card needed.
> **Open source:** MIT license on GitHub.
>
> Would love your feedback — what security checks do you wish your AI assistant could run?

---

## Maker Intro

I'm a backend/full-stack developer who got tired of manual security checks. Built this over a few weekends using Python + FastMCP. The goal: make security scanning as natural as asking your AI assistant a question.

---

## Topics/Tags

security, devtools, mcp, ai, opensource, code-scanning, static-analysis, sast
