# 🛡️ Skill Auditor - MCP Server

> **Security Audit Tool for MCP Servers & AI Skills**
>
> Automatically detects backdoors, privacy risks, and suspicious code in third-party MCP Servers before you use them.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)](https://www.typescriptlang.org/)

---

## 📖 Overview

**Skill Auditor** is an MCP (Model Context Protocol) server that implements the **Skill-First Protocol** — a security-first approach to using third-party AI Skills/MCP Servers.

As the MCP ecosystem grows, anyone can publish a "Skill" that runs on your machine. **Skill Auditor** helps you stay safe by automatically auditing any Skill's source code for:

- 🔴 **Backdoors** — unauthorized API calls, data exfiltration, command execution
- 🔴 **Privacy Risks** — scanning `.env`, `.ssh`, credentials, and other sensitive files
- 🟡 **Suspicious Dependencies** — obfuscation packages, crypto miners, stealth tools
- 🟡 **README Red Flags** — claims of data collection, remote access, phone-home
- 🟢 **License Compliance** — open-source license verification

---

## ✨ Features

### 4 Powerful Tools

| Tool | Description |
|------|-------------|
| **`audit_skill`** | 🚀 **Full Pipeline** — Task decomposition → Local tool check → Market search → Security audit → Risk report |
| **`search_market_skills`** | 🔍 **Market Search** — Search GitHub for existing MCP Servers/Skills related to your task |
| **`audit_skill_code`** | 🔒 **Deep Audit** — 6-point security audit of any GitHub repository |
| **`check_local_mcp_tools`** | 📋 **Local Check** — Verify which MCP tools are available locally |

### Security Checks (6-Point Audit)

1. **README Analysis** — Detects suspicious claims (data collection, remote access, phone-home)
2. **Source Code Access** — Verifies source files are readable and analyzable
3. **Backdoor Detection** — 13 pattern categories including:
   - External API calls to unknown endpoints
   - System command execution (`child_process`, `exec`, `spawn`)
   - Dynamic code execution (`eval`, `Function()`)
   - WebSocket connections, Beacon API, pixel tracking
   - Base64 encoding/decoding (potential obfuscation)
4. **Privacy Risk Detection** — 15 pattern categories including:
   - `.env` file access (API keys, secrets)
   - SSH key access (`id_rsa`, `known_hosts`, `authorized_keys`)
   - Credential and secret file access
   - System file access (`passwd`, `shadow`)
5. **License Check** — Verifies open-source license presence
6. **Dependency Analysis** — Detects suspicious packages (obfuscation, crypto mining, stealth)

### Risk Levels

| Level | Meaning |
|-------|---------|
| 🟢 **Low** | No significant security issues — safe to use |
| 🟡 **Medium** | Some concerns found — review before use |
| 🔴 **High** | Backdoors or privacy risks detected — DO NOT use |
| ⚫ **Unknown** | Could not access repository for analysis |

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18 or later
- **npm** or **yarn**

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/skill-auditor.git
cd skill-auditor

# Install dependencies
npm install

# Build the project
npm run build

# Start the server
npm start
```

### MCP Configuration

Add to your `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "skill-auditor": {
      "command": "node",
      "args": ["/path/to/skill-auditor/build/index.js"],
      "env": {
        "BRAVE_SEARCH_API_KEY": "your_brave_api_key_here"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

> **Note:** `BRAVE_SEARCH_API_KEY` is optional. Without it, market search features will be unavailable, but code audit features still work.

### Get a Brave Search API Key

1. Visit [Brave Search API](https://brave.com/search/api/)
2. Sign up for a **Free Plan** (2,000 queries/month)
3. Copy your API key (format: `BS-xxxxxxxxxxxxxxxxxxxxxxxx`)

---

## 🎯 Usage Examples

### Example 1: Full Audit Pipeline

When you receive a task, Skill Auditor runs the complete SOP:

```
Task: "Monitor Twitter for keyword AI"
```

**What happens:**
1. ✅ Task decomposed into keywords: `["monitor", "twitter", "keyword", "ai"]`
2. ✅ Local MCP tools checked
3. ✅ GitHub searched for existing Twitter monitoring Skills
4. ✅ Top 3 Skills audited for security
5. ✅ Risk report generated with recommendations

### Example 2: Audit a Specific Skill

```json
{
  "name": "audit_skill_code",
  "arguments": {
    "repoName": "owner/repository-name"
  }
}
```

**Sample output:**
```
╔════════════════════════════════════════════╗
║  SECURITY AUDIT REPORT: owner/repo         ║
╚════════════════════════════════════════════╝

📊 Overall Risk Level: 🟢 LOW

🔍 Security Checks:
✅ README Analysis: No suspicious claims found
✅ Source Code Access: Analyzed 8 source files
✅ Backdoor Detection: No backdoor patterns detected
✅ Privacy Risk Detection: No privacy risks detected
✅ License Check: License file found
✅ Dependency Analysis: 12 dependencies checked, no suspicious packages

📋 Summary: 🟢 LOW RISK: No significant security issues detected. Safe to use.
```

### Example 3: Search Market Skills

```json
{
  "name": "search_market_skills",
  "arguments": {
    "keywords": ["twitter", "monitor", "mcp server"],
    "maxResults": 5
  }
}
```

---

## 🏗️ Architecture

```
skill-auditor/
├── src/
│   └── index.ts          # Main server implementation
├── build/
│   └── index.js          # Compiled output
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── LICENSE               # MIT License
└── README.md             # This file
```

### Technology Stack

- **Runtime:** Node.js
- **Language:** TypeScript (ES2022)
- **Framework:** [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk)
- **HTTP Client:** [axios](https://axios-http.com/)
- **API:** GitHub REST API v3

---

## 🔒 Security & Privacy

**Skill Auditor itself is designed with security in mind:**

- ✅ **No data collection** — Does not collect, store, or transmit any user data
- ✅ **No telemetry** — No phone-home functionality
- ✅ **Read-only** — Only reads public GitHub repository data
- ✅ **Minimal dependencies** — Only 2 runtime dependencies (SDK + axios)
- ✅ **Open source** — MIT licensed, fully auditable code
- ✅ **No local file access** — Does not read your `.env`, `.ssh`, or any local files

---

## ⚠️ Limitations

- **GitHub API Rate Limit:** Unauthenticated requests are limited to 60/hour. For production use, consider adding a GitHub token.
- **Brave Search API:** Required for market search features (free tier: 2,000 queries/month)
- **Top-level files only:** Currently audits files at the repository root level (not recursive directory traversal)
- **Pattern-based detection:** May produce false positives — always review flagged items manually

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report bugs** — Open an issue with reproduction steps
2. **Suggest features** — Open an issue with your idea
3. **Submit PRs** — Fork the repo and submit a pull request
4. **Improve patterns** — Add new backdoor/privacy detection patterns

### Development

```bash
# Clone and install
git clone https://github.com/your-username/skill-auditor.git
cd skill-auditor
npm install

# Development with auto-rebuild
npm run build -- --watch

# Run tests (when available)
npm test
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io) — The MCP specification
- [Brave Search API](https://brave.com/search/api/) — Web search capabilities
- [GitHub API](https://docs.github.com/en/rest) — Repository data access

---

## 📬 Support

- **Issues:** [GitHub Issues](https://github.com/your-username/skill-auditor/issues)
- **Discussions:** [GitHub Discussions](https://github.com/your-username/skill-auditor/discussions)

---

<p align="center">
  <strong>Stay safe in the MCP ecosystem. Audit before you trust. 🛡️</strong>
</p>
