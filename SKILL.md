---
name: skill-auditor
description: "Security audit tool for MCP Servers & AI Skills. Detects backdoors, privacy risks, and suspicious code."
author: JaggerHouse
tags: [mcp, security, audit, ai-security, backdoor-detection, privacy]
icon: https://raw.githubusercontent.com/JaggerHouse/skill-auditor/main/assets/icon.png
---

# Skill Auditor

A security audit tool for MCP Servers and AI Skills. Implements the "Skill-First Protocol" to ensure safe usage of third-party AI tools.

## Features

- **Task Decomposition**: Break down user tasks and check local tools
- **Market Search**: Search GitHub and Smithery.ai for existing MCP Servers
- **Security Audit**: 6-point security check (README, backdoors, privacy, license, dependencies, source code)
- **Risk Assessment**: Automated risk level classification (Low/Medium/High)

## Tools

### 1. `audit_skill`
Full Skill-First Protocol pipeline: decompose task, check local tools, search market, audit top 3 skills, output risk report.

### 2. `search_market_skills`
Search GitHub and Smithery.ai for existing MCP Servers/Skills related to a task.

### 3. `audit_skill_code`
Audit a specific Skill/MCP Server source code for security issues (backdoors, privacy risks).

### 4. `check_local_mcp_tools`
Check what MCP tools are currently available locally.

## Installation

```json
{
  "mcpServers": {
    "skill-auditor": {
      "command": "npx",
      "args": ["-y", "skill-auditor"],
      "env": {
        "BRAVE_SEARCH_API_KEY": "your-brave-api-key"
      }
    }
  }
}
```

## Requirements

- Node.js 18+
- BRAVE_SEARCH_API_KEY (optional, for market search)
- GITHUB_TOKEN (optional, for higher API rate limits)

## License

MIT
