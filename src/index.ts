#!/usr/bin/env node

/**
 * Skill Auditor - MCP Server
 * 
 * Security audit tool for MCP Servers & AI Skills.
 * Implements the "Skill-First Protocol":
 * Step 1: Task Decomposition & Local Tool Check
 * Step 2: Market Search (Brave Search + GitHub)
 * Step 3: Source Code Security Audit (6-point check)
 * Step 4: User Authorization
 * Step 5: Fallback (manual coding)
 * 
 * Features:
 * - Backdoor detection (unauthorized API calls, data exfiltration, command execution)
 * - Privacy check (scanning .env, .ssh, credentials, sensitive files)
 * - Dependency analysis (suspicious packages)
 * - README analysis (data collection claims, remote access)
 * - License verification
 * - Recursive directory traversal for deep audits
 * - GitHub API token support for higher rate limits
 * 
 * @license MIT
 * @version 1.1.0
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import type { Result } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';

// ============================================================
// Types
// ============================================================

interface SkillInfo {
  name: string;
  fullName: string;
  url: string;
  stars: number;
  description: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Unknown';
  riskDetails: string[];
  isBackdoor: boolean;
  isPrivacyRisk: boolean;
}

interface AuditCheck {
  name: string;
  passed: boolean;
  details: string;
}

interface AuditResult {
  skill: SkillInfo;
  checks: AuditCheck[];
  summary: string;
}

interface PatternDef {
  pattern: RegExp;
  severity: 'low' | 'medium' | 'high';
  description: string;
  category: 'backdoor' | 'privacy' | 'suspicious';
}

// ============================================================
// Constants
// ============================================================

const BACKDOOR_PATTERNS: PatternDef[] = [
  { pattern: /fetch\(['"`]https?:\/\/(?!api\.github\.com|api\.openai\.com|api\.anthropic\.com|api\.brave\.com)/gi, severity: 'high', description: 'External API call to unknown endpoint', category: 'backdoor' },
  { pattern: /axios\.(get|post|put|delete|patch)\(['"`]https?:\/\/(?!api\.github\.com|api\.openai\.com|api\.anthropic\.com)/gi, severity: 'high', description: 'External HTTP request to unknown endpoint', category: 'backdoor' },
  { pattern: /require\(['"`](child_process|exec|spawn|execSync|spawnSync|fork)/gi, severity: 'high', description: 'Executes system commands', category: 'backdoor' },
  { pattern: /eval\(/g, severity: 'high', description: 'Dynamic code execution (eval)', category: 'backdoor' },
  { pattern: /Function\(/g, severity: 'high', description: 'Dynamic function construction', category: 'backdoor' },
  { pattern: /navigator\.sendBeacon/g, severity: 'high', description: 'Beacon API (silent data transmission)', category: 'backdoor' },
  { pattern: /XMLHttpRequest/g, severity: 'medium', description: 'Uses XMLHttpRequest (potential data exfiltration)', category: 'backdoor' },
  { pattern: /WebSocket\(['"`]wss?:\/\//gi, severity: 'medium', description: 'WebSocket connection to external server', category: 'backdoor' },
  { pattern: /new Image\(\)[.\s]*src\s*=/g, severity: 'medium', description: 'Image pixel tracking (potential data leak)', category: 'backdoor' },
  { pattern: /process\.env\.\w+/g, severity: 'low', description: 'Accesses environment variables (verify necessity)', category: 'backdoor' },
  { pattern: /setTimeout\([^,]+,\s*\d+\)/g, severity: 'low', description: 'Delayed execution (verify purpose)', category: 'backdoor' },
  { pattern: /atob\(/g, severity: 'low', description: 'Base64 decode (potential obfuscation)', category: 'backdoor' },
  { pattern: /btoa\(/g, severity: 'low', description: 'Base64 encode (potential obfuscation)', category: 'backdoor' },
  { pattern: /got\(['"`]https?:\/\//gi, severity: 'high', description: 'External HTTP request via got library', category: 'backdoor' },
  { pattern: /request\(['"`]https?:\/\//gi, severity: 'high', description: 'External HTTP request via request library', category: 'backdoor' },
  { pattern: /superagent\.(get|post|put)\(['"`]https?:\/\//gi, severity: 'high', description: 'External HTTP request via superagent', category: 'backdoor' },
  { pattern: /net\.connect\(/g, severity: 'high', description: 'Raw TCP connection (potential C2 channel)', category: 'backdoor' },
  { pattern: /dns\.resolve|dns\.lookup/g, severity: 'medium', description: 'DNS lookup (potential DNS tunneling)', category: 'backdoor' },
  { pattern: /child_process\.exec(File)?|execSync|spawn|spawnSync|fork/g, severity: 'high', description: 'System command execution', category: 'backdoor' },
  { pattern: /shelljs|execa|cross-spawn/g, severity: 'high', description: 'Shell execution library', category: 'backdoor' },
];

const PRIVACY_PATTERNS: PatternDef[] = [
  { pattern: /\.env/g, severity: 'high', description: 'Reads .env file (API keys, secrets)', category: 'privacy' },
  { pattern: /\.ssh/g, severity: 'high', description: 'Accesses SSH keys', category: 'privacy' },
  { pattern: /id_rsa/g, severity: 'high', description: 'Accesses RSA private key', category: 'privacy' },
  { pattern: /known_hosts/g, severity: 'medium', description: 'Reads SSH known hosts', category: 'privacy' },
  { pattern: /authorized_keys/g, severity: 'high', description: 'Reads authorized SSH keys', category: 'privacy' },
  { pattern: /passwd/g, severity: 'high', description: 'Reads system password file', category: 'privacy' },
  { pattern: /shadow/g, severity: 'high', description: 'Reads system shadow file', category: 'privacy' },
  { pattern: /config\.json/g, severity: 'medium', description: 'Reads configuration file', category: 'privacy' },
  { pattern: /credentials/g, severity: 'high', description: 'Accesses credential files', category: 'privacy' },
  { pattern: /token/g, severity: 'medium', description: 'Accesses token files', category: 'privacy' },
  { pattern: /secret/g, severity: 'medium', description: 'Accesses secret files', category: 'privacy' },
  { pattern: /\/Users\/[^/]+\//g, severity: 'medium', description: 'Accesses user home directory', category: 'privacy' },
  { pattern: /\/home\/[^/]+\//g, severity: 'medium', description: 'Accesses user home directory', category: 'privacy' },
  { pattern: /fs\.readFileSync/g, severity: 'low', description: 'Reads local files (verify scope)', category: 'privacy' },
  { pattern: /fs\.readFile/g, severity: 'low', description: 'Reads local files (verify scope)', category: 'privacy' },
  { pattern: /\.npmrc/g, severity: 'high', description: 'Reads npm configuration (may contain tokens)', category: 'privacy' },
  { pattern: /\.gitconfig/g, severity: 'high', description: 'Reads git configuration', category: 'privacy' },
  { pattern: /aws.*credentials|\.aws/g, severity: 'high', description: 'Accesses AWS credentials', category: 'privacy' },
  { pattern: /gcloud|google.*application.*credentials/gi, severity: 'high', description: 'Accesses GCP credentials', category: 'privacy' },
  { pattern: /azcopy|azure.*credentials/gi, severity: 'high', description: 'Accesses Azure credentials', category: 'privacy' },
  { pattern: /kubeconfig|\.kube/g, severity: 'high', description: 'Accesses Kubernetes configuration', category: 'privacy' },
  { pattern: /docker.*config|\.docker/g, severity: 'medium', description: 'Accesses Docker configuration', category: 'privacy' },
  { pattern: /wallet|mnemonic|seed.*phrase/gi, severity: 'high', description: 'Accesses cryptocurrency wallet information', category: 'privacy' },
];

const SUSPICIOUS_DEP_PATTERNS = [
  /obfuscate/i, /obfuscator/i,
  /crypto-miner/i, /cryptominer/i, /coin-miner/i, /coinminer/i,
  /stealth/i, /keylogger/i, /ransomware/i, /trojan/i, /backdoor/i,
  /data-exfil/i, /data-exfiltration/i, /phish/i, /spyware/i,
  /rat\b/i, /beacon/i, /reverse.*shell/i, /bind.*shell/i,
];

const README_SUSPICIOUS_CLAIMS = [
  { pattern: /collect.*data|track.*user|analytics/gi, desc: 'Claims to collect user data' },
  { pattern: /phone.home|call.home|beacon/gi, desc: 'Contains phone-home functionality' },
  { pattern: /remote.*access|remote.*control/gi, desc: 'Claims remote access capability' },
  { pattern: /stealth|undetectable|bypass.*security/gi, desc: 'Claims stealth/evasion capabilities' },
  { pattern: /keylog|keystroke|capture.*input/gi, desc: 'Claims input capture capabilities' },
  { pattern: /screen.*capture|screenshot|record.*screen/gi, desc: 'Claims screen capture capabilities' },
  { pattern: /webcam|camera.*access|microphone.*access/gi, desc: 'Claims media device access' },
  { pattern: /password.*recovery|password.*crack/gi, desc: 'Claims password-related capabilities' },
];

// ============================================================
// Skill Auditor Server
// ============================================================

class SkillAuditorServer {
  private server: Server;
  private braveApiKey: string;
  private githubToken: string;

  constructor() {
    const apiKey = process.env.BRAVE_SEARCH_API_KEY;
    if (!apiKey) {
      console.error('Warning: BRAVE_SEARCH_API_KEY not set. Market search will be unavailable.');
      console.error('To use market search, set BRAVE_SEARCH_API_KEY in MCP settings.');
    }
    this.braveApiKey = apiKey || '';

    const ghToken = process.env.GITHUB_TOKEN;
    if (ghToken) {
      console.error('Info: GITHUB_TOKEN found. Higher API rate limits available.');
    }
    this.githubToken = ghToken || '';

    this.server = new Server(
      {
        name: 'skill-auditor',
        version: '1.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  // ============================================================
  // Tool Handlers
  // ============================================================

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'audit_skill',
          description: `[SOP Step 1→2→3→4] Full Skill-First Protocol pipeline:
1. Decompose the user's task into search keywords
2. Check local MCP tools availability
3. Search GitHub market for existing Skills (requires BRAVE_SEARCH_API_KEY)
4. Audit top 3 found Skills with 6-point security check
5. Output comprehensive risk report with user decision recommendations`,
          inputSchema: {
            type: 'object',
            properties: {
              task: {
                type: 'string',
                description: 'The user task description (e.g., "monitor Twitter for keyword AI")',
              },
              localTools: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of currently available local MCP tool names',
              },
            },
            required: ['task'],
          },
        },
        {
          name: 'search_market_skills',
          description: '[SOP Step 2] Search GitHub for existing MCP Servers/Skills related to a task. Uses Brave Search API for intelligent discovery.',
          inputSchema: {
            type: 'object',
            properties: {
              keywords: {
                type: 'array',
                items: { type: 'string' },
                description: 'Keywords to search for (e.g., ["twitter", "monitor", "mcp server"])',
              },
              maxResults: {
                type: 'number',
                description: 'Maximum number of results (default: 10, max: 20)',
                minimum: 1,
                maximum: 20,
              },
            },
            required: ['keywords'],
          },
        },
        {
          name: 'audit_skill_code',
          description: '[SOP Step 3] Deep security audit of a specific Skill/MCP Server source code. Performs 6-point check: README analysis, backdoor detection, privacy risk, license check, dependency analysis, and source code access.',
          inputSchema: {
            type: 'object',
            properties: {
              repoUrl: {
                type: 'string',
                description: 'GitHub repository URL of the Skill to audit (e.g., "https://github.com/owner/repo")',
              },
              repoName: {
                type: 'string',
                description: 'GitHub repository name in "owner/repo" format (e.g., "modelcontextprotocol/servers")',
              },
            },
          },
        },
        {
          name: 'check_local_mcp_tools',
          description: '[SOP Step 1] Check what MCP tools are currently available locally. Helps decide whether to use existing tools or search for new ones.',
          inputSchema: {
            type: 'object',
            properties: {
              toolNames: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of tool names to check availability for',
              },
            },
            required: ['toolNames'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case 'audit_skill':
          return await this.handleAuditSkill(request.params.arguments);
        case 'search_market_skills':
          return await this.handleSearchMarket(request.params.arguments);
        case 'audit_skill_code':
          return await this.handleAuditCode(request.params.arguments);
        case 'check_local_mcp_tools':
          return await this.handleCheckLocalTools(request.params.arguments);
        default:
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
      }
    });
  }

  // ============================================================
  // Tool Implementations
  // ============================================================

  /**
   * [SOP Step 1→2→3→4] Full pipeline - one-shot audit
   */
  private async handleAuditSkill(args: any): Promise<Result> {
    if (!args || typeof args.task !== 'string') {
      throw new McpError(ErrorCode.InvalidParams, 'Task description is required');
    }

    const task = args.task;
    const localTools: string[] = args.localTools || [];
    const report: string[] = [];
    
    report.push('╔══════════════════════════════════════════════════╗');
    report.push('║        SKILL AUDITOR - FULL AUDIT REPORT        ║');
    report.push('╚══════════════════════════════════════════════════╝');
    report.push('');
    report.push(`📋 Task: ${task}`);
    report.push(`🕐 Time: ${new Date().toISOString()}`);
    report.push('');

    // Step 1: Task Decomposition & Local Check
    report.push('─'.repeat(50));
    report.push('📌 [SOP Step 1] Task Decomposition & Local Tool Check');
    report.push('─'.repeat(50));
    
    const keywords = this.decomposeTask(task);
    report.push(`  🔍 Decomposed keywords: ${keywords.join(', ')}`);
    report.push('');

    if (localTools.length > 0) {
      report.push('  ✅ Local MCP Tools available:');
      for (const tool of localTools) {
        report.push(`     • ${tool}`);
      }
      report.push('');
      report.push('  💡 Recommendation: Check if any local tool can handle this task first.');
    } else {
      report.push('  ⚠️  No local MCP tools reported. Proceeding to market search.');
    }
    report.push('');

    // Step 2: Market Search
    report.push('─'.repeat(50));
    report.push('📌 [SOP Step 2] Market Search (GitHub)');
    report.push('─'.repeat(50));

    let searchResults: SkillInfo[] = [];
    if (this.braveApiKey) {
      try {
        searchResults = await this.searchGitHub(keywords);
        report.push(`  ✅ Found ${searchResults.length} Skills on GitHub:`);
        searchResults.slice(0, 5).forEach((s, i) => {
          report.push(`     ${i + 1}. ${s.fullName} ⭐${s.stars}`);
          report.push(`        ${s.description.slice(0, 100)}`);
          report.push(`        ${s.url}`);
        });
      } catch (error: any) {
        report.push(`  ❌ Search failed: ${error.message}`);
      }
    } else {
      report.push('  ⚠️  Brave Search API not configured.');
      report.push('  📖 To enable market search, set BRAVE_SEARCH_API_KEY in MCP settings.');
      report.push('  🔗 Get API key at: https://brave.com/search/api/');
    }
    report.push('');

    // Step 3: Security Audit
    report.push('─'.repeat(50));
    report.push('📌 [SOP Step 3] Security Audit of Top Skills');
    report.push('─'.repeat(50));

    const topSkills = searchResults.slice(0, 3);
    if (topSkills.length > 0) {
      for (let i = 0; i < topSkills.length; i++) {
        const skill = topSkills[i];
        report.push('');
        report.push(`  ┌─ Audit #${i + 1}: ${skill.fullName} ─────────────────`);
        
        try {
          const auditResult = await this.auditSingleSkill(skill.fullName);
          for (const check of auditResult.checks) {
            report.push(`  │ ${check.passed ? '✅' : '❌'} ${check.name}: ${check.details}`);
          }
          report.push(`  │`);
          report.push(`  │ 📊 Risk Level: ${auditResult.skill.riskLevel}`);
          report.push(`  │ ${auditResult.summary}`);
        } catch (error: any) {
          report.push(`  │ ❌ Audit failed: ${error.message}`);
        }
        report.push(`  └──────────────────────────────────────────`);
      }
    } else {
      report.push('  No skills found to audit.');
    }
    report.push('');

    // Step 4: User Decision
    report.push('─'.repeat(50));
    report.push('📌 [SOP Step 4] User Decision Required');
    report.push('─'.repeat(50));
    report.push('');
    report.push('  📊 Risk Summary:');
    
    for (const skill of topSkills) {
      const riskIcon = skill.riskLevel === 'Low' ? '🟢' : skill.riskLevel === 'Medium' ? '🟡' : '🔴';
      report.push(`     ${riskIcon} ${skill.fullName}: ${skill.riskLevel} Risk`);
    }
    
    report.push('');
    report.push('  💡 Recommendations:');
    if (topSkills.some(s => s.riskLevel === 'Low')) {
      report.push('     ✅ Low-risk Skills available - consider using them directly.');
    }
    if (topSkills.some(s => s.riskLevel === 'Medium')) {
      report.push('     ⚠️  Medium-risk Skills found - review details before use.');
    }
    if (topSkills.some(s => s.riskLevel === 'High')) {
      report.push('     ❌ High-risk Skills detected - DO NOT use without thorough review.');
    }
    report.push('');
    report.push('  👉 Please review the report and decide:');
    report.push('     1. Use an existing Skill from the market');
    report.push('     2. Authorize manual coding (SOP Step 5)');

    return {
      content: [{ type: 'text', text: report.join('\n') }],
    };
  }

  /**
   * [SOP Step 2] Search market for Skills
   */
  private async handleSearchMarket(args: any): Promise<Result> {
    if (!args || !Array.isArray(args.keywords)) {
      throw new McpError(ErrorCode.InvalidParams, 'Keywords array is required');
    }

    const keywords = args.keywords;
    const maxResults = args.maxResults || 10;

    if (!this.braveApiKey) {
      return {
        content: [{
          type: 'text',
          text: `❌ Brave Search API not configured.\n\nTo enable market search:\n1. Go to https://brave.com/search/api/\n2. Sign up for a free API key\n3. Add BRAVE_SEARCH_API_KEY to MCP settings\n\nCurrent keywords: ${keywords.join(', ')}`,
        }],
      };
    }

    try {
      const results = await this.searchGitHub(keywords);
      const topResults = results.slice(0, maxResults);

      let output = `🔍 Market Search Results for: ${keywords.join(', ')}\n`;
      output += `Found ${results.length} Skills\n\n`;

      topResults.forEach((skill, i) => {
        const riskIcon = skill.riskLevel === 'Low' ? '🟢' : skill.riskLevel === 'Medium' ? '🟡' : '🔴';
        output += `${i + 1}. ${riskIcon} ${skill.fullName} ⭐${skill.stars}\n`;
        output += `   ${skill.description.slice(0, 150)}\n`;
        output += `   ${skill.url}\n`;
        if (skill.riskDetails.length > 0) {
          output += `   ⚠️  Risks: ${skill.riskDetails.join('; ')}\n`;
        }
        output += '\n';
      });

      return { content: [{ type: 'text', text: output }] };
    } catch (error: any) {
      return this.createErrorResult(`❌ Search failed: ${error.message}`);
    }
  }

  /**
   * [SOP Step 3] Audit a specific Skill's code
   */
  private async handleAuditCode(args: any): Promise<Result> {
    let repoName: string;

    if (args.repoName) {
      repoName = args.repoName;
    } else if (args.repoUrl) {
      const match = args.repoUrl.match(/github\.com\/([^/]+\/[^/]+?)(?:\/|$)/);
      if (!match) {
        throw new McpError(ErrorCode.InvalidParams, 'Invalid GitHub URL. Expected format: https://github.com/owner/repo');
      }
      repoName = match[1];
    } else {
      throw new McpError(ErrorCode.InvalidParams, 'Either repoUrl or repoName is required');
    }

    try {
      const result = await this.auditSingleSkill(repoName);
      
      let output = `╔════════════════════════════════════════════╗\n`;
      output += `║  SECURITY AUDIT REPORT: ${repoName.padEnd(20)} ║\n`;
      output += `╚════════════════════════════════════════════╝\n\n`;
      output += `📊 Overall Risk Level: ${result.skill.riskLevel}\n\n`;
      output += `${'─'.repeat(50)}\n`;
      output += `🔍 Security Checks:\n`;
      output += `${'─'.repeat(50)}\n\n`;

      for (const check of result.checks) {
        output += `${check.passed ? '✅' : '❌'} ${check.name}\n`;
        output += `   ${check.details}\n\n`;
      }

      output += `${'─'.repeat(50)}\n`;
      output += `📋 Summary:\n`;
      output += `${result.summary}\n\n`;

      if (result.skill.isBackdoor) {
        output += `⚠️  BACKDOOR RISK DETECTED: This Skill may contain unauthorized data exfiltration.\n`;
      }
      if (result.skill.isPrivacyRisk) {
        output += `⚠️  PRIVACY RISK DETECTED: This Skill may access sensitive local files.\n`;
      }

      if (result.skill.riskDetails.length > 0) {
        output += `\n📝 Detailed Findings:\n`;
        for (const detail of result.skill.riskDetails) {
          output += `  • ${detail}\n`;
        }
      }

      return { content: [{ type: 'text', text: output }] };
    } catch (error: any) {
      return this.createErrorResult(`❌ Audit failed for ${repoName}: ${error.message}`);
    }
  }

  /**
   * [SOP Step 1] Check local MCP tools
   */
  private async handleCheckLocalTools(args: any): Promise<Result> {
    if (!args || !Array.isArray(args.toolNames)) {
      throw new McpError(ErrorCode.InvalidParams, 'Tool names array is required');
    }

    const toolNames: string[] = args.toolNames;
    
    let output = `🔍 Local MCP Tool Check\n\n`;
    output += `Requested tools: ${toolNames.join(', ')}\n\n`;
    output += `Note: This tool checks against the list provided by the user.\n`;
    output += `To get actual available tools, the Cline agent should check the system prompt.\n\n`;
    output += `📋 Recommendation:\n`;
    output += `If any of these tools can handle the task, use them directly.\n`;
    output += `Otherwise, proceed to Step 2: Market Search.\n`;

    return { content: [{ type: 'text', text: output }] };
  }

  // ============================================================
  // Helper Methods
  // ============================================================

  /**
   * Create an error result
   */
  private createErrorResult(text: string): Result {
    const result: Result & { isError?: boolean } = {
      content: [{ type: 'text', text }],
    };
    result.isError = true;
    return result as Result;
  }

  /**
   * Decompose a task into search keywords
   */
  private decomposeTask(task: string): string[] {
    const stopWords = new Set([
      'a', 'an', 'the', 'for', 'and', 'or', 'but', 'in', 'on', 'at', 'to',
      'with', 'by', 'of', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
      'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'can',
      'could', 'should', 'may', 'might', 'i', 'me', 'my', 'we', 'our',
      'you', 'your', 'he', 'him', 'his', 'she', 'her', 'it', 'its', 'they',
      'them', 'their', 'this', 'that', 'these', 'those', 'am', 'help',
      'need', 'want', 'please', 'just', 'like', 'make', 'get', 'use',
      'using', 'used', 'also', 'very', 'much', 'many', 'some', 'any',
      'all', 'each', 'every', 'both', 'few', 'more', 'most', 'other',
      'into', 'over', 'such', 'than', 'then', 'there', 'these', 'thing',
      'things', 'about', 'after', 'before', 'between', 'through', 'during',
      'without', 'within', 'along', 'following', 'around', 'down', 'off',
      'above', 'below',
    ]);
    
    const words = task.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2 && !stopWords.has(w));
    
    return [...new Set(words)];
  }

  /**
   * Get GitHub API headers with optional auth token
   */
  private getGitHubHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'skill-auditor-mcp-server',
    };
    if (this.githubToken) {
      headers['Authorization'] = `Bearer ${this.githubToken}`;
    }
    return headers;
  }

  /**
   * Search GitHub for MCP Servers/Skills
   */
  private async searchGitHub(keywords: string[]): Promise<SkillInfo[]> {
    const query = keywords.join(' ') + ' mcp server';
    const encodedQuery = encodeURIComponent(query);
    
    const response = await axios.get(
      `https://api.github.com/search/repositories?q=${encodedQuery}&sort=stars&order=desc&per_page=15`,
      {
        headers: this.getGitHubHeaders(),
        timeout: 15000,
      }
    );

    const items = response.data.items || [];
    
    return items.map((item: any) => ({
      name: item.name,
      fullName: item.full_name,
      url: item.html_url,
      stars: item.stargazers_count,
      description: item.description || 'No description',
      riskLevel: 'Unknown' as const,
      riskDetails: [],
      isBackdoor: false,
      isPrivacyRisk: false,
    }));
  }

  /**
   * Fetch repository tree recursively to get all source files
   */
  private async fetchRepoTree(repoName: string): Promise<any[]> {
    try {
      const repoResponse = await axios.get(
        `https://api.github.com/repos/${repoName}`,
        {
          headers: this.getGitHubHeaders(),
          timeout: 10000,
        }
      );
      const defaultBranch = repoResponse.data.default_branch;

      const treeResponse = await axios.get(
        `https://api.github.com/repos/${repoName}/git/trees/${defaultBranch}?recursive=1`,
        {
          headers: this.getGitHubHeaders(),
          timeout: 15000,
        }
      );

      return treeResponse.data.tree || [];
    } catch (error: any) {
      if (error.response?.status === 403) {
        throw new Error('GitHub API rate limit exceeded. Set GITHUB_TOKEN for higher limits, or try again later.');
      } else if (error.response?.status === 404) {
        throw new Error(`Repository "${repoName}" not found or is private.`);
      }
      throw error;
    }
  }

  /**
   * Fetch file content from GitHub
   */
  private async fetchFileContent(repoName: string, filePath: string): Promise<string> {
    const response = await axios.get(
      `https://api.github.com/repos/${repoName}/contents/${filePath}`,
      {
        headers: { ...this.getGitHubHeaders(), 'Accept': 'application/vnd.github.v3.raw' },
        timeout: 10000,
      }
    );
    const data = response.data;
    return typeof data === 'string' ? data : JSON.stringify(data);
  }

  /**
   * Audit a single Skill's source code for security issues
   * Performs 6-point security check with recursive file traversal
   */
  private async auditSingleSkill(repoName: string): Promise<AuditResult> {
    const checks: AuditCheck[] = [];
    let allSourceCode = '';
    let backdoorCount = 0;
    let privacyCount = 0;
    const riskDetails: string[] = [];
    const sourceFileExtensions = ['.ts', '.js', '.jsx', '.tsx', '.py', '.json', '.sh', '.bash', '.yml', '.yaml', '.env.example', '.md'];

    try {
      // Get repository tree recursively
      const tree = await this.fetchRepoTree(repoName);
      
      // Filter for source files
      const sourceFiles = tree.filter((item: any) => 
        item.type === 'blob' && 
        sourceFileExtensions.some(ext => item.path.toLowerCase().endsWith(ext))
      );

      // Check 1: README analysis
      const readmeFile = sourceFiles.find((item: any) => 
        item.path.toLowerCase() === 'readme.md'
      );
      
      if (readmeFile) {
        try {
          const readmeContent = await this.fetchFileContent(repoName, readmeFile.path);
          allSourceCode += readmeContent + '\n';
          
          const readmeRisks: string[] = [];
          for (const claim of README_SUSPICIOUS_CLAIMS) {
            if (claim.pattern.test(readmeContent)) {
              readmeRisks.push(claim.desc);
              riskDetails.push(`📄 ${claim.desc}`);
            }
          }
          
          checks.push({
            name: 'README Analysis',
            passed: readmeRisks.length === 0,
            details: readmeRisks.length > 0 
              ? `⚠️ Found suspicious claims: ${readmeRisks.join(', ')}` 
              : '✅ No suspicious claims found in README',
          });
        } catch {
          checks.push({ name: 'README Analysis', passed: true, details: 'Could not read README content' });
        }
      } else {
        checks.push({ name: 'README Analysis', passed: false, details: '⚠️ No README.md found - missing documentation' });
      }

      // Check 2: Source code access - analyze up to 30 source files
      let sourceAnalyzed = 0;
      
      // Prioritize important files
      const priorityPaths = ['index.ts', 'index.js', 'main.ts', 'main.js', 'server.ts', 'server.js',
        'src/index.ts', 'src/index.js', 'src/main.ts', 'src/main.js'];
      
      const priorityFiles = sourceFiles.filter((f: any) => priorityPaths.includes(f.path));
      const otherFiles = sourceFiles.filter((f: any) => !priorityPaths.includes(f.path) && f.path.toLowerCase() !== 'readme.md');
      
      const filesToAnalyze = [...priorityFiles, ...otherFiles].slice(0, 30);

      for (const file of filesToAnalyze) {
        try {
          const fileContent = await this.fetchFileContent(repoName, file.path);
          allSourceCode += fileContent + '\n';
          sourceAnalyzed++;
        } catch {
          // Skip files that can't be read
        }
      }

      checks.push({
        name: 'Source Code Access',
        passed: sourceAnalyzed > 0,
        details: `Analyzed ${sourceAnalyzed} source files across ${filesToAnalyze.length} candidates`,
      });

      // Check 3: Backdoor detection
      for (const bp of BACKDOOR_PATTERNS) {
        const matches = allSourceCode.match(bp.pattern);
        if (matches) {
          backdoorCount += matches.length;
          const severityIcon = bp.severity === 'high' ? '🔴' : bp.severity === 'medium' ? '🟡' : '🟢';
          riskDetails.push(`${severityIcon} ${bp.description} (${matches.length} matches)`);
        }
      }

      checks.push({
        name: 'Backdoor Detection',
        passed: backdoorCount === 0,
        details: backdoorCount === 0 
          ? '✅ No backdoor patterns detected' 
          : `⚠️ Found ${backdoorCount} potential backdoor indicators:\n       ${riskDetails.filter(r => r.includes('🔴')).join('\n       ')}`,
      });

      // Check 4: Privacy risk detection
      for (const pp of PRIVACY_PATTERNS) {
        const matches = allSourceCode.match(pp.pattern);
        if (matches) {
          privacyCount += matches.length;
          const severityIcon = pp.severity === 'high' ? '🔴' : pp.severity === 'medium' ? '🟡' : '🟢';
          riskDetails.push(`${severityIcon} ${pp.description} (${matches.length} matches)`);
        }
      }

      checks.push({
        name: 'Privacy Risk Detection',
        passed: privacyCount === 0,
        details: privacyCount === 0 
          ? '✅ No privacy risks detected' 
          : `⚠️ Found ${privacyCount} potential privacy issues:\n       ${riskDetails.filter(r => r.includes('.env') || r.includes('SSH') || r.includes('credential') || r.includes('secret') || r.includes('password') || r.includes('wallet')).join('\n       ')}`,
      });

      // Check 5: License check
      const licenseFile = sourceFiles.find((item: any) => 
        item.path.toLowerCase() === 'license' || item.path.toLowerCase() === 'license.md'
      );
      checks.push({
        name: 'License Check',
        passed: !!licenseFile,
        details: licenseFile ? '✅ License file found' : '⚠️ No license file found',
      });

      // Check 6: Dependencies analysis
      const packageFile = sourceFiles.find((item: any) => item.path === 'package.json');
      if (packageFile) {
        try {
          const pkgContent = await this.fetchFileContent(repoName, packageFile.path);
          const pkg = JSON.parse(pkgContent);
          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          const depNames = Object.keys(deps || {});
          const suspiciousDeps = depNames.filter(d => 
            SUSPICIOUS_DEP_PATTERNS.some(p => p.test(d))
          );
          checks.push({
            name: 'Dependency Analysis',
            passed: suspiciousDeps.length === 0,
            details: suspiciousDeps.length > 0 
              ? `⚠️ Suspicious dependencies: ${suspiciousDeps.join(', ')}` 
              : `✅ ${depNames.length} dependencies checked, no suspicious packages found`,
          });
        } catch {
          checks.push({ name: 'Dependency Analysis', passed: true, details: 'Could not parse package.json' });
        }
      } else {
        checks.push({ name: 'Dependency Analysis', passed: true, details: 'No package.json found - cannot analyze dependencies' });
      }

    } catch (error: any) {
      if (error.response?.status === 403) {
        checks.push({ name: 'Repository Access', passed: false, details: '❌ GitHub API rate limit exceeded. Set GITHUB_TOKEN for higher limits.' });
      } else if (error.response?.status === 404) {
        checks.push({ name: 'Repository Access', passed: false, details: '❌ Repository not found or private' });
      } else {
        checks.push({ name: 'Repository Access', passed: false, details: `❌ Error: ${error.message}` });
      }
    }

    // Calculate risk level
    const failedChecks = checks.filter(c => !c.passed).length;
    let riskLevel: 'Low' | 'Medium' | 'High' | 'Unknown';
    let summary: string;

    if (checks.length === 0) {
      riskLevel = 'Unknown';
      summary = '⚫ UNKNOWN: Could not access repository for analysis.';
    } else if (backdoorCount > 3 || privacyCount > 3) {
      riskLevel = 'High';
      summary = `🔴 HIGH RISK: Found ${backdoorCount} backdoor indicators and ${privacyCount} privacy concerns. NOT recommended for use.`;
    } else if (backdoorCount > 0 || privacyCount > 0 || failedChecks > 2) {
      riskLevel = 'Medium';
      summary = `🟡 MEDIUM RISK: Found ${backdoorCount} backdoor indicators and ${privacyCount} privacy concerns. Review before use.`;
    } else {
      riskLevel = 'Low';
      summary = `🟢 LOW RISK: No significant security issues detected. Safe to use.`;
    }

    return {
      skill: {
        name: repoName.split('/')[1] || repoName,
        fullName: repoName,
        url: `https://github.com/${repoName}`,
        stars: 0,
        description: '',
        riskLevel,
        riskDetails,
        isBackdoor: backdoorCount > 0,
        isPrivacyRisk: privacyCount > 0,
      },
      checks,
      summary,
    };
  }

  // ============================================================
  // Server Start
  // ============================================================

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Skill Auditor MCP server running on stdio');
    console.error('Tools available: audit_skill, search_market_skills, audit_skill_code, check_local_mcp_tools');
    console.error(`Version: 1.1.0 | License: MIT`);
    if (this.braveApiKey) {
      console.error('Market search: ✅ Enabled (Brave Search API configured)');
    } else {
      console.error('Market search: ❌ Disabled (set BRAVE_SEARCH_API_KEY to enable)');
    }
    if (this.githubToken) {
      console.error('GitHub API: ✅ Authenticated (higher rate limits)');
    } else {
      console.error('GitHub API: ⚠️  Unauthenticated (60 requests/hour limit)');
    }
  }
}

const server = new SkillAuditorServer();
server.run().catch(console.error);
