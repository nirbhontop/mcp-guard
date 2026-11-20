import { Finding } from "./types.js";

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { id: "SEC-001", name: "OpenAI API Key", regex: /sk-(?:proj-)?[A-Za-z0-9_-]{32,}/ },
  { id: "SEC-002", name: "Anthropic API Key", regex: /sk-ant-api03-[A-Za-z0-9_-]{40,}/ },
  { id: "SEC-003", name: "GitHub Personal Access Token", regex: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { id: "SEC-004", name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/ },
  { id: "SEC-005", name: "Generic Hardcoded Bearer/Token", regex: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-.]{20,}["']/i }
];

const INJECTION_PATTERNS: { id: string; title: string; regex: RegExp; detail: string }[] = [
  {
    id: "INJ-001",
    title: "Hidden Unicode Direction/Zero-Width Characters",
    regex: /[\u200B-\u200F\u202A-\u202E\u2066-\u2069]/,
    detail: "Zero-width or bidirectional override characters can hide malicious prompt instructions from human reviewers."
  },
  {
    id: "INJ-002",
    title: "Exfiltration Directive in Agent Instructions",
    regex: /(?:curl|wget|fetch|nc|netcat)\s+.*(?:\$\{?\w*(?:KEY|TOKEN|SECRET|ENV)|~\/\.ssh|~\/\.aws)/i,
    detail: "Instruction file appears to reference sending environment secrets or credential directories over the network."
  },
  {
    id: "INJ-003",
    title: "Instruction Override / Jailbreak Pattern",
    regex: /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
    detail: "Contains classic prompt-injection override phrasing inside a workspace rule file."
  }
];

export function auditMcpJson(filePath: string, rawContent: string): Finding[] {
  const findings: Finding[] = [];
  let parsed: Record<string, unknown>;

  try {
    parsed = JSON.parse(rawContent);
  } catch {
    findings.push({
      ruleId: "MCP-000",
      severity: "LOW",
      file: filePath,
      title: "Malformed JSON in MCP Configuration",
      detail: "Unable to parse MCP configuration as valid JSON.",
      remediation: "Fix JSON syntax errors so the config can be properly validated."
    });
    return findings;
  }

  const servers = (parsed.mcpServers ?? parsed.servers) as Record<string, Record<string, unknown>> | undefined;
  if (!servers || typeof servers !== "object") {
    return findings;
  }

  for (const [serverName, config] of Object.entries(servers)) {
    if (!config || typeof config !== "object") continue;

    const command = String(config.command ?? "");
    const args = Array.isArray(config.args) ? config.args.map(String) : [];
    const env = (config.env ?? {}) as Record<string, string>;
    const fullCmd = `${command} ${args.join(" ")}`.trim();

    if ((command === "npx" || command === "uvx") && !args.includes("-y") === false) {
      const pkgArg = args.find((a) => !a.startsWith("-"));
      if (pkgArg && !/@\d+\.\d+\.\d+/.test(pkgArg)) {
        findings.push({
          ruleId: "MCP-001",
          severity: "MEDIUM",
          file: filePath,
          title: `Unpinned Package Execution in MCP Server "${serverName}"`,
          detail: `Server runs "${fullCmd}" without a pinned semantic version, exposing the host to supply-chain updates.`,
          remediation: `Pin an explicit version (e.g., ${pkgArg}@1.0.0) in args.`
        });
      }
    }

    if (args.some((a) => a === "/" || a === "~" || a === process.env.HOME || a === "C:\\")) {
      findings.push({
        ruleId: "MCP-002",
        severity: "CRITICAL",
        file: filePath,
        title: `Root or Home Directory Exposed to "${serverName}"`,
        detail: `Server "${serverName}" grants filesystem access to an entire root or home directory (${args.join(" ")}).`,
        remediation: "Restrict directory arguments strictly to the active project workspace path."
      });
    }

    if (["bash", "sh", "zsh", "cmd", "powershell"].includes(command)) {
      findings.push({
        ruleId: "MCP-003",
        severity: "HIGH",
        file: filePath,
        title: `Direct Shell Interpreter Configured for "${serverName}"`,
        detail: `Server spawns "${command}" directly, increasing command-injection blast radius.`,
        remediation: "Invoke the specific runtime binary directly instead of wrapping in a shell."
      });
    }

    for (const [envKey, envVal] of Object.entries(env)) {
      if (typeof envVal !== "string") continue;
      if (!envVal.startsWith("${") && envVal.length >= 16 && /(KEY|TOKEN|SECRET|PASS|PWD)/i.test(envKey)) {
        findings.push({
          ruleId: "MCP-004",
          severity: "HIGH",
          file: filePath,
          title: `Hardcoded Credential "${envKey}" in "${serverName}"`,
          detail: `Plaintext secret found inside MCP JSON config under env.${envKey}.`,
          remediation: `Use environment variable interpolation (e.g., "\$\{${envKey}\}") instead of hardcoding values.`
        });
      }
    }
  }

  return findings;
}

export function auditTextFile(filePath: string, content: string, checkInjections: boolean): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(lineText)) {
        findings.push({
          ruleId: pattern.id,
          severity: "CRITICAL",
          file: filePath,
          line: lineNum,
          title: `Exposed ${pattern.name}`,
          detail: `Matched secret signature on line ${lineNum}.`,
          remediation: "Revoke the exposed credential immediately and move it to an untracked .env file."
        });
      }
    }

    if (checkInjections) {
      for (const inj of INJECTION_PATTERNS) {
        if (inj.regex.test(lineText)) {
          findings.push({
            ruleId: inj.id,
            severity: "HIGH",
            file: filePath,
            line: lineNum,
            title: inj.title,
            detail: inj.detail,
            remediation: "Inspect and remove suspicious instructions or hidden characters from the rule file."
          });
        }
      }
    }
  });

  return findings;
}
