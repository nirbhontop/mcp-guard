import fs from "node:fs";
import path from "node:path";
import { auditMcpJson, auditTextFile } from "./rules.js";
import { AuditReport, Finding, Severity } from "./types.js";

const IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"]);

const MCP_FILENAMES = new Set([
  "mcp.json",
  ".mcp.json",
  "claude_desktop_config.json",
  "cline_mcp_settings.json"
]);

const RULE_FILENAMES = new Set([
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  "CLAUDE.md",
  "AGENTS.md",
  "GEMINI.md",
  "copilot-instructions.md"
]);

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 7,
  LOW: 2
};

function walkFiles(dir: string, out: string[] = []): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, out);
    } else if (entry.isFile()) {
      out.push(fullPath);
    }
  }
  return out;
}

export function scanDirectory(targetDir: string): AuditReport {
  const resolvedDir = path.resolve(targetDir);
  const allFiles = walkFiles(resolvedDir);
  const findings: Finding[] = [];
  let filesChecked = 0;

  const hasEnv = allFiles.some((f) => path.basename(f) === ".env");
  const gitignorePath = path.join(resolvedDir, ".gitignore");
  if (hasEnv) {
    let gitignoreContent = "";
    if (fs.existsSync(gitignorePath)) {
      gitignoreContent = fs.readFileSync(gitignorePath, "utf8");
    }
    if (!/^\s*\.env\b/m.test(gitignoreContent)) {
      findings.push({
        ruleId: "ENV-001",
        severity: "HIGH",
        file: ".env",
        title: "Unignored .env File Detected",
        detail: "A .env file exists in the workspace, but .env is not listed in .gitignore.",
        remediation: "Add .env to your .gitignore file before committing."
      });
    }
  }

  for (const fullPath of allFiles) {
    const base = path.basename(fullPath);
    const relPath = path.relative(resolvedDir, fullPath);
    const isMcp = MCP_FILENAMES.has(base);
    const isRule = RULE_FILENAMES.has(base) || fullPath.includes(`${path.sep}.cursor${path.sep}rules${path.sep}`);
    const isEnv = base.startsWith(".env") && base !== ".env.example";

    if (!isMcp && !isRule && !isEnv) continue;

    let content: string;
    try {
      content = fs.readFileSync(fullPath, "utf8");
    } catch {
      continue;
    }

    filesChecked++;

    if (isMcp) {
      findings.push(...auditMcpJson(relPath, content));
      findings.push(...auditTextFile(relPath, content, false));
    } else if (isRule) {
      findings.push(...auditTextFile(relPath, content, true));
    } else if (isEnv) {
      findings.push(...auditTextFile(relPath, content, false));
    }
  }

  const penalty = findings.reduce((acc, f) => acc + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(0, 100 - penalty);

  return {
    scannedPath: resolvedDir,
    filesChecked,
    findings,
    score
  };
}
