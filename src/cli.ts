#!/usr/bin/env node
import { scanDirectory } from "./scanner.js";
import { Severity } from "./types.js";

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  orange: "\x1b[38;5;208m"
};

function colorSeverity(sev: Severity): string {
  switch (sev) {
    case "CRITICAL":
      return `${COLORS.bold}${COLORS.red}[CRITICAL]${COLORS.reset}`;
    case "HIGH":
      return `${COLORS.orange}[HIGH]${COLORS.reset}`;
    case "MEDIUM":
      return `${COLORS.yellow}[MEDIUM]${COLORS.reset}`;
    case "LOW":
      return `${COLORS.cyan}[LOW]${COLORS.reset}`;
  }
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
${COLORS.bold}mcp-guard${COLORS.reset} — Security auditor for MCP servers & AI agent configs

Usage:
  mcp-guard [path] [--json] [--strict]

Options:
  --json     Output machine-readable JSON report
  --strict   Exit with code 1 if any findings are detected
  -h, --help Show this help message
`);
    process.exit(0);
  }

  const jsonMode = args.includes("--json");
  const strictMode = args.includes("--strict");
  const targetPath = args.find((a) => !a.startsWith("-")) ?? ".";

  const report = scanDirectory(targetPath);

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n${COLORS.bold}${COLORS.orange}■ MCP-GUARD SECURITY AUDIT${COLORS.reset}`);
    console.log(`${COLORS.dim}Target: ${report.scannedPath}${COLORS.reset}`);
    console.log(`${COLORS.dim}Config/Rule files inspected: ${report.filesChecked}${COLORS.reset}\n`);

    if (report.findings.length === 0) {
      console.log(`${COLORS.green}✔ No security issues detected.${COLORS.reset}`);
    } else {
      for (const f of report.findings) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        console.log(`${colorSeverity(f.severity)} ${COLORS.bold}${f.title}${COLORS.reset} (${f.ruleId})`);
        console.log(`  ${COLORS.dim}Location:${COLORS.reset} ${loc}`);
        console.log(`  ${COLORS.dim}Detail:${COLORS.reset}   ${f.detail}`);
        console.log(`  ${COLORS.dim}Fix:${COLORS.reset}      ${f.remediation}\n`);
      }
    }

    const scoreColor = report.score >= 80 ? COLORS.green : report.score >= 50 ? COLORS.yellow : COLORS.red;
    console.log(`${COLORS.bold}Security Score:${COLORS.reset} ${scoreColor}${report.score}/100${COLORS.reset}\n`);
  }

  const hasCriticalOrHigh = report.findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
  if (hasCriticalOrHigh || (strictMode && report.findings.length > 0)) {
    process.exit(1);
  }
}

main();
