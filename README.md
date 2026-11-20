# mcp-guard

[![CI](https://github.com/nirbhontop/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/nirbhontop/mcp-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0.0-brightgreen.svg)](https://nodejs.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-black.svg)](#)

**Zero-dependency CLI security auditor for Model Context Protocol (MCP) server configurations, AI agent rule files, and local workspace secrets.**

---

## Overview

Modern AI coding workflows rely on local MCP servers and repository-level instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`). Misconfigured servers can silently expose root filesystems, execute unpinned remote packages, or leak plaintext API keys—while compromised rule files can conceal zero-width prompt injections.

`mcp-guard` scans your workspace locally or inside CI/CD pipelines and calculates a deterministic security score (`0–100`) before code ships.

## Key Features

- **Zero Runtime Dependencies:** Built exclusively on native Node.js standard library APIs (`node:fs`, `node:path`, `node:test`).
- **MCP Server Auditing:** Inspects `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, and `cline_mcp_settings.json`.
- **Prompt Injection & Unicode Detection:** Scans `.cursorrules`, `.windsurfrules`, `.clinerules`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, and `copilot-instructions.md` for hidden zero-width/bidi characters and exfiltration directives.
- **Credential & `.env` Leak Protection:** Catches hardcoded OpenAI, Anthropic, GitHub, and AWS keys, and verifies `.env` is ignored in `.gitignore`.
- **CI-Ready Output:** Supports human-readable terminal telemetry as well as `--json` and `--strict` flags for automated pipelines.

## Installation & Quickstart

```bash
# Clone the repository
git clone https://github.com/nirbhontop/mcp-guard.git
cd mcp-guard

# Install TypeScript dev dependency and compile
npm install
npm run build

# Audit the current workspace
node dist/cli.js .
```

### Global CLI Link (Optional)

```bash
npm link
mcp-guard /path/to/any/project
```

## CLI Usage

```text
Usage:
  mcp-guard [path] [--json] [--strict]

Options:
  --json     Output machine-readable JSON report
  --strict   Exit with code 1 if any finding (including LOW/MEDIUM) is detected
  -h, --help Show help message
```

### Example Terminal Output

```text
■ MCP-GUARD SECURITY AUDIT
Target: /Users/dev/workspace
Config/Rule files inspected: 2

[CRITICAL] Root or Home Directory Exposed to "fsServer" (MCP-002)
  Location: mcp.json
  Detail:   Server "fsServer" grants filesystem access to an entire root or home directory (-y @modelcontextprotocol/server-filesystem /).
  Fix:      Restrict directory arguments strictly to the active project workspace path.

[HIGH] Hardcoded Credential "GITHUB_TOKEN" in "fsServer" (MCP-004)
  Location: mcp.json
  Detail:   Plaintext secret found inside MCP JSON config under env.GITHUB_TOKEN.
  Fix:      Use environment variable interpolation (e.g., "${GITHUB_TOKEN}") instead of hardcoding values.

Security Score: 60/100
```

## Security Rules Reference

| Rule ID | Severity | Penalty | Description |
| :--- | :--- | :---: | :--- |
| `MCP-000` | `LOW` | `-2` | Malformed JSON syntax inside an MCP configuration file |
| `MCP-001` | `MEDIUM` | `-7` | Unpinned `npx` or `uvx` package version in MCP server arguments |
| `MCP-002` | `CRITICAL` | `-25` | MCP filesystem server granted `/` or `~` root/home access |
| `MCP-003` | `HIGH` | `-15` | MCP server configured to invoke a raw shell (`bash`, `sh`, `cmd`, `powershell`) |
| `MCP-004` | `HIGH` | `-15` | Plaintext API key or token hardcoded in an MCP server `env` block |
| `SEC-001..005` | `CRITICAL` | `-25` | Exposed OpenAI, Anthropic, GitHub, AWS, or generic bearer secrets |
| `INJ-001` | `HIGH` | `-15` | Hidden Unicode zero-width or bidirectional override characters in rule files |
| `INJ-002` | `HIGH` | `-15` | Network exfiltration commands referencing secrets or `~/.ssh` / `~/.aws` |
| `INJ-003` | `HIGH` | `-15` | Instruction-override / prompt-injection phrasing in agent rules |
| `ENV-001` | `HIGH` | `-15` | `.env` file present in workspace without a matching `.gitignore` entry |

## GitHub Actions Integration

Add `mcp-guard` to your repository CI to block insecure agent configs on pull requests:

```yaml
name: Agent Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx github:nirbhontop/mcp-guard . --strict
```

## Running Tests

```bash
npm test
```

## Contributing

1. Fork the repository (`https://github.com/nirbhontop/mcp-guard/fork`)
2. Create your feature branch (`git checkout -b feat/new-rule`)
3. Commit your changes (`git commit -m "feat: add new audit rule"`)
4. Push to the branch (`git push origin feat/new-rule`)
5. Open a Pull Request

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```text
MIT License

Copyright (c) 2026 nirbhontop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
