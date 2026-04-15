#!/usr/bin/env node

/**
 * EVM Access Control Analysis Script
 *
 * Analyzes Solidity contracts for access control vulnerabilities.
 * Can be run standalone or as part of xlayer-trust-review.
 */

import { readFileSync, existsSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Parse command line arguments
 */
function parseArgs(argv) {
  const args = {
    target: null,
    output: null,
    format: "json"
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--target" || arg === "-t") {
      args.target = argv[++i];
    } else if (arg === "--output" || arg === "-o") {
      args.output = argv[++i];
    } else if (arg === "--format") {
      args.format = argv[++i];
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }

  if (!args.target) {
    console.error("Error: --target is required");
    printHelp();
    process.exit(1);
  }

  return args;
}

function printHelp() {
  console.log(`
EVM Access Control Analysis

Usage:
  node analyze.mjs --target <contract.sol|directory>

Options:
  --target, -t     Contract file or directory to analyze (required)
  --output, -o     Output file (default: stdout)
  --format         Output format: json|markdown (default: json)
  --help, -h       Show this help message

Examples:
  # Analyze single contract
  node analyze.mjs --target ./contracts/MyToken.sol

  # Analyze directory
  node analyze.mjs --target ./contracts/ --output results.json

  # Output as markdown
  node analyze.mjs --target ./contracts/MyToken.sol --format markdown
`);
}

/**
 * Read Solidity source files
 */
function readSourceFiles(target) {
  const sources = [];

  if (!existsSync(target)) {
    throw new Error(`Target not found: ${target}`);
  }

  // Check if it's a file or directory
  const stats = statSync(target);

  if (stats.isFile()) {
    // Single file
    const content = readFileSync(target, "utf8");
    sources.push({
      path: target,
      content: content,
      lines: content.split("\n")
    });
  } else if (stats.isDirectory()) {
    // Directory - find all .sol files
    const files = readdirSync(target, { recursive: true });
    for (const file of files) {
      if (file.endsWith(".sol")) {
        const filePath = join(target, file);
        const content = readFileSync(filePath, "utf8");
        sources.push({
          path: filePath,
          content: content,
          lines: content.split("\n")
        });
      }
    }
  }

  return sources;
}

/**
 * Parse function definitions from Solidity source
 */
function parseFunctions(source) {
  const functions = [];
  const lines = source.lines;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Match function declarations
    // Examples:
    //   function transfer(address to, uint256 amount) public returns (bool)
    //   function mint() onlyOwner external
    //   function withdraw() public

    const functionMatch = line.match(
      /function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?/i
    );

    if (functionMatch) {
      const functionName = functionMatch[1];
      const parameters = functionMatch[2];
      const visibility = functionMatch[3] || "internal";

      // Check for modifiers on the same line
      const modifiers = [];
      const modifierMatch = line.match(/(onlyOwner|onlyAdmin|onlyRole|initializer|whenNotPaused|whenPaused)/gi);
      if (modifierMatch) {
        modifiers.push(...modifierMatch);
      }

      // Extract full function signature
      functions.push({
        name: functionName,
        parameters: parameters,
        visibility: visibility,
        modifiers: modifiers,
        line: lineNum,
        signature: line.trim()
      });
    }
  }

  return functions;
}

/**
 * Check for missing access control
 */
function checkAccessControl(functions, source) {
  const findings = [];
  const sensitiveOps = [
    "initialize", "mint", "burn", "transfer", "withdraw", "deposit",
    "set", "update", "change", "add", "remove", "pause", "unpause",
    "emergency", "rescue", "admin", "owner", "governor", "controller"
  ];

  for (const func of functions) {
    // Skip internal/private functions
    if (func.visibility === "internal" || func.visibility === "private") {
      continue;
    }

    // Check if function name suggests privileged operation
    const isSensitive = sensitiveOps.some(op =>
      func.name.toLowerCase().includes(op.toLowerCase())
    );

    if (isSensitive) {
      // Check if has access control modifier
      const hasAccessControl = func.modifiers.some(mod =>
        /^(onlyOwner|onlyAdmin|onlyRole|initializer|whenNotPaused|whenPaused)/i.test(mod)
      );

      if (!hasAccessControl) {
        findings.push({
          kind: "FINDING",
          group_key: `${func.name} | unauthorized | access-control`,
          title: `Missing access control on privileged function '${func.name}'`,
          skill: "access-control",
          severity: getSeverity(func.name),
          confidence: 75,
          function_or_handler: func.name,
          primary_account_or_authority: "unrestricted",
          evidence: [`${source.path}:${func.line}`],
          trust_consequence: `anyone can call ${func.name}() without authorization`,
          exploit_path: `attacker calls ${func.name}() directly to perform privileged operation`,
          why_it_matters: "privileged operations without access control can lead to unauthorized state changes or fund loss",
          remediation: `Add access control modifier (e.g., onlyOwner) to ${func.name}()`,
          ship_blocker: isShipBlocker(func.name)
        });
      }
    }

    // Check for dangerous tx.origin usage
    if (func.signature.includes("tx.origin")) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | tx.origin | access-control`,
        title: `Dangerous tx.origin authentication in '${func.name}'`,
        skill: "access-control",
        severity: "high",
        confidence: 90,
        function_or_handler: func.name,
        primary_account_or_authority: "tx.origin",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "vulnerable to phishing attacks",
        exploit_path: "attacker tricks user into visiting malicious site which calls this function",
        why_it_matters: "tx.origin can be spoofed through phishing, allowing unauthorized access",
        remediation: "Replace tx.origin with msg.sender for proper authorization",
        ship_blocker: true
      });
    }
  }

  return findings;
}

/**
 * Determine severity based on function name
 */
function getSeverity(functionName) {
  const name = functionName.toLowerCase();

  const critical = ["initialize", "mint", "burn", "withdraw"];
  const high = ["set", "update", "change", "emergency", "rescue"];
  const medium = ["pause", "unpause", "admin", "owner"];

  if (critical.some(op => name.includes(op))) return "critical";
  if (high.some(op => name.includes(op))) return "high";
  if (medium.some(op => name.includes(op))) return "medium";

  return "low";
}

/**
 * Determine if this should block deployment
 */
function isShipBlocker(functionName) {
  const name = functionName.toLowerCase();
  const blockers = ["initialize", "mint", "withdraw", "transfer"];

  return blockers.some(op => name.includes(op));
}

/**
 * Generate unique finding ID
 */
function generateId(source, index) {
  const hash = Buffer.from(`${source.path}:${index}`).toString("base64").slice(0, 8);
  return `access-control-${hash}`;
}

/**
 * Main analysis function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`[Access Control] Analyzing: ${args.target}`);

  // Read source files
  const sources = readSourceFiles(args.target);
  console.error(`[Access Control] Found ${sources.length} source file(s)`);

  const allFindings = [];

  // Analyze each source file
  for (const source of sources) {
    console.error(`[Access Control] Analyzing: ${source.path}`);

    // Parse functions
    const functions = parseFunctions(source);
    console.error(`[Access Control] Found ${functions.length} function(s)`);

    // Check for access control issues
    const findings = checkAccessControl(functions, source);
    allFindings.push(...findings);
  }

  // Generate output
  const output = {
    specialist: "access-control",
    target: args.target,
    analysis_time: new Date().toISOString(),
    sources_analyzed: sources.length,
    functions_analyzed: sources.reduce((sum, s) => sum + s.functions || 0, 0),
    findings: allFindings.map((f, i) => ({
      ...f,
      id: generateId(sources[0], i)
    }))
  };

  // Write output
  if (args.format === "markdown") {
    console.log(formatMarkdown(output));
  } else {
    console.log(JSON.stringify(output, null, 2));
  }

  // Write to file if specified
  if (args.output) {
    const content = args.format === "markdown"
      ? formatMarkdown(output)
      : JSON.stringify(output, null, 2);
    writeFileSync(args.output, content);
    console.error(`[Access Control] Output written to: ${args.output}`);
  }

  console.error(`[Access Control] Analysis complete: ${allFindings.length} finding(s)`);
}

/**
 * Format output as markdown
 */
function formatMarkdown(output) {
  let md = `# Access Control Analysis\n\n`;
  md += `**Target**: ${output.target}\n`;
  md += `**Analysis Time**: ${output.analysis_time}\n`;
  md += `**Sources Analyzed**: ${output.sources_analyzed}\n`;
  md += `**Findings**: ${output.findings.length}\n\n`;

  if (output.findings.length === 0) {
    md += `✅ No access control issues found.\n`;
  } else {
    md += `## Findings\n\n`;

    for (const finding of output.findings) {
      md += `### ${finding.severity.toUpperCase()}: ${finding.title}\n\n`;
      md += `- **Function**: \`${finding.function_or_handler}\`\n`;
      md += `- **Severity**: ${finding.severity}\n`;
      md += `- **Confidence**: ${finding.confidence}%\n`;
      md += `- **Ship Blocker**: ${finding.ship_blocker ? "🚫 Yes" : "No"}\n`;
      md += `- **Evidence**: \`${finding.evidence.join("`, `")}\`\n\n`;
      md += `**Trust Consequence**: ${finding.trust_consequence}\n\n`;
      md += `**Exploit Path**: ${finding.exploit_path}\n\n`;
      md += `**Why It Matters**: ${finding.why_it_matters}\n\n`;
      md += `**Remediation**: ${finding.remediation}\n\n`;
      md += `---\n\n`;
    }
  }

  return md;
}

// Run main
main().catch(error => {
  console.error(error);
  process.exit(1);
});
