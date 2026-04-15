#!/usr/bin/env node

/**
 * EVM Token & Vault Accounting Analysis Script
 *
 * Analyzes Solidity contracts for accounting invariants, token issues,
 * and vault-specific vulnerabilities.
 * Can be run standalone or as part of xlayer-trust-review.
 */

import { readFileSync, existsSync, readdirSync, statSync, writeFileSync as fsWriteFileSync } from "node:fs";
import { join } from "node:path";

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
EVM Token & Vault Accounting Analysis

Usage:
  node analyze.mjs --target <contract.sol|directory>

Options:
  --target, -t     Contract file or directory to analyze (required)
  --output, -o     Output file (default: stdout)
  --format         Output format: json|markdown (default: json)
  --help, -h       Show this help message

Examples:
  # Analyze single contract
  node analyze.mjs --target ./contracts/MyVault.sol

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

  const stats = statSync(target);

  if (stats.isFile()) {
    const content = readFileSync(target, "utf8");
    sources.push({
      path: target,
      content: content,
      lines: content.split("\n")
    });
  } else if (stats.isDirectory()) {
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
 * Detect token-related functions
 */
function detectTokenFunctions(source) {
  const functions = [];
  const lines = source.lines;

  const tokenPatterns = [
    /function\s+(transfer|transferFrom|approve|mint|burn)\s*\(/gi,
    /function\s+(deposit|withdraw|stake|unstake)\s*\(/gi
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pattern of tokenPatterns) {
      const match = line.match(pattern);
      if (match) {
        // Find function signature
        let funcStart = i;
        while (funcStart >= 0 && !lines[funcStart].match(/function\s+/)) {
          funcStart--;
        }

        if (funcStart >= 0) {
          const funcLine = lines[funcStart];
          const funcMatch = funcLine.match(/function\s+(\w+)\s*\(/);
          if (funcMatch) {
            functions.push({
              name: funcMatch[1],
              type: match[1] ? match[1].toLowerCase() : "unknown",
              line: funcStart + 1,
              signature: funcLine.trim()
            });
          }
        }
      }
    }
  }

  return functions;
}

/**
 * Detect balance-related state variables
 */
function detectBalanceVariables(source) {
  const variables = [];
  const lines = source.lines;

  const balancePatterns = [
    /mapping\s*\(\s*address\s*=>\s*uint256\s*\)\s+(public|private|internal)?\s+balances/gi,
    /uint256\s+(public|private|internal)?\s+totalSupply/gi,
    /uint256\s+(public|private|internal)?\s+totalAssets/gi,
    /uint256\s+(public|private|internal)?\s+totalShares/gi
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pattern of balancePatterns) {
      const match = line.match(pattern);
      if (match) {
        variables.push({
          type: match[0].includes("balances") ? "balances" :
                match[0].includes("totalSupply") ? "totalSupply" :
                match[0].includes("totalAssets") ? "totalAssets" :
                match[0].includes("totalShares") ? "totalShares" : "unknown",
          line: lineNum,
          declaration: line.trim()
        });
      }
    }
  }

  return variables;
}

/**
 * Check for accounting issues
 */
function checkAccountingIssues(source) {
  const findings = [];

  const tokenFunctions = detectTokenFunctions(source);
  const balanceVars = detectBalanceVariables(source);
  const hasTotalSupply = balanceVars.some(v => v.type === "totalSupply");
  const hasBalances = balanceVars.some(v => v.type === "balances");

  // Check 1: Transfer without balance debit
  const transferFunctions = tokenFunctions.filter(f => f.name.toLowerCase() === "transfer");
  for (const func of transferFunctions) {
    const funcCode = source.lines.slice(func.line - 1, Math.min(func.line + 20, source.lines.length)).join("\n");

    // Check if balance is debited
    const hasDebit = /balances\[msg\.sender\]\s*-=/.test(funcCode) ||
                     /balances\[msg\.sender\]\s*=\s*balances\[msg\.sender\]\s*-/.test(funcCode);

    if (!hasDebit && hasBalances) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | missing_debit | token-accounting`,
        title: `Missing balance debit in '${func.name}' function`,
        skill: "token-accounting",
        severity: "critical",
        confidence: 95,
        function_or_handler: func.name,
        primary_account_or_authority: "token_holder",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "users can transfer tokens without their balance decreasing",
        exploit_path: "attacker calls transfer() repeatedly, balance never decreases, can transfer more tokens than owned",
        why_it_matters: "missing balance debit allows double-spending and complete drain of token contract",
        remediation: `Add balances[msg.sender] -= amount before or at the same time as balances[to] += amount`,
        ship_blocker: true
      });
    }
  }

  // Check 2: Mint without totalSupply update
  const mintFunctions = tokenFunctions.filter(f => f.name.toLowerCase() === "mint");
  for (const func of mintFunctions) {
    const funcCode = source.lines.slice(func.line - 1, Math.min(func.line + 20, source.lines.length)).join("\n");

    const updatesBalance = /balances\[.+?\]\s*\+=/.test(funcCode);
    const updatesTotalSupply = /totalSupply\s*\+=/.test(funcCode);

    if (updatesBalance && hasTotalSupply && !updatesTotalSupply) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | missing_supply_update | token-accounting`,
        title: `Mint function '${func.name}' does not update totalSupply`,
        skill: "token-accounting",
        severity: "critical",
        confidence: 90,
        function_or_handler: func.name,
        primary_account_or_authority: "minter",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "totalSupply does not match actual token supply, breaking token invariants",
        exploit_path: "attacker mints tokens, their balance increases but totalSupply unchanged, can manipulate circulating supply",
        why_it_matters: "totalSupply invariance is critical for token contracts and DeFi integrations",
        remediation: `Add totalSupply += amount to the ${func.name}() function`,
        ship_blocker: true
      });
    }
  }

  // Check 3: Integer division before multiplication
  const divisionPattern = /\/\s*\d+/g;
  const lines = source.lines;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check for division before multiplication in same line
    if (/(\w+\s*\/\s*\d+|\w+\s*\/\s*\w+)\s*\*\s*\w+/.test(line)) {
      findings.push({
        kind: "FINDING",
        group_key: `calculation | precision_loss | token-accounting`,
        title: "Division before multiplication causes precision loss",
        skill: "token-accounting",
        severity: "medium",
        confidence: 75,
        function_or_handler: "calculation",
        primary_account_or_authority: "n/a",
        evidence: [`${source.path}:${lineNum}`],
        trust_consequence: "precision loss in calculations can be exploited to drain small amounts over time",
        exploit_path: "attacker performs many small operations, rounding errors accumulate to steal value",
        why_it_matters: "in DeFi, precision loss can be weaponized through dust attacks and share manipulation",
        remediation: "Rearrange calculation to multiply before dividing: (amount * totalShares) / totalAssets",
        ship_blocker: false
      });
    }
  }

  // Check 4: Missing event emission
  for (const func of tokenFunctions) {
    if (["transfer", "transferfrom", "approve", "mint", "burn"].includes(func.name.toLowerCase())) {
      const funcCode = source.lines.slice(func.line - 1, Math.min(func.line + 30, source.lines.length)).join("\n");

      const requiredEvent = func.name.toLowerCase() === "transfer" ? "Transfer" :
                          func.name.toLowerCase() === "transferfrom" ? "Transfer" :
                          func.name.toLowerCase() === "approve" ? "Approval" :
                          func.name.toLowerCase() === "mint" ? "Transfer" :
                          func.name.toLowerCase() === "burn" ? "Transfer" : "";

      if (requiredEvent && !new RegExp(`emit\\s+${requiredEvent}`).test(funcCode)) {
        findings.push({
          kind: "LEAD",
          group_key: `${func.name} | missing_event | token-accounting`,
          title: `Missing event emission in '${func.name}' function`,
          skill: "token-accounting",
          severity: "low",
          confidence: 70,
          function_or_handler: func.name,
          primary_account_or_authority: "n/a",
          evidence: [`${source.path}:${func.line}`],
          trust_consequence: "off-chain systems cannot track token transfers or approvals",
          exploit_path: "difficulty monitoring and debugging token operations",
          why_it_matters: "events are critical for blockchain explorers, wallets, and integrations to track token activity",
          remediation: `Add emit ${requiredEvent}(...) to the ${func.name}() function`,
          ship_blocker: false
        });
      }
    }
  }

  // Check 5: Vault share calculation issues
  const vaultFunctions = tokenFunctions.filter(f =>
    ["deposit", "withdraw", "stake", "unstake"].includes(f.name.toLowerCase())
  );

  for (const func of vaultFunctions) {
    const funcCode = source.lines.slice(func.line - 1, Math.min(func.line + 25, source.lines.length)).join("\n");

    // Check for unsafe division in share calculation
    if (/\bshares\s*=\s*amount\s*\*\s*totalShares\s*\/\s*totalAssets/.test(funcCode) ||
        /\bshares\s*=\s*\(\s*amount\s*\*\s*totalShares\s*\)\s*\/\s*totalAssets/.test(funcCode)) {
      findings.push({
        kind: "LEAD",
        group_key: `${func.name} | share_rounding | token-accounting`,
        title: `Share calculation in '${func.name}' may round unfavorably`,
        skill: "token-accounting",
        severity: "medium",
        confidence: 70,
        function_or_handler: func.name,
        primary_account_or_authority: "depositor",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "users lose dust due to rounding in share calculation",
        exploit_path: "attacker makes many small deposits to accumulate rounding errors",
        why_it_matters: "share calculation rounding can be exploited for profit in high-frequency vault operations",
        remediation: "Use multiply-then-divide with rounding: (amount * totalShares + totalAssets - 1) / totalAssets",
        ship_blocker: false
      });
    }
  }

  // Check 6: Allowance vs balance confusion
  const approveFunctions = tokenFunctions.filter(f => f.name.toLowerCase() === "approve" || f.name.toLowerCase() === "setapprovalforall");
  for (const func of approveFunctions) {
    const funcCode = source.lines.slice(func.line - 1, Math.min(func.line + 20, source.lines.length)).join("\n");

    // Check if function also modifies balance
    if (/balances\[/.test(funcCode)) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | allowance_balance_confusion | token-accounting`,
        title: `Approval function '${func.name}' modifies balance`,
        skill: "token-accounting",
        severity: "high",
        confidence: 85,
        function_or_handler: func.name,
        primary_account_or_authority: "token_owner",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "approval and balance operations are confused, breaking ERC20 standard",
        exploit_path: "user calls approve expecting to set allowance, but balance changes instead",
        why_it_matters: "ERC20 standard requires approve() to only modify allowances, not balances",
        remediation: `Remove balance modifications from ${func.name}() function, only update allowances`,
        ship_blocker: true
      });
    }
  }

  return findings;
}

/**
 * Generate unique finding ID
 */
function generateId(source, index) {
  const hash = Buffer.from(`${source.path}:${index}`).toString("base64").slice(0, 8);
  return `token-accounting-${hash}`;
}

/**
 * Main analysis function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`[Token Accounting] Analyzing: ${args.target}`);

  // Read source files
  const sources = readSourceFiles(args.target);
  console.error(`[Token Accounting] Found ${sources.length} source file(s)`);

  const allFindings = [];
  let tokenFunctionsCount = 0;
  let vaultFunctionsCount = 0;

  // Analyze each source file
  for (const source of sources) {
    console.error(`[Token Accounting] Analyzing: ${source.path}`);

    const tokenFunctions = detectTokenFunctions(source);
    const vaultFuncs = tokenFunctions.filter(f =>
      ["deposit", "withdraw", "stake", "unstake"].includes(f.name.toLowerCase())
    );

    tokenFunctionsCount += tokenFunctions.length;
    vaultFunctionsCount += vaultFuncs.length;

    console.error(`[Token Accounting] Found ${tokenFunctions.length} token function(s)`);

    // Check for accounting issues
    const findings = checkAccountingIssues(source);
    allFindings.push(...findings);
  }

  // Generate output
  const output = {
    specialist: "token-accounting",
    target: args.target,
    analysis_time: new Date().toISOString(),
    sources_analyzed: sources.length,
    token_functions_detected: tokenFunctionsCount,
    vault_functions_detected: vaultFunctionsCount,
    accounting_issues_found: allFindings.length,
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
    fsWriteFileSync(args.output, content);
    console.error(`[Token Accounting] Output written to: ${args.output}`);
  }

  console.error(`[Token Accounting] Analysis complete: ${allFindings.length} finding(s)`);
}

/**
 * Format output as markdown
 */
function formatMarkdown(output) {
  let md = `# Token & Vault Accounting Analysis\n\n`;
  md += `**Target**: ${output.target}\n`;
  md += `**Analysis Time**: ${output.analysis_time}\n`;
  md += `**Sources Analyzed**: ${output.sources_analyzed}\n`;
  md += `**Token Functions**: ${output.token_functions_detected}\n`;
  md += `**Vault Functions**: ${output.vault_functions_detected}\n`;
  md += `**Accounting Issues**: ${output.accounting_issues_found}\n`;
  md += `**Findings**: ${output.findings.length}\n\n`;

  if (output.findings.length === 0) {
    md += `✅ No accounting issues found.\n`;
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
