#!/usr/bin/env node

/**
 * EVM Proxy Risk Analysis Script
 *
 * Analyzes Solidity contracts for proxy pattern risks.
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
EVM Proxy Risk Analysis

Usage:
  node analyze.mjs --target <contract.sol|directory>

Options:
  --target, -t     Contract file or directory to analyze (required)
  --output, -o     Output file (default: stdout)
  --format         Output format: json|markdown (default: json)
  --help, -h       Show this help message

Examples:
  # Analyze single contract
  node analyze.mjs --target ./contracts/MyProxy.sol

  # Analyze directory
  node analyze.mjs --target ./contracts/ --output results.json

  # Output as markdown
  node analyze.mjs --target ./contracts/MyProxy.sol --format markdown
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
 * Detect proxy type
 */
function detectProxyType(source) {
  const content = source.content;

  if (/delegatecall\s*\(/.test(content)) {
    // Check for specific proxy patterns
    if (/ERC1967Proxy|IMPLEMENTATION_SLOT|ADMIN_SLOT/.test(content)) {
      return "erc1967";
    }
    if (/TransparentUpgradeableProxy|_admin/.test(content)) {
      return "transparent";
    }
    if (/BeaconProxy|_beacon/.test(content)) {
      return "beacon";
    }
    if (/clone|CREATE2|eip1167/.test(content)) {
      return "minimal";
    }
    return "custom";
  }

  return "none";
}

/**
 * Parse delegatecall functions
 */
function parseDelegatecallFunctions(source) {
  const functions = [];
  const lines = source.lines;

  const delegatecallPattern = /delegatecall\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (delegatecallPattern.test(line)) {
      // Find function signature
      let funcStart = i;
      while (funcStart >= 0 && !lines[funcStart].match(/function\s+\w+/)) {
        funcStart--;
      }

      if (funcStart >= 0) {
        const funcMatch = lines[funcStart].match(/function\s+(\w+)\s*\(/);
        if (funcMatch) {
          // Check for modifiers
          const modifiers = [];
          const modifierMatch = lines[funcStart].match(/(onlyOwner|onlyAdmin|onlyRole|whenPaused)/gi);
          if (modifierMatch) {
            modifiers.push(...modifierMatch);
          }

          functions.push({
            name: funcMatch[1],
            modifiers: modifiers,
            line: funcStart + 1,
            delegatecallLine: lineNum,
            signature: lines[funcStart].trim()
          });
        }
      }
    }
  }

  return functions;
}

/**
 * Parse fallback function
 */
function parseFallback(source) {
  const lines = source.lines;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (/fallback\s*\(\)/.test(line)) {
      return {
        line: lineNum,
        signature: line.trim(),
        hasDelegatecall: /delegatecall/.test(source.content.slice(i, Math.min(i + 20, lines.length)))
      };
    }
  }

  return null;
}

/**
 * Check for proxy risks
 */
function checkProxyRisks(source, proxyType) {
  const findings = [];

  if (proxyType === "none") {
    // Not a proxy, but check if it's an implementation that could be called directly
    const implRisks = checkImplementationRisks(source);
    findings.push(...implRisks);
    return findings;
  }

  // Check delegatecall safety
  const delegatecallFunctions = parseDelegatecallFunctions(source);
  for (const func of delegatecallFunctions) {
    // Check if unprotected
    if (func.modifiers.length === 0) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | delegatecall | proxy-risk`,
        title: `Unprotected delegatecall in '${func.name}'`,
        skill: "proxy-risk",
        severity: "critical",
        confidence: 90,
        function_or_handler: func.name,
        primary_account_or_authority: "anyone",
        evidence: [`${source.path}:${func.delegatecallLine}`],
        trust_consequence: "anyone can execute arbitrary code in proxy context",
        exploit_path: "attacker calls function with malicious contract address to steal funds or takeover proxy",
        why_it_matters: "unprotected delegatecall allows complete control of proxy state and logic",
        remediation: "Add access control (e.g., onlyAdmin) and validate/whitelist target addresses",
        ship_blocker: true
      });
    }

    // Check for delegatecall to user-supplied addresses
    const hasUserSuppliedTarget = /delegatecall\s*\([^)]*\)/.test(
      source.lines.slice(func.line - 1, func.delegatecallLine).join("\n")
    );

    if (hasUserSuppliedTarget && func.modifiers.length === 0) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | user_delegatecall | proxy-risk`,
        title: `Delegatecall to user-supplied address in '${func.name}'`,
        skill: "proxy-risk",
        severity: "critical",
        confidence: 85,
        function_or_handler: func.name,
        primary_account_or_authority: "user",
        evidence: [`${source.path}:${func.delegatecallLine}`],
        trust_consequence: "user can execute arbitrary code through proxy",
        exploit_path: "attacker provides malicious contract address as parameter",
        why_it_matters: "user-controlled delegatecall targets are extremely dangerous",
        remediation: "Remove user-supplied addresses or implement strict whitelist validation",
        ship_blocker: true
      });
    }
  }

  // Check fallback function safety
  const fallback = parseFallback(source);
  if (fallback && fallback.hasDelegatecall) {
    // Check if fallback has error handling
    const fallbackCode = source.lines.slice(fallback.line - 1, Math.min(fallback.line + 20, source.lines.length)).join("\n");

    if (!/require\s*\(/.test(fallbackCode) && !/\?\s*[^?]+\s*:/.test(fallbackCode)) {
      findings.push({
        kind: "FINDING",
        group_key: "fallback | error_handling | proxy-risk",
        title: "Unsafe fallback function - missing error handling",
        skill: "proxy-risk",
        severity: "high",
        confidence: 75,
        function_or_handler: "fallback",
        primary_account_or_authority: "n/a",
        evidence: [`${source.path}:${fallback.line}`],
        trust_consequence: "failed delegatecalls silently revert without proper error reporting",
        exploit_path: "failed calls provide no feedback, making debugging and security monitoring difficult",
        why_it_matters: "proper error handling is critical for proxy security and debugging",
        remediation: "Add success check on delegatecall and revert with error message on failure",
        ship_blocker: false
      });
    }

    // Check if fallback returns data properly
    if (!/returndatacopy|returndatasize/.test(fallbackCode)) {
      findings.push({
        kind: "FINDING",
        group_key: "fallback | return_data | proxy-risk",
        title: "Fallback function missing return data handling",
        skill: "proxy-risk",
        severity: "medium",
        confidence: 70,
        function_or_handler: "fallback",
        primary_account_or_authority: "n/a",
        evidence: [`${source.path}:${fallback.line}`],
        trust_consequence: "return data from implementation calls is lost",
        exploit_path: "calls to implementation fail silently or return incorrect data",
        why_it_matters: "proper return data handling is essential for proxy-implementation communication",
        remediation: "Add assembly block to copy and return returndata from delegatecall",
        ship_blocker: false
      });
    }
  }

  // Check for slot conflicts
  const slotConflicts = checkSlotConflicts(source, proxyType);
  findings.push(...slotConflicts);

  // Check admin safety
  const adminRisks = checkAdminRisks(source);
  findings.push(...adminRisks);

  return findings;
}

/**
 * Check for implementation risks (when contract can be called directly)
 */
function checkImplementationRisks(source) {
  const findings = [];

  // Check if this looks like an implementation contract
  const isImplementation =
    /Initializable|initializer|UUPSUpgradeable/.test(source.content) &&
    !/delegatecall/.test(source.content);

  if (isImplementation) {
    // Check for privileged functions that don't validate proxy context
    const privilegedFunctions = source.lines
      .map((line, i) => {
        const match = line.match(/function\s+(onlyAdmin|admin|owner|upgrade|withdraw)\s*\(/i);
        return match ? { name: match[1], line: i + 1 } : null;
      })
      .filter(f => f !== null);

    for (const func of privilegedFunctions) {
      const funcCode = source.lines.slice(func.line - 1, Math.min(func.line + 10, source.lines.length)).join("\n");

      // Check if function validates proxy context
      if (!/msg\.sender\s*==\s*address\(this\)|this\.getImplementation\(\)/.test(funcCode)) {
        findings.push({
          kind: "FINDING",
          group_key: `${func.name} | direct_call | proxy-risk`,
          title: `Implementation function '${func.name}' can be called directly`,
          skill: "proxy-risk",
          severity: "high",
          confidence: 70,
          function_or_handler: func.name,
          primary_account_or_authority: "anyone",
          evidence: [`${source.path}:${func.line}`],
          trust_consequence: "implementation can be called directly, bypassing proxy access control",
          exploit_path: "attacker calls implementation directly with different storage context",
          why_it_matters: "implementation contracts should not be callable directly to avoid storage confusion attacks",
          remediation: "Add proxy context check (e.g., require(msg.sender == address(this))) or use onlyProxyContext modifier",
          ship_blocker: false
        });
      }
    }
  }

  return findings;
}

/**
 * Check for slot conflicts
 */
function checkSlotConflicts(source, proxyType) {
  const findings = [];

  // ERC1967 standard slots
  const standardSlots = {
    IMPLEMENTATION_SLOT: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    ADMIN_SLOT: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    BEACON_SLOT: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
  };

  // Look for custom slot definitions
  const customSlotPattern = /bytes32\s+(?:constant\s+)?(\w+_?SLOT)\s*=\s*0x[a-fA-F0-9]{64}/g;
  const matches = [...source.content.matchAll(customSlotPattern)];

  for (const match of matches) {
    const slotName = match[1];
    const slotValue = match[0].match(/0x[a-fA-F0-9]{64}/)[0];

    // Check if custom slot conflicts with standard slots
    if (Object.values(standardSlots).includes(slotValue)) {
      findings.push({
        kind: "FINDING",
        group_key: `${slotName} | slot_conflict | proxy-risk`,
        title: `Custom slot '${slotName}' conflicts with ERC1967 standard slot`,
        skill: "proxy-risk",
        severity: "high",
        confidence: 95,
        function_or_handler: "storage",
        primary_account_or_authority: "n/a",
        evidence: [`${source.path}:${slotName} = ${slotValue}`],
        trust_consequence: "custom storage slot conflicts with standard proxy slot, causing data corruption",
        exploit_path: "proxy and implementation overwrite same storage slot, breaking proxy functionality",
        why_it_matters: "slot conflicts can break proxy operation or allow unauthorized state modification",
        remediation: "Use a different storage slot that doesn't conflict with ERC1967 standard slots",
        ship_blocker: true
      });
    }
  }

  // Check if implementation uses proxy slots
  if (Object.values(standardSlots).some(slot => source.content.includes(slot))) {
    findings.push({
      kind: "FINDING",
      group_key: "implementation | proxy_slots | proxy-risk",
      title: "Implementation contract uses proxy storage slots",
      skill: "proxy-risk",
      severity: "high",
      confidence: 80,
      function_or_handler: "storage",
      primary_account_or_authority: "n/a",
      evidence: [`${source.path}:ERC1967 slot usage detected`],
      trust_consequence: "implementation may corrupt proxy state by writing to proxy slots",
      exploit_path: "implementation functions modify proxy admin/implementation slots",
      why_it_matters: "implementation contracts should not touch proxy-specific storage slots",
      remediation: "Move proxy-specific storage slots to separate proxy contract only",
      ship_blocker: false
    });
  }

  return findings;
}

/**
 * Check admin-related risks
 */
function checkAdminRisks(source) {
  const findings = [];

  // Check if admin can call implementation functions
  if (/admin\s*\(\)|_admin\s*\(|owner\s*\(\)/.test(source.content)) {
    // Check for admin functions that might bypass proxy
    const adminFunctionPattern = /function\s+(\w*admin\w*|\w*owner\w*)\s*\(/gi;
    const matches = [...source.content.matchAll(adminFunctionPattern)];

    for (const match of matches) {
      findings.push({
        kind: "LEAD",
        group_key: `${match[1]} | admin_interface | proxy-risk`,
        title: `Admin function '${match[1]}' - verify proxy isolation`,
        skill: "proxy-risk",
        severity: "low",
        confidence: 60,
        function_or_handler: match[1],
        primary_account_or_authority: "admin",
        evidence: [`${source.path}:${match[1]} function found`],
        trust_consequence: "admin may be able to call implementation functions directly",
        exploit_path: "admin bypasses proxy and calls implementation directly with different storage context",
        why_it_matters: "admin functions should be properly isolated in proxy contracts",
        remediation: "Ensure admin functions are in proxy contract, not implementation",
        ship_blocker: false
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
  return `proxy-risk-${hash}`;
}

/**
 * Main analysis function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`[Proxy Risk] Analyzing: ${args.target}`);

  // Read source files
  const sources = readSourceFiles(args.target);
  console.error(`[Proxy Risk] Found ${sources.length} source file(s)`);

  const allFindings = [];
  let detectedProxyType = "none";
  let hasDelegatecall = false;
  let implementationCallable = false;

  // Analyze each source file
  for (const source of sources) {
    console.error(`[Proxy Risk] Analyzing: ${source.path}`);

    // Detect proxy type
    const proxyType = detectProxyType(source);
    if (proxyType !== "none") {
      detectedProxyType = proxyType;
    }
    console.error(`[Proxy Risk] Proxy type: ${proxyType}`);

    // Check for delegatecall
    if (/delegatecall/.test(source.content)) {
      hasDelegatecall = true;
    }

    // Check if implementation is callable
    if (detectedProxyType === "none" && /Initializable|initializer/.test(source.content)) {
      implementationCallable = true;
    }

    // Check for proxy risks
    const findings = checkProxyRisks(source, proxyType);
    allFindings.push(...findings);
  }

  // Generate output
  const output = {
    specialist: "proxy-risk",
    target: args.target,
    analysis_time: new Date().toISOString(),
    sources_analyzed: sources.length,
    proxy_type: detectedProxyType,
    has_delegatecall: hasDelegatecall,
    implementation_callable: implementationCallable,
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
    console.error(`[Proxy Risk] Output written to: ${args.output}`);
  }

  console.error(`[Proxy Risk] Analysis complete: ${allFindings.length} finding(s)`);
}

/**
 * Format output as markdown
 */
function formatMarkdown(output) {
  let md = `# Proxy Risk Analysis\n\n`;
  md += `**Target**: ${output.target}\n`;
  md += `**Analysis Time**: ${output.analysis_time}\n`;
  md += `**Sources Analyzed**: ${output.sources_analyzed}\n`;
  md += `**Proxy Type**: ${output.proxy_type}\n`;
  md += `**Has Delegatecall**: ${output.has_delegatecall ? "Yes" : "No"}\n`;
  md += `**Implementation Callable**: ${output.implementation_callable ? "Yes" : "No"}\n`;
  md += `**Findings**: ${output.findings.length}\n\n`;

  if (output.findings.length === 0) {
    md += `✅ No proxy risks found.\n`;
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
