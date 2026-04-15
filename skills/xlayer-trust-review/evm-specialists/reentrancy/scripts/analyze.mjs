#!/usr/bin/env node

/**
 * EVM Reentrancy Analysis Script
 *
 * Analyzes Solidity contracts for reentrancy vulnerabilities.
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
EVM Reentrancy Analysis

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
  node analyze.mjs --target ./contracts/MyVault.sol --format markdown
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
 * Detect external call patterns
 */
function detectExternalCalls(source) {
  const calls = [];
  const lines = source.lines;

  const externalCallPatterns = [
    /\.call\s*\{/gi,
    /\.delegatecall\s*\(/gi,
    /\.send\s*\(/gi,
    /\.transfer\s*\(/gi,
    /\.transferFrom\s*\(/gi,
    /IERC20.*\.transfer/gi,
    /IERC20.*\.transferFrom/gi,
    /IERC777.*\.send/gi,
    /IERC1155.*\.safeTransferFrom/gi
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pattern of externalCallPatterns) {
      const matches = [...line.matchAll(pattern)];
      for (const match of matches) {
        calls.push({
          line: lineNum,
          type: match[0].trim(),
          code: line.trim()
        });
      }
    }
  }

  return calls;
}

/**
 * Check for reentrancy guard usage
 */
function hasReentrancyGuard(source) {
  const guardPatterns = [
    /nonReentrant/gi,
    /ReentrancyGuard/gi,
    /Mutex/gi
  ];

  for (const pattern of guardPatterns) {
    if (pattern.test(source.content)) {
      return true;
    }
  }

  return false;
}

/**
 * Check for checks-effects-interactions pattern
 */
function usesChecksEffectsInteractions(source) {
  // Look for comments indicating CEI pattern
  const ceiPatterns = [
    /checks\s*-\s*effects\s*-\s*interactions/gi,
    /CEI\s*pattern/gi
  ];

  for (const pattern of ceiPatterns) {
    if (pattern.test(source.content)) {
      return true;
    }
  }

  // Check if state updates happen before external calls in vulnerable functions
  // This is a heuristic - not perfect
  return false;
}

/**
 * Parse functions
 */
function parseFunctions(source) {
  const functions = [];
  const lines = source.lines;

  const functionPattern = /function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?/gi;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    const match = line.match(functionPattern);
    if (match) {
      const functionName = match[1];
      const parameters = match[2];
      const visibility = match[3] || "internal";

      // Check for modifiers
      const modifiers = [];
      const modifierMatch = line.match(/(nonReentrant|onlyOwner|onlyAdmin|whenPaused)/gi);
      if (modifierMatch) {
        modifiers.push(...modifierMatch);
      }

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
 * Check for reentrancy vulnerabilities
 */
function checkReentrancy(source) {
  const findings = [];

  const functions = parseFunctions(source);
  const externalCalls = detectExternalCalls(source);
  const hasGuard = hasReentrancyGuard(source);

  // Group external calls by function
  const callsByFunction = {};
  for (const call of externalCalls) {
    // Find which function contains this call
    for (const func of functions) {
      if (call.line >= func.line) {
        // Find next function or end of file
        let nextFuncLine = source.lines.length;
        for (const nextFunc of functions) {
          if (nextFunc.line > func.line && nextFunc.line < nextFuncLine) {
            nextFuncLine = nextFunc.line;
          }
        }

        if (call.line < nextFuncLine) {
          if (!callsByFunction[func.name]) {
            callsByFunction[func.name] = [];
          }
          callsByFunction[func.name].push(call);
          break;
        }
      }
    }
  }

  // Check each function with external calls
  for (const [funcName, calls] of Object.entries(callsByFunction)) {
    const func = functions.find(f => f.name === funcName);
    if (!func || func.visibility === "private" || func.visibility === "internal") {
      continue;
    }

    // Check if function has nonReentrant modifier
    if (func.modifiers.some(m => /nonReentrant/gi.test(m))) {
      continue;
    }

    // Check for high-risk functions
    const highRiskFunctions = ["withdraw", "deposit", "transfer", "swap", "borrow", "repay", "mint", "burn", "stake", "unstake"];
    const isHighRisk = highRiskFunctions.some(risk =>
      funcName.toLowerCase().includes(risk.toLowerCase())
    );

    if (isHighRisk && calls.length > 0) {
      findings.push({
        kind: "FINDING",
        group_key: `${funcName} | reentrancy | reentrancy`,
        title: `Potential reentrancy vulnerability in '${funcName}' function`,
        skill: "reentrancy",
        severity: "critical",
        confidence: 85,
        function_or_handler: funcName,
        primary_account_or_authority: "any caller",
        evidence: calls.map(c => `${source.path}:${c.line}`),
        trust_consequence: "attacker can reenter this function before state updates complete",
        exploit_path: "attacker calls function → external call triggers reentrancy → state not yet updated → attacker drains funds",
        why_it_matters: "reentrancy in high-value functions can lead to complete fund drainage",
        remediation: `Add nonReentrant modifier to ${funcName}() or use checks-effects-interactions pattern`,
        ship_blocker: true
      });
    }
  }

  // Check for cross-function reentrancy patterns
  const stateUpdateFunctions = functions.filter(f =>
    /withdraw|transfer|swap|borrow|mint/i.test(f.name)
  );

  const depositFunctions = functions.filter(f =>
    /deposit|stake|add/i.test(f.name)
  );

  if (stateUpdateFunctions.length > 0 && depositFunctions.length > 0 && !hasGuard) {
    findings.push({
      kind: "LEAD",
      group_key: "cross_function | reentrancy | reentrancy",
      title: "Potential cross-function reentrancy - multiple state-modifying functions",
      skill: "reentrancy",
      severity: "medium",
      confidence: 65,
      function_or_handler: "multiple_functions",
      primary_account_or_authority: "user",
      evidence: [
        ...stateUpdateFunctions.slice(0, 2).map(f => `${source.path}:${f.line}`),
        ...depositFunctions.slice(0, 2).map(f => `${source.path}:${f.line}`)
      ],
      trust_consequence: "attacker may be able to reenter between related functions",
      exploit_path: "attacker calls function A → external call → reenters into function B before A completes",
      why_it_matters: "cross-function reentrancy is harder to detect but can be just as dangerous",
      remediation: "Add reentrancy guards to all state-modifying functions or use shared mutex",
      ship_blocker: false
    });
  }

  // Check for unsafe token callbacks
  const callbackFunctions = functions.filter(f =>
    /onTokenTransfer|onReceived|tokensReceived|tokensToSend/i.test(f.name)
  );

  for (const func of callbackFunctions) {
    if (!func.modifiers.some(m => /nonReentrant/gi.test(m))) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | callback | reentrancy`,
        title: `Unsafe token callback '${func.name}' missing reentrancy guard`,
        skill: "reentrancy",
        severity: "high",
        confidence: 80,
        function_or_handler: func.name,
        primary_account_or_authority: "token contract",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "token contract can reenter during callback execution",
        exploit_path: "malicious token contract calls back into this contract during transfer",
        why_it_matters: "token callbacks are trusted entry points that can be exploited for reentrancy",
        remediation: `Add nonReentrant modifier to ${func.name}() callback function`,
        ship_blocker: true
      });
    }
  }

  // Check for view functions that access sensitive state
  const viewFunctions = functions.filter(f => {
    const signature = f.signature.toLowerCase();
    return /view/.test(signature) && /balance|total|supply|price/i.test(signature);
  });

  if (viewFunctions.length > 0 && !hasGuard) {
    findings.push({
      kind: "LEAD",
      group_key: "view_functions | readonly_reentrancy | reentrancy",
      title: "View functions access sensitive state - potential read-only reentrancy",
      skill: "reentrancy",
      severity: "low",
      confidence: 60,
      function_or_handler: "view_functions",
      primary_account_or_authority: "any caller",
      evidence: viewFunctions.slice(0, 3).map(f => `${source.path}:${f.line}`),
      trust_consequence: "view functions may return manipulated state during reentrancy",
      exploit_path: "attacker reenters contract and queries view functions for stale/manipulated data",
      why_it_matters: "read-only reentrancy can be exploited in DeFi protocols that rely on view function data",
      remediation: "Ensure view functions return consistent data or add reentrancy guards",
      ship_blocker: false
    });
  }

  return findings;
}

/**
 * Generate unique finding ID
 */
function generateId(source, index) {
  const hash = Buffer.from(`${source.path}:${index}`).toString("base64").slice(0, 8);
  return `reentrancy-${hash}`;
}

/**
 * Main analysis function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`[Reentrancy] Analyzing: ${args.target}`);

  // Read source files
  const sources = readSourceFiles(args.target);
  console.error(`[Reentrancy] Found ${sources.length} source file(s)`);

  const allFindings = [];
  let totalExternalCalls = 0;
  let hasReentrancyGuardFound = false;
  let usesCEIFound = false;

  // Analyze each source file
  for (const source of sources) {
    console.error(`[Reentrancy] Analyzing: ${source.path}`);

    // Detect external calls
    const externalCalls = detectExternalCalls(source);
    totalExternalCalls += externalCalls.length;
    console.error(`[Reentrancy] Found ${externalCalls.length} external call(s)`);

    // Check for reentrancy guard
    if (hasReentrancyGuard(source)) {
      hasReentrancyGuardFound = true;
      console.error(`[Reentrancy] Reentrancy guard detected`);
    }

    // Check for CEI pattern
    if (usesChecksEffectsInteractions(source)) {
      usesCEIFound = true;
      console.error(`[Reentrancy] CEI pattern detected`);
    }

    // Check for reentrancy vulnerabilities
    const findings = checkReentrancy(source);
    allFindings.push(...findings);
  }

  // Generate output
  const output = {
    specialist: "reentrancy",
    target: args.target,
    analysis_time: new Date().toISOString(),
    sources_analyzed: sources.length,
    external_calls_detected: totalExternalCalls,
    has_reentrancy_guard: hasReentrancyGuardFound,
    uses_checks_effects_interactions: usesCEIFound,
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
    console.error(`[Reentrancy] Output written to: ${args.output}`);
  }

  console.error(`[Reentrancy] Analysis complete: ${allFindings.length} finding(s)`);
}

/**
 * Format output as markdown
 */
function formatMarkdown(output) {
  let md = `# Reentrancy Analysis\n\n`;
  md += `**Target**: ${output.target}\n`;
  md += `**Analysis Time**: ${output.analysis_time}\n`;
  md += `**Sources Analyzed**: ${output.sources_analyzed}\n`;
  md += `**External Calls**: ${output.external_calls_detected}\n`;
  md += `**Has Reentrancy Guard**: ${output.has_reentrancy_guard ? "Yes ✅" : "No ⚠️"}\n`;
  md += `**Uses CEI Pattern**: ${output.uses_checks_effects_interactions ? "Yes ✅" : "No ⚠️"}\n`;
  md += `**Findings**: ${output.findings.length}\n\n`;

  if (output.findings.length === 0) {
    md += `✅ No reentrancy vulnerabilities found.\n`;
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
