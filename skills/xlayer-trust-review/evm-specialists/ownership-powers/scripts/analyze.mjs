#!/usr/bin/env node

/**
 * EVM Ownership & Powers Analysis Script
 *
 * Analyzes Solidity contracts for ownership and privilege risks.
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
EVM Ownership & Powers Analysis

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
 * Parse privileged roles
 */
function parseRoles(source) {
  const roles = [];
  const content = source.content;

  // Look for role definitions
  const rolePatterns = [
    { name: "owner", pattern: /address\s+(?:public\s+)?owner/gi },
    { name: "admin", pattern: /address\s+(?:public\s+)?admin/gi },
    { name: "guardian", pattern: /address\s+(?:public\s+)?guardian/gi },
    { name: "governor", pattern: /address\s+(?:public\s+)?governor/gi },
    { name: "controller", pattern: /address\s+(?:public\s+)?controller/gi }
  ];

  for (const roleType of rolePatterns) {
    const matches = [...content.matchAll(roleType.pattern)];
    for (const match of matches) {
      // Find line number
      const lineNum = content.slice(0, match.index).split("\n").length;
      roles.push({
        type: roleType.name,
        line: lineNum,
        declaration: match[0]
      });
    }
  }

  // Look for role-based access control (RBAC)
  const rbacPattern = /bytes32\s+(?:public\s+constant\s+)?(\w+_ROLE)\s*=\s*keccak256\s*\(\s*["']([^"']+)["']\s*\)/gi;
  const rbacMatches = [...content.matchAll(rbacPattern)];

  for (const match of rbacMatches) {
    const lineNum = content.slice(0, match.index).split("\n").length;
    roles.push({
      type: "rbac_role",
      roleName: match[1],
      roleValue: match[2],
      line: lineNum,
      declaration: match[0]
    });
  }

  return roles;
}

/**
 * Parse privileged functions
 */
function parsePrivilegedFunctions(source) {
  const functions = [];
  const lines = source.lines;

  const privilegedPatterns = [
    /onlyOwner/gi,
    /onlyAdmin/gi,
    /onlyGuardian/gi,
    /onlyGovernor/gi,
    /onlyRole\(/gi,
    /hasRole\(/gi
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check if line has privileged modifier
    for (const pattern of privilegedPatterns) {
      const match = line.match(pattern);
      if (match) {
        // Find function signature
        let funcStart = i;
        while (funcStart >= 0 && !lines[funcStart].match(/function\s+\w+/)) {
          funcStart--;
        }

        if (funcStart >= 0) {
          const funcMatch = lines[funcStart].match(/function\s+(\w+)\s*\(/);
          if (funcMatch) {
            const functionName = funcMatch[1];

            // Skip duplicates
            if (!functions.find(f => f.name === functionName && f.line === funcStart + 1)) {
              // Extract all modifiers
              const modifiers = [];
              const allModifiers = lines[funcStart].match(/(onlyOwner|onlyAdmin|onlyGuardian|onlyGovernor|whenNotPaused|whenPaused)/gi);
              if (allModifiers) {
                modifiers.push(...allModifiers);
              }

              functions.push({
                name: functionName,
                modifiers: modifiers,
                line: funcStart + 1,
                signature: lines[funcStart].trim(),
                modifierName: match[1] || match[0]
              });
            }
          }
        }
      }
    }
  }

  return functions;
}

/**
 * Check for ownership and powers issues
 */
function checkOwnershipPowers(source) {
  const findings = [];

  const roles = parseRoles(source);
  const privilegedFunctions = parsePrivilegedFunctions(source);

  // Check 1: Single EOA controls multiple roles
  const uniqueRoleTypes = [...new Set(roles.map(r => r.type))];
  if (uniqueRoleTypes.length >= 2) {
    findings.push({
      kind: "FINDING",
      group_key: "roles | concentration | ownership-powers",
      title: `${uniqueRoleTypes.length} privileged roles controlled by single addresses`,
      skill: "ownership-powers",
      severity: "medium",
      confidence: 75,
      function_or_handler: "role_definitions",
      primary_account_or_authority: uniqueRoleTypes.join(", "),
      evidence: roles.map(r => `${source.path}:${r.line}`),
      trust_consequence: "multiple roles can be controlled by single address, creating centralization risk",
      exploit_path: "compromise of single address affects multiple privileged operations",
      why_it_matters: "role concentration creates single point of failure for multiple operations",
      remediation: "Consider separating roles across different addresses/contracts (multisig, DAO)",
      ship_blocker: false
    });
  }

  // Check 2: Analyze privileged functions
  for (const func of privilegedFunctions) {
    // Check if function is too powerful
    const powerfulFunctions = ["withdraw", "mint", "burn", "transfer", "pause", "unpause", "emergency", "rescue", "set", "update", "upgrade"];
    const isPowerful = powerfulFunctions.some(op =>
      func.name.toLowerCase().includes(op.toLowerCase())
    );

    if (isPowerful && func.modifiers.length === 0) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | unauthorized | ownership-powers`,
        title: `Privileged function '${func.name}' missing access control`,
        skill: "ownership-powers",
        severity: func.name.toLowerCase().includes("withdraw") ? "critical" : "high",
        confidence: 85,
        function_or_handler: func.name,
        primary_account_or_authority: "anyone",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: `anyone can call ${func.name}() without authorization`,
        exploit_path: `attacker calls ${func.name}() directly to perform privileged operation`,
        why_it_matters: "privileged operations without access control can lead to unauthorized actions or fund loss",
        remediation: `Add access control modifier (e.g., onlyOwner) to ${func.name}()`,
        ship_blocker: true
      });
    }

    // Check for dangerous functions controlled by single EOA
    if (isPowerful && func.modifiers.some(m => /^(onlyOwner|onlyAdmin)$/i.test(m))) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | single_eoa | ownership-powers`,
        title: `Critical function '${func.name}' controlled by single EOA`,
        skill: "ownership-powers",
        severity: func.name.toLowerCase().includes("emergency") ? "high" : "medium",
        confidence: 70,
        function_or_handler: func.name,
        primary_account_or_authority: func.modifiers.find(m => /^(onlyOwner|onlyAdmin)$/i.test(m)),
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "compromise of single EOA leads to unauthorized execution of critical function",
        exploit_path: "attacker compromises owner/admin private key and calls privileged function",
        why_it_matters: "single EOA creates centralization risk for critical operations",
        remediation: "Consider using multisig or DAO for critical function authorization",
        ship_blocker: false
      });
    }
  }

  // Check 3: Renounce ownership dangers
  const renouncePattern = /function\s+renounceOwnership\s*\(/gi;
  const renounceMatch = [...source.content.matchAll(renouncePattern)];
  if (renounceMatch.length > 0) {
    for (const match of renounceMatch) {
      const lineNum = source.content.slice(0, match.index).split("\n").length;

      findings.push({
        kind: "FINDING",
        group_key: "renounceOwnership | lockup | ownership-powers",
        title: "Renounce ownership function can permanently lock protocol",
        skill: "ownership-powers",
        severity: "high",
        confidence: 80,
        function_or_handler: "renounceOwnership",
        primary_account_or_authority: "owner",
        evidence: [`${source.path}:${lineNum}`],
        trust_consequence: "protocol can be permanently locked if ownership is renounced",
        exploit_path: "malicious or mistaken admin calls renounceOwnership(), making protocol permanently unadministerable",
        why_it_matters: "renounceOwnership with no recovery mechanism creates permanent protocol lock risk",
        remediation: "Remove renounceOwnership or add timelock + governance approval + recovery mechanism",
        ship_blocker: false
      });
    }
  }

  // Check 4: Unprotected ownership transfer
  const transferPattern = /function\s+transferOwnership\s*\(/gi;
  const transferMatches = [...source.content.matchAll(transferPattern)];

  for (const match of transferMatches) {
    const lineNum = source.content.slice(0, match.index).split("\n").length;
    const funcCode = source.content.split("\n").slice(lineNum - 1, Math.min(lineNum + 20, source.lines.length)).join("\n");

    // Check if protected
    const hasProtection = /onlyOwner|onlyAdmin|onlyRole/.test(funcCode);

    if (!hasProtection) {
      findings.push({
        kind: "FINDING",
        group_key: "transferOwnership | unauthorized | ownership-powers",
        title: "Unprotected ownership transfer function",
        skill: "ownership-powers",
        severity: "critical",
        confidence: 90,
        function_or_handler: "transferOwnership",
        primary_account_or_authority: "anyone",
        evidence: [`${source.path}:${lineNum}`],
        trust_consequence: "anyone can claim ownership of the contract",
        exploit_path: "attacker calls transferOwnership(attackerAddress) to take control",
        why_it_matters: "unprotected ownership transfer allows complete protocol takeover",
        remediation: "Add onlyOwner modifier to transferOwnership function",
        ship_blocker: true
      });
    }
  }

  // Check 5: Missing timelock on critical operations
  const criticalOps = privilegedFunctions.filter(f =>
    ["upgrade", "setfee", "setlimit", "setprotocol", "pause", "unpause"].some(op =>
      f.name.toLowerCase().includes(op)
    )
  );

  for (const func of criticalOps) {
    const hasTimelock = func.modifiers.some(m => /timelock/i.test(m));
    if (!hasTimelock) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | timelock | ownership-powers`,
        title: `Critical operation '${func.name}' missing timelock protection`,
        skill: "ownership-powers",
        severity: "medium",
        confidence: 65,
        function_or_handler: func.name,
        primary_account_or_authority: func.modifiers[0] || "unknown",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "critical parameters can be changed immediately without warning",
        exploit_path: "malicious admin changes critical parameters instantly, preventing users from exiting",
        why_it_matters: "timelocks provide users time to react to potentially malicious parameter changes",
        remediation: "Add timelock delay (e.g., 48 hours) to critical operation",
        ship_blocker: false
      });
    }
  }

  // Check 6: Role assignment without protection
  const grantRolePattern = /function\s+grantRole\s*\(/gi;
  const grantRoleMatches = [...source.content.matchAll(grantRolePattern)];

  for (const match of grantRoleMatches) {
    const lineNum = source.content.slice(0, match.index).split("\n").length;
    const funcCode = source.content.split("\n").slice(lineNum - 1, Math.min(lineNum + 10, source.lines.length)).join("\n");

    const hasProtection = /onlyOwner|onlyAdmin|onlyRole/.test(funcCode);

    if (!hasProtection) {
      findings.push({
        kind: "FINDING",
        group_key: "grantRole | unauthorized | ownership-powers",
        title: "Unprotected grantRole function allows privilege escalation",
        skill: "ownership-powers",
        severity: "critical",
        confidence: 85,
        function_or_handler: "grantRole",
        primary_account_or_authority: "anyone",
        evidence: [`${source.path}:${lineNum}`],
        trust_consequence: "anyone can grant themselves privileged roles",
        exploit_path: "attacker calls grantRole(ADMIN_ROLE, attackerAddress) to gain admin privileges",
        why_it_matters: "unprotected role assignment allows complete privilege escalation",
        remediation: "Add access control (e.g., onlyAdmin) to grantRole function",
        ship_blocker: true
      });
    }
  }

  // Check 7: Self-destruct authorization
  const selfdestructPattern = /selfdestruct\s*\(/;
  if (selfdestructPattern.test(source.content)) {
    findings.push({
      kind: "FINDING",
      group_key: "selfdestruct | destruction | ownership-powers",
      title: "Contract contains self-destruct function",
      skill: "ownership-powers",
      severity: "high",
      confidence: 90,
      function_or_handler: "selfdestruct",
      primary_account_or_authority: "authorized",
      evidence: [`${source.path}:selfdestruct found`],
      trust_consequence: "authorized address can destroy contract, making it permanently unusable",
      exploit_path: "compromised admin calls selfdestruct to destroy contract and all funds",
      why_it_matters: "selfdestruct creates permanent denial of service risk",
      remediation: "Remove selfdestruct or add strict multisig + timelock protection",
      ship_blocker: true
    });
  }

  return findings;
}

/**
 * Determine role concentration level
 */
function determineRoleConcentration(roles, functions) {
  if (roles.length === 0) return "none";

  // Count unique role types
  const uniqueTypes = new Set(roles.map(r => r.type));

  // Count functions controlled by single modifier
  const onlyOwnerCount = functions.filter(f =>
    f.modifiers.some(m => /^onlyOwner$/i.test(m))
  ).length;
  const onlyAdminCount = functions.filter(f =>
    f.modifiers.some(m => /^onlyAdmin$/i.test(m))
  ).length;

  if (uniqueTypes.size >= 3 || onlyOwnerCount >= 5 || onlyAdminCount >= 5) {
    return "high";
  } else if (uniqueTypes.size >= 2 || onlyOwnerCount >= 2 || onlyAdminCount >= 2) {
    return "medium";
  }

  return "low";
}

/**
 * Check for multisig protection
 */
function hasMultisigProtection(source) {
  const multisigPatterns = [
    /multisig/i,
    /GnosisSafe/i,
    /Safe/i,
    / multisig/i,
    /Threshold\s*>\s*1/
  ];

  return multisigPatterns.some(pattern => pattern.test(source.content));
}

/**
 * Check for timelock protection
 */
function hasTimelockProtection(source) {
  const timelockPatterns = [
    /timelock/i,
    /TimelockController/i,
    /delay\s*\(/,
    /timestamp\s*\+\s*\d+\s*(hours|days)/
  ];

  return timelockPatterns.some(pattern => pattern.test(source.content));
}

/**
 * Generate unique finding ID
 */
function generateId(source, index) {
  const hash = Buffer.from(`${source.path}:${index}`).toString("base64").slice(0, 8);
  return `ownership-powers-${hash}`;
}

/**
 * Main analysis function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`[Ownership & Powers] Analyzing: ${args.target}`);

  // Read source files
  const sources = readSourceFiles(args.target);
  console.error(`[Ownership & Powers] Found ${sources.length} source file(s)`);

  const allFindings = [];
  let allRoles = [];
  let allFunctions = [];
  let hasMultisig = false;
  let hasTimelock = false;
  let roleConcentration = "none";

  // Analyze each source file
  for (const source of sources) {
    console.error(`[Ownership & Powers] Analyzing: ${source.path}`);

    // Parse roles and functions
    const roles = parseRoles(source);
    const functions = parsePrivilegedFunctions(source);
    allRoles.push(...roles);
    allFunctions.push(...functions);

    // Check protections
    if (!hasMultisig && hasMultisigProtection(source)) {
      hasMultisig = true;
    }
    if (!hasTimelock && hasTimelockProtection(source)) {
      hasTimelock = true;
    }

    // Check for ownership and powers issues
    const findings = checkOwnershipPowers(source);
    allFindings.push(...findings);
  }

  // Determine overall role concentration
  roleConcentration = determineRoleConcentration(allRoles, allFunctions);

  // Generate output
  const output = {
    specialist: "ownership-powers",
    target: args.target,
    analysis_time: new Date().toISOString(),
    sources_analyzed: sources.length,
    privileged_roles: [...new Set(allRoles.map(r => r.type))],
    role_concentration: roleConcentration,
    has_multisig: hasMultisig,
    has_timelock: hasTimelock,
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
    console.error(`[Ownership & Powers] Output written to: ${args.output}`);
  }

  console.error(`[Ownership & Powers] Analysis complete: ${allFindings.length} finding(s)`);
}

/**
 * Format output as markdown
 */
function formatMarkdown(output) {
  let md = `# Ownership & Powers Analysis\n\n`;
  md += `**Target**: ${output.target}\n`;
  md += `**Analysis Time**: ${output.analysis_time}\n`;
  md += `**Sources Analyzed**: ${output.sources_analyzed}\n`;
  md += `**Privileged Roles**: ${output.privileged_roles.join(", ") || "None detected"}\n`;
  md += `**Role Concentration**: ${output.role_concentration}\n`;
  md += `**Has Multisig**: ${output.has_multisig ? "Yes ✅" : "No ⚠️"}\n`;
  md += `**Has Timelock**: ${output.has_timelock ? "Yes ✅" : "No ⚠️"}\n`;
  md += `**Findings**: ${output.findings.length}\n\n`;

  if (output.findings.length === 0) {
    md += `✅ No ownership/powers issues found.\n`;
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
