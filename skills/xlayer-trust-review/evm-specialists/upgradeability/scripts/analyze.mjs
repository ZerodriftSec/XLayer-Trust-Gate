#!/usr/bin/env node

/**
 * EVM Upgradeability Analysis Script
 *
 * Analyzes Solidity contracts for upgradeability vulnerabilities.
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
EVM Upgradeability Analysis

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
 * Detect proxy pattern in contract
 */
function detectProxyPattern(source) {
  const content = source.content;
  const patterns = {
    uups: /UUPSUpgradeable|@custom:storage-location erc7201|_authorizeUpgrade/i,
    transparent: /TransparentUpgradeableProxy|ITransparentUpgradeableProxy|@unsecure-storage-upgrade/i,
    beacon: /BeaconProxy|IBeacon|upgradeBeaconToAndCall/i,
    minimal: /clone|CREATE2|eip1167|minimal proxy/i,
    none: /^/  // Will match nothing
  };

  for (const [pattern, regex] of Object.entries(patterns)) {
    if (regex.test(content) && pattern !== "none") {
      return pattern;
    }
  }

  return "unknown";
}

/**
 * Parse upgrade functions
 */
function parseUpgradeFunctions(source) {
  const functions = [];
  const lines = source.lines;

  const upgradePatterns = [
    /function\s+(upgradeTo|upgradeToAndCall|upgrade)\s*\(/i,
    /function\s+_authorizeUpgrade\s*\(/
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pattern of upgradePatterns) {
      const match = line.match(pattern);
      if (match) {
        const functionName = match[1] || "upgrade";

        // Check for modifiers
        const modifiers = [];
        const modifierMatch = line.match(/(onlyOwner|onlyAdmin|onlyRole|whenPaused)/gi);
        if (modifierMatch) {
          modifiers.push(...modifierMatch);
        }

        functions.push({
          name: functionName,
          modifiers: modifiers,
          line: lineNum,
          signature: line.trim()
        });
      }
    }
  }

  return functions;
}

/**
 * Parse initialization functions
 */
function parseInitialization(source) {
  const initFunctions = [];
  const lines = source.lines;

  const initPatterns = [
    /function\s+initialize\s*\(/i,
    /function\s+reinitialize\s*\(/i
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const pattern of initPatterns) {
      const match = line.match(pattern);
      if (match) {
        const functionName = match[1] || "initialize";

        // Check for initializer modifier
        const hasInitializer = /initializer\s*(?:\(\s*\d+\s*\))?/.test(line);

        initFunctions.push({
          name: functionName,
          hasInitializer: hasInitializer,
          line: lineNum,
          signature: line.trim()
        });
      }
    }
  }

  return initFunctions;
}

/**
 * Check for upgradeability issues
 */
function checkUpgradeability(source, proxyPattern) {
  const findings = [];
  const upgradeFunctions = parseUpgradeFunctions(source);
  const initFunctions = parseInitialization(source);

  // Check 1: Upgrade authorization
  for (const func of upgradeFunctions) {
    // Skip _authorizeUpgrade internal function (UUPS)
    if (func.name === "_authorizeUpgrade") {
      // Check if it's empty or weak
      if (func.modifiers.length === 0) {
        findings.push({
          kind: "FINDING",
          group_key: `${func.name} | upgrade_authority | upgradeability`,
          title: `Missing or weak authorization in '${func.name}'`,
          skill: "upgradeability",
          severity: "critical",
          confidence: 85,
          function_or_handler: func.name,
          primary_account_or_authority: "unrestricted",
          evidence: [`${source.path}:${func.line}`],
          trust_consequence: "anyone can authorize upgrades, leading to complete protocol takeover",
          exploit_path: "attacker calls upgradeTo() directly to replace implementation with malicious code",
          why_it_matters: "unprotected upgrade functions allow complete control of the contract",
          remediation: "Add access control modifier (e.g., onlyAdmin, onlyRole) to upgrade function",
          ship_blocker: true
        });
      }
      continue;
    }

    // Check for missing timelock on public upgrade functions
    if (func.modifiers.length === 0 || !func.modifiers.some(m => /timelock/i.test(m))) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | timelock | upgradeability`,
        title: `Missing timelock on upgrade function '${func.name}'`,
        skill: "upgradeability",
        severity: "high",
        confidence: 75,
        function_or_handler: func.name,
        primary_account_or_authority: func.modifiers.length > 0 ? func.modifiers[0] : "unrestricted",
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "upgrades can be executed instantly without delay",
        exploit_path: "malicious admin upgrades to malicious implementation immediately, preventing users from exiting",
        why_it_matters: "timelocks provide users time to exit before potentially malicious upgrades",
        remediation: "Add timelock delay (e.g., 48h) to upgrade function",
        ship_blocker: false
      });
    }

    // Check for single EOA admin (high risk)
    if (func.modifiers.some(m => /^(onlyOwner|onlyAdmin)$/i.test(m))) {
      findings.push({
        kind: "FINDING",
        group_key: `${func.name} | single_admin | upgradeability`,
        title: `Upgrade controlled by single EOA in '${func.name}'`,
        skill: "upgradeability",
        severity: "medium",
        confidence: 70,
        function_or_handler: func.name,
        primary_account_or_authority: func.modifiers.find(m => /^(onlyOwner|onlyAdmin)$/i.test(m)),
        evidence: [`${source.path}:${func.line}`],
        trust_consequence: "single point of failure - compromise of EOA leads to protocol takeover",
        exploit_path: "attacker compromises owner EOA private key and upgrades to malicious implementation",
        why_it_matters: "single EOA admin creates centralization risk and single point of failure",
        remediation: "Consider using multisig or DAO for upgrade authorization",
        ship_blocker: false
      });
    }
  }

  // Check 2: Initialization safety
  for (const init of initFunctions) {
    if (!init.hasInitializer) {
      findings.push({
        kind: "FINDING",
        group_key: `${init.name} | initialization | upgradeability`,
        title: `Missing initializer modifier on '${init.name}'`,
        skill: "upgradeability",
        severity: init.name === "initialize" ? "critical" : "high",
        confidence: 80,
        function_or_handler: init.name,
        primary_account_or_authority: "anyone",
        evidence: [`${source.path}:${init.line}`],
        trust_consequence: "initialize can be called multiple times, potentially resetting critical state",
        exploit_path: "attacker calls initialize() again to reset admin or other critical state",
        why_it_matters: "unprotected initialization functions can be called repeatedly, breaking contract invariants",
        remediation: "Add @openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol initializer modifier",
        ship_blocker: true
      });
    }
  }

  // Check 3: Self-destruct in implementation (critical for upgradeable contracts)
  const selfdestructPattern = /selfdestruct\s*\(|selfdestruct\s*\(/i;
  if (selfdestructPattern.test(source.content)) {
    const match = source.content.match(selfdestructPattern);
    findings.push({
      kind: "FINDING",
      group_key: "selfdestruct | implementation | upgradeability",
      title: "Self-destruct found in upgradeable contract",
      skill: "upgradeability",
      severity: "critical",
      confidence: 90,
      function_or_handler: "selfdestruct",
      primary_account_or_authority: "authorized",
      evidence: [`${source.path}:selfdestruct found`],
      trust_consequence: "implementation can be destroyed, breaking all proxy instances",
      exploit_path: "authorized admin calls selfdestruct to destroy implementation, rendering all proxies unusable",
      why_it_matters: "selfdestruct in upgradeable contracts creates permanent denial of service risk",
      remediation: "Remove selfdestruct or add strict access control with timelock and multisig",
      ship_blocker: true
    });
  }

  // Check 4: Storage layout warnings (pattern-based)
  const storagePatternWarnings = checkStorageLayoutWarnings(source);
  findings.push(...storagePatternWarnings);

  // Check 5: Proxy pattern specific risks
  const patternRisks = checkProxyPatternRisks(source, proxyPattern);
  findings.push(...patternRisks);

  return findings;
}

/**
 * Check for storage layout warnings
 */
function checkStorageLayoutWarnings(source) {
  const findings = [];

  // Look for state variable definitions that could be problematic in upgrades
  const stateVarPattern = /^\s*(?:mutable\s+)?(?:uint\d+|address|bool|bytes\d+|string|contract|enum|struct)\s+\w+\s*(?:public|private|internal|external)?\s*(?:=.+)?;/gm;
  const matches = source.content.matchAll(stateVarPattern);

  // Count state variables
  const stateVars = [];
  for (const match of matches) {
    stateVars.push(match[0]);
  }

  // Warn if contract has many state variables (higher upgrade risk)
  if (stateVars.length > 20) {
    findings.push({
      kind: "LEAD",
      group_key: "storage_layout | complexity | upgradeability",
      title: "Complex state layout with many state variables",
      skill: "upgradeability",
      severity: "low",
      confidence: 60,
      function_or_handler: "state_variables",
      primary_account_or_authority: "n/a",
      evidence: [`${stateVars.length} state variables found`],
      trust_consequence: "high risk of storage collision in future upgrades",
      exploit_path: "future upgrades may inadvertently overwrite storage slots",
      why_it_matters: "many state variables increase complexity and risk of storage layout conflicts",
      remediation: "Consider consolidating state variables or using diamond pattern for complex upgrades",
      ship_blocker: false
    });
  }

  return findings;
}

/**
 * Check for proxy pattern specific risks
 */
function checkProxyPatternRisks(source, proxyPattern) {
  const findings = [];

  switch (proxyPattern) {
    case "uups":
      // UUPS-specific: check if _authorizeUpgrade is defined
      if (!/_authorizeUpgrade\s*\(/.test(source.content)) {
        findings.push({
          kind: "FINDING",
          group_key: "_authorizeUpgrade | uups | upgradeability",
          title: "Missing _authorizeUpgrade function in UUPS contract",
          skill: "upgradeability",
          severity: "critical",
          confidence: 95,
          function_or_handler: "_authorizeUpgrade",
          primary_account_or_authority: "anyone",
          evidence: [`${source.path}:UUPSUpgradeable inherited without _authorizeUpgrade`],
          trust_consequence: "UUPS upgrade authorization is missing, potentially allowing unauthorized upgrades",
          exploit_path: "attacker calls upgradeTo() to replace implementation",
          why_it_matters: "UUPS requires _authorizeUpgrade to control upgrade permissions",
          remediation: "Implement _authorizeUpgrade(address) internal function with access control",
          ship_blocker: true
        });
      }
      break;

    case "transparent":
      // Transparent-specific: check if admin is protected
      findings.push({
        kind: "LEAD",
        group_key: "admin | transparent | upgradeability",
        title: "Transparent proxy pattern detected - verify admin security",
        skill: "upgradeability",
        severity: "low",
        confidence: 65,
        function_or_handler: "admin",
        primary_account_or_authority: "admin",
        evidence: [`${source.path}:Transparent pattern detected`],
        trust_consequence: "admin can call implementation functions directly if not properly isolated",
        exploit_path: "admin may accidentally call implementation functions through proxy",
        why_it_matters: "transparent proxies require careful admin implementation to avoid security issues",
        remediation: "Ensure admin is a separate contract with proper access control and timelock",
        ship_blocker: false
      });
      break;

    case "beacon":
      // Beacon-specific: check beacon implementation
      findings.push({
        kind: "LEAD",
        group_key: "beacon | upgradeability | upgradeability",
        title: "Beacon proxy pattern detected - verify beacon contract security",
        skill: "upgradeability",
        severity: "low",
        confidence: 65,
        function_or_handler: "beacon",
        primary_account_or_authority: "beacon_admin",
        evidence: [`${source.path}:Beacon pattern detected`],
        trust_consequence: "beacon controls implementation for all proxy instances",
        exploit_path: "compromised beacon admin can upgrade all proxies at once",
        why_it_matters: "beacon pattern centralizes upgrade control - single point of failure",
        remediation: "Ensure beacon admin is multisig/DAO with timelock",
        ship_blocker: false
      });
      break;

    case "minimal":
      findings.push({
        kind: "FINDING",
        group_key: "minimal_proxy | upgradeability | upgradeability",
        title: "Minimal proxy pattern is not upgradeable",
        skill: "upgradeability",
        severity: "low",
        confidence: 80,
        function_or_handler: "minimal_proxy",
        primary_account_or_authority: "n/a",
        evidence: [`${source.path}:Minimal proxy pattern detected`],
        trust_consequence: "minimal proxies cannot be upgraded - implementation is immutable",
        exploit_path: "n/a - not upgradeable",
        why_it_matters: "minimal proxies are designed for immutability - this may be intentional",
        remediation: "If upgradeability is needed, consider UUPS or transparent proxy instead",
        ship_blocker: false
      });
      break;
  }

  return findings;
}

/**
 * Determine upgrade authority type
 */
function determineUpgradeAuthority(functions, proxyPattern) {
  const upgradeFuncs = functions.filter(f =>
    f.name.includes("upgrade") || f.name.includes("authorize")
  );

  if (upgradeFuncs.length === 0) {
    return proxyPattern === "none" ? "none" : "unknown";
  }

  // Check for multisig
  const hasMultisig = upgradeFuncs.some(f =>
    f.modifiers.some(m => /multisig|onlyDao/gi.test(m))
  );
  if (hasMultisig) return "multisig";

  // Check for timelock
  const hasTimelock = upgradeFuncs.some(f =>
    f.modifiers.some(m => /timelock/gi.test(m))
  );
  if (hasTimelock) return "timelock";

  // Check for single admin
  const hasSingleAdmin = upgradeFuncs.some(f =>
    f.modifiers.some(m => /^(onlyOwner|onlyAdmin)$/i.test(m))
  );
  if (hasSingleAdmin) return "single_eoa";

  return "unknown";
}

/**
 * Generate unique finding ID
 */
function generateId(source, index) {
  const hash = Buffer.from(`${source.path}:${index}`).toString("base64").slice(0, 8);
  return `upgradeability-${hash}`;
}

/**
 * Main analysis function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`[Upgradeability] Analyzing: ${args.target}`);

  // Read source files
  const sources = readSourceFiles(args.target);
  console.error(`[Upgradeability] Found ${sources.length} source file(s)`);

  const allFindings = [];
  let detectedPattern = "unknown";
  let isUpgradeable = false;
  let upgradeAuthority = "unknown";

  // Analyze each source file
  for (const source of sources) {
    console.error(`[Upgradeability] Analyzing: ${source.path}`);

    // Detect proxy pattern
    const proxyPattern = detectProxyPattern(source);
    if (proxyPattern !== "unknown" && proxyPattern !== "none") {
      detectedPattern = proxyPattern;
      isUpgradeable = true;
    }
    console.error(`[Upgradeability] Proxy pattern: ${proxyPattern}`);

    // Check for upgradeability issues
    const findings = checkUpgradeability(source, proxyPattern);
    allFindings.push(...findings);

    // Determine upgrade authority
    const upgradeFunctions = parseUpgradeFunctions(source);
    upgradeAuthority = determineUpgradeAuthority(upgradeFunctions, proxyPattern);
  }

  // Generate output
  const output = {
    specialist: "upgradeability",
    target: args.target,
    analysis_time: new Date().toISOString(),
    sources_analyzed: sources.length,
    proxy_pattern: detectedPattern,
    upgradeable: isUpgradeable,
    upgrade_authority: upgradeAuthority,
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
    console.error(`[Upgradeability] Output written to: ${args.output}`);
  }

  console.error(`[Upgradeability] Analysis complete: ${allFindings.length} finding(s)`);
}

/**
 * Format output as markdown
 */
function formatMarkdown(output) {
  let md = `# Upgradeability Analysis\n\n`;
  md += `**Target**: ${output.target}\n`;
  md += `**Analysis Time**: ${output.analysis_time}\n`;
  md += `**Sources Analyzed**: ${output.sources_analyzed}\n`;
  md += `**Proxy Pattern**: ${output.proxy_pattern}\n`;
  md += `**Upgradeable**: ${output.upgradeable ? "Yes" : "No"}\n`;
  md += `**Upgrade Authority**: ${output.upgrade_authority}\n`;
  md += `**Findings**: ${output.findings.length}\n\n`;

  if (output.findings.length === 0) {
    md += `✅ No upgradeability issues found.\n`;
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
