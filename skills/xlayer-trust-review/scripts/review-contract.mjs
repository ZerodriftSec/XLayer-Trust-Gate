#!/usr/bin/env node

/**
 * XLayer Trust Review - Main Orchestrator
 *
 * Coordinates OnchainOS skills and EVM specialists to produce
 * a comprehensive risk brief for XLayer contracts.
 */

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import OnchainOSWrapper from "../shared/onchainos-wrapper.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Parse command line arguments
 */
function parseArgs(argv) {
  const args = {
    target: null,
    action: "integrate",
    outDir: null,
    wallet: null,
    sampleTx: null
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--target" || arg === "-t") {
      args.target = argv[++i];
    } else if (arg === "--action" || arg === "-a") {
      args.action = argv[++i];
    } else if (arg === "--out-dir" || arg === "-o") {
      args.outDir = argv[++i];
    } else if (arg === "--wallet" || arg === "-w") {
      args.wallet = argv[++i];
    } else if (arg === "--sample-tx") {
      args.sampleTx = argv[++i];
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

  // Validate action
  const validActions = ["ship", "integrate", "allocate"];
  if (!validActions.includes(args.action)) {
    console.error(`Error: --action must be one of: ${validActions.join(", ")}`);
    process.exit(1);
  }

  return args;
}

function printHelp() {
  console.log(`
XLayer Trust Review - Complete Trust Gate for XLayer Contracts

Usage:
  node review-contract.mjs --target <ADDRESS|PATH> [OPTIONS]

Options:
  --target, -t         Contract address or local path (required)
  --action, -a         Action type: ship|integrate|allocate (default: integrate)
  --out-dir, -o        Output directory (default: /tmp/xlayer-trust-agent/)
  --wallet, -w         Wallet address (for approval checks in allocate mode)
  --sample-tx          Sample transaction to simulate
  --help, -h           Show this help message

Examples:
  # Review deployed contract for integration
  node review-contract.mjs --target 0x1234... --action integrate

  # Review local code before deployment
  node review-contract.mjs --target ./contracts/MyToken.sol --action ship

  # Review before allocating capital
  node review-contract.mjs --target 0x5678... --action allocate --wallet 0xabcd...

  # Custom output directory
  node review-contract.mjs --target 0x1234... --out-dir ./audits
`);
}

/**
 * Create output directory structure
 */
function createOutputDir(baseDir, target) {
  const reviewDir = join(baseDir, target);
  mkdirSync(reviewDir, { recursive: true });
  return reviewDir;
}

/**
 * Check if target is a contract address, local path, or GitHub repo URL
 */
function classifyTarget(target) {
  // Check if it looks like an EVM address (0x...)
  if (/^0x[a-fA-F0-9]{40}$/.test(target)) {
    return "address";
  }

  // Check if it's a GitHub file URL (contains /blob/) - must check BEFORE general github URL
  if (/^https?:\/\/github\.com\/[^\/]+\/[^\/]+\/blob\/.+\.(sol|json)/.test(target)) {
    return "github-file";
  }

  // Check if it's a GitHub repo URL
  const githubPatterns = [
    /^https?:\/\/github\.com\/[^\/]+\/[^\/]+/,
    /^github\.com\/[^\/]+\/[^\/]+/,
    /^[^\/]+\/[^\/]+\.git$/  // owner/repo.git format
  ];

  for (const pattern of githubPatterns) {
    if (pattern.test(target)) {
      return "github";
    }
  }

  // Check if it's a file path
  if (existsSync(target)) {
    return "path";
  }

  throw new Error(`Invalid target: ${target}. Must be an EVM address (0x...), local path, or GitHub repo URL.`);
}

/**
 * Clone GitHub repository
 */
async function cloneGitHubRepo(repoUrl, targetDir) {
  console.error(`[GitHub] Cloning repository: ${repoUrl}`);

  // Normalize GitHub URL
  let normalizedUrl = repoUrl;
  if (!normalizedUrl.startsWith('http')) {
    // Convert owner/repo or owner/repo.git to full URL
    const repoPath = normalizedUrl.replace(/\.git$/, '');
    normalizedUrl = `https://github.com/${repoPath}`;
  }

  // Generate unique temp directory name
  const tempDirName = `repo-${randomBytes(8).toString('hex')}`;
  const cloneDir = join(targetDir, tempDirName);

  try {
    // Clone the repository
    execFileSync('git', [
      'clone',
      '--depth', '1',  // Shallow clone for speed
      '--single-branch',
      normalizedUrl,
      cloneDir
    ], {
      stdio: 'pipe',
      timeout: 60000  // 60 second timeout
    });

    console.error(`[GitHub] ✓ Repository cloned to: ${cloneDir}`);
    return cloneDir;
  } catch (error) {
    throw new Error(`Failed to clone GitHub repository: ${error.message}`);
  }
}

/**
 * Find Solidity files in a directory
 */
function findSolidityFiles(dir) {
  const files = [];
  const { execSync } = require('node:child_process');

  try {
    const result = execSync(`find "${dir}" -name "*.sol" -type f`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });

    const filePaths = result.trim().split('\n').filter(f => f);
    return filePaths;
  } catch (error) {
    console.error(`[GitHub] Warning: Could not find .sol files: ${error.message}`);
    return [];
  }
}

/**
 * Step 1: Resolve Input
 */
async function resolveInput(target, targetType, reviewDir) {
  console.error(`\n[Step 1] Resolving input...`);

  const resolution = {
    target,
    target_type: targetType,
    timestamp: new Date().toISOString()
  };

  if (targetType === "address") {
    resolution.chain = "xlayer";
    resolution.address = target;
    // Source fetching would happen here in full implementation
    resolution.source_available = false; // Simplified for MVP
  } else if (targetType === "github-file") {
    console.error(`[Step 1] GitHub file URL detected`);

    // Parse GitHub file URL to extract repo and file path
    // Format: https://github.com/owner/repo/blob/branch/path/to/file.sol
    const urlMatch = target.match(/github\.com\/([^\/]+)\/([^\/]+)\/blob\/([^\/]+)\/(.+)$/);
    if (!urlMatch) {
      throw new Error(`Invalid GitHub file URL format: ${target}`);
    }

    const [, owner, repo, branch, filePath] = urlMatch;
    // Decode URL-encoded characters (e.g., %20 -> space)
    const decodedFilePath = decodeURIComponent(filePath);
    const repoUrl = `https://github.com/${owner}/${repo}`;
    const rawFileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;

    console.error(`[GitHub] Repository: ${owner}/${repo}`);
    console.error(`[GitHub] File: ${decodedFilePath}`);

    // Clone the repository
    const cloneDir = await cloneGitHubRepo(repoUrl, reviewDir);

    // Find the specific file
    const targetFile = join(cloneDir, decodedFilePath);

    if (!existsSync(targetFile)) {
      throw new Error(`File not found in cloned repository: ${filePath}`);
    }

    resolution.github_url = target;
    resolution.github_file_url = rawFileUrl;
    resolution.clone_path = cloneDir;
    resolution.target_file = targetFile;
    resolution.source_available = true;

    // For analysis, we use the target file directly
    resolution.analysis_path = targetFile;

    console.error(`[GitHub] ✓ Target file located: ${decodedFilePath}`);
  } else if (targetType === "github") {
    console.error(`[Step 1] GitHub repository detected`);

    // Clone the repository
    const cloneDir = await cloneGitHubRepo(target, reviewDir);

    // Find Solidity files
    const solidityFiles = findSolidityFiles(cloneDir);
    console.error(`[Step 1] Found ${solidityFiles.length} Solidity file(s)`);

    if (solidityFiles.length === 0) {
      throw new Error(`No Solidity files found in repository: ${target}`);
    }

    resolution.github_url = target;
    resolution.clone_path = cloneDir;
    resolution.solidity_files = solidityFiles;
    resolution.source_available = true;

    // For analysis, we'll use the clone directory as the path
    resolution.analysis_path = cloneDir;
  } else {
    resolution.path = target;
    resolution.source_available = true;
  }

  // Save resolution
  const resolutionPath = join(reviewDir, "resolution.json");
  writeFileSync(resolutionPath, JSON.stringify(resolution, null, 2));
  console.error(`[Step 1] ✓ Resolution saved to: ${resolutionPath}`);

  return resolution;
}

/**
 * Step 2: Run OnchainOS Analysis
 */
async function runOnchainOSAnalysis(target, targetType, action, reviewDir) {
  console.error(`\n[Step 2] Running OnchainOS analysis...`);

  const onchainos = new OnchainOSWrapper();
  const results = {
    timestamp: new Date().toISOString(),
    checks: {}
  };

  // Only run token-specific checks for deployed addresses
  if (targetType === "address") {
    try {
      console.error(`  → Token risk scan...`);
      results.checks.token_scan = await onchainos.scanTokenRisk(target, {
        chain: "xlayer"
      });
      console.error(`  ✓ Token scan complete`);
    } catch (error) {
      console.error(`  ⚠ Token scan failed: ${error.message}`);
      results.checks.token_scan = { error: error.message };
    }

    try {
      console.error(`  → Token info...`);
      results.checks.token_info = await onchainos.getTokenInfo(target, {
        chain: "xlayer"
      });
      console.error(`  ✓ Token info complete`);
    } catch (error) {
      console.error(`  ⚠ Token info failed: ${error.message}`);
      results.checks.token_info = { error: error.message };
    }
  }

  // Save OnchainOS results
  const onchainosResultsPath = join(reviewDir, "onchainos-results.json");
  writeFileSync(onchainosResultsPath, JSON.stringify(results, null, 2));
  console.error(`[Step 2] ✓ OnchainOS analysis saved to: ${onchainosResultsPath}`);

  return results;
}

/**
 * Step 3: Run EVM Analysis
 */
async function runEVMAnalysis(target, targetType, reviewDir, scriptDir, resolution) {
  console.error(`\n[Step 3] Running EVM static analysis...`);

  const results = {
    timestamp: new Date().toISOString(),
    specialists: {}
  };

  // Determine the actual path to analyze
  let analysisPath = target;
  if (resolution.analysis_path) {
    analysisPath = resolution.analysis_path;
  }

  // Define all specialists
  const specialists = [
    { name: "access_control", script: "access-control", displayName: "Access control" },
    { name: "upgradeability", script: "upgradeability", displayName: "Upgradeability" },
    { name: "proxy_risk", script: "proxy-risk", displayName: "Proxy risk" },
    { name: "ownership_powers", script: "ownership-powers", displayName: "Ownership & powers" },
    { name: "reentrancy", script: "reentrancy", displayName: "Reentrancy" },
    { name: "token_accounting", script: "token-accounting", displayName: "Token accounting" }
  ];

  // Run each specialist
  for (const specialist of specialists) {
    try {
      console.error(`  → ${specialist.displayName} analysis...`);
      const specialistScript = join(scriptDir, `../evm-specialists/${specialist.script}/scripts/analyze.mjs`);

      const output = execFileSync("node", [
        specialistScript,
        "--target", analysisPath,
        "--output", "-",
        "--format", "json"
      ], { encoding: "utf8" });

      results.specialists[specialist.name] = JSON.parse(output);
      const findingCount = results.specialists[specialist.name].findings?.length || 0;
      console.error(`  ✓ ${specialist.displayName} complete: ${findingCount} finding(s)`);
    } catch (error) {
      console.error(`  ⚠ ${specialist.displayName} analysis failed: ${error.message}`);
      results.specialists[specialist.name] = { error: error.message, findings: [] };
    }
  }

  // Save EVM results
  const evmResultsPath = join(reviewDir, "evm-analysis-results.json");
  writeFileSync(evmResultsPath, JSON.stringify(results, null, 2));
  console.error(`[Step 3] ✓ EVM analysis saved to: ${evmResultsPath}`);

  return results;
}

/**
 * Step 4: Aggregate Findings
 */
function aggregateFindings(onchainosResults, evmResults) {
  console.error(`\n[Step 4] Aggregating findings...`);

  const findings = [];

  // Process OnchainOS results
  if (onchainosResults.checks.token_scan) {
    const tokenScan = onchainosResults.checks.token_scan;
    // Convert OnchainOS format to our finding format
    if (tokenScan.action === "block" || tokenScan.action === "warn") {
      findings.push({
        id: `onchainos-token-scan-${Date.now()}`,
        title: `Token risk detected: ${tokenScan.action}`,
        source: "okx-security",
        severity: tokenScan.action === "block" ? "critical" : "high",
        confidence: 90,
        evidence: ["onchainos:token-scan"],
        trust_consequence: "Token may be unsafe to interact with",
        exploit_path: "Token may have high taxes, be a honeypot, or have other risks",
        why_it_matters: "Interacting with risky tokens can lead to loss of funds",
        remediation: "Review token details and proceed with caution",
        ship_blocker: tokenScan.action === "block"
      });
    }
  }

  // Process EVM analysis results from all specialists
  const specialistNames = ["access_control", "upgradeability", "proxy_risk", "ownership_powers", "reentrancy", "token_accounting"];

  for (const specialistName of specialistNames) {
    const specialistResult = evmResults.specialists[specialistName];
    if (specialistResult && specialistResult.findings) {
      const specialistFindings = specialistResult.findings || [];
      findings.push(...specialistFindings);
    }
  }

  console.error(`[Step 4] ✓ Aggregated ${findings.length} finding(s)`);

  return findings;
}

/**
 * Step 5: Judge and Output Risk Brief
 */
function judgeRiskBrief(findings, target, action) {
  console.error(`\n[Step 5] Judging risk for action: ${action}...`);

  // Calculate risk score
  let riskScore = 50;

  for (const finding of findings) {
    if (finding.severity === "critical") riskScore += 25;
    else if (finding.severity === "high") riskScore += 15;
    else if (finding.severity === "medium") riskScore += 5;
    else if (finding.severity === "low") riskScore += 1;
  }

  riskScore = Math.min(riskScore, 100);

  // Count findings by severity
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const shipBlockers = findings.filter(f => f.ship_blocker === true);

  // Make action-specific decision
  let recommendation;
  let whyThisVerdict;

  if (action === "ship") {
    if (criticalCount > 0 || riskScore > 70) {
      recommendation = "deny";
      whyThisVerdict = `Critical findings (${criticalCount}) or high risk score (${riskScore}) block deployment`;
    } else if (highCount > 0 || riskScore > 50) {
      recommendation = "warn";
      whyThisVerdict = `High-severity findings (${highCount}) or elevated risk score (${riskScore}) require review before deployment`;
    } else {
      recommendation = "allow";
      whyThisVerdict = `Acceptable risk profile for deployment (score: ${riskScore})`;
    }
  } else if (action === "integrate") {
    if (criticalCount >= 2 || riskScore > 80) {
      recommendation = "deny";
      whyThisVerdict = `Multiple critical findings (${criticalCount}) or very high risk score (${riskScore}) make integration unsafe`;
    } else if (criticalCount > 0 || riskScore > 60) {
      recommendation = "warn";
      whyThisVerdict = `Critical findings present or high risk score (${riskScore}) - review carefully before integrating`;
    } else {
      recommendation = "allow";
      whyThisVerdict = `Acceptable risk profile for integration (score: ${riskScore})`;
    }
  } else if (action === "allocate") {
    if (criticalCount > 0 || highCount > 0 || riskScore > 60) {
      recommendation = "deny";
      whyThisVerdict = `Any critical/high findings or elevated risk score (${riskScore}) block capital allocation`;
    } else if (riskScore > 40) {
      recommendation = "warn";
      whyThisVerdict = `Moderate risk score (${riskScore}) - review capital allocation carefully`;
    } else {
      recommendation = "allow";
      whyThisVerdict = `Acceptable risk profile for capital allocation (score: ${riskScore})`;
    }
  }

  const riskBrief = {
    target,
    action,
    recommendation,
    risk_score: riskScore,
    ship_blocker: shipBlockers.length > 0 || recommendation === "deny",
    why_this_verdict: whyThisVerdict,
    findings,
    sources: [
      "okx-security",
      "okx-dex-token",
      "evm-access-control",
      "evm-upgradeability",
      "evm-proxy-risk",
      "evm-ownership-powers",
      "evm-reentrancy",
      "evm-token-accounting"
    ],
    metadata: {
      timestamp: new Date().toISOString(),
      version: "0.1.0",
      chain: "xlayer",
      framework: "solidity"
    }
  };

  console.error(`[Step 5] ✓ Judgment: ${recommendation.toUpperCase()} (score: ${riskScore})`);

  return riskBrief;
}

/**
 * Generate human-readable report
 */
function generateReport(riskBrief, onchainosResults, evmResults) {
  let md = `# XLayer Trust Review Report\n\n`;
  md += `**Target**: \`${riskBrief.target}\`\n`;
  md += `**Action**: ${riskBrief.action}\n`;
  md += `**Recommendation**: ${riskBrief.recommendation.toUpperCase()}\n`;
  md += `**Risk Score**: ${riskBrief.risk_score}/100\n`;
  md += `**Ship Blocker**: ${riskBrief.ship_blocker ? "🚫 Yes" : "No"}\n`;
  md += `**Timestamp**: ${riskBrief.metadata.timestamp}\n\n`;

  md += `## Verdict\n\n`;
  md += `**${riskBrief.recommendation.toUpperCase()}** - ${riskBrief.why_this_verdict}\n\n`;

  if (riskBrief.findings.length === 0) {
    md += `## Findings\n\n`;
    md += `✅ No significant findings. This contract appears safe for ${riskBrief.action}.\n\n`;
  } else {
    md += `## Findings (${riskBrief.findings.length})\n\n`;

    for (const finding of riskBrief.findings) {
      md += `### ${finding.severity.toUpperCase()}: ${finding.title}\n\n`;
      md += `- **Source**: ${finding.source}\n`;
      md += `- **Confidence**: ${finding.confidence}%\n`;
      md += `- **Ship Blocker**: ${finding.ship_blocker ? "🚫 Yes" : "No"}\n`;

      if (finding.evidence && finding.evidence.length > 0) {
        md += `- **Evidence**: \`${finding.evidence.join("`, `")}\`\n`;
      }

      md += `\n`;
      md += `**Trust Consequence**: ${finding.trust_consequence}\n\n`;

      if (finding.exploit_path) {
        md += `**Exploit Path**: ${finding.exploit_path}\n\n`;
      }

      if (finding.why_it_matters) {
        md += `**Why It Matters**: ${finding.why_it_matters}\n\n`;
      }

      if (finding.remediation) {
        md += `**Remediation**: ${finding.remediation}\n\n`;
      }

      md += `---\n\n`;
    }
  }

  md += `## Analysis Sources\n\n`;
  md += `- okx-security (token risk, honeypot detection)\n`;
  md += `- okx-dex-token (token info, liquidity)\n`;
  md += `- evm-access-control (access control analysis)\n`;
  md += `- evm-upgradeability (upgrade mechanism analysis)\n`;
  md += `- evm-proxy-risk (proxy pattern safety)\n`;
  md += `- evm-ownership-powers (privilege and governance analysis)\n`;
  md += `- evm-reentrancy (reentrancy vulnerability detection)\n`;
  md += `- evm-token-accounting (token and vault accounting analysis)\n\n`;

  md += `---\n\n`;
  md += `Generated by [XLayer Trust Agent](https://github.com/xlayer-trust-agent)\n`;

  return md;
}

/**
 * Main function
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));

  console.error(`\n╔════════════════════════════════════════════════════════════╗`);
  console.error(`║        XLayer Trust Agent - Contract Review              ║`);
  console.error(`╚════════════════════════════════════════════════════════════╝`);
  console.error(`\nTarget: ${args.target}`);
  console.error(`Action: ${args.action}`);

  // Classify target first (before checking OnchainOS)
  console.error(`\n[Pre-flight] Classifying target...`);
  const targetType = classifyTarget(args.target);
  console.error(`Type: ${targetType}`);

  // Check OnchainOS configuration (only for address targets)
  let onchainos = null;
  if (targetType === "address") {
    console.error(`\n[Pre-flight] Checking OnchainOS CLI configuration...`);
    onchainos = new OnchainOSWrapper();
    const configCheck = onchainos.checkConfiguration();
    if (!configCheck.ok) {
      console.error(`\n❌ Configuration Error:`);
      console.error(configCheck.error);
      console.error(`\nThis skill requires OnchainOS CLI to be installed and configured.`);
      console.error(`Please fix the above issues and try again.\n`);
      process.exit(1);
    }
    console.error(`✓ OnchainOS CLI configured correctly`);
  } else {
    console.error(`\n[Info] Skipping OnchainOS CLI check (not required for ${targetType} targets)`);
  }

  // Create output directory
  const outDir = args.outDir || "/tmp/xlayer-trust-agent";
  const reviewDir = createOutputDir(outDir, args.target);
  console.error(`Output: ${reviewDir}`);

  try {
    // Step 1: Resolve Input
    const resolution = await resolveInput(args.target, targetType, reviewDir);

    // Step 2: Run OnchainOS Analysis
    const onchainosResults = await runOnchainOSAnalysis(
      args.target,
      targetType,
      args.action,
      reviewDir
    );

    // Step 3: Run EVM Analysis
    const evmResults = await runEVMAnalysis(
      args.target,
      targetType,
      reviewDir,
      __dirname,
      resolution
    );

    // Step 4: Aggregate Findings
    const findings = aggregateFindings(onchainosResults, evmResults);

    // Save aggregated findings
    const aggregatedPath = join(reviewDir, "aggregated-findings.json");
    writeFileSync(aggregatedPath, JSON.stringify({ findings }, null, 2));

    // Step 5: Judge and Output Risk Brief
    const riskBrief = judgeRiskBrief(findings, args.target, args.action);

    // Save risk brief
    const riskBriefPath = join(reviewDir, "judged-risk-brief.json");
    writeFileSync(riskBriefPath, JSON.stringify(riskBrief, null, 2));
    console.error(`\n✅ Risk brief saved to: ${riskBriefPath}`);

    // Generate human-readable report
    const report = generateReport(riskBrief, onchainosResults, evmResults);
    const reportPath = join(reviewDir, "report.md");
    writeFileSync(reportPath, report);
    console.error(`✅ Report saved to: ${reportPath}`);

    // Print summary
    console.error(`\n╔════════════════════════════════════════════════════════════╗`);
    console.error(`║                     Review Complete                        ║`);
    console.error(`╚════════════════════════════════════════════════════════════╝`);
    console.error(`\n📊 Summary:`);
    console.error(`   Recommendation: ${riskBrief.recommendation.toUpperCase()}`);
    console.error(`   Risk Score: ${riskBrief.risk_score}/100`);
    console.error(`   Findings: ${findings.length}`);
    console.error(`   Ship Blocker: ${riskBrief.ship_blocker ? "🚫 YES" : "✅ NO"}`);
    console.error(`\n📁 Artifacts:`);
    console.error(`   ${reviewDir}/`);
    console.error(`\n`);

  } catch (error) {
    console.error(`\n❌ Error: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run main
main().catch(error => {
  console.error(error);
  process.exit(1);
});
