/**
 * OKX Security Wrapper
 *
 * Wraps okx-security skill commands for XLayer Trust Gate.
 * Provides token risk, transaction safety, and approval checks.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

class OKXSecurityWrapper {
  constructor() {
    this.cliPath = this.findOnchainOSCLI();
  }

  /**
   * Find OnchainOS CLI binary
   */
  findOnchainOSCLI() {
    const possiblePaths = [
      "~/.local/bin/onchainos",
      "/usr/local/bin/onchainos",
      "./onchainos"
    ];

    for (const path of possiblePaths) {
      const expandedPath = path.replace("~", process.env.HOME || "");
      if (existsSync(expandedPath)) {
        return expandedPath;
      }
    }

    return "onchainos"; // Assume it's in PATH
  }

  /**
   * Execute okx-security command
   */
  async execCommand(args, timeout = 30000) {
    try {
      const output = execFileSync(this.cliPath, args, {
        encoding: "utf8",
        stdio: "pipe",
        timeout
      });
      return JSON.parse(output);
    } catch (error) {
      if (error.stdout) {
        try {
          return JSON.parse(error.stdout);
        } catch {
          // Return error as-is if not JSON
        }
      }
      throw new Error(`OKX Security command failed: ${error.message}`);
    }
  }

  /**
   * Token Risk Scan
   * Detect honeypot, high tax, and other token risks
   *
   * @param {string} address - Token contract address
   * @param {string} chain - Chain name (xlayer, ethereum, etc.)
   * @returns {Promise<object>} Token risk report
   */
  async tokenScan(address, chain = "xlayer") {
    return await this.execCommand([
      "security",
      "token-scan",
      "--address", address,
      "--chain", chain
    ]);
  }

  /**
   * DApp/URL Phishing Scan
   * Check if a URL or domain is a phishing site
   *
   * @param {string} url - URL or domain to check
   * @returns {Promise<object>} Phishing risk report
   */
  async dappScan(url) {
    return await this.execCommand([
      "security",
      "dapp-scan",
      "--url", url
    ]);
  }

  /**
   * Transaction Pre-execution Scan
   * Check transaction safety before execution
   *
   * @param {string} from - Sender address
   * @param {string} to - Recipient contract address
   * @param {string} value - Native token value (hex)
   * @param {string} data - Calldata (hex)
   * @param {string} chain - Chain name
   * @returns {Promise<object>} Transaction risk report
   */
  async txScan(from, to, value, data, chain = "xlayer") {
    return await this.execCommand([
      "security",
      "tx-scan",
      "--from", from,
      "--to", to,
      "--value", value || "0x0",
      "--input-data", data || "0x",
      "--chain", chain
    ]);
  }

  /**
   * Signature Safety Scan
   * Check if a signature request is safe
   *
   * @param {string} from - Signer address
   * @param {string} message - Message to sign (for personalSign)
   * @param {string} chain - Chain name
   * @param {string} type - Signature type (personal, eip712)
   * @returns {Promise<object>} Signature safety report
   */
  async sigScan(from, message, chain = "xlayer", type = "personal") {
    const args = [
      "security",
      "sig-scan",
      "--from", from,
      "--message", message,
      "--chain", chain
    ];

    if (type === "eip712") {
      args.push("--type", "eip712");
    }

    return await this.execCommand(args);
  }

  /**
   * Token Approval Query
   * Query ERC20/Permit2 approvals for an address
   *
   * @param {string} address - Wallet address
   * @param {string} chain - Chain name
   * @returns {Promise<object>} Approval list
   */
  async getApprovals(address, chain = "xlayer") {
    return await this.execCommand([
      "security",
      "approvals",
      "--address", address,
      "--chain", chain
    ]);
  }

  /**
   * Convert OKX Security findings to XLayer Trust Gate format
   *
   * @param {string} source - okx-security command name
   * @param {object} result - OKX Security result
   * @param {string} target - Analysis target
   * @returns {Array} Formatted findings
   */
  convertToFindings(source, result, target) {
    const findings = [];

    // Process token-scan results
    if (source === "token-scan" && result.action) {
      const riskLevels = {
        "block": "critical",
        "warn": "high",
        "": "low"
      };

      const severity = riskLevels[result.action] || "medium";

      findings.push({
        kind: result.action === "block" ? "FINDING" : "LEAD",
        group_key: `token_risk | ${source} | okx-security`,
        title: `Token risk detected: ${result.action}`,
        skill: "okx-security",
        severity: severity,
        confidence: 85,
        function_or_handler: "token-scan",
        primary_account_or_authority: "token_contract",
        evidence: [target],
        trust_consequence: result.riskDescription || "Token may have security risks",
        exploit_path: "Interaction with risky token may lead to loss of funds",
        why_it_matters: "Token security is critical for DeFi operations",
        remediation: "Exercise caution or avoid interaction with this token",
        ship_blocker: result.action === "block"
      });

      // Add individual risk labels as findings
      if (result.riskItemDetail && Array.isArray(result.riskItemDetail)) {
        for (const item of result.riskItemDetail) {
          findings.push({
            kind: "LEAD",
            group_key: `token_label | ${item.label} | okx-security`,
            title: `Token risk label: ${item.label}`,
            skill: "okx-security",
            severity: "medium",
            confidence: 80,
            function_or_handler: "token-scan",
            primary_account_or_authority: "token_contract",
            evidence: [target],
            trust_consequence: item.description || `Token flagged with ${item.label} label`,
            exploit_path: "N/A",
            why_it_matters: "Risk labels indicate potential token issues",
            remediation: "Review token details before proceeding",
            ship_blocker: false
          });
        }
      }
    }

    // Process tx-scan results
    if (source === "tx-scan" && result.action) {
      const riskLevels = {
        "block": "critical",
        "warn": "high",
        "": "low"
      };

      const severity = riskLevels[result.action] || "medium";

      findings.push({
        kind: result.action === "block" ? "FINDING" : "LEAD",
        group_key: `tx_risk | ${source} | okx-security`,
        title: `Transaction risk detected: ${result.action}`,
        skill: "okx-security",
        severity: severity,
        confidence: 90,
        function_or_handler: "tx-scan",
        primary_account_or_authority: "tx_caller",
        evidence: [target],
        trust_consequence: result.message || "Transaction may have security risks",
        exploit_path: result.riskItemDetail?.[0]?.description || "Proceeding may lead to loss of funds",
        why_it_matters: "Pre-execution transaction check prevents fund loss",
        remediation: "Review transaction details or cancel operation",
        ship_blocker: result.action === "block"
      });
    }

    // Process dapp-scan results
    if (source === "dapp-scan" && result.riskType) {
      findings.push({
        kind: "FINDING",
        group_key: `phishing | ${source} | okx-security`,
        title: `Phishing detected: ${result.riskType}`,
        skill: "okx-security",
        severity: "critical",
        confidence: 95,
        function_or_handler: "dapp-scan",
        primary_account_or_authority: "dapp_url",
        evidence: [target],
        trust_consequence: result.description || "URL is flagged as phishing site",
        exploit_path: "Interacting with phishing site may lead to credential or fund theft",
        why_it_matters: "Phishing sites mimic legitimate interfaces to steal assets",
        remediation: "Avoid visiting this URL or interacting with this DApp",
        ship_blocker: true
      });
    }

    return findings;
  }
}

export default OKXSecurityWrapper;
