/**
 * OnchainOS CLI Wrapper
 *
 * Provides a JavaScript interface to OnchainOS CLI commands.
 * Handles token scanning, security checks, and transaction simulation.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

export class OnchainOSWrapper {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.OKX_API_KEY;
    this.secretKey = options.secretKey || process.env.OKX_SECRET_KEY;
    this.passphrase = options.passphrase || process.env.OKX_PASSPHRASE;
    this.defaultChain = options.defaultChain || "xlayer";
    this.verbose = options.verbose || false;
  }

  /**
   * Execute OnchainOS command and return parsed output
   */
  _exec(commandArgs) {
    try {
      if (this.verbose) {
        console.log(`[OnchainOS] Executing: onchainos ${commandArgs.join(" ")}`);
      }

      const result = execFileSync(
        "onchainos",
        commandArgs,
        {
          encoding: "utf8",
          env: {
            ...process.env,
            OKX_API_KEY: this.apiKey,
            OKX_SECRET_KEY: this.secretKey,
            OKX_PASSPHRASE: this.passphrase
          },
          timeout: 30000 // 30 second timeout
        }
      );

      return { success: true, data: result };
    } catch (error) {
      // OnchainOS may return non-zero exit code but still have output
      const output = error.stdout || error.stderr || "";
      if (output) {
        try {
          // Try to parse JSON output
          return { success: true, data: output };
        } catch {
          return { success: false, error: error.message, output };
        }
      }
      return {
        success: false,
        error: error.message,
        code: error.code,
        output: error.stderr
      };
    }
  }

  /**
   * Parse JSON output from OnchainOS
   */
  _parseJSON(output) {
    try {
      // Handle cases where output contains non-JSON prefix/suffix
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
      return JSON.parse(output);
    } catch (error) {
      console.error("[OnchainOS] Failed to parse JSON:", error.message);
      return null;
    }
  }

  /**
   * Check if OnchainOS CLI is installed
   */
  isInstalled() {
    try {
      const result = execFileSync("onchainos", ["--version"], {
        encoding: "utf8",
        stdio: "pipe"
      });
      return result.includes("onchainos");
    } catch {
      return false;
    }
  }

  /**
   * Check if OnchainOS CLI is properly configured
   * Returns { ok: boolean, error?: string }
   */
  checkConfiguration() {
    // Check if CLI is installed
    if (!this.isInstalled()) {
      return {
        ok: false,
        error: "OnchainOS CLI is not installed. Please install it first:\n" +
               "  npx skills add okx/onchainos-skills\n\n" +
               "Or install manually:\n" +
               "  curl -sSL https://raw.githubusercontent.com/okx/onchainos-skills/main/install.sh | sh"
      };
    }

    // Check if API credentials are configured
    if (!this.apiKey || !this.secretKey || !this.passphrase) {
      return {
        ok: false,
        error: "OKX API credentials are not configured.\n\n" +
               "Please set the following environment variables:\n" +
               "  OKX_API_KEY\n" +
               "  OKX_SECRET_KEY\n" +
               "  OKX_PASSPHRASE\n\n" +
               "Get your API keys from: https://web3.okx.com/onchain-os/dev-portal\n\n" +
               "Create a .env file in your project root with:\n" +
               "  OKX_API_KEY=your-key\n" +
               "  OKX_SECRET_KEY=your-secret\n" +
               "  OKX_PASSPHRASE=your-passphrase"
      };
    }

    return { ok: true };
  }

  // ============ Security Commands ============

  /**
   * Token risk scan (token-scan)
   * Detects honeypots, high tax tokens, and other risks
   */
  async scanTokenRisk(address, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "security",
      "token-scan",
      "--address",
      address,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * DApp/URL phishing detection (dapp-scan)
   */
  async scanDApp(url, options = {}) {
    const args = ["security", "dapp-scan", "--url", url];
    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Transaction pre-execution security scan (tx-scan)
   */
  async scanTransaction(txData, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "security",
      "tx-scan",
      "--tx",
      txData,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Signature safety check (sig-scan)
   */
  async scanSignature(signatureData, options = {}) {
    const args = [
      "security",
      "sig-scan",
      "--sig",
      signatureData
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Token approval query (approvals)
   */
  async queryApprovals(address, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "security",
      "approvals",
      "--address",
      address,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  // ============ DEX Token Commands ============

  /**
   * Get token information
   */
  async getTokenInfo(address, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "dex",
      "token",
      "info",
      "--address",
      address,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Get token holders
   */
  async getTokenHolders(address, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "dex",
      "token",
      "holders",
      "--address",
      address,
      "--chain",
      chain
    ];

    if (options.limit) args.push("--limit", options.limit.toString());

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  // ============ Gateway Commands ============

  /**
   * Simulate transaction
   */
  async simulateTransaction(txData, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "gateway",
      "simulate",
      "--tx",
      txData,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Broadcast transaction
   */
  async broadcastTransaction(signedTx, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "gateway",
      "broadcast",
      "--tx",
      signedTx,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Estimate gas
   */
  async estimateGas(txData, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "gateway",
      "estimate-gas",
      "--tx",
      txData,
      "--chain",
      chain
    ];

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  // ============ Agentic Wallet Commands ============

  /**
   * Get wallet balance
   */
  async getWalletBalance(address, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "wallet",
      "balance",
      "--address",
      address,
      "--chain",
      chain
    ];

    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }

  /**
   * Get transaction history
   */
  async getWalletHistory(address, options = {}) {
    const chain = options.chain || this.defaultChain;
    const args = [
      "wallet",
      "history",
      "--address",
      address,
      "--chain",
      chain
    ];

    if (options.limit) args.push("--limit", options.limit.toString());
    if (options.json !== false) args.push("--json");

    const result = this._exec(args);
    if (!result.success) {
      return { error: result.error, output: result.output };
    }

    const parsed = this._parseJSON(result.data);
    return parsed;
  }
}

export default OnchainOSWrapper;
