# XLayer Trust Agent

> Agent-native security judgment layer for XLayer builders, integration agents, and onchain operators.

**⚠️ Important**: This is a **skill repository** for Claude Code. All analysis outputs are written to `/tmp/xlayer-trust-agent/`. **OnchainOS CLI must be installed and configured** before use.

## What It Is

XLayer Trust Agent is a **machine-readable security judgment layer** that provides trust decisions for agents in these scenarios:

- **Pre-Deployment Check**: Determine whether code is safe to deploy
- **Pre-Integration Check**: Determine whether a protocol is trustworthy enough to integrate
- **Pre-Capital-Allocation Check**: Determine whether it's safe to allocate funds

## Prerequisites

**Required:**
- Node.js 20+
- **OnchainOS CLI** (installed and configured in your environment)
- **OKX API credentials** (configured in your OnchainOS environment)

```bash
# Install OnchainOS CLI (if not already installed)
npx skills add okx/onchainos-skills

# Or install manually
curl -sSL https://raw.githubusercontent.com/okx/onchainos-skills/main/install.sh | sh
```

**Configure OKX API credentials in your environment:**

```bash
# Set environment variables in your shell profile (~/.bashrc, ~/.zshrc, etc.)
export OKX_API_KEY=your-api-key
export OKX_SECRET_KEY=your-secret-key
export OKX_PASSPHRASE=your-passphrase
```

**Get API keys from:** https://web3.okx.com/onchain-os/dev-portal

> **Note:** This skill repository uses your **local OnchainOS CLI configuration**. No `.env` file is needed in this project directory.

## Installation

```bash
# Clone this repository
cd /path/to/xlayer-trust-agent

# Install dependencies
npm install
```

## Usage

### Quick Start

```bash
# Review a contract for integration
npm run review-contract -- --target 0x... --action integrate

# Review local code before deployment
npm run review-contract -- --target ./contracts/ --action ship

# Review before allocating capital
npm run review-contract -- --target 0x... --action allocate --wallet 0x...
```

### Output Location

**All analysis results are written to:**
```
/tmp/xlayer-trust-agent/<target>/
├── judged-risk-brief.json       # Machine-readable risk assessment
├── report.md                     # Human-readable report
├── onchainos-results.json        # Raw OnchainOS outputs
└── evm-analysis-results.json     # Raw EVM analysis outputs
```

### Error Handling

**If OnchainOS CLI is not installed or configured:**

The script will **fail fast** with a clear error message:
```
❌ Configuration Error:
OnchainOS CLI is not installed. Please install it first:
  npx skills add okx/onchainos-skills

Or install manually:
  curl -sSL https://raw.githubusercontent.com/okx/onchainos-skills/main/install.sh | sh
```

**If OKX API credentials are not configured:**

```
❌ Configuration Error:
OKX API credentials are not configured.

Please set the following environment variables:
  OKX_API_KEY
  OKX_SECRET_KEY
  OKX_PASSPHRASE

Get your API keys from: https://web3.okx.com/onchain-os/dev-portal
```

## Architecture

```
Input Layer → Orchestration Layer → Trust Judgment Layer → Output Layer
                     │
         ┌───────────┴───────────┐
         │                       │
  OnchainOS Skills        Your EVM Specialists
  (token/transaction risk)  (access control/proxy/upgrade)
```

### Layer Descriptions

**Input Layer**
- Resolve contract addresses, local paths, GitHub repos
- Normalize input formats

**Orchestration Layer**
- Trigger OnchainOS skills (okx-security, okx-dex-token, etc.)
- Trigger EVM static analysis specialists
- Collect all results

**Trust Judgment Layer (Your Core Value)**
- Integrate OnchainOS and EVM analysis results
- Action-specific risk assessment
- Machine-readable trust decision

**Output Layer**
- Output JSON risk brief
- Generate human-readable report
- Provide remediation suggestions

## Quick Start

### Prerequisites

- Node.js 20+
- OnchainOS CLI (`onchainos`)
- OKX API credentials (for OnchainOS)

```bash
# Install OnchainOS
npx skills add okx/onchainos-skills

# Set up API credentials
echo "OKX_API_KEY=your-key" > .env
echo "OKX_SECRET_KEY=your-secret" >> .env
echo "OKX_PASSPHRASE=your-passphrase" >> .env
```

### Install XLayer Trust Agent

```bash
cd /path/to/xlayer-trust-agent
npm install
```

### Usage Examples

#### 1. Integration Check

```bash
npm run review-contract -- --target 0x... --action integrate
```

#### 2. Deployment Check

```bash
npm run review-contract -- --target ./my-contract/ --action ship
```

#### 3. Capital Flow Check

```bash
npm run review-contract -- --target 0x... --wallet 0x... --action allocate
```

#### 4. Full Contract Review

```bash
npm run review-contract -- --target 0x... --action integrate --out-dir ./audits
```

## Skills Overview

### Main Skills

| Skill | Purpose | When to Use |
|-------|---------|-------------|
| `xlayer-trust-review` | Complete contract trust review workflow | Need comprehensive risk assessment |
| `xlayer-integration-check` | Pre-integration check | Before integrating third-party protocols |
| `xlayer-deployment-check` | Pre-deployment check | Before deploying contracts |
| `xlayer-capital-check` | Pre-capital-allocation check | Before allocating funds |

### EVM Specialists

| Specialist | Focus | Detects |
|------------|-------|---------|
| `access-control` | Access control analysis | Missing permissions, privileged function exposure |
| `upgradeability` | Upgradeability risk | Proxy patterns, upgrade mechanism defects |
| `proxy-risk` | Proxy pattern risk | Proxy vulnerabilities, slot conflicts |
| `ownership-powers` | Ownership & privilege | Role concentration, missing multisig/timelock |
| `reentrancy` | Reentrancy vulnerability | Classic/cross-function/callback reentrancy |

### Run Individual Specialists

```bash
npm run analyze-access-control -- --target ./contracts/
npm run analyze-upgradeability -- --target ./contracts/
npm run analyze-proxy-risk -- --target ./contracts/
npm run analyze-ownership-powers -- --target ./contracts/
npm run analyze-reentrancy -- --target ./contracts/
```

## Output Format

### Risk Brief JSON Schema

```json
{
  "target": "0x...",
  "action": "ship|integrate|allocate",
  "recommendation": "allow|warn|deny",
  "risk_score": 0-100,
  "ship_blocker": boolean,
  "findings": [
    {
      "id": "unique-id",
      "title": "Finding title",
      "severity": "critical|high|medium|low",
      "confidence": 0-100,
      "source": "okx-security|evm-access-control|...",
      "evidence": ["file:line", ...],
      "trust_consequence": "what can happen",
      "exploit_path": "how to exploit",
      "why_it_matters": "impact analysis"
    }
  ],
  "sources": [
    "okx-security",
    "okx-dex-token",
    "evm-access-control",
    "evm-upgradeability",
    "evm-proxy-risk",
    "evm-ownership-powers",
    "evm-reentrancy"
  ],
  "metadata": {
    "timestamp": "2025-04-15T...",
    "chain": "xlayer",
    "framework": "solidity"
  }
}
```

## Integration with OnchainOS

XLayer Trust Agent depends on the following OnchainOS Skills:

- `okx-security` - Token risk scanning, DApp phishing detection, transaction pre-execution
- `okx-dex-token` - Token information, liquidity, holder analysis
- `okx-onchain-gateway` - Transaction simulation, gas estimation
- `okx-agentic-wallet` - Wallet operations (for capital flow scenarios)

## Development

### Running Specialists

```bash
# Run individual EVM specialists
npm run analyze-access-control -- --target ./contracts/
npm run analyze-upgradeability -- --target ./contracts/
npm run analyze-proxy-risk -- --target ./contracts/
npm run analyze-ownership-powers -- --target ./contracts/
npm run analyze-reentrancy -- --target ./contracts/

# Run full review
npm run review-contract -- --target ./contracts/ --action ship
```

### Testing OnchainOS Integration

```bash
# Test OnchainOS CLI directly
onchainos security token-scan --address 0x... --chain xlayer
onchainos dex token info --address 0x... --chain xlayer

# Verify installation
onchainos --version
```

## Project Structure

```
xlayer-trust-agent/
├── skills/
│   └── xlayer-trust-review/          # Main orchestrator skill
│       ├── SKILL.md                   # Skill definition
│       ├── scripts/                   # Main execution script
│       ├── evm-specialists/           # EVM static analysis specialists
│       │   ├── access-control/        # ✅ Implemented
│       │   ├── upgradeability/        # ✅ Implemented
│       │   ├── proxy-risk/            # ✅ Implemented
│       │   ├── ownership-powers/      # ✅ Implemented
│       │   └── reentrancy/            # ✅ Implemented
│       └── shared/                    # Shared utilities and schemas
├── test-contracts/                    # Example contracts for testing
├── package.json
├── README.md
└── .claude-plugin/plugin.json
```

## Hackathon Submission

### OKX BuildX Hackathon

This project satisfies all requirements:

- ✅ **Deploy on XLayer** - All reviews target XLayer contracts
- ✅ **Use OnchainOS Skills** - Integrates okx-security, okx-dex-token, okx-gateway
- ✅ **Use Agentic Wallet** - Leverages okx-agentic-wallet for capital flow scenarios
- ✅ **Agent-native workflow** - Outputs machine-readable risk briefs
- ✅ **Original value** - Adds EVM static analysis + action-specific judgment

### Implemented Specialists

| Status | Specialist | Description |
|--------|-----------|-------------|
| ✅ | access-control | Missing permissions, privilege escalation |
| ✅ | upgradeability | Proxy patterns, upgrade mechanisms |
| ✅ | proxy-risk | Delegatecall risks, slot conflicts |
| ✅ | ownership-powers | Role concentration, governance risks |
| ✅ | reentrancy | Reentrancy vulnerabilities, unsafe callbacks |

### OnchainOS Integration (Pause/Freeze/Blacklist)

Pause/freeze/blacklist detection **relies on OnchainOS**:

```bash
# OnchainOS provides:
onchainos security tx-scan --chain xlayer --from 0x... --data 0x...
# Detects: black_tag, ACCOUNT_IN_RISK, SPENDER_ADDRESS_BLACK

onchainos security token-scan --chain xlayer --address 0x...
# Detects: honeypot, high tax, blacklist, freeze risks
```

### External Call Detection

External call risks **rely on OnchainOS**:

```bash
onchainos security tx-scan --chain xlayer ...
# Detects: approve_eoa, approve_anycall_contract, multicall_phishing_risk
```

## License

MIT

## Acknowledgments

- Built on top of [OKX OnchainOS Skills](https://github.com/okx/onchainos-skills)
- Inspired by [Sealevel Guard](https://github.com/NewmanXBT/sealevel-guard)
