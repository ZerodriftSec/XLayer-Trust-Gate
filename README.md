# XLayer Trust Gate

Agent-native security judgment layer for XLayer contracts. Orchestrates OnchainOS skills with EVM static analysis to produce machine-readable risk briefs for deployment, integration, and capital allocation decisions.

## Available Skills

| Skill | Description |
|-------|-------------|
| `xlayer-trust-review` | Complete contract trust review: address/local/GitHub targets → 6 EVM specialists + OnchainOS integration → action-specific risk judgment |

## EVM Specialists

| Specialist | Focus |
|------------|-------|
| `access-control` | Missing permissions, privilege escalation, role concentration |
| `upgradeability` | Proxy patterns, upgrade mechanisms, admin key risks |
| `proxy-risk` | Delegatecall vulnerabilities, storage slot conflicts |
| `ownership-powers` | Centralization risks, missing multisig/timelock |
| `reentrancy` | Reentrancy vulnerabilities, unsafe external callbacks |
| `token-accounting` | Balance manipulation, precision loss, vault vulnerabilities |

## Prerequisites

- Node.js 20+
- OnchainOS CLI (for address targets only)
- OKX API credentials (for OnchainOS integration)

```bash
# Install OnchainOS CLI
npx skills add okx/onchainos-skills

# Configure OKX API credentials
export OKX_API_KEY=your-key
export OKX_SECRET_KEY=your-secret
export OKX_PASSPHRASE=your-passphrase
```

Get API keys from: https://web3.okx.com/onchain-os/dev-portal

> **Note**: For local paths and GitHub URLs, OnchainOS CLI is not required.

## Installation

```bash
git clone https://github.com/ZerodriftSec/XLayer-Trust-Gate.git
cd XLayer-Trust-Gate
npm install
```

## Skill Workflows

**Pre-Deployment**: `xlayer-trust-review` (local path) → ship verdict → deploy or fix critical issues

**Pre-Integration**: `xlayer-trust-review` (contract address) → integrate verdict → connect or avoid risky protocols

**Pre-Allocation**: `xlayer-trust-review` (address + wallet) → allocate verdict → route capital or blacklist

**GitHub Contract Audit**: `xlayer-trust-review` (GitHub file URL) → full analysis + report

## Usage

```bash
# Review deployed contract for integration
npm run review-contract -- --target 0x... --action integrate

# Review local code before deployment
npm run review-contract -- --target ./contracts/ --action ship

# Review before allocating capital
npm run review-contract -- --target 0x... --action allocate --wallet 0x...

# Review GitHub contract
npm run review-contract -- --target "https://github.com/user/repo/blob/main/Contract.sol" --action ship
```

## Output

All analysis results are written to `/tmp/xlayer-trust-agent/<target>/`:

```
/tmp/xlayer-trust-agent/<target>/
├── judged-risk-brief.json       # Machine-readable risk assessment
├── report.md                     # Human-readable report
├── onchainos-results.json        # Raw OnchainOS outputs (if applicable)
└── evm-analysis-results.json     # Raw EVM analysis outputs
```

### Risk Brief Schema

```json
{
  "target": "0x... | ./path | https://github.com/...",
  "action": "ship|integrate|allocate",
  "recommendation": "allow|warn|deny",
  "risk_score": 0-100,
  "ship_blocker": true|false,
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
      "remediation": "how to fix"
    }
  ]
}
```

## Action-Specific Judgment

Different risk thresholds for different actions:

| Action | Threshold | Deny Criteria |
|--------|-----------|---------------|
| **ship** | High scrutiny | ANY critical OR risk_score > 70 |
| **integrate** | Medium scrutiny | 2+ critical OR risk_score > 80 |
| **allocate** | Conservative | ANY critical/high OR risk_score > 60 |

## OnchainOS Integration

Depends on OnchainOS Skills for address targets:

- `okx-security` - Token risk, honeypot detection, phishing scan
- `okx-dex-token` - Token info, liquidity, holder analysis
- `okx-onchain-gateway` - Transaction simulation, gas estimation

## Project Structure

```
xlayer-trust-agent/
└── skills/
    └── xlayer-trust-review/
        ├── SKILL.md                   # Skill definition
        ├── scripts/
        │   └── review-contract.mjs     # Main orchestrator
        ├── evm-specialists/            # 6 EVM analysis modules
        │   ├── access-control/
        │   ├── upgradeability/
        │   ├── proxy-risk/
        │   ├── ownership-powers/
        │   ├── reentrancy/
        │   └── token-accounting/
        └── shared/                     # Shared utilities
            ├── onchainos-wrapper.mjs
            └── xlayer-risk-brief.schema.json
```

## License

MIT

## Acknowledgments

Built on top of [OKX OnchainOS Skills](https://github.com/okx/onchainos-skills)
