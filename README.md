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

**Recommended**

```
npx skills add ZerodriftSec/XLayer-Trust-Gate
```


## Usage


```
claude

/xlayer-trust-review <path-to-project>
```

## Skill Workflows

**Pre-Deployment**: `xlayer-trust-review` (local path) → ship verdict → deploy or fix critical issues

**Pre-Integration**: `xlayer-trust-review` (contract address) → integrate verdict → connect or avoid risky protocols

**Pre-Allocation**: `xlayer-trust-review` (address + wallet) → allocate verdict → route capital or blacklist

**GitHub Contract Audit**: `xlayer-trust-review` (GitHub file URL) → full analysis + report

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

### Core Skills Used

| Skill | Commands | Purpose |
|-------|----------|---------|
| `okx-security` | token-scan, tx-scan, dapp-scan, sig-scan, approvals | Token risk, honeypot detection, phishing scan |
| `okx-dex-token` | token info, liquidity, holders | Token metadata, market data, holder analysis |
| `okx-onchain-gateway` | simulate, broadcast | Transaction simulation, gas estimation |

### OKX Security Wrapper

Our project includes a custom wrapper (`shared/okx-security-wrapper.mjs`) that:

- ✅ Wraps all 5 okx-security commands
- ✅ Converts OKX findings to XLayer Trust Gate format
- ✅ Provides unified interface for token/tx/dapp/sig/approval checks
- ✅ Enables action-specific risk judgment

**Supported Operations:**
- `tokenScan(address, chain)` - Check token security
- `txScan(from, to, value, data, chain)` - Pre-execution transaction check
- `dappScan(url)` - Phishing detection
- `sigScan(from, message, chain, type)` - Signature safety
- `getApprovals(address, chain)` - Query ERC20/Permit2 approvals

**Note**: OnchainOS skills focus on **runtime transaction/token risks**, not static source code analysis. Our EVM specialists complement this with static code analysis.

## Project Structure

```
xlayer-trust-agent/
└── skills/
    └── xlayer-trust-review/
        ├── SKILL.md                      # Skill definition
        ├── scripts/
        │   └── review-contract.mjs       # Main orchestrator
        ├── evm-specialists/              # 6 EVM analysis modules
        │   ├── access-control/
        │   ├── upgradeability/
        │   ├── proxy-risk/
        │   ├── ownership-powers/
        │   ├── reentrancy/
        │   └── token-accounting/
        └── shared/                       # Shared utilities
            ├── onchainos-wrapper.mjs     # OnchainOS CLI wrapper
            ├── okx-security-wrapper.mjs  # OKX Security wrapper
            └── xlayer-risk-brief.schema.json
```

## Agentic Wallet

**Project Identity (Skills Arena Submission):**
- **EVM:** `0x32eccee2d292112781c31a4d69384f558b724269` (XLayer, Ethereum, Polygon + 18 EVM chains)
- **Solana:** `Fz4YdiD8VvKcFg2F5SApgppYE84w4U2RHd7CqsdsUa1j`

**Hackathon Submission - Skills Arena**

This project participates in OKX BuildX Hackathon - Skills Arena:

| Requirement | Status |
|-------------|--------|
| Agentic Wallet created | ✅ See above |
| OnchainOS Skill integration | ✅ `okx-security`, `okx-dex-token`, `okx-onchain-gateway` |
| Public GitHub repo | ✅ https://github.com/ZerodriftSec/XLayer-Trust-Gate |
| README complete | ✅ Project intro, architecture, OnchainOS usage, XLayer positioning |

**XLayer Ecosystem Positioning:**

XLayer Trust Gate serves as the **security judgment layer** for XLayer agents:
- Pre-deployment gate for XLayer contract deployments
- Pre-integration check for XLayer protocol dependencies
- Pre-allocation filter for capital routing to XLayer DeFi
- Reduces agent risk exposure in XLayer ecosystem

**Team:** XLayer Trust Agent Team

## License

MIT

## Acknowledgments

Built on top of [OKX OnchainOS Skills](https://github.com/okx/onchainos-skills)
