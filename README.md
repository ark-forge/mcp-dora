# mcp-dora — DORA Compliance Scanner

**Digital Operational Resilience Act (EU) 2022/2554** compliance scanner as an MCP server.

DORA has been in force since **January 17, 2025**. It applies to banks, payment institutions, investment firms, crypto CASPs, insurers, and ICT service providers operating in the EU.

[![PyPI version](https://img.shields.io/pypi/v/mcp-dora)](https://pypi.org/project/mcp-dora/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Quick Install

```bash
pip install mcp-dora
```

Add to your Claude Desktop config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dora": {
      "command": "python3",
      "args": ["-m", "mcp_dora"],
      "env": {}
    }
  }
}
```

Or use the CLI:

```bash
dora-scanner /path/to/project --entity credit_institution
```

---

## 7 Tools

| Tool | DORA Articles | Plan |
|------|--------------|------|
| `scan_project` | Art.9, 10, 11, 17, 24, 25, 28, 31 | Free |
| `classify_entity` | All | Free |
| `assess_organization` | Art.5, 6, 11, 17, 18, 19, 26, 28, 30, 31 | Free |
| `generate_report` | Combined | Free |
| `generate_ict_register` | **Art.31** | Pro |
| `generate_incident_template` | **Art.17-18** | Pro |
| `certify_report` | All | Certified |

### `scan_project`

Scans source code for DORA compliance gaps:

- **Art. 9** — Hardcoded credentials, missing secrets management
- **Art. 10 + 17** — Mutable logging files (tamper-prone incident records)
- **Art. 11** — Missing retry logic and circuit breakers for external calls
- **Art. 24 + 25** — Missing security testing tooling (bandit, semgrep, safety)
- **Art. 28 + 31** — ICT third-party dependencies (AWS, Stripe, Kafka, etc.)

### `classify_entity`

Returns all DORA articles applicable to your entity type:

```
credit_institution | payment_institution | e_money_institution
investment_firm | crypto_casp | insurance_undertaking
ict_provider | trading_venue | central_counterparty
```

### `assess_organization`

Scores DORA organizational readiness from YES/NO answers across 12 checks covering Art.5, 6, 11, 17, 18, 19, 26, 28, 30, 31.

### `generate_ict_register` *(Pro)*

Auto-generates your **Art. 31 ICT third-party register** from a code scan — detects vendors and scaffolds all mandatory fields (classification, SLA, audit rights, data location, exit strategy).

### `generate_incident_template` *(Pro)*

Generates an **Art. 17-18 incident management template** with:
- Classification framework (major / significant / minor)
- Regulatory reporting deadlines (initial: 4h, intermediate: 72h, final: 1 month)
- Full incident record fields

### `certify_report` *(Certified)*

Certifies your DORA compliance report with **ArkForge Trust Layer**: Ed25519 signature + RFC 3161 timestamp + Sigstore/Rekor anchoring. Verifiable by regulators without routing through ArkForge.

---

## Trust Layer — DORA Art. 17 Compliance

DORA Art. 17 requires incident records to be **tamper-proof and available for supervisory inspection**. A standard log file (mutable, deletable) does not satisfy this requirement.

ArkForge Trust Layer seals each incident record at creation — cryptographic proof, independently verifiable:

```
→ https://arkforge.tech/trust
```

---

## Pricing

| Plan | Price | Scans | Features |
|------|-------|-------|----------|
| **Free** | €0 | 10/day | scan_project, classify_entity, assess_organization, generate_report |
| **Pro** | €29/mo | Unlimited | + generate_ict_register, generate_incident_template, CI/CD API |
| **Certified** | €99/mo | Unlimited | + certify_report (Trust Layer) |

Get your API key: https://mcp.arkforge.tech/en/mcp-dora.html

---

## What DORA Covers

| Chapter | Articles | What it requires |
|---------|----------|-----------------|
| ICT Risk Management | 5–16 | Board oversight, security policies, detection, BCP |
| Incident Management | 17–23 | Tamper-proof logs, classification, regulatory reporting |
| Resilience Testing | 24–27 | Annual vulnerability scans, SAST, TLPT (significant entities) |
| Third-Party Risk | 28–44 | ICT register, contract provisions, concentration risk |

---

## Entity Types in Scope

All financial entities regulated under DORA:

- **Credit institutions** (banks) — full scope, TLPT required
- **Payment institutions** — full scope
- **Electronic money institutions** — full scope
- **Investment firms** — full scope, TLPT required
- **Crypto asset service providers (CASPs)** — full scope
- **Insurance / reinsurance undertakings** — full scope
- **ICT third-party service providers** — Art. 28-31 only
- **Trading venues** — full scope, TLPT required
- **Central counterparties** — full scope, TLPT required

---

## License

MIT — © ArkForge

Questions: contact@arkforge.tech
