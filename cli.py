#!/usr/bin/env python3
"""
CLI interface for the DORA Compliance Scanner.

Usage:
    dora-scanner /path/to/project
    dora-scanner /path/to/project --entity credit_institution
    dora-scanner /path/to/project --json
"""

import sys
import json
import argparse

from server import DORAChecker, _ENTITY_TYPES

PRICING_URL = "https://mcp.arkforge.tech/en/mcp-dora.html?utm_source=cli"

UPSELL_BLOCK = f"""
================================================================================
  UPGRADE TO PRO — Full DORA compliance intelligence
================================================================================

  Your scan is complete. With Pro, you also get:

    * Art.31 ICT third-party register (auto-generated from scan)
    * Art.17-18 incident management template
    * CI/CD integration — block deploys on critical DORA gaps
    * Unlimited scans + scan history
    * Trust Layer certification for supervisor-ready proof

  29 EUR/month — Start now:
  {PRICING_URL}

  Questions? contact@arkforge.tech
================================================================================
"""

_SEVERITY_ICON = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}


def _print_scan(scan: dict) -> None:
    findings = scan.get("findings", {})
    gaps = scan.get("gaps", [])
    print(f"\n  Files scanned: {scan.get('files_scanned', 0)}")

    deps = findings.get("third_party_dependencies", {})
    if deps:
        print(f"  ICT third-party dependencies detected: {len(deps)}")
        for vendor in list(deps.keys())[:6]:
            print(f"    - {vendor}")
        if len(deps) > 6:
            print(f"    ... +{len(deps) - 6} more")
    else:
        print("  ICT third-party dependencies: none detected")

    print(f"\n  DORA Gaps Found: {len(gaps)}")
    for gap in gaps:
        icon = _SEVERITY_ICON.get(gap.get("severity", "medium"), "[?]")
        print(f"    {icon} {gap.get('article', '')} — {gap.get('description', '')[:80]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dora-scanner",
        description="DORA Compliance Scanner — Scan your project for Digital Operational Resilience Act gaps.",
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument(
        "--entity",
        choices=list(_ENTITY_TYPES.keys()),
        default=None,
        help="DORA entity type (e.g. credit_institution, payment_institution, crypto_casp)",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    args = parser.parse_args(argv)

    checker = DORAChecker(args.project_path)
    scan = checker.scan_project()

    if scan.get("error"):
        print(f"Error: {scan['error']}", file=sys.stderr)
        return 1

    if args.json:
        output: dict = {"scan": scan}
        if args.entity:
            output["entity_classification"] = checker.classify_entity(args.entity)
        print(json.dumps(output, indent=2))
        return 0

    print("=" * 72)
    print("  DORA Compliance Scanner — Digital Operational Resilience Act")
    print("=" * 72)

    _print_scan(scan)

    if args.entity:
        entity = checker.classify_entity(args.entity)
        print(f"\n  Entity: {entity.get('label', args.entity)}")
        print(f"  Articles applicable: {entity.get('applicable_articles_count', 0)}")
        print(f"  TLPT required: {'Yes' if entity.get('tlpt_required') else 'No'}")

    print(UPSELL_BLOCK)
    return 0


if __name__ == "__main__":
    sys.exit(main())
