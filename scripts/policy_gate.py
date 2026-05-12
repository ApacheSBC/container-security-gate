#!/usr/bin/env python3
"""
Container Image Security Policy Gate
Scans a Docker image with Trivy and Grype, enforces a CVE threshold policy,
and exits non-zero to fail a CI/CD pipeline if the policy is violated.
"""

import subprocess
import json
import sys
import argparse
from datetime import datetime, timezone


# ── Policy defaults (can be overridden via CLI args) ──────────────────────────
DEFAULT_POLICY = {
    "fail_on_critical": True,
    "fail_on_high": True,
    "max_critical": 0,   # Zero tolerance for CRITICAL
    "max_high": 0,       # Zero tolerance for HIGH
}


def run_trivy(image: str) -> dict:
    """Run Trivy and return parsed JSON results."""
    print(f"\n[*] Running Trivy against {image}...")
    cmd = [
        "trivy", "image",
        "--severity", "HIGH,CRITICAL",
        "--format", "json",
        "--quiet",
        image
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):  # Trivy exits 1 when vulns found
        print(f"[!] Trivy error: {result.stderr}")
        sys.exit(2)

    data = json.loads(result.stdout)
    counts = {"CRITICAL": 0, "HIGH": 0, "findings": []}

    for resource in data.get("Results", []):
        for vuln in resource.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity", "").upper()
            if severity in ("CRITICAL", "HIGH"):
                counts[severity] += 1
                counts["findings"].append({
                    "tool": "trivy",
                    "id": vuln.get("VulnerabilityID"),
                    "severity": severity,
                    "package": vuln.get("PkgName"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": vuln.get("FixedVersion", "No fix available"),
                })

    print(f"    Trivy → CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}")
    return counts


def run_grype(image: str) -> dict:
    """Run Grype and return parsed JSON results."""
    print(f"[*] Running Grype against {image}...")
    cmd = [
        "grype", image,
        "--output", "json",
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        print(f"[!] Grype error: {result.stderr}")
        sys.exit(2)

    data = json.loads(result.stdout)
    counts = {"CRITICAL": 0, "HIGH": 0, "findings": []}

    for match in data.get("matches", []):
        severity = match.get("vulnerability", {}).get("severity", "").upper()
        if severity in ("CRITICAL", "HIGH"):
            counts[severity] += 1
            counts["findings"].append({
                "tool": "grype",
                "id": match["vulnerability"].get("id"),
                "severity": severity,
                "package": match.get("artifact", {}).get("name"),
                "installed": match.get("artifact", {}).get("version"),
                "fixed": (match["vulnerability"].get("fix", {}) or {}).get("versions", ["No fix available"]),
            })

    print(f"    Grype → CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}")
    return counts


def evaluate_policy(trivy: dict, grype: dict, policy: dict) -> tuple[bool, dict]:
    """Merge results and apply the policy gate. Returns (passed, report)."""

    # Use the HIGHER count from either tool (conservative approach)
    critical = max(trivy["CRITICAL"], grype["CRITICAL"])
    high = max(trivy["HIGH"], grype["HIGH"])

    # Deduplicate findings by CVE ID
    seen = set()
    all_findings = []
    for f in trivy["findings"] + grype["findings"]:
        if f["id"] not in seen:
            seen.add(f["id"])
            all_findings.append(f)

    violations = []
    if policy["fail_on_critical"] and critical > policy["max_critical"]:
        violations.append(
            f"CRITICAL CVEs: {critical} found, {policy['max_critical']} allowed"
        )
    if policy["fail_on_high"] and high > policy["max_high"]:
        violations.append(
            f"HIGH CVEs: {high} found, {policy['max_high']} allowed"
        )

    passed = len(violations) == 0
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "policy": policy,
        "summary": {
            "trivy_critical": trivy["CRITICAL"],
            "trivy_high": trivy["HIGH"],
            "grype_critical": grype["CRITICAL"],
            "grype_high": grype["HIGH"],
            "effective_critical": critical,
            "effective_high": high,
            "unique_cves": len(seen),
        },
        "violations": violations,
        "passed": passed,
        "findings": sorted(all_findings, key=lambda x: (x["severity"], x["id"])),
    }
    return passed, report


def print_report(report: dict, image: str):
    """Print a human-readable summary to stdout."""
    status = "✅ PASSED" if report["passed"] else "❌ FAILED"
    s = report["summary"]

    print("\n" + "═" * 60)
    print(f"  SECURITY POLICY GATE REPORT — {status}")
    print("═" * 60)
    print(f"  Image   : {image}")
    print(f"  Scanned : {report['timestamp']}")
    print(f"  Unique CVEs found: {s['unique_cves']}")
    print()
    print(f"  {'Tool':<10} {'CRITICAL':>10} {'HIGH':>8}")
    print(f"  {'─'*10} {'─'*10} {'─'*8}")
    print(f"  {'Trivy':<10} {s['trivy_critical']:>10} {s['trivy_high']:>8}")
    print(f"  {'Grype':<10} {s['grype_critical']:>10} {s['grype_high']:>8}")
    print(f"  {'Effective':<10} {s['effective_critical']:>10} {s['effective_high']:>8}")

    if report["violations"]:
        print("\n  POLICY VIOLATIONS:")
        for v in report["violations"]:
            print(f"    ✗ {v}")

    print("═" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Container Image Security Policy Gate (Trivy + Grype)"
    )
    parser.add_argument("image", help="Docker image to scan (e.g. python:3.6-slim)")
    parser.add_argument("--max-critical", type=int, default=DEFAULT_POLICY["max_critical"],
                        help="Max allowed CRITICAL CVEs (default: 0)")
    parser.add_argument("--max-high", type=int, default=DEFAULT_POLICY["max_high"],
                        help="Max allowed HIGH CVEs (default: 0)")
    parser.add_argument("--allow-high", action="store_true",
                        help="Don't fail on HIGH CVEs (only fail on CRITICAL)")
    parser.add_argument("--output-json", metavar="FILE",
                        help="Write full JSON report to this file")
    args = parser.parse_args()

    policy = {
        "fail_on_critical": True,
        "fail_on_high": not args.allow_high,
        "max_critical": args.max_critical,
        "max_high": args.max_high,
    }

    print(f"\n{'═'*60}")
    print(f"  Container Security Policy Gate")
    print(f"  Scanning: {args.image}")
    print(f"{'═'*60}")

    trivy_results = run_trivy(args.image)
    grype_results = run_grype(args.image)
    passed, report = evaluate_policy(trivy_results, grype_results, policy)
    print_report(report, args.image)

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Full JSON report saved to: {args.output_json}")

    # Exit code drives the pipeline — this is the gate
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()