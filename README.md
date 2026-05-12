# Container Image Security Policy Gate

Automated container image vulnerability scanning policy gate using **Trivy** and **Grype**, integrated into a GitHub Actions CI/CD pipeline.

## What It Does

- Scans Docker images with two independent CVE scanners (defence in depth)
- Applies a configurable policy — zero tolerance for CRITICAL/HIGH by default
- Exits non-zero to **automatically fail** pipelines when policy is violated
- Generates a JSON report for every scan as an audit trail

## Results

| Image | Trivy CRITICAL | Grype CRITICAL | Gate |
|-------|---------------|----------------|------|
| python:3.6-slim (vulnerable) | 28 | 34 | ❌ FAILED |
| python:3.13-slim (current) | 0 | 3 | ✅ PASSED |

## Usage

```bash
# Zero tolerance — fail on any CRITICAL or HIGH
python3 scripts/policy_gate.py python:3.6-slim

# Enterprise policy — allow up to 5 CRITICAL, ignore HIGH
python3 scripts/policy_gate.py python:3.13-slim --max-critical 5 --allow-high

# Save JSON report for audit trail
python3 scripts/policy_gate.py myapp:latest --output-json results/report.json
```

## Why Two Scanners?

Trivy and Grype use different vulnerability databases. Running both catches CVEs that either tool might miss individually. On python:3.6-slim, Trivy found 28 CRITICAL CVEs while Grype found 34 — a 21% difference. In a security context, that gap matters.

## Tools
- [Trivy](https://github.com/aquasecurity/trivy) — Aqua Security
- [Grype](https://github.com/anchore/grype) — Anchore

## Portfolio
This is Project 5 in my cybersecurity portfolio, building on:
- Project 1: CI/CD Pipeline with GitHub Actions (Bandit + Trivy)
- Project 2: AWS Infrastructure with Terraform (VPC, EC2, least-privilege)
- Project 3: IaC Security Scanning with Checkov
- Project 4: Secret Scanning with GitLeaks and TruffleHog
