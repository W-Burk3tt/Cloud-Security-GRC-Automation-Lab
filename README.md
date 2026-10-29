# Local AWS Cloud Security & Kubernetes Security Lab

Two self-contained labs built on an 8GB RAM laptop: a cloud misconfiguration/compliance lab using Terraform and LocalStack, and a web application attack lab using a containerized OWASP Juice Shop instance. Both run entirely locally — no AWS costs, no cloud account required.

## Lab 1: Cloud Misconfiguration & Compliance Auditing

**Stack:** Terraform, LocalStack Community Edition (v4.13.0), Prowler, Docker (WSL2 backend)

### What was built

Using Terraform, I stood up a small mock AWS environment inside LocalStack with two deliberately flawed resources, modeled on common real-world misconfigurations:

1. **Public S3 bucket** (`san-antonio-hr-records-2026`) — all public access blocks explicitly disabled
2. **Overly permissive IAM policy** — a basic user role granted wildcard (`"Action": "*"`) administrator privileges

### Auditing and remediation

Ran Prowler (open-source cloud security auditor) against the environment to evaluate it against CIS Benchmarks and NIST SP 800-53 controls.

- **Baseline scan**: 72.41% compliance failure rate, with high-severity findings for unencrypted storage, missing public access blocks, and excessive IAM permissions (see `Prowler.png`)
- **Remediation**: rewrote the Terraform configuration to enforce AES-256 server-side encryption, set `block_public_acls = true` and related public-access-block settings, and replaced the wildcard IAM policy with a scoped least-privilege policy (`s3:GetObject` only)
- **Verification**: re-ran Prowler after remediation and confirmed the targeted findings were resolved (see `Prowler2.png`)

## Lab 2: Web Application Attack Analysis

**Stack:** k3d (lightweight Kubernetes), Helm, OWASP Juice Shop, Wireshark

### What was built

Deployed OWASP Juice Shop (a deliberately vulnerable web application) inside a local k3d Kubernetes cluster, with resource limits set (`memory: "300Mi"`, `cpu: "500m"`) to stay within the 8GB RAM budget. Exposed the app only on localhost (`127.0.0.1:9090`), never on a public interface.

### Attack testing

- Used browser dev tools to inspect session structure and locate client-side routes (e.g. `/#/score-board`)
- Performed a manual SQL injection against the login form using a classic auth-bypass payload:
  ```
  admin@juice-sh.op' --
  ```
  This comments out the rest of the SQL query server-side, bypassing the password check entirely and logging in as an administrator without valid credentials
- Captured and reviewed local traffic with Wireshark to observe request/response behavior during testing

### Monitoring

Created a `security` namespace in the cluster and deployed a basic runtime monitor (`defender.yaml`) to log pod-level activity during testing.

## Why this project

Built to apply cybersecurity/information assurance coursework hands-on: configuring and breaking real infrastructure, auditing it against actual compliance frameworks, and fixing what's found — rather than only working through theory. Companion project: [GRC-automation-agent](https://github.com/W-Burk3tt/GRC-automation-agent), which focuses on AI-assisted compliance crosswalking (CMMC 2.0 / PCI-DSS) rather than infrastructure-level testing.

## Setup

Requires Docker Desktop (WSL2 backend), Terraform CLI, LocalStack, Prowler, and k3d. See `main.tf` for the Terraform configuration and `k8s/` for the Kubernetes manifests.

## Disclaimer

All testing was performed against intentionally vulnerable, self-hosted infrastructure and applications (LocalStack mock resources, OWASP Juice Shop) for learning purposes only. No real or third-party systems were accessed.
