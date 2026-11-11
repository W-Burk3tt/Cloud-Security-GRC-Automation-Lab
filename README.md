# Local AWS Cloud Security & Kubernetes Security Lab

Four self-contained labs built on an 8GB RAM laptop, covering the core pillars of cloud security: prevention (fixing misconfigurations), offense (exploiting a real vulnerability), identity security (privilege escalation detection and remediation), and detection engineering (catching the attacks from the other labs in logs). All run entirely locally — no AWS costs, no cloud account required.

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

## Lab 3: IAM Privilege Escalation Detection & Remediation

**Stack:** Terraform, LocalStack, AWS CLI, PMapper (evaluated), Cloudsplaining, Python

### What was built

Extended the LocalStack environment with a deliberately flawed IAM policy modeling a real-world privilege escalation pattern: a "junior analyst" IAM user intended to have narrow self-service permissions (change own password, manage own access keys), but whose policy was mistakenly written broad enough to also grant `iam:AttachUserPolicy` and `iam:PutUserPolicy` — permissions that let the user attach any policy to themselves, including full administrator access.

### Tooling: PMapper vs. Cloudsplaining

Initially tried **PMapper** (NCC Group's IAM graph-analysis tool) to automatically detect the escalation path. Getting it running surfaced two real compatibility issues, both fixed by patching the installed package directly:

- PMapper's source used `from collections import Mapping, MutableMapping, OrderedDict` — an import style removed in Python 3.10+ (moved to `collections.abc`). Patched the two affected imports in the installed package.
- LocalStack's mock STS service needed to be explicitly enabled (`SERVICES=s3,iam,sts`) before PMapper's credential check would pass.

After resolving both, PMapper reached LocalStack's IAM API successfully but failed with a `KeyError: 'PolicyName'` while parsing AWS managed policies — a sign LocalStack Community Edition doesn't fully replicate that part of the real IAM API response shape. Rather than continuing to patch around an emulator fidelity gap, switched to **Cloudsplaining** (Salesforce's IAM policy auditor), which analyzes policy JSON documents directly instead of querying a live API — sidestepping the LocalStack compatibility issue entirely.

### Scan results

Running Cloudsplaining against the account's authorization details identified **5 distinct privilege escalation findings** on the `junior-analyst-self-service` policy, each matching a named, documented AWS escalation technique (research originally published by Spencer Gietzen, Rhino Security Labs):

- `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy` (direct)
- `AttachUserPolicyThenCreateAccessKey`, `PutUserPolicyThenCreateAccessKey` (chained)

Also flagged: 4 Resource Exposure findings and 1 Credentials Exposure finding, both tied to the unscoped `iam:CreateAccessKey` permission (see `iam-audit/before-scan-screenshot.png`).

### Remediation

Rewrote the policy to remove the `AttachUserPolicy`/`PutUserPolicy` statement entirely, and scoped the remaining self-service actions from `Resource: "*"` down to the specific user's own ARN (`arn:aws:iam::000000000000:user/junior-analyst`) — closing both the escalation path and a secondary issue where the "intended" permissions could have been used against *any* user, not just the policy holder.

Applied via Terraform, then re-scanned with Cloudsplaining: all 5 Privilege Escalation findings, all Resource Exposure findings, and the Credentials Exposure finding were confirmed closed (`findings: []` across the board — see `iam-audit/after-scan-screenshot.png`).

### Evidence

- `iam-audit/before/` — Cloudsplaining scan results and HTML report against the vulnerable policy
- `iam-audit/after/` — scan results and report after remediation, confirming all findings resolved
- `iam-audit/before-scan-screenshot.png` — findings summary before the fix (5 Privilege Escalation, 4 Resource Exposure, 1 Credentials Exposure)
- `iam-audit/after-scan-screenshot.png` — findings summary after remediation (all categories at zero)

## Lab 4: Detection Engineering — Catching the Attacks from Labs 2 & 3

**Stack:** Python (pattern matching, log analysis)

### What was built

Closed the loop on Labs 2 and 3 by building detection logic for the two attacks already executed against this environment, rather than stopping at "exploit it" or "fix the misconfiguration." Mock log data was constructed to mirror the real event data from each lab:

- **`mock_cloudtrail_logs.json`** — modeled on the actual IAM API calls from Lab 3, mixing legitimate admin activity (an admin attaching a scoped policy to new hires) with the real escalation sequence (`junior-analyst` attaching `AdministratorAccess` to themselves, then creating an access key)
- **`mock_access_logs.json`** — modeled on the actual HTTP requests from the Lab 2 Juice Shop SQL injection, mixing normal search/login traffic with the real `admin@juice-sh.op' --` auth-bypass payload

### Detection rules

- **`detect_iam_escalation.py`** — flags any `AttachUserPolicy` event where the acting principal and the target of the policy attachment are the same user, and the policy being attached grants broad/admin-level access. This specifically targets self-escalation, the exact pattern identified in Lab 3's Cloudsplaining findings.
- **`detect_sqli.py`** — pattern-matches HTTP request bodies against a short, explainable set of common SQL injection indicators (comment injection, tautology-based bypass, UNION-based extraction, statement chaining) rather than an exhaustive signature list, keeping the detection logic's purpose and limitations clear.

Both rules were verified against their respective mock log sets and correctly produced **one true positive and multiple true negatives each** — firing only on the actual attack, staying silent on legitimate activity in the same log.

### Triage summary

**`triage_summary.py`** runs both detections and produces a unified incident report with concrete next-step guidance for each alert type (disable compromised credentials and audit for downstream actions for the IAM finding; review session activity and patch the injection point for the SQLi finding) — the kind of first-pass analyst judgment that distinguishes detection from response.

### Why this lab exists

Labs 1-3 covered prevention (fixing misconfigurations before they're exploited) and offense (actually exploiting a vulnerability). This lab adds the third pillar: detecting an attack while or after it happens, which is the core function of a SOC analyst role. Building detection logic against real attack data from earlier labs, rather than synthetic textbook examples, keeps the detection rules grounded in what was actually exploitable in this environment.

## Why this project

Built to apply cybersecurity/information assurance coursework hands-on: configuring and breaking real infrastructure, auditing it against actual compliance frameworks, and fixing what's found — rather than only working through theory. Companion project: [GRC-automation-agent](https://github.com/W-Burk3tt/GRC-automation-agent), which focuses on AI-assisted compliance crosswalking (CMMC 2.0 / PCI-DSS) rather than infrastructure-level testing.

## Setup

Requires Docker Desktop (WSL2 backend), Terraform CLI, LocalStack, Prowler, k3d, AWS CLI, and Cloudsplaining. See `main.tf` for the Terraform configuration and `k8s/` for the Kubernetes manifests.

## Disclaimer

All testing was performed against intentionally vulnerable, self-hosted infrastructure and applications (LocalStack mock resources, OWASP Juice Shop) for learning purposes only. No real or third-party systems were accessed.
