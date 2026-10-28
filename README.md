# Local AWS Cloud Security GRC & Advanced Kubernetes DevSecOps Lab

## 📌 Project Overview
This multi-layered engineering lab demonstrates the deployment, continuous compliance auditing, engineering remediation, and runtime threat detection of enterprise cloud and containerized topologies. To optimize resource utilization under a strict personal hardware constraint (**8GB host RAM**), the entire playground runs locally within an optimized containerized ecosystem, eliminating real-world cloud service expenses.

---

## 🏗️ Phase 1: Cloud Architecture, IaC, & GRC Automation

### 🛠️ Technology Stack & Tooling
*   **Infrastructure as Code:** Terraform CLI
*   **Cloud Emulation Sandbox:** LocalStack Community Edition (v4.13.0)
*   **GRC Compliance Engine:** Prowler Open-Source Cloud Security Auditor
*   **Container Runtime:** Docker Desktop Engine (WSL2 Backend)

### 🚨 Flawed Architecture Deployment
Using declarative Terraform configuration, a mock enterprise cloud perimeter was stood up containing deliberate structural compliance failures against standard frameworks (**CIS Benchmarks / NIST SP 800-53**):
1.  **Exposed Storage:** An Amazon S3 bucket (`san-antonio-hr-records-2026`) with all public access blocks explicitly disabled.
2.  **Over-Permissive Identity Routing:** An IAM policy assigning blanket wildcard (`"Action": "*"`) administrator privileges to a basic user role.

### 📊 Compliance Auditing & Engineering Remediation
The environment was programmatically evaluated using the **Prowler** security framework inside an isolated container bridge network interface. 
*   **Initial Baseline Scan:** Detected a **72.41% Compliance Failure Rate**, capturing high-severity alerts regarding unencrypted object storage, lack of public data blocks, and identity permission expansion.
*   **Remediation Action:** Refactored the infrastructure source code to enforce strict `AES256` server-side encryption, absolute public block storage policies (`block_public_acls = true`), and stripped identity wildcards in favor of local, scoped **Least Privilege** policies (`s3:GetObject`).
*   *Subsequent Prowler verification cycles confirmed the absolute erasure of the targeted structural data risks.*

---

## 🌐 Phase 2: Advanced Kubernetes Application Security & Threat Detection

### 🛠️ Technology Stack & Tooling
*   **Cluster Orchestration Engine:** k3d Kubernetes (Consuming <300MB idle RAM)
*   **Package Manager:** Helm.Helm Package Management
*   **Target Application Cluster Node:** OWASP Juice Shop
*   **Threat Telemetry Logger:** Custom Cloud-Native Runtime Monitor (`defender.yaml`)

### 📦 Cluster Topology & Deployment Manifests
To transition from standalone containers into modern cloud-native architectures, the web application workload was migrated into a managed **Local Kubernetes Cluster** using **k3d**. 
*   Deployed a custom declarative application manifest (`juiceshop.yaml`) configuring explicit computing resource safety thresholds (`memory: "300Mi"`, `cpu: "500m"`) to prevent host memory bottlenecks.
*   Established a loopback strict network port tunnel (`127.0.0.1:9090`) to safely navigate browser endpoint contexts past proxy routing layers without exposure over public gateway systems.

### 🕵️‍♂️ Web Vulnerability Auditing & Exploit Mechanics
Conducted extensive manual application security assessments, leveraging native Browser Developer Tools (F12) to inspect active session structures, locate hidden client-side routing definitions (`/#/score-board`), and reverse-engineer token verification components.
*   **Authentication Bypass Exploit:** Executed a client-side **SQL Injection (SQLi)** attack on the live login matrix portal by passing a specialized database query breakout command sequence:
    ```text
    admin@juice-sh.op' --
    ```
*   **The Backend Impact:** The input successfully manipulated direct SQL string concatenations, forcing the database parser to treat downstream authentication filters and password validation statements as dead comments, granting full administrative hijacking privileges without valid credentials.

### 📡 Blue-Team Automated Telemetry Monitoring
To establish automated, cloud-native runtime threat logging, an isolated cluster workspace partition room was initialized (`kubectl create namespace security`), and a dedicated system activity monitor manifest (`defender.yaml`) was injected.
*   The automated micro-defender watches pod behaviors and kernel boundaries in real time, streaming immutable alert warning messages instantly across the security telemetry console the moment an unauthorized terminal breakout or systemic configuration dump is executed inside the application container loop.

---

## 💼 Core Engineering & Troubleshooting Competencies
1.  **Systems & Resource Optimization:** Proved engineering capability to host comprehensive cloud IaC mockups, container orchestration node loops, and alert log streams running simultaneously on a restricted **8GB memory footprint** using optimized micro-distributions.
2.  **Infrastructure as Code SecOps:** Demonstrated practical application of managing data perimeters, security baselines, and identity structures natively in source code files before systems are ever launched.
3.  **Defensive Telemetry Interpretation:** Gained hands-on experience tracking raw transaction states, inspecting JSON Web Token (JWT) session properties, reverse-engineering client-side framework tables, and interpreting automated alert triggers.
