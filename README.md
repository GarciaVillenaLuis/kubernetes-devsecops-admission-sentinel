# Kubernetes DevSecOps Admission Sentinel & Policy Auditor ☸️🛡️

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/kubernetes-devsecops-admission-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/kubernetes-devsecops-admission-sentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GarciaVillenaLuis/kubernetes-devsecops-admission-sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/GarciaVillenaLuis/kubernetes-devsecops-admission-sentinel/actions/workflows/codeql.yml)
[![Pod Security Standards](https://img.shields.io/badge/Kubernetes-PSS%20Restricted-326CE5?style=flat-square&logo=kubernetes&logoColor=white)](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
[![CIS Benchmark](https://img.shields.io/badge/CIS-Kubernetes%20v1.8-0052cc?style=flat-square&logo=securityscorecard&logoColor=white)](https://www.cisecurity.org/)
[![NIST Compliance](https://img.shields.io/badge/NIST-SP%20800--190%20(Container)-orange?style=flat-square)](https://csrc.nist.gov/)
[![OPA & Kyverno Ready](https://img.shields.io/badge/Policy-OPA%20%7C%20Kyverno-brightgreen?style=flat-square&logo=open-policy-agent&logoColor=white)](https://www.openpolicyagent.org/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)

Autonomous Kubernetes Admission Controller and DevSecOps policy auditor enforcing **Kubernetes Pod Security Standards (PSS)**, **CIS Kubernetes Benchmark v1.8**, and zero-trust container execution guardrails.

Developed and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🌟 Architectural Highlights

- **Full Pod Security Standards (PSS) Coverage**:
  - **Baseline Profile**: Prohibits privileged containers, host namespaces (`hostPID`, `hostNetwork`, `hostIPC`), `hostPath` volume mounts, and dangerous Linux capabilities (`CAP_SYS_ADMIN`, `NET_ADMIN`).
  - **Restricted Profile**: Mandates non-root user execution (`runAsNonRoot: true`, `runAsUser > 0`), immutable root filesystems (`readOnlyRootFilesystem: true`), explicit capability dropping (`drop: ['ALL']`), and required CPU/memory limits.
- **ValidatingAdmissionWebhook Ready**: Ingests raw Kubernetes manifests or processes live `AdmissionReview` (v1) JSON webhooks, generating standard Kubernetes admission decisions (`allowed: true / false`).
- **Zero-Dependency Core**: Built purely with Python standard library modules for universal compatibility across air-gapped CI/CD runners, bastion nodes, and lightweight admission containers.
- **CI/CD Shift-Left Gating**: Integrates natively into pre-commit hooks, GitHub Actions, GitLab CI, and ArgoCD deployment pipelines with `--strict` exit codes.
- **Live Cluster Telemetry**: Continuous posture assessment and historical compliance tracking in [`data/k8s_cluster_posture.json`](./data/k8s_cluster_posture.json).

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (No external pip packages required)

### Syntax & Available Options

```bash
python k8s_admission_sentinel.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--file, -f PATH` | `string` | Path to Kubernetes YAML/JSON manifest or AdmissionReview payload |
| `--level, -l PROFILE` | `choice` | Security profile to enforce: `baseline` or `restricted` (default: `restricted`) |
| `--admission-webhook` | `flag` | Process input as AdmissionReview webhook payload and return standard response |
| `--format FMT` | `choice` | Output format: `table` (default) or `json` |
| `--strict` | `flag` | Exit with non-zero exit code (2) if any violations or admission denial occurs |
| `--stats` | `flag` | Display live cluster posture baseline metrics |

---

## 💻 Practical Usage Scenarios

### 1. Audit a workload manifest against Restricted PSS
```bash
python k8s_admission_sentinel.py --file samples/hardened_deployment.yaml
```
**Sample Output:**
```text
---------------------------------------------------------------------------------
RESOURCE                     | LEVEL      | DECISION | SCORE   | VIOLATIONS
---------------------------------------------------------------------------------
Deployment/hardened-cloud-native-service | restricted | ALLOWED  | 100.0%  | 0         
---------------------------------------------------------------------------------
```

### 2. Detect Critical Violations in Insecure Workloads
```bash
python k8s_admission_sentinel.py --file samples/vulnerable_deployment.yaml
```
**Sample Findings Output:**
```text
[!] Findings for Deployment/vulnerable-workload:
  - [CRITICAL] PSS-01: Privileged Container Detected
    Remediation: Set spec.containers[].securityContext.privileged to false.
  - [HIGH] PSS-02: Insecure Host Namespace Enabled (hostPID)
    Remediation: Disable hostPID in pod spec.
  - [HIGH] PSS-03: HostPath Volume Mount Detected: host-root
    Remediation: Replace hostPath with PersistentVolumeClaim or ConfigMap/Secret.
  - [HIGH] PSS-05: Dangerous Linux Capabilities Added: ['SYS_ADMIN']
    Remediation: Remove ['SYS_ADMIN'] from securityContext.capabilities.add.
  - [HIGH] PSS-06: Container May Run As Root User
    Remediation: Set runAsNonRoot: true and define runAsUser > 1000.
```

### 3. ValidatingAdmissionWebhook Webhook Simulation
```bash
python k8s_admission_sentinel.py --admission-webhook --file samples/admission_review_request.json
```

---

## 🧪 Automated Testing

Execute the test suite locally:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📜 Standards & Compliance Mapping

| Control ID | Standard | Policy Name | Enforcement |
| :--- | :--- | :--- | :---: |
| **PSS-01** | CIS K8s 5.2.1 | Prohibit Privileged Containers | Deny |
| **PSS-02** | CIS K8s 5.2.2 | Restrict Host PID / Network / IPC | Deny |
| **PSS-03** | CIS K8s 5.2.5 | Restrict Insecure HostPath Mounts | Deny |
| **PSS-06** | CIS K8s 5.2.6 | Enforce Non-Root Container Execution | Deny |
| **PSS-07** | NIST SP 800-190 | Enforce Read-Only Root Filesystem | Deny |
| **PSS-08** | CIS K8s 5.2.7 | Drop ALL Linux Capabilities | Deny |
| **PSS-09** | Cloud Native WAF | Mandate Memory/CPU Resource Limits | Audit |

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
