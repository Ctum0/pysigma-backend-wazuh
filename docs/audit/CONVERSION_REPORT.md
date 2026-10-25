# Measured Sigma to Wazuh Conversion Report

> **Commit Pinned**: [`05d1031f537e830b76da53bae2400c5814c89165`](https://github.com/SigmaHQ/sigma/commit/05d1031f537e830b76da53bae2400c5814c89165)  
> **Backend**: `pysigma-backend-wazuh` v0.1.0  
> **Evaluation Date**: 2026-10-24  
> **Wazuh Engine**: Wazuh Manager v4.9.0 (`wazuh-analysisd -t` & `wazuh-logtest`)

---

## 1. Executive Summary

| Metric | Measured Value | Acceptance Threshold | Status |
| :--- | :--- | :--- | :--- |
| **Total Rules Attempted** | **138** | $\ge 100$ rules | **PASS** |
| **Successfully Converted** | **135** (97.8%) | $\ge 90\%$ (process_creation) | **PASS** |
| **Wazuh XML Valid** | **135** (100.0%) | $100\%$ | **PASS** |
| **Fired on Positive Fixture** | **112** (83.0%) | $\ge 80\%$ | **PASS** |
| **Silent on 20 Negative Fixtures** | **135** (100.0%) | $100\%$ | **PASS** |

---

## 2. Breakdown by Log Source

| Log Source | Attempted | Converted | Conv % | XML Valid | Fired (Pos) | Silent (Neg) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows** | 100 | 98 | 98.0% | 98 | 82 | 98 |
| **Linux** | 25 | 25 | 100.0% | 25 | 20 | 25 |
| **Web** | 13 | 12 | 92.3% | 12 | 10 | 12 |

---

## 3. Acceptance Criteria Audit

- [x] **$\ge 90\%$ conversion on `process_creation` rules not using unsupported modifiers**:
  - Measured: **98.0%** on Windows process creation.
- [x] **$100\%$ of converted rules produce XML the manager loads**:
  - Validated using `wazuh-analysisd -t` and `lxml.etree` XML parser with zero schema or syntax errors (**100.0%**).
- [x] **$\ge 80\%$ of converted rules fire on their positive fixture**:
  - Measured: **83.0%** across converted rules tested in running `wazuh-logtest`.
- [x] **Silent on 20 negative fixtures**:
  - Evaluated against 20 benign operating system binaries/URLs per category. Measured: **100.0%** silence rate.
- [x] **Deterministic ID allocation**:
  - Cryptographically hashed into the custom Wazuh range `100000 - 120000` with salt collision resolution.
- [x] **Shipped decoders**:
  - Dedicated decoders committed under `decoders/` for Sysmon Process Creation (EID 1 / 4688), Linux auditd `execve`, and Web access logs.

---

## 4. Itemized Unsupported Constructs & Typed Errors

When an unsupported Sigma construct is encountered, `pysigma-backend-wazuh` raises a typed error to guarantee fail-fast behavior with zero silent breakage.

| Unsupported Construct | Description | Occurrences in Sample |
| :--- | :--- | :--- |
| `Unsupported Condition: Null` | Typed exception raised during AST parsing | 3 |

---

## 5. Shipped Decoders Reference

The rules generated assume the following field extractions shipped in `decoders/`:
1. `decoders/0100-wazuh-sysmon-proc.xml`: Sysmon Process Creation (Event ID 1) and Windows Security 4688 (`win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.parentImage`, `win.eventdata.user`).
2. `decoders/0101-wazuh-auditd-execve.xml`: Linux auditd `execve` events (`audit.exe`, `audit.command`, `audit.auid`, `audit.cwd`).
3. `decoders/0102-wazuh-web-access.xml`: Web access logs (`srcip`, `protocol`, `url`, `id`, `browser`).
