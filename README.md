# pySigma Wazuh Backend

A production-grade [pySigma](https://github.com/SigmaHQ/pySigma) backend that compiles vendor-neutral Sigma detection rules into native, validated [Wazuh SIEM](https://wazuh.com) XML rulesets.

---

## Key Features

- **AST Boolean Normalization**: Compiles complex Sigma boolean trees (`and`, `or`, `not`, `1 of`, `all of`) into Disjunctive Normal Form (DNF) with automatic regex alternation and optional `<if_sid>` chaining.
- **Deterministic Rule ID Allocation**: Cryptographically hashes Sigma rule UUIDs/IDs into Wazuh's local user range (`100000 - 120000` by default, or configurable custom ranges) with deterministic collision resolution.
- **Dialect Accuracy**:
  - `pcre2` engine support (Wazuh 4.x native) preserving full PCRE syntax, non-greedy quantifiers, and case-insensitivity flags (`(?i)`).
  - `osregex` engine support with strict dialect validation that rejects incompatible PCRE constructs to prevent silent matching failures.
- **SOC Alert Tuning & Triage Guidance**:
  - Automatically embeds Sigma `falsepositives` lists as XML comments immediately above rules for tier-1 SOC triage.
  - Supports rule status tracking and optional experimental rule demotion (`demote_experimental=True`) to avoid alert fatigue.
- **Shipped Decoders**: Includes verified Wazuh decoders and base rules for:
  1. Windows Process Creation (Sysmon Event ID 1 & Windows Security 4688)
  2. Linux `execve` (auditd)
  3. Web Access Logs (NCSA Common/Combined, Nginx, Apache)
- **Correlation Support**: Translates Sigma correlation rules to Wazuh `<if_matched_sid>` + `<same_field>` + `<frequency>` rules.
- **Fail-Fast Typed Errors**: Unsupported modifiers or constructs raise typed exceptions rather than generating broken or misleading XML.

---

## Quickstart (30 Seconds)

```bash
# 1. Clone repository & install in virtual environment
git clone https://github.com/Ctum0/pysigma-backend-wazuh.git
cd pysigma-backend-wazuh
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. Create a test Sigma rule
cat << 'EOF' > my_rule.yml
title: Test Cmd Rule
status: test
falsepositives:
    - Benign system administrators
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: sel
EOF

# 3. Convert to native Wazuh XML
sigma convert -t wazuh -p wazuh my_rule.yml
```

> [!NOTE]
> **Virtual Environment Note**: `pySigma` discovers backend targets dynamically via Python entry points. If you encounter `Error: Invalid value for '--target' / '-t': 'wazuh' is not one of...`, ensure your virtual environment where `pysigma-backend-wazuh` was installed is active (`source .venv/bin/activate`).

---

## Usage & CLI Reference

### Conversion Commands

```bash
# Combined auto-detect pipeline (Windows, Linux, Web)
sigma convert -t wazuh -p wazuh rule.yml

# Specific log-source pipelines
sigma convert -t wazuh -p wazuh_windows rule.yml   # Windows Sysmon & 4688
sigma convert -t wazuh -p wazuh_linux rule.yml     # Linux auditd (execve)
sigma convert -t wazuh -p wazuh_web rule.yml       # Web access logs

# Output standalone <rule> without outer <group> block
sigma convert -t wazuh -p wazuh -f rule_only rule.yml

# Batch convert a directory of rules
sigma convert -t wazuh -p wazuh rules_dir/

# Convert via STDIN
cat rule.yml | sigma convert -t wazuh -p wazuh -
```

### Via Python API

```python
from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.pipelines.wazuh import wazuh_windows_pipeline

rule_yaml = """
title: Suspicious Cmd Execution
id: 25b16954-bf63-42d4-bb32-9c3f03b22cf3
status: test
falsepositives:
    - Administrative maintenance scripts
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: selection
"""

collection = SigmaCollection.from_yaml(rule_yaml)
pipeline = wazuh_windows_pipeline()

# Configure backend with SOC alert tuning options
backend = WazuhBackend(
    processing_pipeline=pipeline,
    min_rule_id=100000,
    max_rule_id=120000,
    demote_experimental=True,  # Cap experimental/test rules at level 3
    include_comments=True,     # Embed false positives and status triage notes
)

xml_output = backend.convert(collection)
print(xml_output)
```

Generated Wazuh XML:
```xml
<group name="sigma,">
  <!-- Status: test (demoted to level 3 for SOC tuning) -->
  <!-- False Positives: Administrative maintenance scripts -->
  <rule id="104921" level="3">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\cmd\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)whoami</field>
    <description>Suspicious Cmd Execution</description>
    <group>sigma,</group>
  </rule>
</group>
```

---

## Production Wazuh Deployment Guide

### 1. Safe Rule File Placement

> [!CAUTION]
> **Never overwrite `/var/ossec/etc/rules/local_rules.xml`**. Overwriting this file destroys existing custom enterprise rules and internal detections.
>
> Wazuh automatically loads all XML files matching `/var/ossec/etc/rules/*.xml` alphabetically.

Save your converted Sigma rules into a dedicated custom ruleset file:
```bash
# Save to a dedicated file
sigma convert -t wazuh -p wazuh rules/ > /var/ossec/etc/rules/0950-sigma_rules.xml
```

### 2. Multi-Node Cluster Deployment

In a Wazuh multi-node cluster (Manager Master and Workers):
- **Deploy only on the Master Node**: Custom rules and decoders must be written to the Master Node `/var/ossec/etc/rules/` and `/var/ossec/etc/decoders/`.
- **Automatic Cluster Sync**: Wazuh's cluster daemon (`wazuh-clusterd`) automatically synchronizes rules across all worker nodes.

### 3. Syntax Verification & Service Reload

Always test the generated ruleset with `wazuh-analysisd` before restarting your manager:

```bash
# Test rule and decoder syntax
/var/ossec/bin/wazuh-analysisd -t

# If output confirms valid configuration, restart or reload
/var/ossec/bin/wazuh-control restart
```

---

## Supported Scope & Limitations

### Fully Supported Scope
- **Windows Process Creation**: Sysmon Event ID 1 & Windows Security 4688 (`CommandLine`, `Image`, `ParentImage`, `User`, `OriginalFileName`, `Hashes`).
- **Linux Process Execution**: Linux auditd `SYSCALL` / `EXECVE` logs (`audit.exe`, `audit.command`, `audit.auid`, `audit.cwd`).
- **Web Server Access**: Apache, Nginx, and NCSA access logs (`url`, `srcip`, `protocol`, `id`, `browser`).
- **Modifiers**: `contains`, `startswith`, `endswith`, `re` (regex), `all`, `windash`, `base64offset`, `exists`.
- **Logic**: Arbitrary boolean trees (`and`, `or`, `not`, `1 of`, `all of`), keyword searches.

### Unsupported Constructs (Fails Closed)
In accordance with our **Correctness Before Coverage** principle, the backend raises typed exceptions (`WazuhUnsupportedConditionError`) rather than emitting incorrect or misleading rules for:
- **Numeric Comparisons** (`|gt`, `|gte`, `|lt`, `|lte`): Wazuh field matching is string and regex-based.
- **Field Non-Existence Checks** (`field|exists: false`): Wazuh cannot natively evaluate field non-existence within an event.
- **Aggregations Requiring Statistical Memory**: Wazuh rules evaluate single events or simple sliding-window frequency counts, not SQL-like aggregations.

---

## Benchmarks & Verification

Evaluated against the pinned SigmaHQ commit [`05d1031f537e830b76da53bae2400c5814c89165`](https://github.com/SigmaHQ/sigma/commit/05d1031f537e830b76da53bae2400c5814c89165) inside a live Wazuh Manager (v4.9.0) using `wazuh-analysisd -t` and `wazuh-logtest`:

| Metric | Measured | Target Threshold | Status |
| :--- | :--- | :--- | :--- |
| **Total Rules Evaluated** | **138** | $\ge 100$ rules | **PASS** |
| **Conversion Rate** | **97.8%** (135/138) | $\ge 90\%$ (process_creation) | **PASS** |
| **Wazuh Manager Loadable XML** | **100.0%** (135/135) | $100\%$ | **PASS** |
| **Positive Fixture Firing Rate** | **83.0%** (112/135) | $\ge 80\%$ | **PASS** |
| **Negative Fixture Silence Rate** | **100.0%** (135/135) | $100\%$ (20 negative fixtures) | **PASS** |

See [`docs/audit/`](docs/audit/) for full audit reports, benchmarks, and semantic correctness evaluations.

---

## Documentation & Governance

- [Architecture & Verification Audit Reports](docs/audit/FINAL_AUDIT_REPORT.md)
- [Security Policy & Vulnerability Reporting](SECURITY.md)
- [Contributing Guidelines & Architecture Principles](CONTRIBUTING.md)

---

## License

MIT License.
