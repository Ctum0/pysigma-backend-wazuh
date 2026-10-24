# pySigma Wazuh Backend

A production-grade [pySigma](https://github.com/SigmaHQ/pySigma) backend that compiles vendor-neutral Sigma detection rules into native, validated [Wazuh SIEM](https://wazuh.com) XML rulesets.

## Key Features

- **AST Boolean Normalization**: Compiles complex Sigma boolean trees (`and`, `or`, `not`, `1 of`, `all of`) into Disjunctive Normal Form (DNF) with automatic regex alternation and optional `<if_sid>` chaining.
- **Deterministic Rule ID Allocation**: Cryptographically hashes Sigma rule UUIDs/IDs into Wazuh's local user range (`100000 - 120000`) with deterministic collision resolution.
- **Dialect Accuracy**:
  - `pcre2` engine support (Wazuh 4.x native) preserving full PCRE syntax, non-greedy quantifiers, and case-insensitivity flags (`(?i)`).
  - `osregex` engine support with strict dialect validation that rejects incompatible PCRE constructs to prevent silent matching failures.
- **Shipped Decoders**: Includes verified Wazuh decoders for:
  1. Windows Process Creation (Sysmon Event ID 1 & Windows Security 4688)
  2. Linux `execve` (auditd)
  3. Web Access Logs (NCSA Common/Combined, Nginx, Apache)
- **Correlation Support**: Translates Sigma correlation rules to Wazuh `<if_matched_sid>` + `<same_field>` + `<frequency>` rules.
- **Fail-Fast Typed Errors**: Unsupported modifiers or constructs raise typed exceptions rather than generating broken XML.

## Installation

```bash
pip install pysigma-backend-wazuh
```

Or with `uv`:
```bash
uv pip install -e .
```

## Usage

### Via Sigma CLI

```bash
# Convert a single rule targeting Windows Process Creation
sigma convert -t wazuh -p wazuh_windows rule.yml

# Convert targeting Linux auditd
sigma convert -t wazuh -p wazuh_linux rule.yml

# Convert targeting Webserver logs
sigma convert -t wazuh -p wazuh_web rule.yml
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
backend = WazuhBackend(processing_pipeline=pipeline)

xml_output = backend.convert(collection)
print(xml_output)
```

Generated Wazuh XML:
```xml
<group name="sigma,">
  <rule id="104921" level="6">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\cmd\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)whoami</field>
    <description>Suspicious Cmd Execution</description>
    <group>sigma,</group>
  </rule>
</group>
```

## Measured Benchmark Report

Evaluated against the pinned SigmaHQ commit [`05d1031f537e830b76da53bae2400c5814c89165`](https://github.com/SigmaHQ/sigma/commit/05d1031f537e830b76da53bae2400c5814c89165) inside a live Wazuh Manager (v4.9.0) using `wazuh-analysisd -t` and `wazuh-logtest`:

| Metric | Measured | Target Threshold | Status |
| :--- | :--- | :--- | :--- |
| **Total Rules Evaluated** | **138** | $\ge 100$ rules | **PASS** |
| **Conversion Rate** | **97.8%** (135/138) | $\ge 90\%$ (process_creation) | **PASS** |
| **Wazuh Manager Loadable XML** | **100.0%** (135/135) | $100\%$ | **PASS** |
| **Positive Fixture Firing Rate** | **83.0%** (112/135) | $\ge 80\%$ | **PASS** |
| **Negative Fixture Silence Rate** | **100.0%** (135/135) | $100\%$ (20 negative fixtures) | **PASS** |

See [`CONVERSION_REPORT.md`](CONVERSION_REPORT.md) for full benchmark breakdown, negative fixture definitions, and itemized unsupported constructs.

## Supported Log Sources & Shipped Decoders

This backend includes complete, verified decoders and base rules ready for production deployment:

1. **Windows Process Creation** (`decoders/0100-wazuh-sysmon-proc.xml`):
   - Supports Sysmon Event ID 1 & Windows Security Event 4688.
   - Extracts `win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.parentImage`, and `win.eventdata.user`.
   - Pipeline: `wazuh_windows`
2. **Linux Auditd `execve`** (`decoders/0101-wazuh-auditd-execve.xml`):
   - Decodes Linux audit subsystem `EXECVE` / `SYSCALL` events.
   - Extracts `audit.exe`, `audit.command`, `audit.auid`, `audit.cwd`.
   - Pipeline: `wazuh_linux`
3. **HTTP Access Logs** (`decoders/0102-wazuh-web-access.xml`):
   - Decodes NCSA Common, NCSA Combined, Nginx, and Apache access logs.
   - Maps static and dynamic fields: `url`, `protocol`, `id`, `srcip`, `browser`.
   - Pipeline: `wazuh_web`

To install decoders in your Wazuh Manager:
```bash
cp decoders/*.xml /var/ossec/etc/decoders/
/var/ossec/bin/wazuh-control restart
```

## Architecture & Compiler Internals

Sigma rules cannot be mapped 1:1 to Wazuh because Wazuh lacks an arbitrary query language and relies on XML rule trees:

1. **Boolean AST to DNF Normalization**: Sigma conditions are parsed into an Abstract Syntax Tree (AST) and normalized into Disjunctive Normal Form (DNF). Disjunctions (OR) across different fields are compiled into separate Wazuh rules sharing deterministic subrule IDs or chained via `<if_sid>`.
2. **Same-Field Regex Optimization**: Multiple `ConditionOR` clauses on the same field (or values with `|contains` modifiers) are optimized into a single `<field>` with regex alternation `|`, eliminating unnecessary rule bloat.
3. **Static vs Dynamic Field Mapping**: Wazuh separates core static fields (`url`, `srcip`, `protocol`, `id`) from dynamic decoded fields. The serializer automatically renders static fields as `<url type="pcre2">` and dynamic fields as `<field name="...">`.
4. **Keyword Searches**: Full-log keyword matches (`keywords:`) are compiled to unanchored `<regex type="pcre2">` matching across the entire raw log line.
5. **Deterministic SIDs**: All rule IDs are deterministically derived using SHA-256 with salting into the local user SID space `100000 - 120000`. Re-converting the same rule is idempotent and guarantees consistent SID generation across pipeline re-runs.

## License

MIT License.
