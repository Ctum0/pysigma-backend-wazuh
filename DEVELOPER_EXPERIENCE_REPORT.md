# Developer Experience (DX) & Public API Audit Report

**Date**: 2026-10-25  
**Auditor**: Senior Developer Experience & Open Source Engineering  
**Package**: `pysigma-backend-wazuh`  
**Status**: DX & Public API Audit Completed  

---

## 1. Installation & Plugin Discovery

### 1.1 Entry Point Configuration
The package integrates directly with `pySigma` and `sigma-cli` via PEP 621 entry points in `pyproject.toml`:
- `sigma.backends`: `wazuh = "sigma.backends.wazuh:WazuhBackend"`
- `sigma.pipelines`:
  - `wazuh`: Combined auto-detect pipeline (Windows, Linux, Web)
  - `wazuh_windows`: Windows Sysmon & Security 4688 pipeline
  - `wazuh_linux`: Linux auditd (`execve`) pipeline
  - `wazuh_web`: Web access log pipeline

### 1.2 Virtual Environment Behavior
`pySigma` discovers backends dynamically at runtime by scanning `sys.path` for installed distributions registering the `sigma.backends` entry point. When users execute `sigma` globally without activating the virtual environment where `pysigma-backend-wazuh` is installed, `sigma-cli` raises:
```
Error: Invalid value for '--target' / '-t': 'wazuh' is not one of 'lucene', 'eql'...
```
**Resolution**: Clearly documented in `README.md` and quickstart guides with zero ambiguity.

---

## 2. CLI Usability & Workflow Support

### 2.1 Single Rule & Directory Batch Conversion
```bash
# Convert a single rule targeting Windows Sysmon
sigma convert -t wazuh -p wazuh_windows rule.yml

# Convert entire directories in batch
sigma convert -t wazuh -p wazuh rules_dir/

# Stream conversion via STDIN
cat rule.yml | sigma convert -t wazuh -p wazuh -
```

### 2.2 Output Formats
1. `default`: Generates a standard Wazuh XML file wrapped in `<group name="sigma,">`, ready for `/var/ossec/etc/rules/local_rules.xml`.
2. `rule_only`: Generates bare `<rule>` XML elements without the root `<group>` wrapper, designed for automated templating or rule embedding.
3. `json`: Emits structured JSON representing the converted Intermediate Representation (IR), facilitating downstream programmatic pipelines.

---

## 3. Python API Integration

### 3.1 Standard Programmatic Flow
```python
from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.pipelines.wazuh import wazuh_windows_pipeline

# 1. Parse rule collection
collection = SigmaCollection.from_yaml(rule_yaml_or_file)

# 2. Instantiate backend with target pipeline
backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())

# 3. Convert collection to native Wazuh XML
wazuh_xml = backend.convert(collection)
print(wazuh_xml)
```

### 3.2 Correlation Rules Support
Multi-document YAML collections containing both base detection rules and `SigmaCorrelationRule` objects are converted seamlessly via `backend.convert(collection)`:
- Base rules are allocated unique SIDs.
- Correlation rules link to primary base SIDs via `<if_matched_sid>`, `<frequency>`, and `<timeframe>`.

---

## 4. Error Diagnostics & Fail-Fast Behavior

Every unsupported condition or incompatible dialect construct raises a typed exception derived from `WazuhError` / `SigmaBackendError`:

| Exception Class | Trigger Condition | Diagnostic Message Example |
| :--- | :--- | :--- |
| `WazuhUnsupportedModifierError` | Unsupported value modifier | `Unsupported modifier 'custom_mod' for Wazuh backend.` |
| `WazuhUnsupportedConditionError` | Numeric compare / field equality / null / non-existence | `Unsupported condition 'FieldNotExists' in Wazuh backend. Wazuh field engine cannot test for the non-existence of dynamic field 'X' because <field negate='yes'> requires the field to exist in decoded output.` |
| `WazuhRegexDialectError` | PCRE lookaheads/flags in `osregex` mode | `Cannot translate pattern '(?=.*abc)' to Wazuh engine 'osregex'. Reason: Pattern contains PCRE group/assertion modifiers unsupported by OS_Regex.` |
| `WazuhIDCollisionError` | SID allocation space exhaustion | `Rule ID allocation collision for rule 'X' at Wazuh SID 119999.` |

The exceptions provide immediate clarity on what caused the failure and what detection engineers should do to adjust their rules.
