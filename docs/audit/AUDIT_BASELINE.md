# Baseline Audit Report: pySigma Wazuh Backend

**Date**: 2026-10-25  
**Auditor**: Senior Engineering & Quality Assurance Audit Team  
**Repository**: `pysigma-backend-wazuh`  
**Git Baseline Commit**: `1032cdf` (`main`)  

---

## 1. System & Environment Inventory

| Component | Verified Specification |
| :--- | :--- |
| **Operating System** | Linux Parrot 7.1.13+parrot7-amd64 (x86_64 GNU/Linux) |
| **Python Runtime** | Python 3.12.15 (`.venv/bin/python`) |
| **pySigma Core** | `1.5.1` |
| **sigma-cli** | `3.1.0` |
| **pytest / pytest-cov** | `9.1.1` / `7.1.0` |
| **lxml** | `6.1.3` |
| **Build Backend** | `hatchling 1.32.4` |
| **Live Wazuh Container** | `wazuh/wazuh-manager:4.9.0` (Docker / Podman) |
| **Target Wazuh Engines** | `pcre2` (Wazuh 4.x/5.x native) & `osregex` |

---

## 2. Baseline Test & Coverage Metrics

### 2.1 Initial Test Suite (Offline)
- **Command**: `.venv/bin/pytest --cov=sigma.backends.wazuh --cov=sigma.pipelines.wazuh --cov-report=term-missing`
- **Collected**: 40 items
- **Passed**: 37
- **Skipped**: 3 (`tests/test_live_wazuh.py` - when container runtime check was skipped)
- **Coverage**: **78%** overall (140 missed statements)

```
Name                                   Stmts   Miss  Cover   Missing
--------------------------------------------------------------------
sigma/backends/wazuh/__init__.py           5      0   100%
sigma/backends/wazuh/errors.py            34      7    79%   19-23, 58-59
sigma/backends/wazuh/id_allocator.py      38      1    97%   72
sigma/backends/wazuh/models.py           112     19    83%   11, 40, 62-68, 74, 107-108, 123-124, 130-133, 151
sigma/backends/wazuh/wazuh.py            407    112    72%   54, 56, 58, 108, 128, 133, 136-139, 150, 156, 162-168...
sigma/pipelines/wazuh/__init__.py          8      1    88%   11
sigma/pipelines/wazuh/linux.py             7      0   100%
sigma/pipelines/wazuh/web.py               7      0   100%
sigma/pipelines/wazuh/windows.py           7      0   100%
--------------------------------------------------------------------
TOTAL                                    625    140    78%
```

### 2.2 Live Wazuh Integration Test (Initial Run with Active Container)
- **Command**: `.venv/bin/pytest tests/test_live_wazuh.py`
- **Result**: **1 FAILED, 2 PASSED**
- **Failure**:
  `tests/test_live_wazuh.py::test_live_wazuh_windows_execution`
  ```
  FAILED: assert "id: '103862'" in output
  Actual output: Rule 60000 ('Group of windows rules') fired, but Rule 103862 did not.
  ```
- **Root Cause**: Base rule 100000 in `BASE_RULES` lacked `<if_sid>60000</if_sid>`. In Wazuh 4.x, all Windows JSON events are claimed by core parent rule 60000; unchained custom rules never evaluate.

---

## 3. Static Analysis & Type Checking Baseline

### 3.1 Mypy Type Checking
- **Command**: `.venv/bin/mypy --explicit-package-bases sigma`
- **Errors**: **38 type errors**
- **Key Categories**:
  1. **Liskov Substitution Violations**:
     - `convert_correlation_*_rule` signatures in `WazuhBackend` declared `(self, rule, state: ConversionState)` instead of `(self, rule, output_format=None, method='default') -> list[Any]`.
     - `convert_condition` parameter typed as `ConditionItem` instead of `ConditionItem | ConditionFieldEqualsValueExpression | ConditionValueExpression | None`.
  2. **pySigma Base Class Attribute Omission**:
     - `correlation_methods` was missing on `WazuhBackend`, causing `Backend.convert()` to raise `NotImplementedError` when parsing correlation collections.
  3. **Exception Constructor Incompatibilities**:
     - `WazuhConversionError` inherits `SigmaConversionError` whose constructor signature is `(rule: SigmaRuleBase, source: SigmaRuleLocation | None = None, *args)`. Passing a bare string passed the message as the `rule` parameter.

### 3.2 Ruff Linter
- **Command**: `.venv/bin/ruff check sigma tests`
- **Errors**: 117 issues (import sorting, unused imports, unnecessary f-strings, RUF015 slice optimizations).

---

## 4. Critical Baseline Defects Discovered

1. **DEF-01 (P0 - Semantic Loss)**: `_convert_sigma_string` dropped intermediate multi-wildcards `*` if the pattern had a trailing `*` (e.g. `*foo*bar*` compiled to `(?i)foobar` instead of `(?i)foo.*bar`).
2. **DEF-02 (P0 - API Breakage)**: `convert_correlation_rule` signature mismatch with `sigma.conversion.base.Backend`. Calling `backend.convert(collection)` on correlation rules raised `TypeError: takes 2-3 positional arguments but 5 given`.
3. **DEF-03 (P0 - Fatal XML Syntax)**: Static IP fields (`srcip`, `dstip`) generated regex-escaped strings with `type="pcre2"` (e.g. `<srcip type="pcre2">(?i)^192\.168\.1\.1$</srcip>`). `wazuh-analysisd` threw fatal XML parsing error `Invalid ip address`.
4. **DEF-04 (P1 - Detection Failure)**: Shipped Windows base rule 100000 lacked `<if_sid>60000</if_sid>` and `type="pcre2"`, preventing Windows Sysmon events from triggering downstream detection rules in a real manager.
5. **DEF-05 (P1 - Semantic Fallacy)**: `convert_condition_field_not_exists` generated `<field negate="yes">.`. In Wazuh, `<field negate="yes">` evaluates to `False` if the field does not exist in decoded output, so field non-existence rules never fired.
6. **DEF-06 (P2 - Exception Hierarchy)**: `WazuhConversionError` improperly subclassed `SigmaConversionError` without adhering to its `rule` parameter requirement.

---

## 5. Compatibility Contract

| Dimension | Supported & Tested Specification |
| :--- | :--- |
| **Python** | 3.9, 3.10, 3.11, 3.12 (CI-verified across 3.10-3.12) |
| **pySigma Core** | `>=0.11.0, <=1.5.x` |
| **Sigma Rule Spec** | v1 and v2 Core Specifications |
| **Wazuh Manager** | Wazuh v4.4.x - v4.14.x (Live tested against v4.9.0) |
| **Regex Engines** | `pcre2` (Default, full PCRE2 syntax) & `osregex` (strict dialect validation) |
| **Log Sources** | Windows Process Creation (Sysmon 1 / 4688), Linux `execve` (auditd), HTTP access logs |
