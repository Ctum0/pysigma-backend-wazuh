# Engineering Improvement Roadmap: pySigma Wazuh Backend

**Date**: 2026-10-25  
**Auditor**: Senior Architecture & Detection Engineering Team  
**Package**: `pysigma-backend-wazuh`  
**Status**: Active Engineering Backlog  

---

## 1. Prioritization Framework

Issues are classified using four engineering priority tiers:
- **P0 (Critical)**: Security risks, corrupted detection semantics, broken base APIs, fatal parser crashes.
- **P1 (High)**: Common construct translation errors, silent omissions, missing base rule chaining, incorrect exception signatures.
- **P2 (Medium)**: Coverage gaps, poor diagnostics, typing incompatibilities, sub-optimal default configurations.
- **P3 (Low)**: Minor performance optimizations, code quality formatting, non-blocking cosmetic enhancements.

---

## 2. Itemized Engineering Backlog

### [DEF-01] P0: Multi-Wildcard Internal Wildcard Drop in String Conversion
- **Severity**: P0 — Critical Semantic Loss
- **Category**: Detection Rule Semantic Correctness
- **Affected Symbol**: `sigma.backends.wazuh.wazuh.WazuhBackend._convert_sigma_string`
- **Reproduction**: Convert a Sigma string containing internal wildcards with a trailing wildcard, e.g., `*foo*bar*`.
- **Expected Behavior**: Compiles to `(?i)foo.*bar`.
- **Actual Behavior (Before Fix)**: Compiled to `(?i)foobar`, silently omitting the internal wildcard `.*`.
- **Technical Root Cause**: Line compared `item != items[-1]` by value. When the string ended with `SpecialChars.WILDCARD_MULTI`, any internal `WILDCARD_MULTI` matched `items[-1]`, skipping the `parts.append(".*")` call.
- **User Impact**: Real-world detections such as `*powershell*bypass*` silently failed to match any events where tokens were separated by spaces or arguments.
- **Fix Implemented**: Replaced loop with index-slice tracking: `start_idx = 1 if has_start_wildcard else 0` and `end_idx = (len(items) - 1) if (has_end_wildcard and len(items) > 1) else len(items)`.
- **Regression Test**: `tests/test_adversarial_and_properties.py::test_multi_wildcard_pattern_variations`
- **Status**: **RESOLVED & VERIFIED**

---

### [DEF-02] P0: Base Class Correlation Conversion Method Signature Mismatch
- **Severity**: P0 — Fatal API Breakdown
- **Category**: pySigma Framework API Contract
- **Affected Symbol**: `sigma.backends.wazuh.wazuh.WazuhBackend.convert_correlation_rule`
- **Reproduction**: Execute `backend.convert(collection)` on a collection containing both base and correlation rules.
- **Expected Behavior**: Successfully converts collection into a unified Wazuh XML ruleset.
- **Actual Behavior (Before Fix)**: Raised `TypeError: WazuhBackend.convert_correlation_rule() takes from 2 to 3 positional arguments but 5 were given`.
- **Technical Root Cause**: In `sigma.conversion.base.Backend`, `convert_correlation_rule(self, rule, output_format=None, method=None, callback=None)` expects 4 positional parameters and checks `self.correlation_methods`. `WazuhBackend` defined an incompatible signature without declaring `correlation_methods`.
- **User Impact**: Inability to run standard `sigma convert` CLI or `backend.convert()` on Sigma correlation rules.
- **Fix Implemented**: Added `correlation_methods` class attribute and separated internal IR builder `convert_correlation_rule_to_wazuh` from pySigma's dispatcher method.
- **Regression Test**: `tests/test_adversarial_and_properties.py::test_collection_conversion_with_correlations`
- **Status**: **RESOLVED & VERIFIED**

---

### [DEF-03] P0: Fatal Wazuh XML Parsing Crash on Static IP Fields
- **Severity**: P0 — Manager Startup Failure
- **Category**: Wazuh SIEM Engine Compatibility
- **Affected Symbol**: `sigma.backends.wazuh.models.WazuhField.to_xml`
- **Reproduction**: Convert any Sigma rule referencing `c-ip`, `cs-ip`, `src_ip`, or `srcip` (e.g. `c-ip: '192.168.1.50'`).
- **Expected Behavior**: Wazuh manager loads the rule successfully.
- **Actual Behavior (Before Fix)**: Generated `<srcip type="pcre2">(?i)^192\.168\.1\.50$</srcip>`. `wazuh-analysisd` threw fatal XML error `ERROR: (1237): Invalid ip address: '(?i)^192\.168\.1\.50$'` and crashed.
- **Technical Root Cause**: In Wazuh, `<srcip>` and `<dstip>` are static IP parser tags that reject regex attributes and regex metacharacters (`(?i)`, `^`, `$`, `\`).
- **User Impact**: Any rule involving IP addresses caused the entire Wazuh analysisd daemon to fail startup.
- **Fix Implemented**: Stripped regex anchors/flags in `models.py` when emitting `<srcip>` and `<dstip>`, and omitted `type="..."`.
- **Regression Test**: `tests/test_adversarial_and_properties.py::test_static_ip_fields_syntax_and_cidr`
- **Status**: **RESOLVED & VERIFIED**

---

### [DEF-04] P1: Shipped Base Rule Missing Native Windows JSON Context (`if_sid 60000`)
- **Severity**: P1 — Detection Inaction
- **Category**: Detection Engineering & Wazuh Engine Semantics
- **Affected Symbol**: `decoders/0100-wazuh-sysmon-proc.xml` (Rule 100000)
- **Reproduction**: Send a valid Sysmon Event ID 1 JSON event to a running Wazuh manager with rule 100000 loaded.
- **Expected Behavior**: Derived Sigma rules fire alerts.
- **Actual Behavior (Before Fix)**: Rule 60000 ('Group of windows rules') fired, but Rule 100000 never fired because it was not chained as a child of 60000.
- **Technical Root Cause**: Wazuh's default `0575-win-base_rules.xml` matches all Windows JSON events under root rule 60000. Sibling unchained rules in `local_rules.xml` are not evaluated for child branches.
- **User Impact**: Zero Windows process creation Sigma rules ever alerted in a live Wazuh environment.
- **Fix Implemented**: Added `<if_sid>60000</if_sid>` and `type="pcre2"` to base rule 100000.
- **Regression Test**: `tests/test_live_wazuh.py::test_live_wazuh_windows_execution`
- **Status**: **RESOLVED & VERIFIED**

---

### [DEF-05] P1: Semantic Inversion in `field_not_exists` Conversion
- **Severity**: P1 — Misleading Rule Generation
- **Category**: Detection Rule Semantic Correctness
- **Affected Symbol**: `sigma.backends.wazuh.wazuh.WazuhBackend.convert_condition_field_not_exists`
- **Reproduction**: Convert a rule checking that a dynamic field does not exist (`field: null`).
- **Expected Behavior**: Fail fast with an explicit typed error if the target SIEM cannot express field absence.
- **Actual Behavior (Before Fix)**: Emitted `<field name="..." type="pcre2" negate="yes">.</field>`. In Wazuh, `<field negate="yes">` requires the field to exist in decoded output and NOT match. If absent, it evaluates to false.
- **Technical Root Cause**: Conflating "field exists with value not matching" and "field does not exist in event".
- **User Impact**: Generated rules compiled but never fired when the target field was absent.
- **Fix Implemented**: Explicitly reject `field_not_exists` with typed `WazuhUnsupportedConditionError`.
- **Regression Test**: `tests/test_adversarial_and_properties.py::test_field_not_exists_raises_typed_error`
- **Status**: **RESOLVED & VERIFIED**

---

### [DEF-06] P2: Incompatible Exception Inheritance in `errors.py`
- **Severity**: P2 — Diagnostic Inconsistency
- **Category**: Error Handling & Diagnostics
- **Affected Symbol**: `sigma.backends.wazuh.errors.WazuhConversionError`
- **Reproduction**: Raise `WazuhConversionError("Custom message")` without passing a `rule` object.
- **Expected Behavior**: String message formatted properly in exception tracebacks.
- **Actual Behavior (Before Fix)**: String message was passed as the `rule` argument to `SigmaConversionError`.
- **Technical Root Cause**: `SigmaConversionError.__init__` requires `(rule: SigmaRuleBase, source, ...)`.
- **Fix Implemented**: Changed inheritance to `(WazuhError, SigmaBackendError)` with custom `__init__` supporting string messages and optional rule references.
- **Status**: **RESOLVED & VERIFIED**

---

## 3. Top 5 Highest-Value Improvements

1. **Native Base Rule Chaining (`DEF-04`)**: Unlocks end-to-end firing in live Wazuh managers for all Windows Sysmon detections.
2. **Multi-Wildcard Normalization (`DEF-01`)**: Eliminates silent false negatives on command-line pattern rules with multiple wildcards.
3. **Static IP Field Cleansing (`DEF-03`)**: Prevents fatal XML syntax crashes in `wazuh-analysisd` on web and network detections.
4. **pySigma Backend Correlation Integration (`DEF-02`)**: Ensures standard pySigma CLI workflows support correlation rules without runtime crashes.
5. **Fail-Fast Typed Errors on Untranslatable Constructs (`DEF-05`)**: Enforces "Correctness before Coverage" by stopping rules that would otherwise generate silent false negatives.
