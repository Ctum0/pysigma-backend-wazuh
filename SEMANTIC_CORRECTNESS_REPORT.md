# Sigma Semantic-Correctness Audit Report

**Date**: 2026-10-25  
**Auditor**: Senior Detection Engineering & Semantic Correctness Team  
**Package**: `pysigma-backend-wazuh`  
**Status**: Rigorous Semantic Audit Completed  

---

## 1. Executive Summary

A detection rule backend must guarantee that the generated target query or rule preserves the exact logical and semantic meaning of the original Sigma specification. Producing valid XML is meaningless if the rule silently fails to match attacks, creates false alerts, or drops criteria.

This audit evaluates the translation fidelity across:
1. Boolean trees and condition normalization (DNF, De Morgan's laws, chaining)
2. Field matching, modifiers, and wildcard semantics
3. Log source scoping, base rule dependencies, and decoders
4. Explicit unsupported construct boundaries and typed rejection errors

---

## 2. Boolean Logic & Condition Normalization

### 2.1 Truth-Table Comparison

| Sigma Logical Construct | Wazuh Target Representation | Semantic Equivalence | Validation Status |
| :--- | :--- | :--- | :--- |
| `A and B` | Single `<rule>` with multiple `<field>` elements | **100% Equivalent** (Wazuh evaluates fields with conjunction AND) | Verified in unit tests & `wazuh-logtest` |
| `A or B` (same field) | Single `<field name="F" type="pcre2">(?i)(A\|B)</field>` | **100% Equivalent** (Regex alternation preserves disjunction) | Verified in unit tests & `wazuh-logtest` |
| `A or B` (different fields, default) | Multiple sibling `<rule>` elements with deterministic IDs | **Equivalent** (First matching rule triggers alert) | Verified in unit tests & `wazuh-logtest` |
| `A or B` (chained mode) | Intermediate `level="0"` rules + parent alert rule with `<if_sid>` | **100% Equivalent** (Single alert firing regardless of which branch matches) | Verified in unit tests & `wazuh-logtest` |
| `A and not B` (single value) | `<field name="A">...`, `<field name="B" negate="yes">...` | **100% Equivalent** | Verified in unit tests & `wazuh-logtest` |
| `A and not (B or C)` | Single rule with `<field name="B" type="pcre2" negate="yes">(?i)(B\|C)</field>` | **100% Equivalent** via De Morgan's Normalization | Verified in unit tests & `wazuh-logtest` |
| `A and not (B and C)` | DNF expansion: `(A and not B) or (A and not C)` | **100% Equivalent** | Verified in unit tests & `wazuh-logtest` |
| `1 of them` / `all of them` | AST expanded to `ConditionOR` or `ConditionAND` | **100% Equivalent** | Verified in unit tests |

### 2.2 Complexity Safeguards
Unbounded boolean normalization from arbitrary boolean expressions to Disjunctive Normal Form (DNF) has a worst-case theoretical complexity of $\mathcal{O}(2^N)$. To protect against algorithmic denial-of-service (ReDoS/Algorithmic DoS) when processing maliciously crafted Sigma rules in automated CI/CD pipelines:
- `MAX_DNF_DISJUNCTS = 256` is strictly enforced.
- Exceeding disjunct counts immediately raises `WazuhConversionError` with an actionable simplification message.

---

## 3. Field Matching & Value Modifiers

### 3.1 Modifier Semantic Assessment

| Modifier | Sigma Semantics | Wazuh Implementation | Fidelity Verdict |
| :--- | :--- | :--- | :--- |
| `contains` | Substring match anywhere in field | `(?i)substring` (unanchored PCRE2) | **Faithfully Supported** |
| `startswith` | Field begins with string | `(?i)^prefix` | **Faithfully Supported** |
| `endswith` | Field ends with string | `(?i)suffix$` | **Faithfully Supported** |
| `re` | Regular expression match | Validated PCRE2 or OS_Regex pattern | **Faithfully Supported** (Rejects PCRE syntax in OS_Regex) |
| `all` | All values in list must match | Generates multiple consecutive `<field>` elements | **Faithfully Supported** |
| `windash` | Accepts `-` or `/` parameter prefixes | Expanded via `SigmaExpansion` into `(-foo\|/foo)` | **Faithfully Supported** |
| `base64` / `base64offset` | Base64 encoded variations | Expanded via `SigmaExpansion` with alternation | **Faithfully Supported** |
| `cidr` | IP network range matching | Supported natively on static fields (`srcip`, `dstip`) | **Faithfully Supported on IP fields** |
| `compare` (`gt`, `lt`, etc.) | Numeric relative comparison | Not supported by Wazuh field matchers | **Explicitly Rejected** (`WazuhUnsupportedConditionError`) |
| `null` | Field is null / empty | Not directly supported by Wazuh field engine | **Explicitly Rejected** (`WazuhUnsupportedConditionError`) |
| `field_exists` | Field exists in event | `<field name="..." type="pcre2">.*</field>` | **Faithfully Supported** |
| `field_not_exists` | Field absent from event | In Wazuh, `<field negate="yes">` fails if field is absent | **Explicitly Rejected** (`WazuhUnsupportedConditionError`) |

### 3.2 Audit of Escaping & Special Regex Characters
Literal strings containing regex metacharacters (`.`, `*`, `+`, `?`, `^`, `$`, `(`, `)`, `[`, `]`, `{`, `}`, `|`, `\`) must never accidentally become regex operators.

1. **Regex Escaping**: `escape_regex_literal` escapes all PCRE2 metacharacters while correctly handling control characters (`\n`, `\r`, `\t`).
2. **XML Escaping**: Handled separately via `models.xml_escape` with full entity encoding (`&quot;`, `&apos;`, `&lt;`, `&gt;`, `&amp;`) and control character sanitization.
3. **Execution Order**: Regex patterns are formulated first, and final strings are XML-escaped during serialization, ensuring zero collision between regex backslashes and XML syntax.

---

## 4. Static vs Dynamic Wazuh Field Semantics

Wazuh distinguishes between core static fields (which have dedicated XML tags) and dynamic decoded fields:

1. **Static Fields**:
   - `url`, `protocol`, `id`, `action`, `user`, `data`, `extra_data`, `system_name`, `hostname`: Natively compiled to `<tag type="pcre2">pattern</tag>`.
   - `srcip`, `dstip`: Wazuh strictly requires valid IP addresses or CIDR blocks without regex anchors or `type="pcre2"`. Regex strings cause fatal manager errors (`Invalid ip address`). The serializer strips anchors and emits clean `<srcip>192.168.1.1</srcip>` or `<srcip>192.168.1.0/24</srcip>`.
2. **Dynamic Fields**:
   - All other fields (e.g. `win.eventdata.image`, `audit.exe`) are serialized as `<field name="field.name" type="pcre2">pattern</field>`.

---

## 5. Explicitly Unsupported Sigma Features

In adherence to the core principle of **Correctness before Coverage**, the following features cannot be faithfully mapped to Wazuh XML and raise typed exceptions:

1. **Dynamic Field Comparisons (`fieldA = fieldB`)**: Wazuh rules match against constant patterns or regexes, not between two dynamic event fields at runtime. Raises `WazuhUnsupportedConditionError`.
2. **Numeric Comparisons (`field > 1024`)**: Wazuh `<field>` elements perform string matching and regex evaluation, not arithmetic comparison. Raises `WazuhUnsupportedConditionError`.
3. **Absence of Dynamic Decoded Field (`field_not_exists`)**: Wazuh evaluates `<field>` only against decoded fields; if a field was not decoded, `<field negate="yes">` evaluates to false. Silently compiling this would create a rule that never alerts. Raises `WazuhUnsupportedConditionError`.
4. **Aggregate Correlations (Sum, Avg, Median, Percentile)**: Wazuh correlation engine (`<frequency>`, `<timeframe>`, `<same_field>`) supports event count and simple value tracking, but cannot compute arithmetic averages or percentiles. Raises `WazuhUnsupportedConditionError`.
