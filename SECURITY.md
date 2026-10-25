# Security Policy

## Supported Versions

We actively maintain and provide security patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability, weakness, or flaw in `pysigma-backend-wazuh`—especially concerning:
- **XML Injection / Breakout**: Unescaped Sigma strings or fields allowing adversary control over Wazuh XML structure.
- **Regular Expression Denial of Service (ReDoS)**: Specially crafted Sigma regexes or expansions causing algorithmic complexity exhaustion.
- **Rule Bypass / Logic Inversion**: Inadvertent negation flips or pattern truncation leading to false negative detection evasion.
- **Supply Chain Vulnerabilities**: Compromised dependencies or malicious package distribution.

**Please do NOT open a public GitHub issue.**

### Reporting Procedure

1. **Email Contact**: Send a detailed report to security contact or open a **Private Vulnerability Report** via GitHub Security Advisories at [Ctum0/pysigma-backend-wazuh/security/advisories](https://github.com/Ctum0/pysigma-backend-wazuh/security/advisories).
2. **Include Details**:
   - A description of the issue and potential security impact.
   - A minimal reproducible Sigma rule (`rule.yml`).
   - The CLI or Python code used to trigger the issue.
   - The generated Wazuh XML showing the flaw.
3. **Response Timeline**:
   - **Initial acknowledgement**: Within 48 hours.
   - **Triage and reproduction**: Within 5 business days.
   - **Fix and advisory release**: Coordinated disclosure within 30 days.

---

## Security Architecture & Defenses

This backend incorporates proactive defensive controls:
- **XML Sanitization**: Strictly escapes characters (`<`, `>`, `&`, `"`, `'`) and filters out illegal XML 1.0 control characters (`\x00-\x08`, `\x0B-\x0C`, `\x0E-\x1F`).
- **Complexity Safeguards**: Sets an upper limit on DNF boolean expansion (`MAX_DNF_DISJUNCTS = 256`) to protect against memory exhaustion attacks from exponential Cartesian products.
- **Regex Dialect Enforcement**: Rejects incompatible PCRE2 features (lookarounds, backreferences) when `regex_engine="osregex"` is targeted to prevent engine crashes.
- **Strict Typing & Error Fail-Closed**: Features with unsupported semantics (e.g., numeric comparisons or non-existence checks) fail explicitly with typed exceptions rather than emitting faulty, silent rules.
