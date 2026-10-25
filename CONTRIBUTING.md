# Contributing to pySigma-backend-wazuh

Thank you for your interest in contributing! This backend translates [SigmaHQ detection rules](https://github.com/SigmaHQ/sigma) into native [Wazuh SIEM XML rulesets](https://documentation.wazuh.com/current/user-manual/ruleset/index.html).

---

## Guiding Principle: Correctness Before Coverage

> **Critical Rule**: Never increase apparent conversion coverage by generating incorrect, incomplete, or misleading rules.

Wazuh's detection engine is rule-based and regex-driven. If a Sigma construct cannot be faithfully mapped without semantic distortion (e.g. numeric range comparisons like `CommandLine|gt: 10` or non-existence checks), the backend **must fail closed** by raising a typed exception (`WazuhUnsupportedConditionError`) rather than emitting a silent false negative or false positive.

---

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Ctum0/pysigma-backend-wazuh.git
   cd pysigma-backend-wazuh
   ```

2. **Set up a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

3. **Verify installation & plugin discovery**:
   ```bash
   sigma list targets
   # Should list 'wazuh'
   sigma list pipelines wazuh
   # Should list 'wazuh', 'wazuh_windows', 'wazuh_linux', 'wazuh_web'
   ```

---

## Running Tests

We maintain strict regression, property-based, and security tests:

```bash
# Run unit, boolean, modifier, and property-based tests:
pytest

# Run excluding live Wazuh container tests:
pytest -k "not test_live_wazuh"

# Run with test coverage report:
pytest --cov=sigma/backends/wazuh --cov=sigma/pipelines/wazuh
```

### Running with a Live Wazuh Manager (Optional)

To validate rules against a real `wazuh-analysisd` daemon:
```bash
docker run -d --name wazuh-manager -p 1514:1514/udp -p 1515:1515 -p 55000:55000 wazuh/wazuh-manager:4.9.0
pytest tests/test_live_wazuh.py
```

---

## Contributing Pipelines & Decoders

When adding support for new log sources or products:

1. **Field Mappings**: Add mappings in `sigma/pipelines/wazuh/pipelines.py` using `FieldMappingTransformation`.
2. **Parent Groups / SIDs**: Specify the parent group (`wazuh_parent_group`) or parent SID (`wazuh_parent_sid`) so child rules hook cleanly into Wazuh's hierarchical rule tree.
3. **Decoders**: Place any custom Wazuh XML decoders required for testing under `decoders/`.
4. **Tests**: Add corresponding unit tests in `tests/test_pipelines.py` and real-world test cases.

---

## Pull Request Guidelines

- Ensure **all tests pass** (`pytest`).
- Follow standard PEP 8 naming and type annotations.
- Include unit tests for every bug fix or newly supported Sigma modifier.
- Keep commits focused and descriptive (e.g. `feat:`, `fix:`, `docs:`, `test:`).
