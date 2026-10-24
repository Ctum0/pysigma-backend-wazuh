"""Tests for Sigma modifiers in Wazuh backend."""

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.backends.wazuh.errors import (
    WazuhUnsupportedConditionError,
    WazuhRegexDialectError,
)
from sigma.pipelines.wazuh import wazuh_windows_pipeline


@pytest.fixture
def backend():
    return WazuhBackend(processing_pipeline=wazuh_windows_pipeline())


def test_modifier_contains(backend):
    yaml_text = """
    title: Test Contains
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains: 'mimikatz'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.commandLine"
    assert "mimikatz" in f.pattern
    assert not f.pattern.endswith("$")
    assert not f.pattern.startswith("^")


def test_modifier_startswith(backend):
    yaml_text = """
    title: Test Startswith
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|startswith: 'powershell'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.commandLine"
    # Should be anchored at start with ^ (or (?i)^)
    assert "^powershell" in f.pattern or "(?i)^powershell" in f.pattern
    assert not f.pattern.endswith("$")


def test_modifier_endswith(backend):
    yaml_text = """
    title: Test Endswith
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\cmd.exe'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.image"
    assert f.pattern.endswith("$")
    assert "\\cmd\\.exe$" in f.pattern


def test_modifier_re(backend):
    yaml_text = """
    title: Test Regex
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: 'powershell.*-enc'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.commandLine"
    assert "powershell.*-enc" in f.pattern


def test_modifier_all(backend):
    yaml_text = """
    title: Test All
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains|all:
                - '-enc'
                - 'hidden'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    fields = w_rules[0].fields
    # Both items must be present as AND fields in the rule
    assert len(fields) == 2
    assert all(f.name == "win.eventdata.commandLine" for f in fields)
    patterns = [f.pattern for f in fields]
    assert any("-enc" in p for p in patterns)
    assert any("hidden" in p for p in patterns)


def test_modifier_windash(backend):
    yaml_text = """
    title: Test Windash
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|windash: '-enc'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.commandLine"
    # Should contain alternation with /enc and -enc
    assert "/enc" in f.pattern and "-enc" in f.pattern


def test_modifier_base64offset(backend):
    yaml_text = """
    title: Test Base64
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|base64offset|contains: 'whoami'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.commandLine"
    # Contains the 3 base64 offset variations
    assert "d2hvYW1p" in f.pattern or "dob2Fta" in f.pattern or "3aG9hbW" in f.pattern


def test_osregex_rejects_incompatible_pcre():
    b_osregex = WazuhBackend(regex_engine="osregex")
    yaml_text = """
    title: Test PCRE in OS_Regex
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: '(?i)foo.*'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    with pytest.raises(WazuhRegexDialectError):
        b_osregex.convert_rule(rule)



def test_unsupported_compare_expression_raises_typed_error(backend):
    yaml_text = """
    title: Test Unsupported Compare
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            ProcessId|gt: 1000
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    with pytest.raises(WazuhUnsupportedConditionError) as exc_info:
        backend.convert_rule(rule)
    assert "CompareExpression" in str(exc_info.value)
