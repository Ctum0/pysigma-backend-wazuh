"""Tests for Boolean tree translation in Wazuh backend."""

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.pipelines.wazuh import wazuh_windows_pipeline


@pytest.fixture
def backend():
    return WazuhBackend(processing_pipeline=wazuh_windows_pipeline())


def test_boolean_and_not_filter(backend):
    yaml_text = """
    title: Selection and not filter
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            Image|endswith: '\\cmd.exe'
            CommandLine|contains: 'whoami'
        filter:
            CommandLine|contains: 'adm'
        condition: selection and not filter
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    fields = w_rules[0].fields
    assert len(fields) == 3

    # Positive fields
    pos_fields = [f for f in fields if not f.negate]
    assert len(pos_fields) == 2
    pos_names = {f.name for f in pos_fields}
    assert pos_names == {"win.eventdata.image", "win.eventdata.commandLine"}

    # Negative field
    neg_fields = [f for f in fields if f.negate]
    assert len(neg_fields) == 1
    assert neg_fields[0].name == "win.eventdata.commandLine"
    assert "adm" in neg_fields[0].pattern


def test_boolean_1_of(backend):
    yaml_text = """
    title: 1 of selection*
    logsource:
        category: process_creation
        product: windows
    detection:
        sel_cmd:
            Image|endswith: '\\cmd.exe'
        sel_ps:
            Image|endswith: '\\powershell.exe'
        condition: 1 of sel_*
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    # Merged onto same field Image using regex alternation
    assert len(w_rules) == 1
    f = w_rules[0].fields[0]
    assert f.name == "win.eventdata.image"
    assert "cmd\\.exe" in f.pattern
    assert "powershell\\.exe" in f.pattern


def test_boolean_all_of(backend):
    yaml_text = """
    title: all of selection*
    logsource:
        category: process_creation
        product: windows
    detection:
        sel_image:
            Image|endswith: '\\cmd.exe'
        sel_cmd:
            CommandLine|contains: 'whoami'
        condition: all of sel_*
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    fields = w_rules[0].fields
    assert len(fields) == 2
    assert {f.name for f in fields} == {"win.eventdata.image", "win.eventdata.commandLine"}


def test_boolean_or_different_fields_without_chaining(backend):
    yaml_text = """
    title: OR across different fields
    logsource:
        category: process_creation
        product: windows
    detection:
        sel_a:
            Image|endswith: '\\cmd.exe'
        sel_b:
            User: 'SYSTEM'
        condition: sel_a or sel_b
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    # Disjunctive normal form produces 2 rules when fields are different
    assert len(w_rules) == 2
    assert w_rules[0].fields[0].name == "win.eventdata.image"
    assert w_rules[1].fields[0].name == "win.eventdata.user"


def test_boolean_or_different_fields_with_chaining():
    b_chain = WazuhBackend(
        processing_pipeline=wazuh_windows_pipeline(),
        chain_rules=True,
    )
    yaml_text = """
    title: Chained OR
    logsource:
        category: process_creation
        product: windows
    detection:
        sel_a:
            Image|endswith: '\\cmd.exe'
        sel_b:
            User: 'SYSTEM'
        condition: sel_a or sel_b
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = b_chain.convert_rule(rule)
    # 2 branch rules (level 0) + 1 aggregating alert rule with if_sid
    assert len(w_rules) == 3
    branch_sids = [r.id for r in w_rules[:2]]
    alert_rule = w_rules[2]
    assert alert_rule.if_sid == branch_sids
    assert alert_rule.level > 0
