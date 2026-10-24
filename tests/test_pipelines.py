"""Tests for Wazuh processing pipelines (Windows, Linux, Web)."""

from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.pipelines.wazuh import (
    wazuh_windows_pipeline,
    wazuh_linux_pipeline,
    wazuh_web_pipeline,
)


def test_windows_pipeline_mappings():
    b = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    yaml_text = """
    title: Windows Process Creation
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image: 'C:\\Windows\\cmd.exe'
            CommandLine: 'whoami'
            ParentImage: 'C:\\Windows\\explorer.exe'
            User: 'SYSTEM'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = b.convert_rule(rule)
    assert len(w_rules) == 1
    names = {f.name for f in w_rules[0].fields}
    assert "win.eventdata.image" in names
    assert "win.eventdata.commandLine" in names
    assert "win.eventdata.parentImage" in names
    assert "win.eventdata.user" in names
    assert w_rules[0].if_group == "sysmon_event1"


def test_linux_pipeline_mappings():
    b = WazuhBackend(processing_pipeline=wazuh_linux_pipeline())
    yaml_text = """
    title: Linux Process Execution
    logsource:
        category: process_creation
        product: linux
    detection:
        sel:
            Image: '/bin/bash'
            CommandLine: 'bash -i'
            User: 'root'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = b.convert_rule(rule)
    assert len(w_rules) == 1
    names = {f.name for f in w_rules[0].fields}
    assert "audit.exe" in names
    assert "audit.command" in names
    assert "audit.auid" in names
    assert w_rules[0].if_group == "audit_execve"


def test_web_pipeline_mappings():
    b = WazuhBackend(processing_pipeline=wazuh_web_pipeline())
    yaml_text = """
    title: Web Directory Traversal
    logsource:
        category: webserver
    detection:
        sel:
            c-uri|contains: '../..'
            cs-method: 'GET'
            sc-status: 200
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = b.convert_rule(rule)
    assert len(w_rules) == 1
    names = {f.name for f in w_rules[0].fields}
    assert "url" in names
    assert "protocol" in names
    assert "id" in names
    assert w_rules[0].if_group == "web_access"

