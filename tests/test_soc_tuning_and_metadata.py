"""Tests for SOC tuning, false positive guidance, status awareness, and SID partitioning."""

import lxml.etree
from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.pipelines.wazuh import wazuh_windows_pipeline


def test_false_positive_comments_rendered():
    """Verify that falsepositives list in Sigma rule is rendered as an XML comment."""
    yaml_text = """
    title: Suspicious Cmd Execution
    status: stable
    falsepositives:
        - Benign administrative backup scripts
        - Internal SCCM deployment tasks --dry-run
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\cmd.exe'
        condition: sel
    """
    col = SigmaCollection.from_yaml(yaml_text)
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    xml_out = backend.convert(col)

    assert "<!-- False Positives: Benign administrative backup scripts, Internal SCCM deployment tasks - -dry-run -->" in xml_out
    assert "<!-- Status: stable -->" in xml_out

    # Must be valid XML
    root = lxml.etree.fromstring(xml_out.encode("utf-8"))
    assert root.tag == "group"
    assert len(root.findall("rule")) == 1


def test_status_comments_and_experimental_demotion():
    """Verify that experimental / test rules are capped at level 3 when demote_experimental=True."""
    yaml_text = """
    title: Experimental Discovery Rule
    status: experimental
    level: critical
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\whoami.exe'
        condition: sel
    """
    col = SigmaCollection.from_yaml(yaml_text)

    # 1. Without demotion: level should be 12 (critical)
    backend_default = WazuhBackend(processing_pipeline=wazuh_windows_pipeline(), demote_experimental=False)
    xml_default = backend_default.convert(col)
    root_default = lxml.etree.fromstring(xml_default.encode("utf-8"))
    assert root_default.find("rule").get("level") == "12"

    # 2. With demotion: level should be capped at 3
    backend_demote = WazuhBackend(processing_pipeline=wazuh_windows_pipeline(), demote_experimental=True)
    xml_demote = backend_demote.convert(col)
    root_demote = lxml.etree.fromstring(xml_demote.encode("utf-8"))
    assert root_demote.find("rule").get("level") == "3"
    assert "<!-- Status: experimental (demoted to level 3 for SOC tuning) -->" in xml_demote


def test_status_deprecated_warning():
    """Verify that deprecated rules include an explicit warning comment."""
    yaml_text = """
    title: Deprecated Legacy Rule
    status: deprecated
    level: medium
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\oldtool.exe'
        condition: sel
    """
    col = SigmaCollection.from_yaml(yaml_text)
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    xml_out = backend.convert(col)

    assert "<!-- WARNING: Upstream Sigma rule is marked DEPRECATED -->" in xml_out
    root = lxml.etree.fromstring(xml_out.encode("utf-8"))
    assert root.tag == "group"


def test_include_comments_disabled():
    """Verify that include_comments=False suppresses comment emission."""
    yaml_text = """
    title: Clean Output Rule
    status: experimental
    falsepositives:
        - Benign activity
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\cmd.exe'
        condition: sel
    """
    col = SigmaCollection.from_yaml(yaml_text)
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline(), include_comments=False)
    xml_out = backend.convert(col)

    assert "<!--" not in xml_out


def test_sid_range_customization():
    """Verify that custom SID boundaries isolate enterprise rule spaces."""
    yaml_text = """
    title: Isolated Space Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\powershell.exe'
        condition: sel
    """
    col = SigmaCollection.from_yaml(yaml_text)
    backend = WazuhBackend(
        processing_pipeline=wazuh_windows_pipeline(),
        min_rule_id=200000,
        max_rule_id=250000,
    )
    xml_out = backend.convert(col)
    root = lxml.etree.fromstring(xml_out.encode("utf-8"))
    rule_id = int(root.find("rule").get("id"))
    assert 200000 <= rule_id <= 250000
