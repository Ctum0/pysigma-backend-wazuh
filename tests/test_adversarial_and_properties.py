"""Property-based tests, adversarial fuzzing, and regression tests for pySigma Wazuh backend."""

import lxml.etree
import pytest
from hypothesis import given, strategies as st, settings

from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.backends.wazuh.errors import (
    WazuhConversionError,
    WazuhUnsupportedConditionError,
)
from sigma.pipelines.wazuh import (
    wazuh_windows_pipeline,
    wazuh_web_pipeline,
)
from sigma.types import SigmaString


def test_multi_wildcard_pattern_variations():
    """Verify that multi-wildcard patterns preserve all internal wildcards."""
    backend = WazuhBackend()

    cases = [
        ("*foo*bar*", "(?i)foo.*bar"),
        ("foo*bar*", "(?i)^foo.*bar"),
        ("*foo*bar", "(?i)foo.*bar$"),
        ("foo*bar", "(?i)^foo.*bar$"),
        ("*", "(?i).*"),
        ("**", "(?i).*"),
        ("*foo?bar*", "(?i)foo.bar"),
        ("foo?bar", "(?i)^foo.bar$"),
    ]

    for pattern_in, expected_out in cases:
        s = SigmaString(pattern_in)
        out, engine = backend._convert_sigma_string(s)
        assert out == expected_out, f"For '{pattern_in}', expected '{expected_out}', got '{out}'"
        assert engine == "pcre2"


def test_collection_conversion_with_correlations():
    """Verify that multi-document collections with correlations convert via backend.convert()."""
    yaml_text = """
title: Suspicious Login Failure
name: login_failure
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\\cmd.exe'
    condition: sel
---
title: Multiple Login Failures Correlation
name: multi_login_fail
correlation:
    type: event_count
    rules:
        - login_failure
    timespan: 10m
    condition:
        gte: 5
    group-by:
        - win.eventdata.user
"""
    collection = SigmaCollection.from_yaml(yaml_text)
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())

    xml_output = backend.convert(collection)
    assert xml_output is not None

    # Verify well-formed XML via real XML parser
    root = lxml.etree.fromstring(xml_output.encode("utf-8"))
    assert root.tag == "group"
    rules = root.findall("rule")
    assert len(rules) == 2

    # Verify correlation rule properties
    corr_rule = rules[1]
    assert corr_rule.get("frequency") == "5"
    assert corr_rule.get("timeframe") == "600"
    assert corr_rule.find("if_matched_sid") is not None
    assert corr_rule.find("same_field").text == "win.eventdata.user"


def test_static_ip_fields_syntax_and_cidr():
    """Verify that static IP fields (srcip, dstip) emit clean IP/CIDR without regex attributes."""
    backend = WazuhBackend(processing_pipeline=wazuh_web_pipeline())

    # Plain IP test
    yaml_ip = """
title: Web Malicious IP
logsource:
    category: webserver
detection:
    sel:
        c-ip: '10.20.30.40'
    condition: sel
"""
    col_ip = SigmaCollection.from_yaml(yaml_ip)
    xml_ip = backend.convert(col_ip)
    assert "<srcip>10.20.30.40</srcip>" in xml_ip
    assert 'type="pcre2"' not in xml_ip
    assert "^" not in xml_ip
    assert "$" not in xml_ip

    # Validate with lxml
    root = lxml.etree.fromstring(xml_ip.encode("utf-8"))
    srcip_elem = root.find(".//srcip")
    assert srcip_elem is not None
    assert srcip_elem.text == "10.20.30.40"
    assert "type" not in srcip_elem.attrib

    # Negated IP test
    yaml_neg_ip = """
title: Web Filter IP
logsource:
    category: webserver
detection:
    sel:
        cs-method: 'POST'
    filt:
        c-ip: '192.168.1.1'
    condition: sel and not filt
"""
    col_neg = SigmaCollection.from_yaml(yaml_neg_ip)
    xml_neg = backend.convert(col_neg)
    assert '<srcip negate="yes">192.168.1.1</srcip>' in xml_neg


def test_field_not_exists_raises_typed_error():
    """Verify that field_not_exists condition raises WazuhUnsupportedConditionError."""
    backend = WazuhBackend()
    yaml_text = """
title: Test Field Not Exists
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image: null
    condition: sel
"""
    col = SigmaCollection.from_yaml(yaml_text)
    with pytest.raises(WazuhUnsupportedConditionError) as exc_info:
        backend.convert(col)
    assert "Null" in str(exc_info.value) or "FieldNotExists" in str(exc_info.value)


def test_field_exists_uses_star_pattern():
    """Verify that field existence matching compiles to .* pattern."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    yaml_text = """
title: Test Field Exists
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|exists: true
    condition: sel
"""
    col = SigmaCollection.from_yaml(yaml_text)
    xml = backend.convert(col)
    assert '<field name="win.eventdata.image" type="pcre2">.*</field>' in xml


def test_numeric_comparison_raises_typed_error():
    """Verify that numeric comparison operators (gt, lt, gte, lte) raise typed errors."""
    backend = WazuhBackend()
    yaml_text = """
title: Test Greater Than
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        ProcessId|gt: 1000
    condition: sel
"""
    col = SigmaCollection.from_yaml(yaml_text)
    with pytest.raises(WazuhUnsupportedConditionError) as exc_info:
        backend.convert(col)
    assert "CompareExpression" in str(exc_info.value)


# -----------------------------------------------------------------------------
# Property-Based Testing with Hypothesis
# -----------------------------------------------------------------------------

@settings(max_examples=30, deadline=1000)
@given(
    cmd=st.text(
        alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="\x00\r\n'\"\\"),
        min_size=1,
        max_size=40,
    )
)
def test_property_conversion_determinism_and_xml_validity(cmd):
    """Property: Any valid Sigma rule converts to 100% deterministic, well-formed XML."""
    yaml_template = f"""
title: Hypothesis Determinism Test
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: '{cmd}'
    condition: sel
"""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    col1 = SigmaCollection.from_yaml(yaml_template)
    col2 = SigmaCollection.from_yaml(yaml_template)

    xml1 = backend.convert(col1)
    backend.id_allocator.reset()
    xml2 = backend.convert(col2)

    assert xml1 == xml2, "Conversion must be strictly idempotent and deterministic."
    root = lxml.etree.fromstring(xml1.encode("utf-8"))
    assert root.tag == "group"


def test_adversarial_malformed_inputs():
    """Verify that malformed or incomplete Sigma rules fail cleanly with informative errors."""
    backend = WazuhBackend()

    # Empty detection block
    with pytest.raises(Exception):
        SigmaCollection.from_yaml("title: Broken\nlogsource:\n  category: test\ndetection:\n")

    # Missing condition
    with pytest.raises(Exception):
        SigmaCollection.from_yaml("title: Broken\nlogsource:\n  category: test\ndetection:\n  sel:\n    Image: test\n")
