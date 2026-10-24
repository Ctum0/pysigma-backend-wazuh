"""Stress tests, security audit, edge case fuzzing, and ReDoS/injection defense tests."""

import lxml.etree
import pytest

from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.backends.wazuh.errors import (
    WazuhConversionError,
    WazuhIDCollisionError,
    WazuhRegexDialectError,
    WazuhUnsupportedConditionError,
)
from sigma.backends.wazuh.id_allocator import WazuhIDAllocator
from sigma.backends.wazuh.models import WazuhField, WazuhRule, WazuhGroup
from sigma.pipelines.wazuh import wazuh_windows_pipeline


# ==============================================================================
# 1. XML Injection & Attribute Breakout Defense
# ==============================================================================

def test_xml_injection_in_title_and_description():
    """Verify that malicious XML tags in title/description cannot break out of <description>."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    yaml_text = """
    title: </description><rule id="1" level="15"><description>PWNED</description></rule><description>
    id: 11111111-2222-3333-4444-555555555555
    description: <script>alert('xss')</script> "test" & 'quote'
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image: 'C:\\Windows\\cmd.exe'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    xml_str = backend.convert(SigmaCollection([rule]))

    # Must parse cleanly with lxml without syntax errors
    root = lxml.etree.fromstring(xml_str.encode("utf-8"))
    assert root.tag == "group"

    # Must only contain 1 rule element
    rules = root.findall("rule")
    assert len(rules) == 1
    assert rules[0].get("id") != "1"  # Injected rule id="1" must not exist

    desc_elem = rules[0].find("description")
    assert desc_elem is not None
    assert "PWNED" in desc_elem.text
    assert "<script>" in desc_elem.text


def test_xml_attribute_injection_in_field_name():
    """Verify that double quotes in field names cannot inject XML attributes."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    f = WazuhField(name='image" injected="true" bad="', pattern="cmd.exe")
    xml_field = f.to_xml()
    # Must be escaped with &quot;
    assert '&quot;' in xml_field
    assert 'injected="true"' not in xml_field

    # Must parse cleanly inside a dummy XML tag
    wrapped = f"<rule>{xml_field}</rule>"
    elem = lxml.etree.fromstring(wrapped.encode("utf-8"))
    field_elem = elem.find("field")
    assert field_elem.attrib["name"] == 'image" injected="true" bad="'
    assert "injected" not in field_elem.attrib


def test_xml_control_characters_sanitization():
    """Verify that ASCII control characters (null bytes, BEL, FF) are sanitized for valid XML."""
    # Test direct sanitization on IR models
    f = WazuhField(name="CommandLine", pattern="powershell.exe \x00\x07\x0c test")
    rule = WazuhRule(id=100000, description="Control chars: \x00\x07\x0c", fields=[f])
    xml_str = rule.to_xml()

    # Null bytes and control characters break standard XML 1.0 parsers unless sanitized
    root = lxml.etree.fromstring(xml_str.encode("utf-8"))
    assert root is not None
    assert "\\x00" in xml_str
    assert "\\x07" in xml_str


# ==============================================================================
# 2. Algorithmic DoS & Combinatorial Explosion Defense
# ==============================================================================

def test_cartesian_conjunction_explosion_safeguard():
    """Verify that an exponential boolean tree across different fields is aborted cleanly."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())

    # Construct a rule with 10 terms of (FieldA_i or FieldB_i) -> 2^10 = 1024 clauses > 256 limit
    detections = {}
    cond_parts = []
    for i in range(10):
        name_a = f"sel_{i}_a"
        name_b = f"sel_{i}_b"
        detections[name_a] = {f"CommandLine": f"param_{i}_a"}
        detections[name_b] = {f"Image": f"param_{i}_b"}
        cond_parts.append(f"({name_a} or {name_b})")

    yaml_text = f"""
    title: Combinatorial Explosion Test
    id: 33333333-4444-5555-6666-777777777777
    logsource:
        category: process_creation
        product: windows
    detection:
{chr(10).join(f"        {k}:" + chr(10) + f"            {list(v.keys())[0]}: '{list(v.values())[0]}'" for k, v in detections.items())}
        condition: {' and '.join(cond_parts)}
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]

    # Must fail fast with typed WazuhConversionError rather than hanging or running out of memory
    with pytest.raises(WazuhConversionError) as exc_info:
        backend.convert_rule(rule)
    assert "complexity exceeds maximum supported disjunctive terms" in str(exc_info.value)


# ==============================================================================
# 3. ID Allocation Exhaustion & Collision Resolution
# ==============================================================================

def test_id_allocator_exhaustion():
    """Verify that exhausting a small ID pool raises WazuhIDCollisionError safely."""
    # Pool with exactly 3 IDs: 100000, 100001, 100002
    allocator = WazuhIDAllocator(min_id=100000, max_id=100002)

    allocated = set()
    for i in range(3):
        sid = allocator.allocate(f"rule_unique_{i}")
        assert 100000 <= sid <= 100002
        allocated.add(sid)

    assert len(allocated) == 3

    # Attempting to allocate a 4th unique rule in a full 3-item pool must raise
    with pytest.raises(WazuhIDCollisionError):
        allocator.allocate("rule_unique_overflow_4")


def test_id_allocator_idempotency_under_stress():
    """Verify that allocating IDs for 500 rules is 100% deterministic across resets."""
    alloc_1 = WazuhIDAllocator(min_id=100000, max_id=120000)
    alloc_2 = WazuhIDAllocator(min_id=100000, max_id=120000)

    rules = [f"rule_uuid_{i:04d}" for i in range(500)]
    sids_1 = [alloc_1.allocate(r) for r in rules]
    sids_2 = [alloc_2.allocate(r) for r in rules]

    assert sids_1 == sids_2
    assert len(set(sids_1)) == 500


# ==============================================================================
# 4. Extreme Values, Unicode, and Large Payloads
# ==============================================================================

def test_extreme_payload_length_handling():
    """Test rule with 10,000 character command line pattern."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    long_string = "A" * 10000
    yaml_text = f"""
    title: Extremely Long Payload Rule
    id: 44444444-5555-6666-7777-888888888888
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: '{long_string}'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    assert len(w_rules[0].fields[0].pattern) >= 10000


def test_unicode_and_multilingual_characters():
    """Test rules containing emojis, non-ASCII UTF-8, and special Unicode runes."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    yaml_text = """
    title: Multilingual Detection 🚀 (Кириллица / 汉语 / 日本語)
    id: 55555555-6666-7777-8888-999999999999
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains:
                - 'взлом'
                - '攻击'
                - 'サイバー'
                - '💀'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    xml_str = backend.convert(SigmaCollection([rule]))
    root = lxml.etree.fromstring(xml_str.encode("utf-8"))
    assert root is not None
    desc = root.find("rule").find("description").text
    assert "Кириллица" in desc
    assert "🚀" in desc


# ==============================================================================
# 5. OS_Regex ReDoS and Incompatible Modifier Rejections
# ==============================================================================

def test_osregex_rejects_lookarounds_and_quantifiers():
    """Verify that OS_Regex dialect strictly rejects PCRE-only constructs."""
    backend = WazuhBackend(regex_engine="osregex")
    yaml_text = """
    title: PCRE Lookahead Rule
    id: 66666666-7777-8888-9999-000000000000
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: '(?<=prefix)payload(?=suffix)'
        condition: sel
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    with pytest.raises(WazuhRegexDialectError) as exc_info:
        backend.convert_rule(rule)
    assert "osregex" in str(exc_info.value)


def test_negated_keyword_search_handling():
    """Verify that `not keywords` translates cleanly to <regex negate="yes">."""
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    yaml_text = """
    title: Negated Keyword Test
    id: 77777777-8888-9999-aaaa-bbbbbbbbbbbb
    logsource:
        category: process_creation
        product: windows
    detection:
        keywords:
            - 'benign_telemetry'
        condition: not keywords
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    xml_str = w_rules[0].to_xml()
    assert '<regex' in xml_str
    assert 'negate="yes"' in xml_str

