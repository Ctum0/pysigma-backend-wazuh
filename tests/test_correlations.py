"""Tests for Sigma correlation rule conversion in Wazuh backend."""

from sigma.correlations import SigmaCorrelationRule
from sigma.backends.wazuh import WazuhBackend
import yaml


def test_correlation_event_count():
    corr_yaml = """
    title: Multiple Failed Logins
    id: 99999999-aaaa-bbbb-cccc-dddddddddddd
    status: test
    correlation:
        type: event_count
        rules:
            - 11111111-2222-3333-4444-555555555555
        group-by:
            - User
        timespan: 5m
        condition:
            gte: 5
    """
    corr_dict = yaml.safe_load(corr_yaml)
    corr_rule = SigmaCorrelationRule.from_dict(corr_dict)

    backend = WazuhBackend()
    w_rules = backend.convert_correlation_rule(corr_rule)
    assert len(w_rules) == 1
    r = w_rules[0]

    assert r.frequency == 5
    assert r.timeframe == 300  # 5m = 300s
    assert r.same_field == "User"
    assert r.if_matched_sid is not None
    assert "correlation" in r.groups


def test_correlation_xml_output():
    corr_yaml = """
    title: Brute Force Detection
    id: 88888888-aaaa-bbbb-cccc-dddddddddddd
    status: test
    correlation:
        type: event_count
        rules:
            - 77777777-2222-3333-4444-555555555555
        group-by:
            - srcip
        timespan: 2m
        condition:
            gte: 10
    """
    corr_dict = yaml.safe_load(corr_yaml)
    corr_rule = SigmaCorrelationRule.from_dict(corr_dict)

    backend = WazuhBackend()
    w_rules = backend.convert_correlation_rule(corr_rule)
    xml_str = backend.finalize_output_default([w_rules])

    assert 'frequency="10"' in xml_str
    assert 'timeframe="120"' in xml_str
    assert '<same_field>srcip</same_field>' in xml_str
    assert '<if_matched_sid>' in xml_str
