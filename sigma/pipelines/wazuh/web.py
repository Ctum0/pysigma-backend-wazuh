"""Wazuh processing pipeline for Web access logs."""

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.processing.conditions import LogsourceCondition


def get_web_items():
    return [
        ProcessingItem(
            identifier="wazuh_web_parent_context",
            transformation=SetStateTransformation("wazuh_parent_group", "web_access"),
            rule_conditions=[
                LogsourceCondition(category="webserver"),
            ],
        ),

        ProcessingItem(
            identifier="wazuh_web_fields",
            transformation=FieldMappingTransformation(
                {
                    "c-uri": "url",
                    "cs-uri": "url",
                    "cs-uri-stem": "url",
                    "cs-uri-query": "url",
                    "uri": "url",
                    "cs-method": "protocol",
                    "c-ip": "srcip",
                    "cs-ip": "srcip",
                    "src_ip": "srcip",
                    "sc-status": "id",
                    "cs-user-agent": "browser",
                    "user_agent": "browser",
                    "cs-host": "hostname",
                }
            ),
            rule_conditions=[
                LogsourceCondition(category="webserver"),
            ],
        ),
    ]


def wazuh_web_pipeline() -> ProcessingPipeline:
    """Processing pipeline mapping Web access log Sigma rules to Wazuh decoded fields."""
    return ProcessingPipeline(
        name="Wazuh Web Access Log Pipeline",
        allowed_backends={"wazuh"},
        priority=20,
        items=get_web_items(),
    )

