"""Wazuh processing pipeline for Linux process creation logs (auditd)."""

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.processing.conditions import LogsourceCondition


def get_linux_items():
    return [
        ProcessingItem(
            identifier="wazuh_linux_parent_context",
            transformation=SetStateTransformation("wazuh_parent_group", "audit_execve"),
            rule_conditions=[
                LogsourceCondition(category="process_creation", product="linux"),
            ],
        ),

        ProcessingItem(
            identifier="wazuh_linux_process_creation_fields",
            transformation=FieldMappingTransformation(
                {
                    "Image": "audit.exe",
                    "CommandLine": "audit.command",
                    "User": "audit.auid",
                    "ProcessId": "audit.pid",
                    "ParentProcessId": "audit.ppid",
                    "CurrentDirectory": "audit.cwd",
                    "Terminal": "audit.tty",
                    "Session": "audit.session",
                    "Key": "audit.key",
                    "Arch": "audit.arch",
                    "Syscall": "audit.syscall",
                    "Success": "audit.success",
                    "Exit": "audit.exit",
                }
            ),
            rule_conditions=[
                LogsourceCondition(category="process_creation", product="linux"),
            ],
        ),
    ]


def wazuh_linux_pipeline() -> ProcessingPipeline:
    """Processing pipeline mapping Linux process creation (auditd) Sigma rules to Wazuh decoded fields."""
    return ProcessingPipeline(
        name="Wazuh Linux Process Creation Pipeline",
        allowed_backends={"wazuh"},
        priority=20,
        items=get_linux_items(),
    )

