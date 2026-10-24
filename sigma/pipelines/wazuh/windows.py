"""Wazuh processing pipeline for Windows process creation logs."""

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.processing.conditions import LogsourceCondition


def get_windows_items():
    return [
        # Set parent group or rule ID for Sysmon Event 1
        ProcessingItem(
            identifier="wazuh_windows_parent_context",
            transformation=SetStateTransformation("wazuh_parent_group", "sysmon_event1"),
            rule_conditions=[
                LogsourceCondition(category="process_creation", product="windows"),
            ],
        ),
        # Field mappings for Windows process creation (Sysmon EID 1 / Security 4688)
        ProcessingItem(
            identifier="wazuh_windows_process_creation_fields",
            transformation=FieldMappingTransformation(
                {
                    "Image": "win.eventdata.image",
                    "CommandLine": "win.eventdata.commandLine",
                    "ParentImage": "win.eventdata.parentImage",
                    "ParentCommandLine": "win.eventdata.parentCommandLine",
                    "User": "win.eventdata.user",
                    "OriginalFileName": "win.eventdata.originalFileName",
                    "CurrentDirectory": "win.eventdata.currentDirectory",
                    "IntegrityLevel": "win.eventdata.integrityLevel",
                    "Hashes": "win.eventdata.hashes",
                    "ProcessId": "win.eventdata.processId",
                    "ParentProcessId": "win.eventdata.parentProcessId",
                    "Company": "win.eventdata.company",
                    "Description": "win.eventdata.description",
                    "Product": "win.eventdata.product",
                    "FileVersion": "win.eventdata.fileVersion",
                    "TargetFilename": "win.eventdata.targetFilename",
                    "LogonId": "win.eventdata.logonId",
                    "TerminalSessionId": "win.eventdata.terminalSessionId",
                    # Windows Security 4688 aliases
                    "NewProcessName": "win.eventdata.image",
                    "ProcessCommandLine": "win.eventdata.commandLine",
                    "ParentProcessName": "win.eventdata.parentImage",
                    "SubjectUserName": "win.eventdata.user",
                }
            ),
            rule_conditions=[
                LogsourceCondition(category="process_creation", product="windows"),
            ],
        ),
    ]


def wazuh_windows_pipeline() -> ProcessingPipeline:
    """Processing pipeline mapping Windows process creation Sigma rules to Wazuh decoded fields."""
    return ProcessingPipeline(
        name="Wazuh Windows Process Creation Pipeline",
        allowed_backends={"wazuh"},
        priority=20,
        items=get_windows_items(),
    )

