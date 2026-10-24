"""Processing pipelines for pySigma Wazuh backend."""

from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.wazuh.windows import wazuh_windows_pipeline, get_windows_items
from sigma.pipelines.wazuh.linux import wazuh_linux_pipeline, get_linux_items
from sigma.pipelines.wazuh.web import wazuh_web_pipeline, get_web_items


def wazuh_combined_pipeline() -> ProcessingPipeline:
    """Unified pipeline combining Windows, Linux, and Web mappings."""
    return ProcessingPipeline(
        name="Wazuh Unified Pipeline",
        allowed_backends={"wazuh"},
        priority=20,
        items=get_windows_items() + get_linux_items() + get_web_items(),
    )


__all__ = [
    "wazuh_windows_pipeline",
    "wazuh_linux_pipeline",
    "wazuh_web_pipeline",
    "wazuh_combined_pipeline",
]
