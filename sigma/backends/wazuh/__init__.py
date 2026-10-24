"""pySigma Wazuh SIEM backend package."""

from sigma.backends.wazuh.wazuh import WazuhBackend
from sigma.backends.wazuh.errors import (
    WazuhError,
    WazuhConversionError,
    WazuhUnsupportedModifierError,
    WazuhUnsupportedConditionError,
    WazuhRegexDialectError,
    WazuhIDCollisionError,
    WazuhUnmappedFieldError,
)
from sigma.backends.wazuh.id_allocator import WazuhIDAllocator
from sigma.backends.wazuh.models import WazuhField, WazuhRule, WazuhGroup

__all__ = [
    "WazuhBackend",
    "WazuhError",
    "WazuhConversionError",
    "WazuhUnsupportedModifierError",
    "WazuhUnsupportedConditionError",
    "WazuhRegexDialectError",
    "WazuhIDCollisionError",
    "WazuhUnmappedFieldError",
    "WazuhIDAllocator",
    "WazuhField",
    "WazuhRule",
    "WazuhGroup",
]
