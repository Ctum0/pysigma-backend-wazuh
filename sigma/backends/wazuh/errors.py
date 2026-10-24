"""Typed exceptions for pySigma Wazuh backend."""

from sigma.exceptions import SigmaConversionError, SigmaError


class WazuhError(SigmaError):
    """Base error for all Wazuh backend errors."""
    pass


class WazuhConversionError(SigmaConversionError, WazuhError):
    """General error during Sigma to Wazuh XML conversion."""
    pass


class WazuhUnsupportedModifierError(WazuhConversionError):
    """Raised when a modifier cannot be mapped to Wazuh rule XML."""
    def __init__(self, modifier: str, message: str = ""):
        self.modifier = modifier
        msg = f"Unsupported modifier '{modifier}' for Wazuh backend."
        if message:
            msg += f" {message}"
        super().__init__(msg)


class WazuhUnsupportedConditionError(WazuhConversionError):
    """Raised when a condition cannot be represented in Wazuh rule XML."""
    def __init__(self, condition_type: str, message: str = ""):
        self.condition_type = condition_type
        msg = f"Unsupported condition '{condition_type}' in Wazuh backend."
        if message:
            msg += f" {message}"
        super().__init__(msg)


class WazuhRegexDialectError(WazuhConversionError):
    """Raised when regex pattern cannot be compiled into target Wazuh regex dialect."""
    def __init__(self, pattern: str, engine: str, reason: str = ""):
        self.pattern = pattern
        self.engine = engine
        msg = f"Cannot translate pattern '{pattern}' to Wazuh engine '{engine}'."
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg)


class WazuhIDCollisionError(WazuhError):
    """Raised when deterministic rule ID allocation encounters unresolvable collisions."""
    def __init__(self, rule_id: str, allocated_id: int):
        super().__init__(
            f"Rule ID allocation collision for rule '{rule_id}' at Wazuh SID {allocated_id}."
        )


class WazuhUnmappedFieldError(WazuhConversionError):
    """Raised when a Sigma field has no known Wazuh decoder mapping in strict mode."""
    def __init__(self, field: str):
        self.field = field
        super().__init__(
            f"Field '{field}' has no known Wazuh decoder mapping. "
            "Configure a processing pipeline or mapping."
        )
