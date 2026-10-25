"""Wazuh SIEM XML backend for pySigma."""

import json
from typing import Any, ClassVar, Dict, List, Optional, Set, Tuple, Union, cast
from xml.sax.saxutils import escape as xml_escape

from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.conditions import (
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
    ConditionItem,
)
from sigma.types import (
    SigmaString,
    SigmaCasedString,
    SigmaNumber,
    SigmaBool,
    SigmaRegularExpression,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaFieldReference,
    SigmaNull,
    SigmaQueryExpression,
    SigmaExpansion,
    SigmaExists,
    SpecialChars,
)
from sigma.exceptions import SigmaError

from sigma.backends.wazuh.errors import (
    WazuhConversionError,
    WazuhUnsupportedModifierError,
    WazuhUnsupportedConditionError,
    WazuhRegexDialectError,
    WazuhIDCollisionError,
)
from sigma.backends.wazuh.id_allocator import WazuhIDAllocator
from sigma.backends.wazuh.models import WazuhField, WazuhRule, WazuhGroup


REGEX_SPECIAL_CHARS = set(r"\.^$*+?()[]{}|")


def escape_regex_literal(text: str) -> str:
    """Escape regex special characters while preserving standard path separators."""
    res = []
    for char in text:
        if char == "\n":
            res.append(r"\n")
        elif char == "\r":
            res.append(r"\r")
        elif char == "\t":
            res.append(r"\t")
        elif char in REGEX_SPECIAL_CHARS:
            res.append("\\" + char)
        else:
            res.append(char)
    return "".join(res)


class WazuhBackend(Backend):
    """
    pySigma backend compiling Sigma rules to native Wazuh XML detection rulesets.
    """

    name: ClassVar[str] = "Wazuh SIEM XML rules"
    MAX_DNF_DISJUNCTS: ClassVar[int] = 256
    formats: ClassVar[Dict[str, str]] = {
        "default": "Standard Wazuh XML ruleset inside <group>",
        "rule_only": "Wazuh XML <rule> elements without root <group>",
        "json": "JSON representation of converted rules",
    }
    default_format: ClassVar[str] = "default"
    requires_pipeline: ClassVar[bool] = False

    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Wazuh if_matched_sid frequency and timeframe correlation",
    }
    default_correlation_method: ClassVar[str] = "default"

    # Severity mapping from Sigma levels to Wazuh rule levels (0-16)
    LEVEL_MAP: ClassVar[Dict[str, int]] = {
        "informational": 1,
        "low": 3,
        "medium": 6,
        "high": 9,
        "critical": 12,
    }
    DEFAULT_LEVEL: ClassVar[int] = 5

    def __init__(
        self,
        processing_pipeline: Optional[Any] = None,
        collect_errors: bool = False,
        min_rule_id: int = WazuhIDAllocator.DEFAULT_MIN_ID,
        max_rule_id: int = WazuhIDAllocator.DEFAULT_MAX_ID,
        regex_engine: str = "pcre2",  # "pcre2" or "osregex"
        default_parent_sid: Optional[int] = None,
        default_parent_group: Optional[str] = None,
        group_name: str = "sigma,",
        chain_rules: bool = False,
        demote_experimental: bool = False,
        include_comments: bool = True,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.id_allocator = WazuhIDAllocator(min_id=min_rule_id, max_id=max_rule_id)
        self.regex_engine = regex_engine.lower()
        if self.regex_engine not in ("pcre2", "osregex"):
            raise ValueError(f"Invalid regex_engine '{regex_engine}'. Must be 'pcre2' or 'osregex'.")
        self.default_parent_sid = default_parent_sid
        self.default_parent_group = default_parent_group
        self.group_name = group_name
        self.chain_rules = chain_rules
        self.demote_experimental = demote_experimental
        self.include_comments = include_comments

    # -------------------------------------------------------------------------
    # Value to Regex / Pattern conversion
    # -------------------------------------------------------------------------

    def convert_value_to_pattern(
        self, value: Any, state: ConversionState, case_sensitive: bool = False, is_keyword: bool = False
    ) -> Tuple[str, Optional[str]]:
        """
        Convert a Sigma value to a Wazuh pattern and return (pattern, engine_type).
        """
        match value:
            case SigmaString():
                return self._convert_sigma_string(value, case_sensitive=case_sensitive, is_keyword=is_keyword)
            case SigmaCasedString():
                return self._convert_sigma_string(value, case_sensitive=True, is_keyword=is_keyword)
            case SigmaNumber():
                num_str = str(value.number)
                if self.regex_engine == "pcre2":
                    return f"^{num_str}$" if not is_keyword else num_str, "pcre2"
                return f"^{num_str}$" if not is_keyword else num_str, "osregex"

            case SigmaBool():
                val_str = "true" if value.val else "false"
                if self.regex_engine == "pcre2":
                    return f"(?i)^{val_str}$" if not is_keyword else f"(?i){val_str}", "pcre2"
                return f"^{val_str}$" if not is_keyword else val_str, "osregex"
            case SigmaRegularExpression():
                return self._convert_sigma_regex(value)
            case SigmaExpansion():
                # Expansion of values (windash, base64) combined with alternation
                patterns = []
                for val in value.values:
                    p, _ = self.convert_value_to_pattern(val, state, case_sensitive=case_sensitive, is_keyword=is_keyword)
                    if p.startswith("(?i)"):
                        patterns.append(p[4:])
                    else:
                        patterns.append(p)
                combined = "|".join(patterns)
                if self.regex_engine == "pcre2" and not case_sensitive:
                    combined = f"(?i)({combined})"
                return combined, self.regex_engine
            case SigmaCIDRExpression():
                return self._convert_cidr(value)
            case SigmaCompareExpression():
                raise WazuhUnsupportedConditionError(
                    "CompareExpression",
                    f"Numeric comparison '{value.op}' is not supported by Wazuh field matchers."
                )
            case SigmaNull():
                raise WazuhUnsupportedConditionError(
                    "Null",
                    "Null field matching is not directly supported in Wazuh field XML."
                )
            case SigmaExists():
                return ".*", "pcre2"
            case _:
                raise WazuhUnsupportedConditionError(
                    value.__class__.__name__,
                    f"Value type {value.__class__.__name__} is not supported."
                )

    def _convert_sigma_string(
        self, s: SigmaString, case_sensitive: bool = False, is_keyword: bool = False
    ) -> Tuple[str, Optional[str]]:
        """Convert a SigmaString containing literal parts and wildcards into a regex pattern."""
        items = list(s)
        if not items:
            return "^$", "pcre2" if self.regex_engine == "pcre2" else "osregex"

        has_start_wildcard = (items[0] == SpecialChars.WILDCARD_MULTI)
        has_end_wildcard = (items[-1] == SpecialChars.WILDCARD_MULTI)

        start_idx = 1 if has_start_wildcard else 0
        end_idx = (len(items) - 1) if (has_end_wildcard and len(items) > 1) else len(items)

        parts = []
        prev_was_wildcard = False
        for item in items[start_idx:end_idx]:
            if item == SpecialChars.WILDCARD_MULTI:
                if not prev_was_wildcard:
                    parts.append(".*")
                    prev_was_wildcard = True
            elif item == SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
                prev_was_wildcard = False
            elif isinstance(item, str):
                parts.append(escape_regex_literal(item))
                prev_was_wildcard = False

        body = "".join(parts)
        if not body:
            body = ".*" if (has_start_wildcard or has_end_wildcard) else ""

        if self.regex_engine == "pcre2":
            prefix = "" if case_sensitive else "(?i)"
            start_anchor = "" if (has_start_wildcard or is_keyword) else "^"
            end_anchor = "" if (has_end_wildcard or is_keyword) else "$"
            return f"{prefix}{start_anchor}{body}{end_anchor}", "pcre2"
        else:
            start_anchor = "" if (has_start_wildcard or is_keyword) else "^"
            end_anchor = "" if (has_end_wildcard or is_keyword) else "$"
            return f"{start_anchor}{body}{end_anchor}", "osregex"

    def _convert_sigma_regex(self, r: SigmaRegularExpression) -> Tuple[str, Optional[str]]:
        pattern = str(r.regexp)
        if self.regex_engine == "osregex":
            if any(construct in pattern for construct in ("(?i)", "(?m)", "(?s)", "(?<", "(?=", "(?!")):
                raise WazuhRegexDialectError(
                    pattern, "osregex", "Pattern contains PCRE group/assertion modifiers unsupported by OS_Regex."
                )
            return pattern, "osregex"
        return pattern, "pcre2"


    def _convert_cidr(self, cidr: SigmaCIDRExpression) -> Tuple[str, Optional[str]]:
        raise WazuhUnsupportedConditionError(
            "CIDRExpression", "CIDR network evaluation is not supported directly in Wazuh field matchers."
        )

    # -------------------------------------------------------------------------
    # Abstract methods implementation for Backend base class
    # -------------------------------------------------------------------------

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        return self._normalize_to_dnf(cond, state)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Any:
        return self._normalize_to_dnf(cond, state)

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        return self._normalize_to_dnf(cond, state)

    def convert_condition_as_in_expression(self, cond: Union[ConditionOR, ConditionAND], state: ConversionState) -> Any:
        return self._normalize_to_dnf(cond, state)

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        pattern, engine = self._convert_sigma_string(cond.value, case_sensitive=False)
        return WazuhField(name=cond.field, pattern=pattern, type=engine, negate=False)

    def convert_condition_field_eq_val_str_case_sensitive(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        pattern, engine = self._convert_sigma_string(cond.value, case_sensitive=True)
        return WazuhField(name=cond.field, pattern=pattern, type=engine, negate=False)

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        pattern, engine = self.convert_value_to_pattern(cond.value, state)
        return WazuhField(name=cond.field, pattern=pattern, type=engine, negate=False)

    def convert_condition_field_eq_val_bool(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        pattern, engine = self.convert_value_to_pattern(cond.value, state)
        return WazuhField(name=cond.field, pattern=pattern, type=engine, negate=False)

    def convert_condition_field_eq_val_re(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        pattern, engine = self._convert_sigma_regex(cond.value)
        return WazuhField(name=cond.field, pattern=pattern, type=engine, negate=False)

    def convert_condition_field_eq_val_cidr(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        field_lower = cond.field.lower()
        if field_lower in ("srcip", "dstip"):
            return WazuhField(name=cond.field, pattern=str(cond.value), type=None, negate=False)
        return self._convert_cidr(cond.value)

    def convert_condition_field_compare_op_val(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("CompareExpression", "Numeric comparison is not supported.")

    def convert_condition_field_eq_field(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("FieldEqualsField", "Comparing two dynamic fields is not supported.")

    def convert_condition_field_eq_val_null(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("Null", "Null check is not supported.")

    def convert_condition_field_eq_query_expr(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("QueryExpression", "Sub-query expressions are not supported.")

    def convert_condition_field_exists(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        return WazuhField(name=cond.field, pattern=".*", type="pcre2", negate=False)

    def convert_condition_field_not_exists(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError(
            "FieldNotExists",
            f"Wazuh field engine cannot test for the non-existence of dynamic field '{cond.field}' "
            "because <field negate='yes'> requires the field to exist in decoded output."
        )

    def convert_condition_val_str(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("UnboundString", "Unbound keyword string without field.")

    def convert_condition_val_num(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("UnboundNumber", "Unbound number without field.")

    def convert_condition_val_re(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("UnboundRegex", "Unbound regex without field.")

    def convert_condition_query_expr(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("UnboundQueryExpr", "Unbound query expression.")

    def convert_condition_field_eq_val_timestamp_part(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        raise WazuhUnsupportedConditionError("TimestampPart", "Timestamp part matching is not supported.")

    # Correlation abstract methods matching pySigma Backend signatures
    def convert_correlation_event_count_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        return self.convert_correlation_rule_to_wazuh(rule)

    def convert_correlation_value_count_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        return self.convert_correlation_rule_to_wazuh(rule)

    def convert_correlation_temporal_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        return self.convert_correlation_rule_to_wazuh(rule)

    def convert_correlation_temporal_ordered_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        return self.convert_correlation_rule_to_wazuh(rule)

    def convert_correlation_extended_temporal_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        return self.convert_correlation_rule_to_wazuh(rule)

    def convert_correlation_extended_temporal_ordered_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        return self.convert_correlation_rule_to_wazuh(rule)

    def convert_correlation_value_avg_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        raise WazuhUnsupportedConditionError("CorrelationAvg", "Average aggregation is not supported by Wazuh.")

    def convert_correlation_value_sum_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        raise WazuhUnsupportedConditionError("CorrelationSum", "Sum aggregation is not supported by Wazuh.")

    def convert_correlation_value_median_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        raise WazuhUnsupportedConditionError("CorrelationMedian", "Median aggregation is not supported by Wazuh.")

    def convert_correlation_value_percentile_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> List[Any]:
        raise WazuhUnsupportedConditionError("CorrelationPercentile", "Percentile aggregation is not supported by Wazuh.")

    # -------------------------------------------------------------------------
    # AST Optimization & Normalization to DNF
    # -------------------------------------------------------------------------

    def _optimize_ast(self, cond: ConditionItem, state: ConversionState) -> ConditionItem:
        """
        Optimize condition AST by merging ConditionOR nodes on the same field into regex alternation.
        """
        match cond:
            case ConditionOR():
                optimized_args = [self._optimize_ast(arg, state) for arg in cond.args]
                # Group by field
                field_expressions: Dict[str, List[ConditionFieldEqualsValueExpression]] = {}
                other_args = []

                for arg in optimized_args:
                    if isinstance(arg, ConditionFieldEqualsValueExpression):
                        field_expressions.setdefault(arg.field, []).append(arg)
                    else:
                        other_args.append(arg)

                merged_args = []
                for fname, exprs in field_expressions.items():
                    if len(exprs) == 1:
                        merged_args.append(exprs[0])
                    else:
                        # Combine multiple values on the same field into regex alternation
                        patterns = []
                        for expr in exprs:
                            p, _ = self.convert_value_to_pattern(expr.value, state)
                            if p.startswith("(?i)"):
                                patterns.append(p[4:])
                            else:
                                patterns.append(p)
                        combined = "|".join(patterns)
                        if self.regex_engine == "pcre2":
                            combined = f"(?i)({combined})"
                        merged_args.append(
                            ConditionFieldEqualsValueExpression(
                                fname, SigmaRegularExpression(combined)
                            )
                        )

                all_children = merged_args + other_args
                if len(all_children) == 1:
                    return all_children[0]
                return ConditionOR(all_children)

            case ConditionAND():
                optimized_args = [self._optimize_ast(arg, state) for arg in cond.args]
                return ConditionAND(optimized_args)

            case ConditionNOT():
                return ConditionNOT([self._optimize_ast(cond.args[0], state)])

            case _:
                return cond

    def _normalize_to_dnf(
        self, cond: ConditionItem, state: ConversionState
    ) -> List[List[Tuple[ConditionFieldEqualsValueExpression, bool]]]:
        """
        Normalize a Sigma condition AST into Disjunctive Normal Form (DNF).
        Returns a list of disjuncts, where each disjunct is a list of (expression, is_positive) tuples.
        """
        match cond:
            case ConditionFieldEqualsValueExpression():
                if isinstance(cond.value, SigmaExpansion):
                    # Combine expansion into single alternation pattern
                    pattern, _ = self.convert_value_to_pattern(cond.value, state)
                    combined_expr = ConditionFieldEqualsValueExpression(
                        cond.field, SigmaRegularExpression(pattern)
                    )
                    return [[(combined_expr, True)]]
                return [[(cond, True)]]


            case ConditionValueExpression():
                pattern, _ = self.convert_value_to_pattern(cond.value, state, is_keyword=True)
                combined_expr = ConditionFieldEqualsValueExpression(
                    "", SigmaRegularExpression(pattern)
                )
                return [[(combined_expr, True)]]

            case ConditionNOT():
                child = cond.args[0]
                if isinstance(child, ConditionFieldEqualsValueExpression):
                    return [[(child, False)]]
                elif isinstance(child, ConditionValueExpression):
                    pattern, _ = self.convert_value_to_pattern(child.value, state, is_keyword=True)
                    combined_expr = ConditionFieldEqualsValueExpression(
                        "", SigmaRegularExpression(pattern)
                    )
                    return [[(combined_expr, False)]]
                elif isinstance(child, ConditionOR):
                    # NOT (A or B) = (NOT A) and (NOT B)
                    dnf_terms = [self._normalize_to_dnf(ConditionNOT([arg], cond.source), state) for arg in child.args]
                    return self._cartesian_conjunction(dnf_terms)
                elif isinstance(child, ConditionAND):
                    # NOT (A and B) = (NOT A) or (NOT B)
                    disjuncts = []
                    for arg in child.args:
                        disjuncts.extend(self._normalize_to_dnf(ConditionNOT([arg], cond.source), state))
                    return disjuncts
                elif isinstance(child, ConditionNOT):
                    # NOT (NOT A) = A
                    return self._normalize_to_dnf(child.args[0], state)
                else:
                    raise WazuhUnsupportedConditionError(child.__class__.__name__, "Complex nested NOT condition.")

            case ConditionOR():
                disjuncts = []
                for arg in cond.args:
                    disjuncts.extend(self._normalize_to_dnf(arg, state))
                return disjuncts

            case ConditionAND():
                dnf_terms = [self._normalize_to_dnf(arg, state) for arg in cond.args]
                return self._cartesian_conjunction(dnf_terms)

            case None:
                return []

            case _:
                raise WazuhUnsupportedConditionError(
                    cond.__class__.__name__, f"Unexpected condition node {cond.__class__.__name__}"
                )

    def _cartesian_conjunction(
        self, dnf_list: List[List[List[Tuple[ConditionFieldEqualsValueExpression, bool]]]]
    ) -> List[List[Tuple[ConditionFieldEqualsValueExpression, bool]]]:
        """Compute the distributive AND of multiple DNF expressions with complexity safeguards."""
        if not dnf_list:
            return []
        result = dnf_list[0]
        for next_dnf in dnf_list[1:]:
            new_result = []
            for clause_a in result:
                for clause_b in next_dnf:
                    new_result.append(clause_a + clause_b)
                    if len(new_result) > self.MAX_DNF_DISJUNCTS:
                        raise WazuhConversionError(
                            f"Boolean condition complexity exceeds maximum supported disjunctive terms ({self.MAX_DNF_DISJUNCTS}). Rule should be refactored or simplified."
                        )
            result = new_result
        return result

    # -------------------------------------------------------------------------
    # Rule Conversion
    # -------------------------------------------------------------------------

    def convert_condition(self, cond: ConditionItem, state: ConversionState) -> List[List[WazuhField]]:
        """
        Convert condition AST to a list of disjuncts, each containing WazuhField objects.
        """
        optimized = self._optimize_ast(cond, state)
        dnf = self._normalize_to_dnf(optimized, state)
        converted_clauses = []

        for clause in dnf:
            fields: List[WazuhField] = []
            for expr, is_positive in clause:
                pattern, engine = self.convert_value_to_pattern(
                    expr.value, state, case_sensitive=isinstance(expr.value, SigmaCasedString)
                )
                fields.append(
                    WazuhField(
                        name=expr.field,
                        pattern=pattern,
                        type=engine,
                        negate=not is_positive,
                    )
                )
            converted_clauses.append(fields)

        return converted_clauses

    def convert_rule(
        self,
        rule: SigmaRule,
        output_format: Optional[str] = None,
        callback: Optional[Any] = None,
    ) -> List[WazuhRule]:
        """Convert a single SigmaRule into one or more WazuhRule IR objects."""
        # 1. Apply processing pipeline if present
        if not hasattr(self, "last_processing_pipeline") or self.last_processing_pipeline is None:
            self.init_processing_pipeline(output_format)
        if self.last_processing_pipeline:
            self.last_processing_pipeline.apply(rule)

        # 2. Extract metadata
        rule_ident = str(rule.id) if rule.id else rule.title
        rule_level = self.LEVEL_MAP.get(rule.level.name.lower() if rule.level else "medium", self.DEFAULT_LEVEL)
        description = rule.title
        if rule.description:
            description = f"{rule.title}: {rule.description}"
        description = description.replace("\n", " ").strip()

        # Status inspection and experimental demotion
        rule_status_str = None
        if hasattr(rule, "status") and rule.status:
            rule_status_str = str(rule.status.name if hasattr(rule.status, "name") else rule.status).lower()

        if self.demote_experimental and rule_status_str in ("experimental", "test"):
            rule_level = min(rule_level, 3)

        # Context triage comments (false positives, status, tuning notes)
        comments: List[str] = []
        if self.include_comments:
            if rule_status_str:
                if self.demote_experimental and rule_status_str in ("experimental", "test"):
                    comments.append(f"Status: {rule_status_str} (demoted to level {rule_level} for SOC tuning)")
                elif rule_status_str == "deprecated":
                    comments.append("WARNING: Upstream Sigma rule is marked DEPRECATED")
                else:
                    comments.append(f"Status: {rule_status_str}")

            if hasattr(rule, "falsepositives") and rule.falsepositives:
                clean_fps = [str(fp).strip() for fp in rule.falsepositives if str(fp).strip()]
                if clean_fps:
                    comments.append(f"False Positives: {', '.join(clean_fps)}")

        # MITRE ATT&CK tags
        mitre_ids = []
        groups = ["sigma"]
        for tag in rule.tags:
            tag_str = str(tag.name if hasattr(tag, "name") else tag).lower()
            if tag_str.startswith("attack.t"):
                mitre_ids.append(tag_str[7:].upper())
            elif tag_str.startswith("attack."):
                groups.append(tag_str[7:])

        # Determine parent SID or group from pipeline state or backend defaults
        parent_sid = self.default_parent_sid
        parent_group = self.default_parent_group

        pipeline_state = dict(self.last_processing_pipeline.state) if self.last_processing_pipeline else {}
        if "wazuh_parent_sid" in pipeline_state:
            parent_sid = int(pipeline_state["wazuh_parent_sid"])
        if "wazuh_parent_group" in pipeline_state:
            parent_group = str(pipeline_state["wazuh_parent_group"])

        # 3. Convert conditions
        state = ConversionState(processing_state=pipeline_state)
        wazuh_rules: List[WazuhRule] = []

        for cond_idx, cond in enumerate(rule.detection.parsed_condition):
            clauses = self.convert_condition(cond.parsed, state)

            if not clauses:
                continue

            if len(clauses) == 1 or not self.chain_rules:
                for branch_idx, fields in enumerate(clauses):
                    sid = (
                        self.id_allocator.allocate(rule_ident)
                        if branch_idx == 0
                        else self.id_allocator.allocate_subrule_id(rule_ident, branch_idx)
                    )
                    w_rule = WazuhRule(
                        id=sid,
                        level=rule_level,
                        description=description,
                        fields=fields,
                        if_sid=[parent_sid] if parent_sid is not None else [],
                        if_group=parent_group,
                        mitre_ids=mitre_ids,
                        groups=groups,
                        comments=comments if branch_idx == 0 else [],
                    )
                    wazuh_rules.append(w_rule)
            else:
                branch_sids = []
                for branch_idx, fields in enumerate(clauses):
                    b_sid = self.id_allocator.allocate_subrule_id(rule_ident, branch_idx)
                    branch_sids.append(b_sid)
                    branch_rule = WazuhRule(
                        id=b_sid,
                        level=0,
                        description=f"Branch {branch_idx + 1} for {rule.title}",
                        fields=fields,
                        if_sid=[parent_sid] if parent_sid is not None else [],
                        if_group=parent_group,
                        groups=["sigma", "sigma_intermediate"],
                    )
                    wazuh_rules.append(branch_rule)

                final_sid = self.id_allocator.allocate(rule_ident)
                alert_rule = WazuhRule(
                    id=final_sid,
                    level=rule_level,
                    description=description,
                    if_sid=branch_sids,
                    mitre_ids=mitre_ids,
                    groups=groups,
                    comments=comments,
                )
                wazuh_rules.append(alert_rule)

        return wazuh_rules

    # -------------------------------------------------------------------------
    # Correlation Rule Conversion
    # -------------------------------------------------------------------------

    def convert_correlation_rule_to_wazuh(
        self,
        rule: SigmaCorrelationRule,
    ) -> List[WazuhRule]:
        """Convert a SigmaCorrelationRule to Wazuh correlation rule using if_matched_sid."""
        rule_ident = str(rule.id) if rule.id else rule.title
        rule_level = self.LEVEL_MAP.get(rule.level.name.lower() if rule.level else "high", 8)
        description = f"Correlation: {rule.title}"

        referenced_sids: List[int] = []
        if rule.rules:
            for ref in rule.rules:
                ref_id = str(ref.name if hasattr(ref, "name") else ref)
                if ref_id in self.id_allocator.allocated_by_rule:
                    referenced_sids.append(self.id_allocator.allocated_by_rule[ref_id])
                else:
                    referenced_sids.append(self.id_allocator.allocate(ref_id))

        primary_matched_sid = referenced_sids[0] if referenced_sids else 100000
        sid = self.id_allocator.allocate(rule_ident)

        timeframe_secs = 300
        if hasattr(rule, "timespan") and rule.timespan:
            if hasattr(rule.timespan, "seconds") and rule.timespan.seconds is not None:
                timeframe_secs = int(rule.timespan.seconds)
            else:
                ts_str = str(rule.timespan).strip().lower()
                if ts_str.endswith("m"):
                    timeframe_secs = int(ts_str[:-1]) * 60
                elif ts_str.endswith("h"):
                    timeframe_secs = int(ts_str[:-1]) * 3600
                elif ts_str.endswith("s"):
                    timeframe_secs = int(ts_str[:-1])
                elif ts_str.isdigit():
                    timeframe_secs = int(ts_str)

        frequency = 5
        if hasattr(rule, "condition") and rule.condition:
            if hasattr(rule.condition, "count") and rule.condition.count is not None:
                frequency = int(rule.condition.count)
            else:
                cond_str = str(rule.condition)
                digits = "".join(filter(str.isdigit, cond_str))
                if digits:
                    frequency = int(digits)

        same_field = None
        if hasattr(rule, "group_by") and rule.group_by:
            same_field = str(rule.group_by[0])

        w_rule = WazuhRule(
            id=sid,
            level=rule_level,
            description=description,
            if_matched_sid=primary_matched_sid,
            same_field=same_field,
            frequency=frequency,
            timeframe=timeframe_secs,
            groups=["sigma", "correlation"],
        )
        return [w_rule]

    def convert_correlation_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
        callback: Optional[Any] = None,
    ) -> List[Any]:
        if method is None and callback is None and (not hasattr(self, "last_processing_pipeline") or self.last_processing_pipeline is None):
            return self.convert_correlation_rule_to_wazuh(rule)
        return super().convert_correlation_rule(rule, output_format, method, callback)

    # -------------------------------------------------------------------------
    # Output Finalization
    # -------------------------------------------------------------------------

    def finalize_query(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Any:
        return query

    def finalize_output_default(self, queries: List[Any]) -> str:
        """Serialize all converted rules into a standard Wazuh <group> XML file."""
        all_rules: List[WazuhRule] = []
        for q in queries:
            if isinstance(q, list):
                for item in q:
                    if isinstance(item, WazuhRule):
                        all_rules.append(item)
                    elif isinstance(item, list):
                        all_rules.extend(item)
            elif isinstance(q, WazuhRule):
                all_rules.append(q)

        group = WazuhGroup(name=self.group_name, rules=all_rules)
        return group.to_xml()

    def finalize_output_rule_only(self, queries: List[Any]) -> str:
        """Serialize rules as XML fragments without <group> root."""
        all_rules: List[WazuhRule] = []
        for q in queries:
            if isinstance(q, list):
                all_rules.extend(q)
            elif isinstance(q, WazuhRule):
                all_rules.append(q)
        return "\n\n".join(r.to_xml(indent="") for r in all_rules)

    def finalize_output_json(self, queries: List[Any]) -> str:
        """Output rules as a JSON structure."""
        rule_dicts = []
        for q in queries:
            rules = q if isinstance(q, list) else [q]
            for r in rules:
                rule_dicts.append({
                    "id": r.id,
                    "level": r.level,
                    "description": r.description,
                    "fields": [
                        {"name": f.name, "pattern": f.pattern, "type": f.type, "negate": f.negate}
                        for f in r.fields
                    ],
                    "if_sid": r.if_sid,
                    "if_group": r.if_group,
                    "if_matched_sid": r.if_matched_sid,
                    "same_field": r.same_field,
                    "frequency": r.frequency,
                    "timeframe": r.timeframe,
                    "mitre_ids": r.mitre_ids,
                    "groups": r.groups,
                })
        return json.dumps(rule_dicts, indent=2)
