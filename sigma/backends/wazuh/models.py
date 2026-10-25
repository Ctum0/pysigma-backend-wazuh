"""Intermediate Representation (IR) and XML Serialization for Wazuh Rules."""

from dataclasses import dataclass, field
from typing import Any, List, Optional
from xml.sax.saxutils import escape as _sax_escape


def xml_escape(value: Any) -> str:
    """Safely escape text for XML elements and attributes, preventing injection and stripping illegal control characters."""
    if value is None:
        return ""
    text = str(value)
    sanitized = []
    for ch in text:
        code = ord(ch)
        if (
            code in (0x9, 0xA, 0xD)
            or (0x20 <= code <= 0xD7FF)
            or (0xE000 <= code <= 0xFFFD)
            or (0x10000 <= code <= 0x10FFFF)
        ):
            sanitized.append(ch)
        else:
            sanitized.append(f"\\x{code:02x}")
    clean_text = "".join(sanitized)
    return _sax_escape(clean_text, entities={'"': "&quot;", "'": "&apos;"})



@dataclass
class WazuhField:
    """Represents a <field> condition element in a Wazuh rule."""
    name: str
    pattern: str
    type: Optional[str] = "pcre2"
    negate: bool = False

    def __post_init__(self):
        if not isinstance(self.pattern, str):
            self.pattern = str(self.pattern)


    WAZUH_STATIC_FIELDS = {
        "url", "srcip", "dstip", "srcport", "dstport", "protocol",
        "action", "user", "id", "status", "data", "extra_data",
        "system_name", "hostname"
    }

    def to_xml(self, indent: str = "    ") -> str:
        escaped_pattern = xml_escape(self.pattern)
        if not self.name:
            attrs = []
            if self.type:
                attrs.append(f'type="{xml_escape(self.type)}"')
            if self.negate:
                attrs.append('negate="yes"')
            attr_str = f" {' '.join(attrs)}" if attrs else ""
            return f"{indent}<regex{attr_str}>{escaped_pattern}</regex>"

        field_lower = self.name.lower()
        if field_lower in ("srcip", "dstip"):
            clean_ip = self.pattern
            if clean_ip.startswith("(?i)"):
                clean_ip = clean_ip[4:]
            if clean_ip.startswith("^"):
                clean_ip = clean_ip[1:]
            if clean_ip.endswith("$"):
                clean_ip = clean_ip[:-1]
            clean_ip = clean_ip.replace(r"\.", ".")
            attrs = []
            if self.negate:
                attrs.append('negate="yes"')
            attr_str = f" {' '.join(attrs)}" if attrs else ""
            return f"{indent}<{field_lower}{attr_str}>{xml_escape(clean_ip)}</{field_lower}>"

        if field_lower in self.WAZUH_STATIC_FIELDS:
            attrs = []
            if self.type:
                attrs.append(f'type="{xml_escape(self.type)}"')
            if self.negate:
                attrs.append('negate="yes"')
            attr_str = f" {' '.join(attrs)}" if attrs else ""
            return f"{indent}<{field_lower}{attr_str}>{escaped_pattern}</{field_lower}>"

        attrs = [f'name="{xml_escape(self.name)}"']
        if self.type:
            attrs.append(f'type="{xml_escape(self.type)}"')
        if self.negate:
            attrs.append('negate="yes"')
        attr_str = " ".join(attrs)
        return f"{indent}<field {attr_str}>{escaped_pattern}</field>"


@dataclass
class WazuhRule:
    """Represents a <rule> element in a Wazuh ruleset."""
    id: int
    level: int = 3
    description: str = ""
    fields: List[WazuhField] = field(default_factory=list)
    if_sid: List[int] = field(default_factory=list)
    if_group: Optional[str] = None
    if_matched_sid: Optional[int] = None
    same_field: Optional[str] = None
    frequency: Optional[int] = None
    timeframe: Optional[int] = None
    mitre_ids: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    options: List[str] = field(default_factory=list)

    def to_xml(self, indent: str = "  ") -> str:
        attrs = [f'id="{self.id}"', f'level="{self.level}"']
        if self.frequency is not None:
            attrs.append(f'frequency="{self.frequency}"')
        if self.timeframe is not None:
            attrs.append(f'timeframe="{self.timeframe}"')

        lines = [f"{indent}<rule {' '.join(attrs)}>"]
        inner_indent = indent + "  "

        if self.if_sid:
            sids_str = ", ".join(str(s) for s in self.if_sid)
            lines.append(f"{inner_indent}<if_sid>{sids_str}</if_sid>")

        if self.if_group:
            lines.append(f"{inner_indent}<if_group>{xml_escape(self.if_group)}</if_group>")

        if self.if_matched_sid is not None:
            lines.append(f"{inner_indent}<if_matched_sid>{self.if_matched_sid}</if_matched_sid>")

        if self.same_field:
            lines.append(f"{inner_indent}<same_field>{xml_escape(self.same_field)}</same_field>")

        for f in self.fields:
            lines.append(f.to_xml(indent=inner_indent))

        if self.options:
            for opt in self.options:
                lines.append(f"{inner_indent}<options>{xml_escape(opt)}</options>")

        if self.description:
            lines.append(f"{inner_indent}<description>{xml_escape(self.description)}</description>")

        if self.mitre_ids:
            lines.append(f"{inner_indent}<mitre>")
            for m_id in self.mitre_ids:
                lines.append(f"{inner_indent}  <id>{xml_escape(m_id)}</id>")
            lines.append(f"{inner_indent}</mitre>")

        if self.groups:
            group_str = ",".join(self.groups) + ","
            lines.append(f"{inner_indent}<group>{xml_escape(group_str)}</group>")

        lines.append(f"{indent}</rule>")
        return "\n".join(lines)


@dataclass
class WazuhGroup:
    """Represents a <group> root element containing rules."""
    name: str = "sigma,"
    rules: List[WazuhRule] = field(default_factory=list)

    def to_xml(self) -> str:
        if not self.rules:
            return f'<group name="{xml_escape(self.name)}">\n</group>'

        lines = [f'<group name="{xml_escape(self.name)}">']
        for rule in self.rules:
            lines.append(rule.to_xml(indent="  "))
        lines.append("</group>")
        return "\n".join(lines)
