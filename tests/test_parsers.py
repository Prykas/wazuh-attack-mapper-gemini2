import pytest
import json
import os
from src.parsers import WazuhParser

def test_json_parser(tmp_path):
    # Cria arquivo mock de alerta JSON
    alert_file = tmp_path / "alert.json"
    mock_data = {
        "rule": {"id": "5710", "description": "Attempt to login using a non-existent user"},
        "full_log": "Failed password for invalid user root"
    }
    alert_file.write_text(json.dumps(mock_data))
    
    res = WazuhParser.parse_json_alert(str(alert_file))
    assert res["id"] == "5710"
    assert "invalid user root" in res["full_log"]

def test_xml_parser(tmp_path):
    # Cria arquivo mock de regra XML
    rule_file = tmp_path / "rule.xml"
    mock_xml = """<rule id="100201" level="5">
        <description>Custom detection test</description>
        <group>syslog,</group>
    </rule>"""
    rule_file.write_text(mock_xml)
    
    res = WazuhParser.parse_xml_rule(str(rule_file))
    assert res["id"] == "100201"
    assert res["description"] == "Custom detection test"
