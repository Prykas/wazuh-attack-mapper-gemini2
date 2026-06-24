import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional

class WazuhParser:
    @staticmethod
    def parse_json_alert(file_path: str) -> Dict[str, Any]:
        """Processa um alerta JSON do Wazuh."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            rule_data = data.get("rule", {})
            return {
                "source_type": "json_alert",
                "id": rule_data.get("id", "Unknown"),
                "description": rule_data.get("description", ""),
                "full_log": data.get("full_log", ""),
                "srcip": data.get("srcip", "N/A"),
                "mitre_existing": rule_data.get("mitre", {}).get("id", [])
            }
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise ValueError(f"Erro ao processar alerta JSON: {str(e)}")

    @staticmethod
    def parse_xml_rule(file_path: str) -> Dict[str, Any]:
        """Processa um arquivo de regras XML do Wazuh."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Trata se o root for <group> ou diretamente <rule>
            rule_node = root.find('.//rule') if root.tag != 'rule' else root
            
            if rule_node is None:
                raise ValueError("Nenhum nó <rule> encontrado no XML.")
                
            mitre_tags = [info.text for info in rule_node.findall('.//info') if info.text and 'mitre' in info.attrib.get('type', '')]
            
            return {
                "source_type": "xml_rule",
                "id": rule_node.attrib.get("id", "Unknown"),
                "description": rule_node.find('description').text if rule_node.find('description') is not None else "",
                "group": rule_node.find('group').text if rule_node.find('group') is not None else "",
                "mitre_existing": mitre_tags
            }
        except (ET.ParseError, FileNotFoundError) as e:
            raise ValueError(f"Erro ao processar XML de regra: {str(e)}")
