import os
import json
import re
from typing import Dict, Any

class AttackMapper:
    def __init__(self, config_path: str = "config/rules_mapping.json"):
        self.config_path = config_path
        self.knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"keywords": []}

    def map_context(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analisa o contexto extraído e cruza com a base de conhecimento.
        Se mapeamentos nativos do MITRE existirem, eles são priorizados.
        """
        # Se o Wazuh já possuir a tag MITRE nativa
        if parsed_data.get("mitre_existing"):
            return {
                "rule_id": parsed_data["id"],
                "mapped": True,
                "technique": parsed_data["mitre_existing"][0],
                "confidence": 1.0,
                "justification": "Mapeamento nativo extraído diretamente das definições do Wazuh.",
                "evidence": ["Metadata nativo do log"]
            }

        # Texto consolidado para busca por Regex/Keywords
        text_pool = f"{parsed_data.get('description', '')} {parsed_data.get('full_log', '')}".lower()
        evidences = []
        
        if parsed_data.get('description'):
            evidences.append(f"Description: {parsed_data['description']}")
        if parsed_data.get('full_log'):
            evidences.append(f"Log line: {parsed_data['full_log']}")

        for item in self.knowledge_base.get("keywords", []):
            pattern = item["pattern"]
            if re.search(pattern, text_pool):
                tech = item["subtechnique"] if item.get("subtechnique") else item["technique"]
                return {
                    "rule_id": parsed_data["id"],
                    "mapped": True,
                    "technique": tech,
                    "confidence": item["confidence"],
                    "justification": item["reason"],
                    "evidence": evidences
                }

        # Fallback caso nada seja encontrado
        return {
            "rule_id": parsed_data["id"],
            "mapped": False,
            "technique": "Unknown",
            "confidence": 0.0,
            "justification": "Nenhum padrão conhecido ou assinatura detectada no payload do evento.",
            "evidence": evidences
        }
