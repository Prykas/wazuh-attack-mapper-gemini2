import json
import csv
from typing import Dict, Any

class ReportExporter:
    @staticmethod
    def to_json(data: Dict[str, Any], output_path: str):
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def to_csv(data: Dict[str, Any], output_path: str):
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Rule ID", "Technique", "Confidence", "Justification"])
            writer.writerow([
                data.get("rule_id"),
                data.get("technique"),
                f"{int(data.get('confidence', 0) * 100)}%",
                data.get("justification")
            ])

    @staticmethod
    def to_markdown(data: Dict[str, Any], output_path: str):
        evidences_str = "\n".join([f"- {ev}" for ev in data.get("evidence", [])])
        md_content = f"""# Wazuh ATT&CK Mapping Report

## Summary
* **Rule ID:** {data.get('rule_id')}
* **Suggested ATT&CK:** {data.get('technique')}
* **Confidence:** {int(data.get('confidence', 0) * 100)}%

## Justification
{data.get('justification')}

## Evidence Trace
{evidences_str}
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

    @staticmethod
    def to_html(data: Dict[str, Any], output_path: str):
        evidences_li = "".join([f"<li>{ev}</li>" for ev in data.get("evidence", [])])
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Wazuh ATT&CK Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1 {{ color: #1e293b; }}
        .badge {{ background-color: #3b82f6; color: white; padding: 5px 10px; border-radius: 4px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Wazuh ATT&CK Mapping Result</h1>
        <p><strong>Rule ID:</strong> {data.get('rule_id')}</p>
        <p><strong>Suggested Technique:</strong> <span class="badge">{data.get('technique')}</span></p>
        <p><strong>Confidence:</strong> {int(data.get('confidence', 0) * 100)}%</p>
        <h3>Justification</h3>
        <p>{data.get('justification')}</p>
        <h3>Evidences</h3>
        <ul>{evidences_li}</ul>
    </div>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
