import sys
import os
import click
from rich.console import Console
from rich.panel import Panel

# Adiciona o diretório raiz ao path para garantir importações corretas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parsers import WazuhParser
from src.mapper import AttackMapper
from src.exporters import ReportExporter

console = Console()

@click.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--export', type=click.Choice(['json', 'csv', 'md', 'html']), help="Exporta o relatório para o formato escolhido.")
@click.option('--out', default="report_output", help="Nome base do arquivo de saída.")
def main(file_path: str, export: str, out: str):
    """Wazuh ATT&CK Mapper - Ferramenta científica para enriquecimento de táticas e técnicas MITRE."""
    console.print("[bold blue]Iniciando análise do artefato Wazuh...[/bold blue]")
    
    try:
        # Detecção automática de tipo de entrada baseada na extensão
        if file_path.endswith('.json'):
            parsed = WazuhParser.parse_json_alert(file_path)
        elif file_path.endswith('.xml'):
            parsed = WazuhParser.parse_xml_rule(file_path)
        else:
            console.print("[bold red]Erro: Formato de arquivo não suportado. Use apenas .json ou .xml[/bold red]")
            return

        # Executa Engine de Mapeamento
        mapper = AttackMapper()
        result = mapper.map_context(parsed)

        # Output Visual no Terminal (Rich)
        output_panel = f"""[bold]Rule ID:[/bold] {result['rule_id']}
[bold]Suggested ATT&CK:[/bold] [yellow]{result['technique']}[/yellow]
[bold]Confidence:[/bold] {int(result['confidence'] * 100)}%

[bold]Justification:[/bold]
{result['justification']}

[bold]Evidence Trace:[/bold]
""" + "\n".join([f"- {ev}" for ev in result['evidence']])

        console.print(Panel(output_panel, title="Mapping Result", expand=False))

        # Fluxo de Exportação
        if export:
            filename = f"{out}.{export}"
            if export == 'json':
                ReportExporter.to_json(result, filename)
            elif export == 'csv':
                ReportExporter.to_csv(result, filename)
            elif export == 'md':
                ReportExporter.to_markdown(result, filename)
            elif export == 'html':
                ReportExporter.to_html(result, filename)
            
            console.print(f"[bold green]Relatório exportado com sucesso para: {filename}[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Ocorreu um erro no pipeline: {str(e)}[/bold red]")

if __name__ == '__main__':
    main()
