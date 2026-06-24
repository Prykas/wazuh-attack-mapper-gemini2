# wazuh-attack-mapper-gemini2
Uso da LLM Gemini para criar Wazuh-attack-mapper
# Wazuh ATT&CK Mapper

O **Wazuh ATT&CK Mapper** é um artefato de software científico desenvolvido para mitigar o gap de visibilidade operacional enfrentado por analistas de SOC (*Security Operations Center*). A ferramenta executa o mapeamento e enriquecimento sintático e semântico de alertas de segurança (JSON) e regras customizadas (XML) geradas pela plataforma SIEM Wazuh diretamente contra a matriz **MITRE ATT&CK Framework**.

## Arquitetura do Artefato

O design do motor foi estruturado utilizando o paradigma de desacoplamento de camadas (*Separation of Concerns*):

1. **Ingestão/Parsing:** Módulos isolados processam logs estruturados de eventos (JSON) e definições gramaticais de assinaturas (XML).
2. **Core Mapper Engine:** Motor de correlação de contexto heurístico baseado em assinaturas, palavras-chave e expressões regulares parametrizáveis.
3. **Fallback Resiliente:** Arquitetura *offline-first* auto-sustentada que descarta dependências externas e custos computacionais de APIs proprietárias (ex: OpenAI/Anthropic), garantindo privacidade corporativa total.

---

## Instalação e Configuração

### Pré-requisitos
* Python 3.10 ou superior instalado localmente.

### Instruções para Instalação

1. Clone ou monte a árvore de diretórios do projeto.
2. Crie e ative um ambiente virtual isolado:
   ```bash
   python -m venv venv
   source venv/bin/activate  # No Windows use: venv\Scripts\activate
## 🛠️ Tecnologias e Dependências

O desenvolvimento e a validação deste artefato científico baseiam-se nos seguintes componentes:

### Core do Sistema (Python)
* **[Click](https://click.palletsprojects.com/)** - Interface de Linha de Comando (CLI).
* **[Rich](https://rich.readthedocs.io/)** - Formatação visual e relatórios no terminal.
* **[Jinja2](https://jinja.palletsprojects.com/)** - Engine de geração de relatórios dinâmicos.

### Rigor Científico e Testes
* **[Pytest](https://docs.pytest.org/)** - Framework de testes de unidade e automação de reprodutibilidade.
* **[Black](https://github.com/psf/black)** / **[Flake8](https://flake8.pycqa.org/)** - Padronização e qualidade estática de código (PEP 8).

### Frameworks de Cibersegurança Referenciados
* **[MITRE ATT&CK Matrix](https://attack.mitre.org/)** - Modelo de taxonomia de ameaças.
* **[Wazuh Core Architecture](https://documentation.wazuh.com/)** - Estrutura gramatical de regras (XML) e esquemas de logs (JSON).
