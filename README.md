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
