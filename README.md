# Pipeline DevSecOps Seguro

![Pipeline Status](https://github.com/Matheus-Max-Lima/devsecops-secure-pipeline/actions/workflows/security-pipeline.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Bandit](https://img.shields.io/badge/SAST-Bandit-yellow)
![pip-audit](https://img.shields.io/badge/SCA-pip--audit-orange)
![detect-secrets](https://img.shields.io/badge/Secrets-detect--secrets-red)
![License](https://img.shields.io/badge/License-MIT-green)

> Projeto de portfolio demonstrando a implementacao de um pipeline CI/CD com
> seguranca integrada (DevSecOps), usando GitHub Actions, Python e ferramentas
> open-source de analise de seguranca.

---

## O que este projeto demonstra

Este repositorio mostra como integrar **seguranca desde o inicio** em um pipeline
de desenvolvimento, automatizando quatro camadas de verificacao a cada `git push`:

| Camada | Ferramenta | O que verifica |
|---|---|---|
| Testes | pytest | Se o codigo funciona corretamente |
| SAST | Bandit | Vulnerabilidades no codigo Python |
| SCA | pip-audit | CVEs em dependencias de terceiros |
| Secrets | detect-secrets | Credenciais hardcoded no codigo |

O pipeline **bloqueia automaticamente** qualquer codigo que contenha problemas
criticos de seguranca, impedindo que vulnerabilidades cheguem ao ambiente de producao.

---

## Arquitetura do Pipeline

```
git push
    |
    v
GitHub Actions (ubuntu-latest)
    |
    |-- [1] Setup: Python 3.11 + ferramentas
    |
    |-- [2] pytest
    |        Falha imediata se testes quebrarem
    |
    |-- [3] Bandit (SAST)        --> reports/bandit-report.json
    |-- [4] pip-audit (SCA)      --> reports/pip-audit-report.json
    |-- [5] detect-secrets       --> reports/secrets-report.json
    |        (rodam em paralelo, todos salvam resultados)
    |
    |-- [6] generate_report.py
    |        Le os 3 JSONs, gera reports/security-report.md
    |        Exit code 1 se encontrar issues criticos
    |
    |-- [7] Upload de artefatos  (sempre executa, salva evidencias)
    |
    |-- [8] Security Gate
             Bloqueia o pipeline se [6] retornou exit code 1
```

---

## Estrutura do Repositorio

```
devsecops-secure-pipeline/
|
|-- .github/
|   +-- workflows/
|       +-- security-pipeline.yml   # Pipeline completo do GitHub Actions
|
|-- src/
|   +-- app.py                      # Aplicacao Python com vulnerabilidades intencionais
|
|-- tests/
|   +-- test_app.py                 # 27 testes automatizados com pytest
|
|-- scripts/
|   +-- generate_report.py          # Gerador do relatorio consolidado Markdown
|
|-- reports/
|   +-- bandit-report.json          # Saida do Bandit (gerado pelo pipeline)
|   +-- pip-audit-report.json       # Saida do pip-audit (gerado pelo pipeline)
|   +-- secrets-report.json         # Saida do detect-secrets (gerado pelo pipeline)
|   +-- security-report.md          # Relatorio final consolidado
|
|-- .bandit                         # Configuracao do Bandit
|-- .secrets.baseline               # Baseline do detect-secrets
|-- requirements.txt                # Dependencias da aplicacao
|-- requirements-dev.txt            # Ferramentas de seguranca e teste
+-- README.md
```

---

## Vulnerabilidades Demonstradas

O arquivo `src/app.py` contem vulnerabilidades **intencionais e falsas** para
demonstrar o funcionamento das ferramentas de seguranca:

| # | Vulnerabilidade | CWE | Ferramenta que detecta |
|---|---|---|---|
| 1 | SQL Injection via f-string | CWE-89 | Bandit B608 |
| 2 | eval() com input externo | CWE-78 | Bandit B307 |
| 3 | subprocess com shell=True | CWE-78 | Bandit B602 |
| 4 | Hash MD5 para senhas | CWE-327 | Bandit B324 |
| 5 | pickle.load() inseguro | CWE-502 | Bandit B301/B403 |
| 6 | API key hardcoded | CWE-259 | detect-secrets |
| 7 | Senha hardcoded | CWE-259 | detect-secrets |
| 8 | Token GitHub hardcoded | CWE-259 | detect-secrets |
| 9 | Dependencias com CVEs | N/A | pip-audit |

> **Aviso:** Todo o codigo vulneravel e falso e existe exclusivamente para fins
> educacionais e de demonstracao de ferramentas de seguranca.

---

## Como Executar Localmente

### Pre-requisitos

- Python 3.11 ou superior
- Git

### Instalacao

```bash
# Clonar o repositorio
git clone https://github.com/Matheus-Max-Lima/devsecops-secure-pipeline.git
cd devsecops-secure-pipeline

# Instalar ferramentas de seguranca
pip install -r requirements-dev.txt
```

### Rodar as verificacoes manualmente

```bash
# Testes automatizados
pytest tests/ -v

# Analise de codigo (Bandit)
bandit -r src/ -f json -o reports/bandit-report.json

# Auditoria de dependencias
pip-audit -r requirements.txt -f json -o reports/pip-audit-report.json

# Deteccao de secrets
detect-secrets scan --all-files src/ \
  | python -c "import sys; open('reports/secrets-report.json','w',encoding='utf-8').write(sys.stdin.read())"

# Gerar relatorio consolidado
python scripts/generate_report.py
```

### Resultado esperado

```
=======================================================
  SUMARIO DE SEGURANCA DO PIPELINE
=======================================================
  Bandit HIGH:            2 issue(s)
  Bandit MEDIUM:          3 issue(s)
  Bandit LOW:             4 issue(s)
  pip-audit CVEs:        11 CVE(s)
  Secrets detectados:     4 secret(s)
=======================================================
  STATUS: PIPELINE BLOQUEADO
=======================================================
```

O pipeline e bloqueado porque encontra problemas criticos de seguranca
propositalmente inseridos no codigo para fins de demonstracao.

---

## Resultado no GitHub Actions

Apos cada `git push`, a aba **Actions** do repositorio mostra a execucao completa:

- Cada etapa com status de passou/falhou
- Logs detalhados de cada ferramenta
- Artefatos para download com todos os relatorios
- Pipeline marcado como vermelho (bloqueado) devido aos problemas encontrados

Os artefatos ficam disponiveis por 90 dias e incluem:
- `bandit-report.json`
- `pip-audit-report.json`
- `secrets-report.json`
- `security-report.md`

---

## Stack Tecnologica

| Tecnologia | Versao | Funcao |
|---|---|---|
| Python | 3.11 | Linguagem principal |
| pytest | 8.3.5 | Framework de testes |
| Bandit | 1.8.3 | SAST — analise estatica de seguranca |
| pip-audit | 2.9.0 | SCA — auditoria de dependencias |
| detect-secrets | 1.5.0 | Deteccao de credenciais hardcoded |
| GitHub Actions | - | Plataforma de CI/CD |

---

## Conceitos Demonstrados

- **DevSecOps:** Seguranca integrada ao ciclo de desenvolvimento, nao como etapa final
- **Shift Left Security:** Verificacoes de seguranca acontecem cedo, no momento do commit
- **SAST:** Static Application Security Testing — analise sem executar o codigo
- **SCA:** Software Composition Analysis — analise da cadeia de dependencias
- **Security Gate:** Portao automatico que bloqueia codigo inseguro
- **CWE:** Common Weakness Enumeration — padrao internacional de classificacao de vulnerabilidades
- **CVE:** Common Vulnerabilities and Exposures — identificadores de vulnerabilidades conhecidas
- **Pipeline as Code:** Configuracao do pipeline versionada junto ao codigo

---

## Proximos Passos (Roadmap)

- [ ] Adicionar DAST com OWASP ZAP
- [ ] Integrar Semgrep como segundo analisador SAST
- [ ] Adicionar notificacao no Slack quando pipeline falhar
- [ ] Implementar SBOM (Software Bill of Materials) com syft
- [ ] Adicionar analise de containers com Trivy
- [ ] Configurar pre-commit hooks locais
- [ ] Implementar gerenciamento de secrets com HashiCorp Vault

---

## Autor

Desenvolvido como projeto de portfolio de DevSecOps e Cybersecurity.

---

## Licenca

MIT License — veja o arquivo [LICENSE](LICENSE) para detalhes.
