# Relatorio de Seguranca - Pipeline DevSecOps

**Data:** 2026-05-05 12:56 UTC  
**Status:** BLOQUEADO - Issues criticos encontrados

---

## Sumario Executivo

| Ferramenta | Categoria | Status | Resultado |
|---|---|---|---|
| Bandit | SAST | FALHOU | HIGH: 2 / MEDIUM: 3 / LOW: 4 |
| pip-audit | SCA | FALHOU | 11 CVE(s) em 4 pacote(s) |
| detect-secrets | Secrets | FALHOU | 4 secret(s) detectado(s) |

---

## 1. Analise de Codigo — Bandit (SAST)

> **O que e SAST?** Static Application Security Testing — analisa o codigo-fonte
> sem executar o programa, procurando por padroes conhecidamente inseguros.

- **HIGH:** 2 issue(s)
- **MEDIUM:** 3 issue(s)
- **LOW:** 4 issue(s)

### Issues Encontrados

| Severidade | Confianca | ID | Descricao | Arquivo | Linha | CWE |
|---|---|---|---|---|---|---|
| LOW | HIGH | B404 | blacklist | app.py | 10 | CWE-78 |
| LOW | HIGH | B403 | blacklist | app.py | 12 | CWE-502 |
| LOW | MEDIUM | B105 | hardcoded_password_string | app.py | 22 | CWE-259 |
| LOW | MEDIUM | B105 | hardcoded_password_string | app.py | 24 | CWE-259 |
| MEDIUM | LOW | B608 | hardcoded_sql_expressions | app.py | 40 | CWE-89 |
| MEDIUM | HIGH | B307 | blacklist | app.py | 58 | CWE-78 |
| HIGH | HIGH | B602 | subprocess_popen_with_shell_equals_true | app.py | 74 | CWE-78 |
| HIGH | HIGH | B324 | hashlib | app.py | 91 | CWE-327 |
| MEDIUM | HIGH | B301 | blacklist | app.py | 105 | CWE-502 |

---

## 2. Dependencias Vulneraveis — pip-audit (SCA)

> **O que e SCA?** Software Composition Analysis — verifica se as bibliotecas
> de terceiros instaladas possuem vulnerabilidades (CVEs) conhecidas publicamente.

**Total de CVEs encontrados:** 11

### `requests==2.25.0`

| ID da Vulnerabilidade | Versoes que Corrigem |
|---|---|
| PYSEC-2023-74 | 2.31.0 |
| GHSA-9wx4-h78v-vm56 | 2.32.0 |
| GHSA-9hjg-9r4m-mvj7 | 2.32.4 |
| GHSA-gc5v-m9x4-r6x2 | 2.33.0 |

### `flask==1.0.2`

| ID da Vulnerabilidade | Versoes que Corrigem |
|---|---|
| PYSEC-2023-62 | 2.2.5, 2.3.2 |
| GHSA-68rp-wp8r-4726 | 3.1.3 |

### `idna==2.10`

| ID da Vulnerabilidade | Versoes que Corrigem |
|---|---|
| PYSEC-2024-60 | 3.7 |

### `urllib3==1.26.20`

| ID da Vulnerabilidade | Versoes que Corrigem |
|---|---|
| GHSA-pq67-6m6q-mj2v | 2.5.0 |
| GHSA-gm62-xv2j-4w53 | 2.6.0 |
| GHSA-2xpw-w6gg-jr37 | 2.6.0 |
| GHSA-38jv-5279-wg99 | 2.6.3 |

---

## 3. Secrets Hardcoded — detect-secrets

> Procura por senhas, tokens, API keys e outros segredos escritos
> diretamente no codigo-fonte. Secrets no codigo sao um risco critico:
> qualquer pessoa com acesso ao repositorio os ve imediatamente.

**Total de secrets detectados:** 4

### Secrets por Arquivo

**`app.py`** — 4 secret(s)

| Tipo de Secret | Linha no Arquivo |
|---|---|
| Secret Keyword | 22 |
| Secret Keyword | 23 |
| Base64 High Entropy String | 24 |
| Secret Keyword | 24 |

> **Nota de seguranca:** O detect-secrets armazena apenas o **hash** do secret,
> nunca o valor real. O arquivo `.secrets.baseline` e seguro para commitar.

---

## Conclusao e Acoes Recomendadas

Este pipeline foi **bloqueado** pelos seguintes motivos:

- 2 issue(s) de severidade **HIGH** no Bandit
- 11 CVE(s) em dependencias desatualizadas
- 4 secret(s) hardcoded no codigo-fonte

### Como corrigir

| Problema | Acao Recomendada |
|---|---|
| Secrets hardcoded | Remover do codigo e usar GitHub Secrets + variaveis de ambiente |
| Dependencias com CVE | Atualizar para as versoes corrigidas listadas acima |
| Issues HIGH Bandit | Reescrever o codigo usando as alternativas seguras indicadas |

---

*Relatorio gerado automaticamente pelo Pipeline DevSecOps Seguro*  
*Timestamp: 2026-05-05 12:56 UTC*