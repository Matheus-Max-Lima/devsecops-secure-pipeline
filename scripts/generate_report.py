#!/usr/bin/env python3
"""
Gera o relatorio consolidado de seguranca do pipeline DevSecOps.

Le os relatorios JSON de cada ferramenta (Bandit, pip-audit, detect-secrets)
e gera um unico arquivo Markdown em reports/security-report.md.

Exit codes:
  0 = nenhum issue critico encontrado (pipeline aprovado)
  1 = issues criticos encontrados (pipeline bloqueado)
"""

import json
import os
import sys
from datetime import datetime, timezone


# Caminhos dos arquivos de entrada e saida
DIR_REPORTS   = "reports"
BANDIT_JSON   = os.path.join(DIR_REPORTS, "bandit-report.json")
PIPAUDIT_JSON = os.path.join(DIR_REPORTS, "pip-audit-report.json")
SECRETS_JSON  = os.path.join(DIR_REPORTS, "secrets-report.json")
RELATORIO_MD  = os.path.join(DIR_REPORTS, "security-report.md")


# =============================================================================
# FUNCOES DE LEITURA
# =============================================================================

def ler_json(caminho):
    """Le um arquivo JSON com seguranca. Retorna None se nao existir.
    Usa utf-8-sig para lidar com BOM gerado pelo PowerShell no Windows.
    """
    if not os.path.exists(caminho):
        print(f"  Aviso: {caminho} nao encontrado. Pulando.")
        return None
    try:
        with open(caminho, encoding="utf-8-sig") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as erro:
        print(f"  Aviso: erro ao ler {caminho}: {erro}")
        return None


# =============================================================================
# FUNCOES DE PROCESSAMENTO
# =============================================================================

def processar_bandit(raw):
    """Extrai metricas e lista de issues do JSON do Bandit."""
    if not raw:
        return {"high": 0, "medium": 0, "low": 0, "issues": []}

    totals = raw.get("metrics", {}).get("_totals", {})
    return {
        "high":   int(totals.get("SEVERITY.HIGH",   0)),
        "medium": int(totals.get("SEVERITY.MEDIUM", 0)),
        "low":    int(totals.get("SEVERITY.LOW",    0)),
        "issues": raw.get("results", []),
    }


def processar_pip_audit(raw):
    """Extrai lista de pacotes vulneraveis do JSON do pip-audit."""
    if not raw:
        return {"total": 0, "pacotes": []}

    pacotes, total = [], 0
    for dep in raw.get("dependencies", []):
        vulns = dep.get("vulns", [])
        if vulns:
            pacotes.append({
                "nome":   dep.get("name", "?"),
                "versao": dep.get("version", "?"),
                "vulns":  vulns,
            })
            total += len(vulns)

    return {"total": total, "pacotes": pacotes}


def processar_secrets(raw):
    """Extrai secrets detectados do JSON do detect-secrets."""
    if not raw:
        return {"total": 0, "arquivos": {}}

    resultados = raw.get("results", {})
    total = sum(len(v) for v in resultados.values())
    return {"total": total, "arquivos": resultados}


# =============================================================================
# GERACAO DO RELATORIO MARKDOWN
# =============================================================================

def gerar_markdown(bandit, pip_audit, secrets, timestamp):
    """Monta o relatorio completo em formato Markdown."""

    bloqueado = (
        bandit["high"] > 0
        or pip_audit["total"] > 0
        or secrets["total"] > 0
    )

    status_linha = (
        "BLOQUEADO - Issues criticos encontrados"
        if bloqueado else
        "APROVADO - Nenhum issue critico"
    )

    L = []  # acumula as linhas do relatorio

    # --- Cabecalho ---
    L += [
        "# Relatorio de Seguranca - Pipeline DevSecOps",
        "",
        f"**Data:** {timestamp}  ",
        f"**Status:** {'BLOQUEADO - Issues criticos encontrados' if bloqueado else 'APROVADO - Nenhum issue critico'}",
        "",
        "---",
        "",
        "## Sumario Executivo",
        "",
        "| Ferramenta | Categoria | Status | Resultado |",
        "|---|---|---|---|",
        f"| Bandit | SAST | {'FALHOU' if bandit['high'] > 0 else 'AVISOS' if bandit['medium'] > 0 else 'OK'} | HIGH: {bandit['high']} / MEDIUM: {bandit['medium']} / LOW: {bandit['low']} |",
        f"| pip-audit | SCA | {'FALHOU' if pip_audit['total'] > 0 else 'OK'} | {pip_audit['total']} CVE(s) em {len(pip_audit['pacotes'])} pacote(s) |",
        f"| detect-secrets | Secrets | {'FALHOU' if secrets['total'] > 0 else 'OK'} | {secrets['total']} secret(s) detectado(s) |",

        "",
        "---",
    ]

    # --- Secao Bandit ---
    L += [
        "",
        "## 1. Analise de Codigo — Bandit (SAST)",
        "",
        "> **O que e SAST?** Static Application Security Testing — analisa o codigo-fonte",
        "> sem executar o programa, procurando por padroes conhecidamente inseguros.",
        "",
        f"- **HIGH:** {bandit['high']} issue(s)",
        f"- **MEDIUM:** {bandit['medium']} issue(s)",
        f"- **LOW:** {bandit['low']} issue(s)",
        "",
    ]

    if bandit["issues"]:
        L += [
            "### Issues Encontrados",
            "",
            "| Severidade | Confianca | ID | Descricao | Arquivo | Linha | CWE |",
            "|---|---|---|---|---|---|---|",
        ]
        for issue in bandit["issues"]:
            sev   = issue.get("issue_severity", "?")
            conf  = issue.get("issue_confidence", "?")
            tid   = issue.get("test_id", "?")
            tname = issue.get("test_name", "?")
            fname = os.path.basename(issue.get("filename", "?"))
            line  = issue.get("line_number", "?")
            cwe   = issue.get("issue_cwe", {}).get("id", "?")
            L.append(f"| {sev} | {conf} | {tid} | {tname} | {fname} | {line} | CWE-{cwe} |")
        L.append("")
    else:
        L.append("Nenhum issue encontrado pelo Bandit.\n")

    L.append("---")

    # --- Secao pip-audit ---
    L += [
        "",
        "## 2. Dependencias Vulneraveis — pip-audit (SCA)",
        "",
        "> **O que e SCA?** Software Composition Analysis — verifica se as bibliotecas",
        "> de terceiros instaladas possuem vulnerabilidades (CVEs) conhecidas publicamente.",
        "",
        f"**Total de CVEs encontrados:** {pip_audit['total']}",
        "",
    ]

    if pip_audit["pacotes"]:
        for pkg in pip_audit["pacotes"]:
            L += [
                f"### `{pkg['nome']}=={pkg['versao']}`",
                "",
                "| ID da Vulnerabilidade | Versoes que Corrigem |",
                "|---|---|",
            ]
            for v in pkg["vulns"]:
                vid = v.get("id", "?")
                fix = ", ".join(v.get("fix_versions", [])) or "sem fix disponivel"
                L.append(f"| {vid} | {fix} |")
            L.append("")
    else:
        L.append("Nenhuma dependencia vulneravel encontrada.\n")

    L.append("---")

    # --- Secao detect-secrets ---
    L += [
        "",
        "## 3. Secrets Hardcoded — detect-secrets",
        "",
        "> Procura por senhas, tokens, API keys e outros segredos escritos",
        "> diretamente no codigo-fonte. Secrets no codigo sao um risco critico:",
        "> qualquer pessoa com acesso ao repositorio os ve imediatamente.",
        "",
        f"**Total de secrets detectados:** {secrets['total']}",
        "",
    ]

    if secrets["arquivos"]:
        L += ["### Secrets por Arquivo", ""]
        for arquivo, lista in secrets["arquivos"].items():
            nome = os.path.basename(arquivo)
            L += [
                f"**`{nome}`** — {len(lista)} secret(s)",
                "",
                "| Tipo de Secret | Linha no Arquivo |",
                "|---|---|",
            ]
            for s in lista:
                L.append(f"| {s.get('type', '?')} | {s.get('line_number', '?')} |")
            L.append("")

        L += [
            "> **Nota de seguranca:** O detect-secrets armazena apenas o **hash** do secret,",
            "> nunca o valor real. O arquivo `.secrets.baseline` e seguro para commitar.",
            "",
        ]
    else:
        L.append("Nenhum secret detectado no codigo.\n")

    L.append("---")

    # --- Conclusao ---
    L += ["", "## Conclusao e Acoes Recomendadas", ""]

    if bloqueado:
        L += [
            "Este pipeline foi **bloqueado** pelos seguintes motivos:",
            "",
        ]
        if bandit["high"] > 0:
            L.append(f"- {bandit['high']} issue(s) de severidade **HIGH** no Bandit")
        if pip_audit["total"] > 0:
            L.append(f"- {pip_audit['total']} CVE(s) em dependencias desatualizadas")
        if secrets["total"] > 0:
            L.append(f"- {secrets['total']} secret(s) hardcoded no codigo-fonte")
        L += [
            "",
            "### Como corrigir",
            "",
            "| Problema | Acao Recomendada |",
            "|---|---|",
            "| Secrets hardcoded | Remover do codigo e usar GitHub Secrets + variaveis de ambiente |",
            "| Dependencias com CVE | Atualizar para as versoes corrigidas listadas acima |",
            "| Issues HIGH Bandit | Reescrever o codigo usando as alternativas seguras indicadas |",
            "",
        ]
    else:
        L += [
            "Nenhum problema critico encontrado. Pipeline **aprovado**.",
            "",
        ]

    L += [
        "---",
        "",
        "*Relatorio gerado automaticamente pelo Pipeline DevSecOps Seguro*  ",
        f"*Timestamp: {timestamp}*",
    ]

    return "\n".join(L)


# =============================================================================
# EXECUCAO PRINCIPAL
# =============================================================================

def main():
    os.makedirs(DIR_REPORTS, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print()
    print("Lendo relatorios das ferramentas de seguranca...")

    bandit    = processar_bandit(ler_json(BANDIT_JSON))
    pip_audit = processar_pip_audit(ler_json(PIPAUDIT_JSON))
    secrets   = processar_secrets(ler_json(SECRETS_JSON))

    # Gerar e salvar o Markdown
    conteudo = gerar_markdown(bandit, pip_audit, secrets, timestamp)
    with open(RELATORIO_MD, "w", encoding="utf-8") as f:
        f.write(conteudo)

    # Imprimir sumario no terminal (aparece nos logs do GitHub Actions)
    print()
    print("=" * 55)
    print("  SUMARIO DE SEGURANCA DO PIPELINE")
    print("=" * 55)
    print(f"  Bandit HIGH:          {bandit['high']:>3} issue(s)")
    print(f"  Bandit MEDIUM:        {bandit['medium']:>3} issue(s)")
    print(f"  Bandit LOW:           {bandit['low']:>3} issue(s)")
    print(f"  pip-audit CVEs:       {pip_audit['total']:>3} CVE(s)")
    print(f"  Secrets detectados:   {secrets['total']:>3} secret(s)")
    print("=" * 55)

    tem_critico = bandit["high"] > 0 or pip_audit["total"] > 0 or secrets["total"] > 0

    if tem_critico:
        print("  STATUS: PIPELINE BLOQUEADO")
        print(f"  Relatorio salvo em: {RELATORIO_MD}")
        print("=" * 55)
        print()
        sys.exit(1)  # exit code 1 = sinaliza falha para o GitHub Actions
    else:
        print("  STATUS: PIPELINE APROVADO")
        print(f"  Relatorio salvo em: {RELATORIO_MD}")
        print("=" * 55)
        print()
        sys.exit(0)  # exit code 0 = sucesso


if __name__ == "__main__":
    main()
