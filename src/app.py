"""
Aplicacao de exemplo para o projeto DevSecOps Portfolio.

AVISO: Este arquivo contem vulnerabilidades PROPOSITAIS e FALSAS.
Objetivo: demonstrar ferramentas de segurança (Bandit, detect-secrets) funcionando.
NAO use este codigo em producao.
"""

import sqlite3
import subprocess
import hashlib
import pickle
import os


# =============================================================================
# VULNERABILIDADE 1 — Credenciais hardcoded (senha e API key falsas)
# Problema: senhas e tokens nunca devem aparecer no codigo-fonte.
# Ferramenta que detecta: detect-secrets, Bandit
# =============================================================================

DB_PASSWORD = "admin123"
API_KEY = "sk-fake1234567890abcdef1234567890abcdef"
SECRET_TOKEN = "ghp_FakeGitHubToken1234567890ABCDEF"


# =============================================================================
# VULNERABILIDADE 2 — Injecao de SQL (SQL Injection)
# Problema: o input do usuario e colocado direto na query sem sanitizacao.
# Um atacante pode digitar: ' OR '1'='1  para bypassar autenticacao.
# Ferramenta que detecta: Bandit (B608)
# =============================================================================

def buscar_usuario(nome_usuario):
    """Busca usuario no banco de dados de forma INSEGURA."""
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()

    # INSEGURO: nunca monte queries SQL com f-string ou concatenacao de string
    query = f"SELECT * FROM usuarios WHERE nome = '{nome_usuario}'"
    cursor.execute(query)

    resultado = cursor.fetchone()
    conn.close()
    return resultado


# =============================================================================
# VULNERABILIDADE 3 — Uso de eval() com input externo
# Problema: eval() executa qualquer codigo Python passado como string.
# Um atacante pode passar: __import__('os').system('del /s /q C:\\')
# Ferramenta que detecta: Bandit (B307)
# =============================================================================

def calcular_expressao(expressao):
    """Calcula uma expressao matematica de forma INSEGURA."""
    # INSEGURO: nunca use eval() com dados vindos do usuario
    resultado = eval(expressao)
    return resultado


# =============================================================================
# VULNERABILIDADE 4 — Execucao de comando com shell=True
# Problema: shell=True permite injecao de comandos do sistema operacional.
# Um atacante pode passar: "arquivo.txt; rm -rf /"
# Ferramenta que detecta: Bandit (B602)
# =============================================================================

def listar_arquivos(diretorio):
    """Lista arquivos de um diretorio de forma INSEGURA."""
    # INSEGURO: shell=True com input externo e perigoso
    resultado = subprocess.run(
        f"dir {diretorio}",
        shell=True,
        capture_output=True,
        text=True
    )
    return resultado.stdout


# =============================================================================
# VULNERABILIDADE 5 — Criptografia fraca (MD5)
# Problema: MD5 e SHA1 sao algoritmos quebrados ha decadas.
# Nao devem ser usados para senhas. Use bcrypt ou argon2.
# Ferramenta que detecta: Bandit (B324)
# =============================================================================

def hash_senha(senha):
    """Gera hash de senha de forma INSEGURA."""
    # INSEGURO: MD5 foi quebrado em 1996. Nao use para senhas.
    return hashlib.md5(senha.encode()).hexdigest()


# =============================================================================
# VULNERABILIDADE 6 — Desserializacao insegura (pickle)
# Problema: pickle pode executar codigo arbitrario ao desserializar dados.
# Um atacante que controla o arquivo pode executar qualquer comando.
# Ferramenta que detecta: Bandit (B301, B403)
# =============================================================================

def carregar_dados(caminho_arquivo):
    """Carrega dados de um arquivo de forma INSEGURA."""
    # INSEGURO: nunca use pickle com dados de fontes nao confiaveis
    with open(caminho_arquivo, "rb") as f:
        dados = pickle.load(f)
    return dados


# =============================================================================
# FUNCAO SEGURA — exemplo de como DEVERIA ser feito
# Esta funcao existe para comparacao e para os testes passarem
# =============================================================================

def somar(a, b):
    """Soma dois numeros. Funcao simples e segura para demonstrar pytest."""
    return a + b


def validar_idade(idade):
    """Valida se uma idade e valida. Funcao segura para demonstrar pytest."""
    if not isinstance(idade, int):
        raise TypeError("Idade deve ser um numero inteiro.")
    if idade < 0 or idade > 150:
        raise ValueError("Idade fora do intervalo valido (0-150).")
    return True


def formatar_nome(nome):
    """Formata um nome removendo espacos extras. Funcao segura."""
    if not isinstance(nome, str):
        raise TypeError("Nome deve ser uma string.")
    return nome.strip().title()
