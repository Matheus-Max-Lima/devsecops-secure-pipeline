"""
Testes automatizados com pytest para o projeto DevSecOps Portfolio.

O que este arquivo faz:
- Testa as funcoes seguras de src/app.py
- Verifica comportamentos esperados (casos normais)
- Verifica comportamentos de erro (casos de borda)
- Documenta que funcoes vulneraveis existem no codigo

Como rodar: pytest tests/ -v
"""

import pytest
import sys
import os

# Adiciona a pasta raiz ao caminho para o Python encontrar src/app.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.app import somar, validar_idade, formatar_nome


# =============================================================================
# TESTES DA FUNCAO: somar(a, b)
# =============================================================================

class TestSomar:
    """Testes para a funcao somar."""

    def test_soma_dois_positivos(self):
        """Caso basico: soma de dois numeros positivos."""
        assert somar(2, 3) == 5

    def test_soma_com_zero(self):
        """Somar com zero deve retornar o proprio numero."""
        assert somar(10, 0) == 10
        assert somar(0, 10) == 10

    def test_soma_dois_negativos(self):
        """Soma de dois negativos deve ser negativa."""
        assert somar(-3, -7) == -10

    def test_soma_positivo_com_negativo(self):
        """Positivo com negativo pode resultar em zero."""
        assert somar(5, -5) == 0

    def test_soma_numeros_decimais(self):
        """Funcao deve aceitar numeros decimais (float)."""
        assert somar(1.5, 2.5) == 4.0

    def test_soma_numeros_grandes(self):
        """Funcao deve lidar com numeros grandes sem erro."""
        assert somar(1_000_000, 2_000_000) == 3_000_000


# =============================================================================
# TESTES DA FUNCAO: validar_idade(idade)
# =============================================================================

class TestValidarIdade:
    """Testes para a funcao validar_idade."""

    def test_idade_valida_adulto(self):
        """Idade de adulto comum deve ser valida."""
        assert validar_idade(30) is True

    def test_idade_zero(self):
        """Idade zero (recem-nascido) deve ser valida."""
        assert validar_idade(0) is True

    def test_idade_maxima(self):
        """Idade 150 e o limite maximo aceito."""
        assert validar_idade(150) is True

    def test_idade_negativa_levanta_erro(self):
        """Idade negativa nao existe — deve levantar ValueError."""
        with pytest.raises(ValueError):
            validar_idade(-1)

    def test_idade_acima_do_limite_levanta_erro(self):
        """Idade acima de 150 e impossivel — deve levantar ValueError."""
        with pytest.raises(ValueError):
            validar_idade(151)

    def test_idade_como_string_levanta_erro(self):
        """Idade como texto deve levantar TypeError."""
        with pytest.raises(TypeError):
            validar_idade("trinta")

    def test_idade_como_float_levanta_erro(self):
        """Idade como decimal deve levantar TypeError."""
        with pytest.raises(TypeError):
            validar_idade(25.5)

    def test_idade_como_none_levanta_erro(self):
        """None nao e uma idade valida — deve levantar TypeError."""
        with pytest.raises(TypeError):
            validar_idade(None)


# =============================================================================
# TESTES DA FUNCAO: formatar_nome(nome)
# =============================================================================

class TestFormatarNome:
    """Testes para a funcao formatar_nome."""

    def test_nome_simples(self):
        """Nome simples deve ser capitalizado."""
        assert formatar_nome("joao") == "Joao"

    def test_nome_com_espacos_extras(self):
        """Espacos no inicio e fim devem ser removidos."""
        assert formatar_nome("  maria  ") == "Maria"

    def test_nome_completo(self):
        """Cada parte do nome deve ser capitalizada."""
        assert formatar_nome("ana paula souza") == "Ana Paula Souza"

    def test_nome_ja_maiusculo(self):
        """Nome todo em maiusculo deve ser formatado corretamente."""
        assert formatar_nome("CARLOS") == "Carlos"

    def test_nome_misto(self):
        """Nome com letras misturadas deve ser normalizado."""
        assert formatar_nome("jOsE sIlVa") == "Jose Silva"

    def test_nome_vazio_retorna_vazio(self):
        """String vazia deve retornar string vazia."""
        assert formatar_nome("") == ""

    def test_nome_como_numero_levanta_erro(self):
        """Numero passado como nome deve levantar TypeError."""
        with pytest.raises(TypeError):
            formatar_nome(123)

    def test_nome_como_none_levanta_erro(self):
        """None passado como nome deve levantar TypeError."""
        with pytest.raises(TypeError):
            formatar_nome(None)


# =============================================================================
# TESTES DE SEGURANCA — verificam a presenca de funcoes vulneraveis
# Esses testes documentam que o codigo vulneravel EXISTE para ser analisado.
# Eles NAO executam as vulnerabilidades, apenas importam e verificam.
# =============================================================================

class TestSegurancaDocumentada:
    """
    Testes que documentam a existencia de funcoes vulneraveis.
    Importante para o portfolio: mostra que voce sabe identificar o problema.
    """

    def test_funcao_vulneravel_sql_existe(self):
        """Documenta que a funcao com SQL Injection existe no modulo."""
        from src.app import buscar_usuario
        assert callable(buscar_usuario), "buscar_usuario deve ser uma funcao"

    def test_funcao_vulneravel_eval_existe(self):
        """Documenta que a funcao com eval() inseguro existe no modulo."""
        from src.app import calcular_expressao
        assert callable(calcular_expressao), "calcular_expressao deve ser uma funcao"

    def test_funcao_vulneravel_subprocess_existe(self):
        """Documenta que a funcao com subprocess inseguro existe no modulo."""
        from src.app import listar_arquivos
        assert callable(listar_arquivos), "listar_arquivos deve ser uma funcao"

    def test_funcao_vulneravel_md5_existe(self):
        """Documenta que a funcao com hash fraco existe no modulo."""
        from src.app import hash_senha
        assert callable(hash_senha), "hash_senha deve ser uma funcao"

    def test_credenciais_hardcoded_existem(self):
        """
        Documenta que credenciais hardcoded existem no codigo.
        O detect-secrets vai detectar isso como vulnerabilidade real.
        """
        from src import app
        assert hasattr(app, "DB_PASSWORD"), "DB_PASSWORD deve existir em app.py"
        assert hasattr(app, "API_KEY"), "API_KEY deve existir em app.py"
        assert hasattr(app, "SECRET_TOKEN"), "SECRET_TOKEN deve existir em app.py"
