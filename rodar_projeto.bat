@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Projeto 1 - Sistema Criptografico ===
where python >nul 2>nul
if errorlevel 1 (
  echo [ERRO] Python nao encontrado.
  echo Instale o Python 3.10 ou mais novo em https://www.python.org/downloads/
  echo e marque a opcao "Add python.exe to PATH" na primeira tela do instalador.
  pause
  exit /b 1
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
  echo [ERRO] O projeto precisa do Python 3.10 ou mais novo. Versao atual:
  python --version
  pause
  exit /b 1
)
python --version
if not exist ".venv" (
  echo [1/4] Criando ambiente virtual .venv ...
  python -m venv .venv
)
call ".venv\Scripts\activate.bat"
echo [2/4] Instalando dependencias (so demora na primeira vez) ...
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt -q
if errorlevel 1 (
  echo [ERRO] Falha ao instalar as dependencias. Veja a mensagem acima.
  pause
  exit /b 1
)
echo [3/4] Gerando eventos e treinando a IA ...
python eventos.py
python ia.py
echo [4/4] Abrindo o dashboard no navegador. Para encerrar, feche esta janela.
python -m streamlit run dashboard.py
pause
