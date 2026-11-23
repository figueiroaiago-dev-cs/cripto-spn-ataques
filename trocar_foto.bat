@echo off
chcp 65001 >nul
cd /d "%~dp0"
if "%~1"=="" (
  echo Arraste uma foto ^(PNG ou JPG^) para cima deste arquivo .bat
  pause
  exit /b 1
)
if not exist ".venv\Scripts\activate.bat" (
  echo Rode primeiro o rodar_projeto.bat para instalar as dependencias.
  pause
  exit /b 1
)
call ".venv\Scripts\activate.bat"
echo Usando a foto: %~1
python stego.py "%~1"
echo.
echo Pronto. Resultados atualizados em resultados\stego.json e nas imagens stego_*.png
pause
