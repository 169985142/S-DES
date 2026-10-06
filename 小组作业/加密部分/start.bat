@echo off
cd /d "%~dp0"

echo ============================================
echo   S-DES Encryption Program - Starting...
echo ============================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8 or above first.
    pause
    exit /b 1
)

python -c "import PyQt5" >nul 2>&1
if errorlevel 1 (
    echo [INFO] PyQt5 not found. Installing dependency...
    python -m pip install PyQt5
    if errorlevel 1 (
        echo [ERROR] Installation failed. Run manually: python -m pip install PyQt5
        pause
        exit /b 1
    )
)

echo [INFO] Launching program...
python main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Program exited with an error. See messages above.
    pause
    exit /b 1
)
