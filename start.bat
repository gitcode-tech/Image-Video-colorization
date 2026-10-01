@echo off
set "VENV_NAME=.venv"

echo.
echo ====================================
echo  LogRay Setup & Initialization
echo ====================================
echo.

:: 1. Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please ensure Python 3.x is installed and in your PATH.
    pause
    goto :eof
)

:: 2. Create venv if it doesn't exist
if not exist "%VENV_NAME%" (
    echo [*] Creating virtual environment...
    python -m venv "%VENV_NAME%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        goto :eof
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

:: 3. Activate venv (using a temporary command to activate and run pip)
echo [*] Installing/Updating requirements...
call "%VENV_NAME%\Scripts\activate"
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install requirements. Check requirements.txt.
    pause
    goto :eof
)
echo [OK] Requirements installed successfully.

:: 4. Provide instructions and keep the window open
echo.
echo ====================================
echo  SETUP COMPLETE
echo ====================================
echo.
echo To run LogRay, use:
echo %VENV_NAME%\Scripts\python logray.py -f <logfile>
echo.
echo Example:
echo %VENV_NAME%\Scripts\python logray.py -f test_log.txt -t 5
echo.
echo Press any key to continue...
pause >nul

:: 5. Go to the start of the batch file logic
goto :eof