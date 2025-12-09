@echo off
echo ================================================
echo         NIGHTACTION SETUP
echo ================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python found
python --version

echo.
echo [*] Installing dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ================================================
echo [SUCCESS] NightAction setup complete!
echo ================================================
echo.
echo Next steps:
echo.
echo 1. Start the server:
echo    python nightaction_server.py
echo.
echo 2. Add agents:
echo    python manage_agents.py
echo.
echo 3. Connect with client:
echo    python nightaction_client.py
echo.
pause
