@echo off
echo Starting VulnScan Application...

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed! Please install Python first.
    pause
    exit /b 1
)

REM Check if pip is installed
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo pip is not installed! Please install pip first.
    pause
    exit /b 1
)

REM Check if virtual environment exists, if not create it
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install requirements if not already installed
echo Installing/Updating requirements...
pip install -r requirements.txt
pip install ngrok

REM Check if ngrok is installed
ngrok --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing ngrok...
    pip install ngrok-python
)

REM Start Flask app in background
start /B python app.py

REM Wait for Flask to start
timeout /t 5 /nobreak

REM Start ngrok tunnel
echo Starting ngrok tunnel...
ngrok http 5000

REM Keep the window open if there's an error
pause 