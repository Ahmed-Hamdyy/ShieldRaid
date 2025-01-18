@echo off
echo Starting VulnScan Application...

REM Activate virtual environment if it exists
if exist "venv\Scripts\activate" (
    call venv\Scripts\activate
) else (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate
    echo Installing requirements...
    pip install -r requirements.txt
)

REM Start the application
python app.py

pause 