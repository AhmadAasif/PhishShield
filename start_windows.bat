@echo off
title PhishShield Launcher
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    py -m venv .venv
    if errorlevel 1 (
        echo Could not create the environment. Check that Python is installed.
        pause
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"
echo Installing required packages...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo Package installation failed. Check your internet connection and Python installation.
    pause
    exit /b 1
)

echo Starting PhishShield...
python app.py
pause
