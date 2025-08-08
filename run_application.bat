@echo off
cls

:: Check if Python is installed and available in the PATH
where python > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH.
    pause
    exit /b
)

:: Run the Python script, ignoring warnings
python -W ignore main.py

pause
