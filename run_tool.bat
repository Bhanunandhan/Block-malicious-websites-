@echo off
echo Website Security ^& Blocking Tool
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH.
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

REM Check if the main script exists
if not exist "website_security_tool.py" (
    echo Error: website_security_tool.py not found in current directory.
    echo Please make sure you're running this from the correct folder.
    pause
    exit /b 1
)

REM Install dependencies if needed
echo Checking dependencies...
pip install -r requirements.txt >nul 2>&1

REM Run the tool
echo Starting the application...
echo.
python website_security_tool.py

REM If the script exits with an error, pause to show the message
if errorlevel 1 (
    echo.
    echo An error occurred. Please check the messages above.
    pause
) 