@echo off
echo ========================================
echo Threat Intelligence API Startup
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Check if .env exists
if not exist ".env" (
    echo Creating .env file from template...
    copy .env.example .env
    echo.
    echo WARNING: Please edit .env file and add your API keys!
    echo.
)

REM Start Redis with Docker (if Docker is available)
echo Checking Redis...
docker ps >nul 2>&1
if %errorlevel% equ 0 (
    echo Starting Redis container...
    docker run -d --name threat-intel-redis -p 6379:6379 redis:latest >nul 2>&1
    if %errorlevel% equ 0 (
        echo Redis started successfully
    ) else (
        echo Redis container already running or failed to start
    )
) else (
    echo Docker not available. Please ensure Redis is running manually.
)

echo.
echo ========================================
echo Starting API Server...
echo ========================================
echo.
echo API will be available at: http://localhost:8000
echo Documentation: http://localhost:8000/docs
echo.
echo Default credentials:
echo   Username: admin
echo   Password: admin123
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

REM Start the API
python main.py
