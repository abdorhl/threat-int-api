#!/bin/bash

echo "========================================"
echo "Threat Intelligence API Startup"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo ""
    echo "WARNING: Please edit .env file and add your API keys!"
    echo ""
fi

# Start Redis with Docker (if Docker is available)
echo "Checking Redis..."
if command -v docker &> /dev/null; then
    echo "Starting Redis container..."
    docker run -d --name threat-intel-redis -p 6379:6379 redis:latest 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Redis started successfully"
    else
        echo "Redis container already running or failed to start"
    fi
else
    echo "Docker not available. Please ensure Redis is running manually."
fi

echo ""
echo "========================================"
echo "Starting API Server..."
echo "========================================"
echo ""
echo "API will be available at: http://localhost:8000"
echo "Documentation: http://localhost:8000/docs"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo ""

# Start the API
python main.py
