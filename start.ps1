# File Scanner CyberDome Startup Script
Write-Host "Starting File Scanner CyberDome..." -ForegroundColor Green
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python found: $pythonVersion" -ForegroundColor Yellow
} catch {
    Write-Host "Error: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8 or higher and try again" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Install requirements
Write-Host "Installing requirements..." -ForegroundColor Yellow
pip install -r requirements.txt

# Start the application
Write-Host ""
Write-Host "Starting Flask application..." -ForegroundColor Green
Write-Host "Access the application at: http://localhost:5000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

try {
    python app.py
} catch {
    Write-Host "Error starting application: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
} 