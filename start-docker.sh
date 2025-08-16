#!/bin/bash

# Cyberdome Sentinel Docker Deployment Script
# This script sets up and starts the Cyberdome Sentinel application

set -e

echo "🚀 Starting Cyberdome Sentinel Docker Deployment..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p data uploads yara-rules static/images logs

# Copy logo to static directory if it exists
if [ -f "templates/images/logo.png" ]; then
    echo "🖼️  Copying logo to static directory..."
    cp templates/images/logo.png static/images/
fi

# Create .gitkeep files to preserve directories
touch data/.gitkeep uploads/.gitkeep yara-rules/.gitkeep static/images/.gitkeep

# Set proper permissions
echo "🔐 Setting proper permissions..."
chmod 755 data uploads yara-rules static logs
chmod 644 static/images/* 2>/dev/null || true

# Check if we want to use the full stack or simple version
if [ "$1" = "--full" ]; then
    echo "🏗️  Starting full stack (with Redis and Nginx)..."
    COMPOSE_FILE="docker-compose.yml"
else
    echo "🚀 Starting simple stack (Flask only)..."
    COMPOSE_FILE="docker-compose.simple.yml"
fi

# Build and start the containers
echo "🔨 Building and starting containers..."
docker-compose -f $COMPOSE_FILE up --build -d

# Wait for the application to be ready
echo "⏳ Waiting for application to be ready..."
sleep 10

# Check if the application is running
if curl -f http://localhost:5000/ > /dev/null 2>&1; then
    echo "✅ Cyberdome Sentinel is now running!"
    echo "🌐 Access the application at: http://localhost:5000"
    echo "📊 Health check: http://localhost:5000/"
    
    if [ "$1" = "--full" ]; then
        echo "🔒 Nginx is running on ports 80 and 443"
        echo "📡 Redis is running on port 6379"
    fi
    
    echo ""
    echo "📋 Useful commands:"
    echo "  View logs: docker-compose -f $COMPOSE_FILE logs -f"
    echo "  Stop: docker-compose -f $COMPOSE_FILE down"
    echo "  Restart: docker-compose -f $COMPOSE_FILE restart"
    echo "  Update: docker-compose -f $COMPOSE_FILE pull && docker-compose -f $COMPOSE_FILE up -d"
    
else
    echo "❌ Application failed to start. Checking logs..."
    docker-compose -f $COMPOSE_FILE logs cyberdome-sentinel
    exit 1
fi
