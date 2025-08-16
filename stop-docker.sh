#!/bin/bash

# Cyberdome Sentinel Docker Stop Script
# This script stops and cleans up the Cyberdome Sentinel application

echo "🛑 Stopping Cyberdome Sentinel Docker Deployment..."

# Check if we want to use the full stack or simple version
if [ "$1" = "--full" ]; then
    echo "🏗️  Stopping full stack (with Redis and Nginx)..."
    COMPOSE_FILE="docker-compose.yml"
else
    echo "🚀 Stopping simple stack (Flask only)..."
    COMPOSE_FILE="docker-compose.simple.yml"
fi

# Stop the containers
echo "⏹️  Stopping containers..."
docker-compose -f $COMPOSE_FILE down

# Remove stopped containers (optional)
if [ "$2" = "--clean" ]; then
    echo "🧹 Cleaning up stopped containers..."
    docker container prune -f
    docker image prune -f
fi

echo "✅ Cyberdome Sentinel has been stopped successfully!"
echo ""
echo "📋 To start again, run: ./start-docker.sh"
echo "📋 To start with full stack: ./start-docker.sh --full"
