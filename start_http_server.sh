#!/bin/bash

# ActiveDirectoryMCP HTTP Server Startup Script
# This script starts the ActiveDirectoryMCP server in HTTP mode

set -e

echo "Starting ActiveDirectoryMCP HTTP Server..."

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment
source .venv/bin/activate

# Load environment variables from .env, if present (see .env.example)
if [ -f ".env" ]; then
    echo "Loading environment variables from .env"
    set -a
    source .env
    set +a
fi

# Check if config file exists
if [ -z "$AD_MCP_CONFIG" ]; then
    export AD_MCP_CONFIG="ad-config/ad-config.json"
fi

if [ ! -f "$AD_MCP_CONFIG" ]; then
    echo "Configuration file not found: $AD_MCP_CONFIG"
    echo "Please copy ad-config/config.example.json to ad-config/ad-config.json and configure it."
    exit 1
fi

echo "Using configuration: $AD_MCP_CONFIG"

# Set default values
HOST=${HTTP_HOST:-0.0.0.0}
PORT=${HTTP_PORT:-8813}
PATH=${HTTP_PATH:-/activedirectory-mcp}

# Set PYTHONPATH
export PYTHONPATH="$PWD/src:$PYTHONPATH"

# Start the HTTP server
echo "Starting ActiveDirectoryMCP HTTP server on $HOST:$PORT$PATH"
python -m active_directory_mcp.server_http --host $HOST --port $PORT --path $PATH
