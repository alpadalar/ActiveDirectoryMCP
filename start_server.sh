#!/bin/bash

# ActiveDirectoryMCP Server Startup Script
# This script starts the ActiveDirectoryMCP server in stdio mode

set -e

echo "Starting ActiveDirectoryMCP Server..."

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

# Set PYTHONPATH
export PYTHONPATH="$PWD/src:$PYTHONPATH"

# Start the server
echo "Starting ActiveDirectoryMCP server in stdio mode..."
python -m active_directory_mcp.server
