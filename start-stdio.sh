#!/bin/bash
cd "/opt/mcp-servers/active-directory/skills"
source .venv/bin/activate
export AD_MCP_CONFIG="/opt/mcp-servers/active-directory/skills/ad-config/ad-config.json"
export PYTHONPATH="/opt/mcp-servers/active-directory/skills/src"
python -m active_directory_mcp.server
