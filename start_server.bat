@echo off
REM ActiveDirectoryMCP Server Startup Script (Windows)
REM This script starts the ActiveDirectoryMCP server in stdio mode.
REM It loads environment variables from a ".env" file in this directory, if present
REM (see ".env.example" for the variables you can set, e.g. Azure Key Vault credentials).

setlocal

echo Starting ActiveDirectoryMCP Server...

if not exist ".venv" (
    echo Virtual environment not found. Please run setup first.
    exit /b 1
)

call ".venv\Scripts\activate.bat"

if exist ".env" (
    echo Loading environment variables from .env
    for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
        if not "%%A"=="" set "%%A=%%B"
    )
)

if "%AD_MCP_CONFIG%"=="" set "AD_MCP_CONFIG=ad-config\ad-config.json"

if not exist "%AD_MCP_CONFIG%" (
    echo Configuration file not found: %AD_MCP_CONFIG%
    echo Please copy ad-config\config.example.json to ad-config\ad-config.json and configure it.
    exit /b 1
)

echo Using configuration: %AD_MCP_CONFIG%

set "PYTHONPATH=%CD%\src;%PYTHONPATH%"

echo Starting ActiveDirectoryMCP server in stdio mode...
python -m active_directory_mcp.server
