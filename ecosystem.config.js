module.exports = {
  apps: [{
    name: 'mcp-ad-skills',
    script: '/opt/mcp-servers/active-directory/skills/start-http.sh',
    interpreter: '/bin/bash',
    cwd: '/opt/mcp-servers/active-directory/skills',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '256M',
    env: {
      AD_MCP_CONFIG: '/opt/mcp-servers/active-directory/skills/ad-config/ad-config.json',
      PYTHONPATH: '/opt/mcp-servers/active-directory/skills/src'
    },
    error_file: '/opt/mcp-servers/shared/logs/ad-skills-error.log',
    out_file: '/opt/mcp-servers/shared/logs/ad-skills-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
