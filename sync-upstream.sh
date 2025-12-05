#!/bin/bash
#
# Script de Sincronização com Upstream
# Skills IT Soluções em TI - www.skillsit.com.br
#
# Este script sincroniza o fork da Skills com o repositório original
# do desenvolvedor (alpadalar/ActiveDirectoryMCP) e aplica as atualizações.
#
# Uso:
#   ./sync-upstream.sh          # Sincroniza e faz merge automático
#   ./sync-upstream.sh --check  # Apenas verifica se há atualizações
#   ./sync-upstream.sh --dry-run # Mostra o que seria feito sem executar
#

set -e

# Cores para output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

# Diretório do projeto
PROJECT_DIR="/opt/mcp-servers/active-directory/skills"
LOG_FILE="/opt/mcp-servers/shared/logs/ad-skills-sync.log"

# Função de log
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" >> "$LOG_FILE"
    
    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC} ${message}" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} ${message}" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} ${message}" ;;
        *)     echo -e "[${level}] ${message}" ;;
    esac
}

# Verificar se estamos no diretório correto
cd "$PROJECT_DIR" || {
    log ERROR "Não foi possível acessar $PROJECT_DIR"
    exit 1
}

# Modo de operação
MODE="sync"
if [[ "$1" == "--check" ]]; then
    MODE="check"
elif [[ "$1" == "--dry-run" ]]; then
    MODE="dry-run"
fi

log INFO "=============================================="
log INFO "Sincronização MCP Active Directory"
log INFO "Skills IT - $(date)"
log INFO "Modo: $MODE"
log INFO "=============================================="

# Verificar branch atual
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    log WARN "Branch atual: $CURRENT_BRANCH (esperado: main)"
    if [[ "$MODE" == "sync" ]]; then
        log INFO "Mudando para branch main..."
        git checkout main
    fi
fi

# Buscar atualizações do upstream
log INFO "Buscando atualizações do upstream (alpadalar/ActiveDirectoryMCP)..."
git fetch upstream main 2>&1 | while read line; do log INFO "$line"; done

# Verificar se há diferenças
UPSTREAM_COMMITS=$(git rev-list HEAD..upstream/main --count)
LOCAL_COMMITS=$(git rev-list upstream/main..HEAD --count)

log INFO "Commits no upstream não aplicados: $UPSTREAM_COMMITS"
log INFO "Commits locais (Skills IT): $LOCAL_COMMITS"

if [[ "$UPSTREAM_COMMITS" -eq 0 ]]; then
    log INFO "✅ Repositório já está atualizado com upstream!"
    exit 0
fi

# Mostrar commits pendentes
log INFO ""
log INFO "Commits do upstream pendentes:"
git log HEAD..upstream/main --oneline | while read line; do
    log INFO "  → $line"
done

# Se modo check, parar aqui
if [[ "$MODE" == "check" ]]; then
    log INFO ""
    log INFO "Para aplicar as atualizações, execute: ./sync-upstream.sh"
    exit 0
fi

# Se modo dry-run, mostrar o que seria feito
if [[ "$MODE" == "dry-run" ]]; then
    log INFO ""
    log INFO "Simulação - O que seria feito:"
    log INFO "  1. git merge upstream/main"
    log INFO "  2. Resolver conflitos (se houver)"
    log INFO "  3. git push origin main"
    log INFO "  4. pm2 restart mcp-ad-skills"
    exit 0
fi

# Modo sync - aplicar atualizações
log INFO ""
log INFO "Aplicando atualizações do upstream..."

# Tentar merge
if git merge upstream/main -m "Merge upstream updates from alpadalar/ActiveDirectoryMCP

Sincronização automática com repositório original.
Skills IT Soluções em TI - www.skillsit.com.br
"; then
    log INFO "✅ Merge realizado com sucesso!"
else
    log ERROR "❌ Conflitos detectados durante o merge!"
    log ERROR ""
    log ERROR "Arquivos com conflito:"
    git diff --name-only --diff-filter=U | while read file; do
        log ERROR "  - $file"
    done
    log ERROR ""
    log ERROR "Para resolver manualmente:"
    log ERROR "  1. Edite os arquivos com conflito"
    log ERROR "  2. git add <arquivos>"
    log ERROR "  3. git commit"
    log ERROR "  4. ./sync-upstream.sh"
    exit 1
fi

# Push para origin (fork Skills)
log INFO "Enviando atualizações para origin (DevSkillsIT/ActiveDirectoryMCP)..."
git push origin main 2>&1 | while read line; do log INFO "$line"; done

# Reiniciar serviço
log INFO "Reiniciando MCP AD Skills..."
pm2 restart mcp-ad-skills

# Aguardar serviço iniciar
sleep 5

# Verificar status
if pm2 show mcp-ad-skills | grep -q "online"; then
    log INFO "✅ Serviço reiniciado com sucesso!"
else
    log ERROR "❌ Erro ao reiniciar serviço!"
    pm2 logs mcp-ad-skills --lines 20 --nostream
    exit 1
fi

log INFO ""
log INFO "=============================================="
log INFO "✅ Sincronização concluída com sucesso!"
log INFO "=============================================="
