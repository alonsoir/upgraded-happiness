#!/bin/bash
# infrastructure/VM/manaage-vagrant-lab.sh
set -euo pipefail

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️${NC} $1"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ❌${NC} $1"; }

show_usage() {
    echo -e "${BLUE}Gestión del Laboratorio Upgraded Happiness${NC}"
    echo
    echo "Uso: $0 <comando>"
    echo
    echo "Comandos:"
    echo -e "  ${GREEN}start${NC}      - Crear e iniciar la VM"
    echo -e "  ${GREEN}stop${NC}       - Parar la VM"
    echo -e "  ${GREEN}restart${NC}    - Reiniciar la VM"
    echo -e "  ${GREEN}destroy${NC}    - Destruir la VM"
    echo -e "  ${GREEN}ssh${NC}        - Conectar por SSH"
    echo -e "  ${GREEN}status${NC}     - Ver estado de la VM"
    echo -e "  ${GREEN}pipeline${NC}   - Gestionar el pipeline"
    echo -e "  ${GREEN}logs${NC}       - Ver logs del pipeline"
    echo -e "  ${GREEN}rebuild${NC}    - Reconstruir imágenes Docker"
    echo
}

check_vagrant() {
    if ! command -v vagrant &> /dev/null; then
        error "Vagrant no está instalado"
        echo "Instala con: brew install vagrant"
        exit 1
    fi
}

start_lab() {
    log "🚀 Iniciando laboratorio..."

    if [ ! -f "Vagrantfile" ]; then
        error "Vagrantfile no encontrado. ¿Estás en el directorio correcto?"
        exit 1
    fi

    vagrant up

    log "✅ Laboratorio iniciado"
    log "🔗 Para conectar: $0 ssh"
    log "🚀 Para iniciar pipeline: $0 pipeline start"
}

stop_lab() {
    log "🛑 Parando laboratorio..."
    vagrant halt
    log "✅ Laboratorio parado"
}

restart_lab() {
    log "🔄 Reiniciando laboratorio..."
    vagrant reload
    log "✅ Laboratorio reiniciado"
}

destroy_lab() {
    warn "⚠️ Esta operación destruirá completamente la VM"
    read -p "¿Continuar? (y/N): " confirm

    if [[ $confirm =~ ^[Yy]$ ]]; then
        log "💥 Destruyendo laboratorio..."
        vagrant destroy -f
        log "✅ Laboratorio destruido"
    else
        log "Operación cancelada"
    fi
}

ssh_lab() {
    log "🔐 Conectando por SSH..."
    vagrant ssh
}

status_lab() {
    log "📊 Estado del laboratorio:"
    vagrant status

    if vagrant status | grep -q "running"; then
        echo
        log "🌐 Puertos mapeados:"
        echo "  SSH:       localhost:2222"
        echo "  Dashboard: http://localhost:8080"
        echo "  k3s API:   https://localhost:6443"
        echo "  etcd:      http://localhost:12379"
    fi
}

manage_pipeline() {
    local action=${2:-""}

    case $action in
        start)
            log "🚀 Iniciando pipeline..."
            vagrant ssh -c "./start-lab.sh"
            ;;
        stop)
            log "🛑 Parando pipeline..."
            vagrant ssh -c "cd upgraded-happiness && docker compose -f infrastructure/docker/docker-compose.yml down"
            ;;
        restart)
            log "🔄 Reiniciando pipeline..."
            vagrant ssh -c "cd upgraded-happiness && docker compose -f infrastructure/docker/docker-compose.yml restart"
            ;;
        status)
            log "📊 Estado del pipeline..."
            vagrant ssh -c "cd upgraded-happiness && docker compose -f infrastructure/docker/docker-compose.yml ps"
            ;;
        *)
            echo "Pipeline commands: start, stop, restart, status"
            ;;
    esac
}

view_logs() {
    log "📋 Logs del pipeline..."
    vagrant ssh -c "cd upgraded-happiness && docker compose -f infrastructure/docker/docker-compose.yml logs -f --tail=50"
}

rebuild_images() {
    log "🔨 Reconstruyendo imágenes Docker..."
    vagrant ssh -c "cd upgraded-happiness && ./infrastructure/docker/build_all_images.sh"
}

main() {
    check_vagrant

    case "${1:-}" in
        start)
            start_lab
            ;;
        stop)
            stop_lab
            ;;
        restart)
            restart_lab
            ;;
        destroy)
            destroy_lab
            ;;
        ssh)
            ssh_lab
            ;;
        status)
            status_lab
            ;;
        pipeline)
            manage_pipeline "$@"
            ;;
        logs)
            view_logs
            ;;
        rebuild)
            rebuild_images
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"