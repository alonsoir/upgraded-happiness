#!/bin/bash
# manage_vm.sh
set -euo pipefail

VM_NAME="ubuntu-infra"
VM_USER="idsadmin"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"

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
    echo -e "${BLUE}Uso: $0 <comando>${NC}"
    echo
    echo "Comandos disponibles:"
    echo -e "  ${GREEN}start${NC}     - Iniciar la VM"
    echo -e "  ${GREEN}stop${NC}      - Parar la VM"
    echo -e "  ${GREEN}restart${NC}   - Reiniciar la VM"
    echo -e "  ${GREEN}status${NC}    - Ver estado de la VM"
    echo -e "  ${GREEN}ssh${NC}       - Conectar por SSH"
    echo -e "  ${GREEN}logs${NC}      - Ver logs del pipeline"
    echo -e "  ${GREEN}pipeline${NC}  - Gestionar el pipeline"
    echo -e "  ${GREEN}backup${NC}    - Crear backup de la VM"
    echo -e "  ${GREEN}restore${NC}   - Restaurar backup de la VM"
    echo -e "  ${GREEN}delete${NC}    - Eliminar la VM"
    echo -e "  ${GREEN}info${NC}      - Mostrar información de conexión"
}

vm_start() {
    log "🚀 Iniciando VM..."
    if VBoxManage showvminfo "$VM_NAME" | grep -q "State:.*running"; then
        warn "La VM ya está ejecutándose"
        return 0
    fi
    VBoxManage startvm "$VM_NAME"
    log "✅ VM iniciada"
}

vm_stop() {
    log "🛑 Parando VM..."
    VBoxManage controlvm "$VM_NAME" acpipowerbutton || true
    sleep 5

    # Forzar parada si es necesario
    if VBoxManage showvminfo "$VM_NAME" | grep -q "State:.*running"; then
        warn "Forzando parada de la VM..."
        VBoxManage controlvm "$VM_NAME" poweroff
    fi
    log "✅ VM parada"
}

vm_restart() {
    vm_stop
    sleep 2
    vm_start
}

vm_status() {
    log "📊 Estado de la VM:"
    VBoxManage showvminfo "$VM_NAME" | grep "State:" || error "VM no encontrada"

    if VBoxManage showvminfo "$VM_NAME" | grep -q "State:.*running"; then
        echo
        log "🌐 Puertos mapeados:"
        echo "  SSH:   127.0.0.1:2222 → VM:22"
        echo "  HTTP:  127.0.0.1:8080 → VM:80"
        echo "  HTTPS: 127.0.0.1:8443 → VM:443"
        echo "  K3s:   127.0.0.1:6443 → VM:6443"

        echo
        log "🔗 Verificando conectividad SSH..."
        if nc -zv 127.0.0.1 2222 2>/dev/null; then
            echo -e "${GREEN}✅ SSH accesible${NC}"
        else
            echo -e "${RED}❌ SSH no accesible${NC}"
        fi
    fi
}

vm_ssh() {
    log "🔐 Conectando por SSH..."
    if ! nc -zv 127.0.0.1 2222 2>/dev/null; then
        error "SSH no está disponible. ¿Está la VM ejecutándose?"
    fi
    ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1"
}

vm_logs() {
    log "📋 Logs del pipeline..."
    if ! nc -zv 127.0.0.1 2222 2>/dev/null; then
        error "SSH no está disponible. ¿Está la VM ejecutándose?"
    fi

    ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" \
        'cd ~/projects/upgraded-happiness && docker compose -f ./infrastructure/docker/docker-compose.yml logs -f --tail=50'
}

vm_pipeline() {
    if ! nc -zv 127.0.0.1 2222 2>/dev/null; then
        error "SSH no está disponible. ¿Está la VM ejecutándose?"
    fi

    echo -e "${BLUE}Gestión del pipeline:${NC}"
    echo "1. Iniciar pipeline"
    echo "2. Parar pipeline"
    echo "3. Reiniciar pipeline"
    echo "4. Ver estado"
    echo "5. Ver logs"
    echo "6. Actualizar código"

    read -p "Selecciona opción (1-6): " option

    case $option in
        1)
            log "🚀 Iniciando pipeline..."
            ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" \
                'cd ~/projects/upgraded-happiness && docker compose -f ./infrastructure/docker/docker-compose.yml up -d'
            ;;
        2)
            log "🛑 Parando pipeline..."
            ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" \
                'cd ~/projects/upgraded-happiness && docker compose -f ./infrastructure/docker/docker-compose.yml down'
            ;;
        3)
            log "🔄 Reiniciando pipeline..."
            ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" \
                'cd ~/projects/upgraded-happiness && docker compose -f ./infrastructure/docker/docker-compose.yml restart'
            ;;
        4)
            log "📊 Estado del pipeline..."
            ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" \
                'cd ~/projects/upgraded-happiness && docker compose -f ./infrastructure/docker/docker-compose.yml ps'
            ;;
        5)
            vm_logs
            ;;
        6)
            log "🔄 Actualizando código..."
            ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" \
                'cd ~/projects/upgraded-happiness && git pull && docker compose -f ./infrastructure/docker/docker-compose.yml up -d --build'
            ;;
        *)
            error "Opción inválida"
            ;;
    esac
}

vm_backup() {
    log "💾 Creando backup de la VM..."
    local backup_name="$VM_NAME-backup-$(date +%Y%m%d-%H%M%S)"
    VBoxManage clonevm "$VM_NAME" --name "$backup_name" --register
    log "✅ Backup creado: $backup_name"
}

vm_restore() {
    echo "⚠️  Esta operación eliminará la VM actual y restaurará el backup"
    read -p "¿Continuar? (y/N): " confirm

    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log "Operación cancelada"
        return 0
    fi

    # Listar backups disponibles
    log "📂 Backups disponibles:"
    VBoxManage list vms | grep "$VM_NAME-backup" || error "No se encontraron backups"

    read -p "Nombre del backup a restaurar: " backup_name

    if ! VBoxManage showvminfo "$backup_name" &>/dev/null; then
        error "Backup no encontrado: $backup_name"
    fi

    log "🗑️ Eliminando VM actual..."
    vm_stop || true
    VBoxManage unregistervm "$VM_NAME" --delete

    log "🔄 Restaurando backup..."
    VBoxManage clonevm "$backup_name" --name "$VM_NAME" --register
    log "✅ Backup restaurado"
}

vm_delete() {
    echo -e "${RED}⚠️  Esta operación eliminará permanentemente la VM${NC}"
    read -p "¿Continuar? (y/N): " confirm

    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log "Operación cancelada"
        return 0
    fi

    vm_stop || true
    VBoxManage unregistervm "$VM_NAME" --delete
    log "✅ VM eliminada"
}

vm_info() {
    log "📋 Información de conexión:"
    echo
    echo -e "${BLUE}🔗 SSH:${NC} ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1"
    echo -e "${BLUE}🌐 Puertos:${NC}"
    echo -e "   SSH:   127.0.0.1:2222 → VM:22"
    echo -e "   HTTP:  127.0.0.1:8080 → VM:80"
    echo -e "   HTTPS: 127.0.0.1:8443 → VM:443"
    echo -e "   K3s:   127.0.0.1:6443 → VM:6443"
    echo
    echo -e "${BLUE}📁 Proyecto:${NC} /home/$VM_USER/projects/upgraded-happiness"
    echo -e "${BLUE}🚀 Iniciar pipeline:${NC} ./start_pipeline.sh"
}

# Función principal
main() {
    case "${1:-}" in
        start)
            vm_start
            ;;
        stop)
            vm_stop
            ;;
        restart)
            vm_restart
            ;;
        status)
            vm_status
            ;;
        ssh)
            vm_ssh
            ;;
        logs)
            vm_logs
            ;;
        pipeline)
            vm_pipeline
            ;;
        backup)
            vm_backup
            ;;
        restore)
            vm_restore
            ;;
        delete)
            vm_delete
            ;;
        info)
            vm_info
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"