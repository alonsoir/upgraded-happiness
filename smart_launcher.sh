#!/bin/bash
# smart_launcher.sh - Launcher inteligente con cleanup automático
# ==============================================================
# Detecta automáticamente si necesita cleanup y ejecuta la acción correspondiente

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Función para detectar si se necesita cleanup
needs_cleanup() {
    # Detectar procesos conflictivos
    local platform_processes=(pgrep -f "smart_broker\|lightweight_ml_detector\|promiscuous_agent\|dashboard_server")
    local process_count=$(eval "${platform_processes[@]}" 2>/dev/null | wc -l)

    # Detectar puertos ocupados
    local port_5555=$(lsof -ti :5555 2>/dev/null)
    local port_8766=$(lsof -ti :8766 2>/dev/null)

    if [ $process_count -gt 0 ] || [ ! -z "$port_5555" ] || [ ! -z "$port_8766" ]; then
        return 0  # Necesita cleanup
    else
        return 1  # No necesita cleanup
    fi
}

# Función para ejecutar comando con cleanup inteligente
smart_execute() {
    local command="$1"
    local description="$2"

    echo -e "${BLUE}🚀 $description${NC}"

    if needs_cleanup; then
        echo -e "${YELLOW}⚠️  Conflictos detectados - ejecutando cleanup automático...${NC}"
        if ./platform_cleanup.sh auto; then
            echo -e "${GREEN}✅ Cleanup completado${NC}"
        else
            echo -e "${YELLOW}⚠️  Cleanup parcial - continuando...${NC}"
        fi
    else
        echo -e "${GREEN}✅ Sistema limpio - no necesita cleanup${NC}"
    fi

    echo -e "${CYAN}▶️  Ejecutando: $command${NC}"
    eval "$command"
}

# Función principal
main() {
    local action="${1:-help}"

    # Asegurar que los scripts tengan permisos de ejecución
    chmod +x platform_cleanup.sh 2>/dev/null || true

    case "$action" in
        "run-all")
            smart_execute "make run-all" "Iniciando plataforma completa"
            ;;
        "run-dashboard")
            smart_execute "make run-dashboard" "Iniciando dashboard web"
            ;;
        "run-daemon")
            smart_execute "make run-daemon" "Iniciando plataforma en modo daemon"
            ;;
        "dashboard-only")
            # Para dashboard solo, necesitamos verificar que la plataforma esté corriendo
            if needs_cleanup; then
                echo -e "${YELLOW}⚠️  Detectados conflictos - limpiando puerto 8766 únicamente...${NC}"
                pkill -f "dashboard_server" 2>/dev/null || true
                local port_8766=$(lsof -ti :8766 2>/dev/null)
                if [ ! -z "$port_8766" ]; then
                    kill -9 $port_8766 2>/dev/null || true
                fi
                sleep 1
            fi
            smart_execute "make run-dashboard" "Iniciando solo dashboard"
            ;;
        "status")
            echo -e "${CYAN}📊 Estado del sistema:${NC}"
            if needs_cleanup; then
                echo -e "${YELLOW}⚠️  Sistema necesita cleanup${NC}"
                ./platform_cleanup.sh check
            else
                echo -e "${GREEN}✅ Sistema limpio${NC}"
                make status
            fi
            ;;
        "cleanup")
            echo -e "${BLUE}🧹 Ejecutando cleanup manual...${NC}"
            ./platform_cleanup.sh auto
            ;;
        "help"|*)
            echo -e "${CYAN}🤖 Smart Launcher - Upgraded Happiness${NC}"
            echo -e "${CYAN}=====================================${NC}"
            echo ""
            echo -e "${YELLOW}Comandos disponibles:${NC}"
            echo "  ./smart_launcher.sh run-all         - Inicia plataforma completa"
            echo "  ./smart_launcher.sh run-dashboard   - Inicia dashboard web"
            echo "  ./smart_launcher.sh run-daemon      - Inicia plataforma daemon"
            echo "  ./smart_launcher.sh dashboard-only  - Solo dashboard (sin cleanup de plataforma)"
            echo "  ./smart_launcher.sh status          - Estado del sistema"
            echo "  ./smart_launcher.sh cleanup         - Cleanup manual"
            echo ""
            echo -e "${GREEN}✨ Características inteligentes:${NC}"
            echo "  • Detecta automáticamente conflictos"
            echo "  • Ejecuta cleanup solo cuando es necesario"
            echo "  • Preserva componentes que no conflictúan"
            echo "  • Reporta estado del sistema en tiempo real"
            ;;
    esac
}

# Ejecutar función principal
main "$@"