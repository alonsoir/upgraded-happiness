#!/bin/bash

# =============================================================================
# MONITOR SCADA Platform
# =============================================================================
# Script de monitoreo en tiempo real para la plataforma SCADA
# =============================================================================

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Función para limpiar pantalla
clear_screen() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    📊 SCADA PLATFORM MONITOR                                 ║"
    echo "║                      Upgraded Happiness - Real Time                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Verificar estado de componentes
check_components() {
    echo -e "${CYAN}🔧 ESTADO DE COMPONENTES:${NC}"
    echo "=================================="

    local broker_status="❌ DETENIDO"
    local detector_status="❌ DETENIDO"
    local agent_status="❌ DETENIDO"

    if pgrep -f "smart_broker" &>/dev/null; then
        broker_status="✅ ACTIVO"
    fi

    if pgrep -f "lightweight_ml_detector" &>/dev/null; then
        detector_status="✅ ACTIVO"
    fi

    if pgrep -f "promiscuous_agent" &>/dev/null; then
        agent_status="✅ ACTIVO"
    fi

    echo -e "  🔌 ZeroMQ Broker:      $broker_status"
    echo -e "  🧠 ML Detector:        $detector_status"
    echo -e "  🕵️  Promiscuous Agent: $agent_status"
    echo ""
}

# Verificar puertos
check_ports() {
    echo -e "${CYAN}🌐 ESTADO DE PUERTOS:${NC}"
    echo "=================================="

    local ports=(5555 5556 55565)

    for port in "${ports[@]}"; do
        if netstat -an 2>/dev/null | grep -q ":$port.*LISTEN" || lsof -i ":$port" &>/dev/null; then
            echo -e "  Puerto $port:          ✅ ACTIVO"
        else
            echo -e "  Puerto $port:          ❌ NO ACTIVO"
        fi
    done
    echo ""
}

# Mostrar uso de recursos
show_resources() {
    echo -e "${CYAN}💻 USO DE RECURSOS:${NC}"
    echo "=================================="

    # CPU y memoria de procesos SCADA
    local scada_processes=$(pgrep -f -d',' "smart_broker\|lightweight_ml\|promiscuous" 2>/dev/null | sed 's/,$//')

    if [[ -n "$scada_processes" ]]; then
        echo -e "${YELLOW}Procesos SCADA:${NC}"
        ps -p "$scada_processes" -o pid,pcpu,pmem,comm --no-headers 2>/dev/null | while read line; do
            echo "  $line"
        done
    else
        echo -e "${RED}  No hay procesos SCADA activos${NC}"
    fi

    echo ""
    echo -e "${YELLOW}Sistema general:${NC}"
    echo "  CPU: $(top -l 1 -s 0 | grep "CPU usage" | awk '{print $3}' | cut -d'%' -f1 2>/dev/null || echo "N/A")%"
    echo "  Memoria: $(free -h 2>/dev/null | awk '/^Mem:/ {print $3"/"$2}' || echo "N/A")"
    echo ""
}

# Mostrar información de red
show_network() {
    echo -e "${CYAN}🌍 INFORMACIÓN DE RED:${NC}"
    echo "=================================="

    # Conexiones activas en puertos SCADA
    echo -e "${YELLOW}Conexiones ZeroMQ:${NC}"
    netstat -an 2>/dev/null | grep -E ":555[56]|:55565" | head -5 | while read line; do
        echo "  $line"
    done

    echo ""
    echo -e "${YELLOW}Interfaces de red activas:${NC}"
    ip -o link show 2>/dev/null | awk -F': ' '{print "  "$2}' | head -5 || \
    ifconfig -a 2>/dev/null | grep "^[a-z]" | awk '{print "  "$1}' | head -5
    echo ""
}

# Función para modo continuo
continuous_monitor() {
    local interval=${1:-5}

    echo -e "${GREEN}Iniciando monitoreo continuo (actualización cada $interval segundos)${NC}"
    echo -e "${YELLOW}Presiona Ctrl+C para salir${NC}"
    echo ""

    while true; do
        clear_screen
        echo -e "${BLUE}Última actualización: $(date)${NC}"
        echo ""

        check_components
        check_ports
        show_resources
        show_network

        echo -e "${CYAN}Comandos disponibles:${NC}"
        echo -e "  ${YELLOW}make stop${NC}        - Parar plataforma"
        echo -e "  ${YELLOW}make status${NC}      - Estado básico"
        echo -e "  ${YELLOW}make test-traffic${NC} - Generar tráfico test"

        sleep $interval
    done
}

# Función para mostrar logs
show_logs() {
    echo -e "${CYAN}📝 LOGS RECIENTES:${NC}"
    echo "=================================="

    if [[ -d "logs" ]]; then
        echo -e "${YELLOW}Archivos de log disponibles:${NC}"
        ls -la logs/ 2>/dev/null || echo "  No hay logs disponibles"
        echo ""

        # Mostrar últimas líneas de logs si existen
        for log_file in logs/*.log; do
            if [[ -f "$log_file" ]]; then
                echo -e "${YELLOW}Últimas líneas de $(basename "$log_file"):${NC}"
                tail -5 "$log_file" 2>/dev/null | sed 's/^/  /'
                echo ""
            fi
        done
    else
        echo -e "${RED}  Directorio de logs no encontrado${NC}"
    fi
}

# Función para diagnóstico rápido
quick_diagnosis() {
    echo -e "${CYAN}🔍 DIAGNÓSTICO RÁPIDO:${NC}"
    echo "=================================="

    local issues_found=false

    # Verificar Python y dependencias
    if ! python3 -c "import zmq, scapy, sklearn, pandas" &>/dev/null; then
        echo -e "${RED}❌ Problemas con dependencias Python${NC}"
        echo -e "   Solución: ${YELLOW}make fix-deps${NC}"
        issues_found=true
    fi

    # Verificar permisos sudo
    if ! sudo -n true 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Permisos sudo no configurados${NC}"
        echo -e "   Solución: ${YELLOW}make setup-sudo${NC}"
        issues_found=true
    fi

    # Verificar Makefile
    if [[ ! -f "Makefile" ]]; then
        echo -e "${RED}❌ Makefile no encontrado${NC}"
        echo -e "   Asegúrate de estar en el directorio correcto"
        issues_found=true
    fi

    if ! $issues_found; then
        echo -e "${GREEN}✅ No se encontraron problemas obvios${NC}"
    fi

    echo ""
}

# Mostrar ayuda
show_help() {
    echo -e "${CYAN}Uso: $0 [opción]${NC}"
    echo ""
    echo -e "${CYAN}Opciones:${NC}"
    echo -e "  (sin argumentos)  Monitoreo simple una vez"
    echo -e "  --live            Monitoreo continuo (cada 5 segundos)"
    echo -e "  --live [segundos] Monitoreo continuo con intervalo personalizado"
    echo -e "  --logs            Mostrar logs recientes"
    echo -e "  --diagnosis       Diagnóstico rápido de problemas"
    echo -e "  --help            Mostrar esta ayuda"
    echo ""
    echo -e "${CYAN}Ejemplos:${NC}"
    echo -e "  $0                 # Monitoreo simple"
    echo -e "  $0 --live          # Monitoreo cada 5 segundos"
    echo -e "  $0 --live 10       # Monitoreo cada 10 segundos"
    echo -e "  $0 --diagnosis     # Verificar problemas"
}

# Función principal
main() {
    case "${1:-}" in
        --live)
            local interval=${2:-5}
            continuous_monitor $interval
            ;;
        --logs)
            clear_screen
            show_logs
            ;;
        --diagnosis)
            clear_screen
            quick_diagnosis
            ;;
        --help|-h)
            show_help
            ;;
        "")
            clear_screen
            echo -e "${BLUE}Monitoreo único - $(date)${NC}"
            echo ""
            check_components
            check_ports
            show_resources

            echo -e "${CYAN}Para monitoreo continuo: ${YELLOW}$0 --live${NC}"
            echo -e "${CYAN}Para más opciones: ${YELLOW}$0 --help${NC}"
            ;;
        *)
            echo -e "${RED}Opción no reconocida: $1${NC}"
            show_help
            exit 1
            ;;
    esac
}

# Manejo de Ctrl+C para modo continuo
trap 'echo -e "\n${YELLOW}Monitoreo detenido por el usuario${NC}"; exit 0' INT TERM

# Ejecutar función principal
main "$@"