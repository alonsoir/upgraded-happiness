#!/bin/bash

# run_gis_dashboard.sh
# Script para ejecutar el dashboard GIS robusto

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_SCRIPT="dashboard_server_gis.py"
LOG_FILE="dashboard_gis.log"
PID_FILE="dashboard_gis.pid"

# Functions
print_banner() {
    echo -e "${CYAN}"
    echo "════════════════════════════════════════════════════════════════"
    echo "    🗺️  SCADA Security Monitor - GIS Dashboard Runner"
    echo "    🔧  Modo Robusto con Manejo Inteligente de Puertos"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

check_dependencies() {
    echo -e "${BLUE}🔍 Verificando dependencias...${NC}"

    # Check Python
    if ! command -v python &> /dev/null; then
        echo -e "${RED}❌ Python no encontrado${NC}"
        exit 1
    fi

    # Check virtual environment
    if [[ -z "$VIRTUAL_ENV" ]]; then
        echo -e "${YELLOW}⚠️ No se detectó entorno virtual${NC}"
        if [[ -d "upgraded_happiness_venv" ]]; then
            echo -e "${BLUE}🔄 Activando entorno virtual...${NC}"
            source upgraded_happiness_venv/bin/activate
        else
            echo -e "${RED}❌ Entorno virtual 'upgraded_happiness_venv' no encontrado${NC}"
            echo -e "${YELLOW}💡 Ejecuta: make setup${NC}"
            exit 1
        fi
    fi

    # Check dashboard script
    if [[ ! -f "$DASHBOARD_SCRIPT" ]]; then
        echo -e "${RED}❌ Script $DASHBOARD_SCRIPT no encontrado${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Dependencias verificadas${NC}"
}

cleanup_processes() {
    echo -e "${BLUE}🧹 Limpiando procesos previos...${NC}"

    # Kill previous dashboard processes
    pkill -f "dashboard.*gis" 2>/dev/null || true
    pkill -f "gis.*dashboard" 2>/dev/null || true

    # Clean PID file
    if [[ -f "$PID_FILE" ]]; then
        rm -f "$PID_FILE"
    fi

    # Clean ports (common GIS dashboard ports)
    for port in 8766 8767 8768 8769 8770; do
        if command -v lsof &> /dev/null; then
            lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
        fi
    done

    sleep 2
    echo -e "${GREEN}✅ Limpieza completada${NC}"
}

check_port_availability() {
    echo -e "${BLUE}🔍 Verificando puertos disponibles...${NC}"

    available_ports=()
    for port in {8767..8776}; do
        if ! nc -z localhost $port 2>/dev/null; then
            available_ports+=($port)
        fi
    done

    if [[ ${#available_ports[@]} -gt 0 ]]; then
        echo -e "${GREEN}✅ Puertos disponibles: ${available_ports[*]}${NC}"
    else
        echo -e "${YELLOW}⚠️ Pocos puertos disponibles, pero el dashboard buscará automáticamente${NC}"
    fi
}

start_dashboard() {
    echo -e "${BLUE}🚀 Iniciando dashboard GIS robusto...${NC}"

    # Start dashboard in background
    python "$DASHBOARD_SCRIPT" > "$LOG_FILE" 2>&1 &
    local pid=$!

    # Save PID
    echo $pid > "$PID_FILE"

    echo -e "${GREEN}✅ Dashboard iniciado con PID: $pid${NC}"
    echo -e "${BLUE}📋 Log file: $LOG_FILE${NC}"

    # Wait a moment and check if it's running
    sleep 3

    if kill -0 $pid 2>/dev/null; then
        echo -e "${GREEN}✅ Dashboard corriendo correctamente${NC}"

        # Try to detect the port from logs
        sleep 2
        local port=$(grep -o "http://.*:[0-9]*" "$LOG_FILE" 2>/dev/null | head -1 | grep -o "[0-9]*$" || echo "unknown")

        if [[ "$port" != "unknown" ]]; then
            echo -e "${CYAN}🌐 Dashboard URL: http://localhost:$port${NC}"
            echo -e "${PURPLE}🗺️ Mapa GIS: http://localhost:$port${NC}"
            echo -e "${PURPLE}📊 Status API: http://localhost:$port/api/status${NC}"
            echo -e "${PURPLE}❤️ Health Check: http://localhost:$port/health${NC}"
        fi

    else
        echo -e "${RED}❌ Error iniciando dashboard${NC}"
        echo -e "${YELLOW}📋 Últimas líneas del log:${NC}"
        tail -10 "$LOG_FILE" 2>/dev/null || echo "No se pudo leer el log"
        exit 1
    fi
}

monitor_dashboard() {
    echo -e "${BLUE}📊 Monitoreando dashboard...${NC}"
    echo -e "${YELLOW}Presiona Ctrl+C para detener${NC}"
    echo ""

    # Follow logs
    tail -f "$LOG_FILE" &
    local tail_pid=$!

    # Wait for interrupt
    trap 'kill $tail_pid 2>/dev/null || true; stop_dashboard' INT

    # Keep monitoring
    while true; do
        if [[ -f "$PID_FILE" ]]; then
            local pid=$(cat "$PID_FILE")
            if ! kill -0 $pid 2>/dev/null; then
                echo -e "${RED}❌ Dashboard se detuvo inesperadamente${NC}"
                kill $tail_pid 2>/dev/null || true
                break
            fi
        else
            echo -e "${RED}❌ Archivo PID no encontrado${NC}"
            kill $tail_pid 2>/dev/null || true
            break
        fi
        sleep 5
    done
}

stop_dashboard() {
    echo -e "\n${BLUE}🛑 Deteniendo dashboard...${NC}"

    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")

        # Try graceful shutdown first
        kill -TERM $pid 2>/dev/null || true
        sleep 3

        # Force kill if still running
        if kill -0 $pid 2>/dev/null; then
            echo -e "${YELLOW}⚡ Forzando cierre...${NC}"
            kill -KILL $pid 2>/dev/null || true
        fi

        rm -f "$PID_FILE"
    fi

    # Additional cleanup
    cleanup_processes

    echo -e "${GREEN}✅ Dashboard detenido${NC}"
}

show_status() {
    echo -e "${BLUE}📊 Estado del dashboard:${NC}"

    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 $pid 2>/dev/null; then
            echo -e "${GREEN}✅ Dashboard corriendo (PID: $pid)${NC}"

            # Try to get port info
            if command -v lsof &> /dev/null; then
                local port=$(lsof -p $pid 2>/dev/null | grep LISTEN | grep -o ":[0-9]*" | head -1 | cut -d: -f2)
                if [[ -n "$port" ]]; then
                    echo -e "${CYAN}🌐 Puerto: $port${NC}"
                    echo -e "${CYAN}🌐 URL: http://localhost:$port${NC}"
                fi
            fi

            # Show resource usage
            if command -v ps &> /dev/null; then
                local cpu_mem=$(ps -p $pid -o %cpu,%mem --no-headers 2>/dev/null)
                if [[ -n "$cpu_mem" ]]; then
                    echo -e "${PURPLE}📈 CPU/MEM: $cpu_mem${NC}"
                fi
            fi

        else
            echo -e "${RED}❌ Dashboard no corriendo (PID obsoleto)${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${RED}❌ Dashboard no corriendo${NC}"
    fi

    # Show recent log entries
    if [[ -f "$LOG_FILE" ]]; then
        echo -e "${BLUE}📋 Últimas líneas del log:${NC}"
        tail -5 "$LOG_FILE"
    fi
}

show_help() {
    echo -e "${YELLOW}Uso: $0 [comando]${NC}"
    echo ""
    echo -e "${CYAN}Comandos disponibles:${NC}"
    echo -e "  ${GREEN}start${NC}     - Iniciar dashboard (por defecto)"
    echo -e "  ${GREEN}stop${NC}      - Detener dashboard"
    echo -e "  ${GREEN}restart${NC}   - Reiniciar dashboard"
    echo -e "  ${GREEN}status${NC}    - Mostrar estado del dashboard"
    echo -e "  ${GREEN}logs${NC}      - Mostrar logs en tiempo real"
    echo -e "  ${GREEN}clean${NC}     - Limpiar procesos y archivos"
    echo -e "  ${GREEN}help${NC}      - Mostrar esta ayuda"
    echo ""
    echo -e "${CYAN}Ejemplos:${NC}"
    echo -e "  $0              # Iniciar dashboard"
    echo -e "  $0 start        # Iniciar dashboard"
    echo -e "  $0 stop         # Detener dashboard"
    echo -e "  $0 restart      # Reiniciar dashboard"
    echo -e "  $0 status       # Ver estado"
}

# Main script logic
main() {
    print_banner

    local command=${1:-start}

    case $command in
        "start")
            check_dependencies
            cleanup_processes
            check_port_availability
            start_dashboard
            monitor_dashboard
            ;;
        "stop")
            stop_dashboard
            ;;
        "restart")
            stop_dashboard
            sleep 2
            check_dependencies
            cleanup_processes
            check_port_availability
            start_dashboard
            monitor_dashboard
            ;;
        "status")
            show_status
            ;;
        "logs")
            if [[ -f "$LOG_FILE" ]]; then
                echo -e "${BLUE}📋 Siguiendo logs (Ctrl+C para salir):${NC}"
                tail -f "$LOG_FILE"
            else
                echo -e "${RED}❌ No se encontró archivo de log${NC}"
            fi
            ;;
        "clean")
            cleanup_processes
            rm -f "$LOG_FILE" "$PID_FILE"
            echo -e "${GREEN}✅ Limpieza completa${NC}"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            echo -e "${RED}❌ Comando desconocido: $command${NC}"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"