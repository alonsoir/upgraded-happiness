#!/bin/bash
# platform_cleanup.sh - Cleanup automático para Upgraded Happiness
# ===============================================================
# Detecta y resuelve conflictos automáticamente antes del arranque

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
PORTS_TO_CHECK=(5555 8766)
PLATFORM_PROCESSES=("smart_broker" "lightweight_ml_detector" "promiscuous_agent" "dashboard_server")

echo -e "${CYAN}🧹 UPGRADED HAPPINESS - CLEANUP AUTOMÁTICO${NC}"
echo -e "${CYAN}===========================================${NC}"

# Función para detectar procesos conflictivos
detect_conflicts() {
    echo -e "${BLUE}🔍 Detectando conflictos...${NC}"

    local conflicts_found=false
    local zombie_pids=()

    # Detectar procesos de la plataforma corriendo
    for process in "${PLATFORM_PROCESSES[@]}"; do
        local pids=$(pgrep -f "$process" 2>/dev/null)
        if [ ! -z "$pids" ]; then
            echo -e "${YELLOW}⚠️  Proceso detectado: $process (PIDs: $pids)${NC}"
            zombie_pids+=($pids)
            conflicts_found=true
        fi
    done

    # Detectar puertos ocupados
    for port in "${PORTS_TO_CHECK[@]}"; do
        local port_check=$(lsof -ti :$port 2>/dev/null)
        if [ ! -z "$port_check" ]; then
            echo -e "${YELLOW}⚠️  Puerto $port ocupado por PID: $port_check${NC}"
            zombie_pids+=($port_check)
            conflicts_found=true
        fi
    done

    if [ "$conflicts_found" = true ]; then
        echo -e "${RED}❌ Conflictos detectados${NC}"
        return 0
    else
        echo -e "${GREEN}✅ No hay conflictos${NC}"
        return 1
    fi
}

# Función para limpiar procesos
cleanup_processes() {
    echo -e "${BLUE}🛑 Limpiando procesos conflictivos...${NC}"

    # Método 1: Terminar gracefully los procesos de la plataforma
    for process in "${PLATFORM_PROCESSES[@]}"; do
        local pids=$(pgrep -f "$process" 2>/dev/null)
        if [ ! -z "$pids" ]; then
            echo -e "${PURPLE}🔄 Terminando $process (PIDs: $pids)${NC}"
            for pid in $pids; do
                kill $pid 2>/dev/null || true
            done
        fi
    done

    # Esperar a que terminen gracefully
    sleep 2

    # Método 2: Force kill si siguen corriendo
    for process in "${PLATFORM_PROCESSES[@]}"; do
        local pids=$(pgrep -f "$process" 2>/dev/null)
        if [ ! -z "$pids" ]; then
            echo -e "${RED}⚡ Force killing $process (PIDs: $pids)${NC}"
            for pid in $pids; do
                kill -9 $pid 2>/dev/null || true
            done
        fi
    done

    # Método 3: Limpiar puertos específicos si siguen ocupados
    for port in "${PORTS_TO_CHECK[@]}"; do
        local port_pids=$(lsof -ti :$port 2>/dev/null)
        if [ ! -z "$port_pids" ]; then
            echo -e "${RED}⚡ Liberando puerto $port (PIDs: $port_pids)${NC}"
            for pid in $port_pids; do
                kill -9 $pid 2>/dev/null || true
            done
        fi
    done

    # Cleanup adicional - procesos huérfanos
    sudo pkill -f "promiscuous_agent" 2>/dev/null || true

    sleep 1
}

# Función para verificar limpieza
verify_cleanup() {
    echo -e "${BLUE}🔍 Verificando limpieza...${NC}"

    local still_conflicts=false

    # Verificar procesos
    for process in "${PLATFORM_PROCESSES[@]}"; do
        local pids=$(pgrep -f "$process" 2>/dev/null)
        if [ ! -z "$pids" ]; then
            echo -e "${RED}❌ $process aún corriendo (PIDs: $pids)${NC}"
            still_conflicts=true
        fi
    done

    # Verificar puertos
    for port in "${PORTS_TO_CHECK[@]}"; do
        local port_check=$(lsof -ti :$port 2>/dev/null)
        if [ ! -z "$port_check" ]; then
            echo -e "${RED}❌ Puerto $port aún ocupado (PID: $port_check)${NC}"
            still_conflicts=true
        fi
    done

    if [ "$still_conflicts" = true ]; then
        echo -e "${RED}❌ Limpieza incompleta - intervención manual requerida${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Limpieza completada exitosamente${NC}"
        return 0
    fi
}

# Función para cleanup completo de archivos temporales
cleanup_temp_files() {
    echo -e "${BLUE}🗂️  Limpiando archivos temporales...${NC}"

    # Limpiar archivos Python cache
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    find . -name "*.pyo" -delete 2>/dev/null || true

    # Limpiar logs antiguos si existen
    if [ -d "logs" ]; then
        find logs -name "*.log" -mtime +7 -delete 2>/dev/null || true
    fi

    # Limpiar sockets ZeroMQ si existen
    rm -f /tmp/zmq-* 2>/dev/null || true

    echo -e "${GREEN}✅ Archivos temporales limpiados${NC}"
}

# Función para mostrar reporte del sistema
system_report() {
    echo -e "${CYAN}📊 REPORTE DEL SISTEMA${NC}"
    echo -e "${CYAN}======================${NC}"

    # Memoria disponible
    if command -v free >/dev/null 2>&1; then
        echo -e "${YELLOW}💾 Memoria:${NC}"
        free -h | head -2
    elif command -v vm_stat >/dev/null 2>&1; then
        echo -e "${YELLOW}💾 Memoria (macOS):${NC}"
        vm_stat | head -5
    fi

    # Puertos críticos
    echo -e "${YELLOW}🔌 Estado de puertos críticos:${NC}"
    for port in "${PORTS_TO_CHECK[@]}"; do
        if lsof -ti :$port >/dev/null 2>&1; then
            echo -e "  Puerto $port: ${RED}OCUPADO${NC}"
        else
            echo -e "  Puerto $port: ${GREEN}LIBRE${NC}"
        fi
    done

    # Procesos de la plataforma
    echo -e "${YELLOW}🏃 Procesos de la plataforma:${NC}"
    for process in "${PLATFORM_PROCESSES[@]}"; do
        local count=$(pgrep -f "$process" 2>/dev/null | wc -l)
        if [ $count -gt 0 ]; then
            echo -e "  $process: ${RED}$count procesos${NC}"
        else
            echo -e "  $process: ${GREEN}DETENIDO${NC}"
        fi
    done
}

# Función principal
main() {
    local mode="${1:-auto}"

    case "$mode" in
        "check")
            system_report
            detect_conflicts
            ;;
        "force")
            echo -e "${RED}🔥 MODO FORCE - Limpieza agresiva${NC}"
            cleanup_processes
            cleanup_temp_files
            verify_cleanup
            ;;
        "report")
            system_report
            ;;
        "auto"|*)
            # Modo automático - el más común
            if detect_conflicts; then
                cleanup_processes
                cleanup_temp_files
                if verify_cleanup; then
                    echo -e "${GREEN}🎉 Sistema listo para iniciar${NC}"
                    exit 0
                else
                    echo -e "${RED}💥 Cleanup falló - usa 'make cleanup-force'${NC}"
                    exit 1
                fi
            else
                echo -e "${GREEN}🎉 Sistema ya está limpio${NC}"
                cleanup_temp_files
                exit 0
            fi
            ;;
    esac
}

# Manejar Ctrl+C
trap 'echo -e "\n${YELLOW}⚠️  Cleanup interrumpido${NC}"; exit 1' INT

# Ejecutar función principal
main "$@"