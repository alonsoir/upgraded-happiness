#!/bin/bash
# cleanup_test.sh - Script básico para probar cleanup automático
# ===========================================================
# Versión de prueba antes de integrar al Makefile

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🧪 CLEANUP TEST - Upgraded Happiness${NC}"
echo -e "${CYAN}===================================${NC}"

# Función para mostrar estado ANTES
show_before_state() {
    echo -e "${BLUE}📊 ESTADO ANTES DEL CLEANUP:${NC}"
    echo -e "${YELLOW}Procesos de la plataforma:${NC}"

    # Mostrar procesos específicos
    echo "  Dashboard servers:"
    ps aux | grep "dashboard_server" | grep -v grep || echo "    (ninguno)"

    echo "  ML Detectors:"
    ps aux | grep "lightweight_ml_detector" | grep -v grep || echo "    (ninguno)"

    echo "  Brokers:"
    ps aux | grep "smart_broker" | grep -v grep || echo "    (ninguno)"

    echo "  Promiscuous Agents:"
    ps aux | grep "promiscuous_agent" | grep -v grep || echo "    (ninguno)"

    echo -e "${YELLOW}Puertos críticos:${NC}"
    echo "  Puerto 5555:"
    lsof -i :5555 2>/dev/null || echo "    LIBRE"
    echo "  Puerto 8766:"
    lsof -i :8766 2>/dev/null || echo "    LIBRE"

    echo ""
}

# Función para mostrar estado DESPUÉS
show_after_state() {
    echo -e "${BLUE}📊 ESTADO DESPUÉS DEL CLEANUP:${NC}"
    echo -e "${YELLOW}Procesos de la plataforma:${NC}"

    # Verificar que no haya procesos residuales
    local dashboard_count=$(ps aux | grep "dashboard_server" | grep -v grep | wc -l)
    local detector_count=$(ps aux | grep "lightweight_ml_detector" | grep -v grep | wc -l)
    local broker_count=$(ps aux | grep "smart_broker" | grep -v grep | wc -l)
    local agent_count=$(ps aux | grep "promiscuous_agent" | grep -v grep | wc -l)

    echo "  Dashboard servers: $dashboard_count"
    echo "  ML Detectors: $detector_count"
    echo "  Brokers: $broker_count"
    echo "  Promiscuous Agents: $agent_count"

    echo -e "${YELLOW}Puertos críticos:${NC}"
    local port_5555_status=$(lsof -i :5555 2>/dev/null && echo "OCUPADO" || echo "LIBRE")
    local port_8766_status=$(lsof -i :8766 2>/dev/null && echo "OCUPADO" || echo "LIBRE")

    echo "  Puerto 5555: $port_5555_status"
    echo "  Puerto 8766: $port_8766_status"

    echo ""
}

# Función de cleanup paso a paso
cleanup_step_by_step() {
    echo -e "${BLUE}🔧 INICIANDO CLEANUP PASO A PASO:${NC}"

    # Paso 1: Terminar gracefully los dashboard servers
    echo -e "${YELLOW}Paso 1: Terminando dashboard servers...${NC}"
    local dashboard_pids=$(pgrep -f "dashboard_server" 2>/dev/null)
    if [ ! -z "$dashboard_pids" ]; then
        echo "  Encontrados PIDs: $dashboard_pids"
        for pid in $dashboard_pids; do
            echo "  Terminando PID $pid..."
            kill $pid 2>/dev/null
        done
        sleep 2
    else
        echo "  No hay dashboard servers corriendo"
    fi

    # Paso 2: Verificar puertos específicos
    echo -e "${YELLOW}Paso 2: Verificando puertos...${NC}"
    local port_8766_pid=$(lsof -ti :8766 2>/dev/null)
    if [ ! -z "$port_8766_pid" ]; then
        echo "  Puerto 8766 ocupado por PID: $port_8766_pid"
        echo "  Terminando proceso..."
        kill -9 $port_8766_pid 2>/dev/null
        sleep 1
    else
        echo "  Puerto 8766 libre"
    fi

    # Paso 3: Cleanup de otros procesos si es necesario
    echo -e "${YELLOW}Paso 3: Verificando otros procesos...${NC}"

    # Solo mostrar, no terminar otros procesos por ahora
    local detector_pids=$(pgrep -f "lightweight_ml_detector" 2>/dev/null)
    local broker_pids=$(pgrep -f "smart_broker" 2>/dev/null)
    local agent_pids=$(pgrep -f "promiscuous_agent" 2>/dev/null)

    if [ ! -z "$detector_pids" ]; then
        echo "  ML Detectors encontrados (PIDs: $detector_pids) - MANTENIENDO"
    fi

    if [ ! -z "$broker_pids" ]; then
        echo "  Brokers encontrados (PIDs: $broker_pids) - MANTENIENDO"
    fi

    if [ ! -z "$agent_pids" ]; then
        echo "  Agents encontrados (PIDs: $agent_pids) - MANTENIENDO"
    fi

    echo -e "${GREEN}✅ Cleanup completado${NC}"
}

# Función para verificar efectividad
verify_cleanup() {
    echo -e "${BLUE}🔍 VERIFICANDO EFECTIVIDAD:${NC}"

    # Verificar que el puerto 8766 esté libre
    if lsof -i :8766 >/dev/null 2>&1; then
        echo -e "${RED}❌ Puerto 8766 AÚN OCUPADO${NC}"
        echo "Proceso ocupando puerto:"
        lsof -i :8766
        return 1
    else
        echo -e "${GREEN}✅ Puerto 8766 LIBRE${NC}"
    fi

    # Verificar dashboard servers
    local dashboard_count=$(ps aux | grep "dashboard_server" | grep -v grep | wc -l)
    if [ $dashboard_count -eq 0 ]; then
        echo -e "${GREEN}✅ No hay dashboard servers residuales${NC}"
    else
        echo -e "${RED}❌ Aún hay $dashboard_count dashboard servers corriendo${NC}"
        return 1
    fi

    return 0
}

# Función principal
main() {
    local mode="${1:-test}"

    case "$mode" in
        "test")
            show_before_state
            cleanup_step_by_step
            show_after_state
            if verify_cleanup; then
                echo -e "${GREEN}🎉 CLEANUP EXITOSO - Listo para arrancar dashboard${NC}"
                echo ""
                echo -e "${CYAN}Puedes ejecutar ahora:${NC}"
                echo "  python dashboard_server_with_real_data.py"
                echo "  # o"
                echo "  make run-dashboard"
            else
                echo -e "${RED}💥 CLEANUP FALLÓ - Se requiere intervención manual${NC}"
            fi
            ;;
        "check-only")
            show_before_state
            ;;
        "verify-only")
            verify_cleanup
            ;;
        *)
            echo "Uso: $0 [test|check-only|verify-only]"
            echo "  test        - Ejecuta cleanup completo"
            echo "  check-only  - Solo muestra estado actual"
            echo "  verify-only - Solo verifica si está limpio"
            ;;
    esac
}

main "$@"