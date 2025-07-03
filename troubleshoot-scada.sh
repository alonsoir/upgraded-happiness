#!/bin/bash

# =============================================================================
# TROUBLESHOOT SCADA Platform (NUEVO v2.0)
# =============================================================================
# Script completo de diagnóstico basado en lecciones aprendidas
# Incluye todas las verificaciones que hemos desarrollado
# =============================================================================

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🔧 SCADA PLATFORM TROUBLESHOOT                           ║"
    echo "║                          Diagnóstico Completo v2.0                          ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Función de logging
log() { echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✅ SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[❌ ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[⚠️ WARNING]${NC} $1"; }

# 1. Verificar entorno básico
check_environment() {
    log "🔍 Verificando entorno básico..."
    echo "=================================="

    # Directorio correcto
    if [[ -f "Makefile" && -f "requirements.txt" ]]; then
        success "Directorio del proyecto correcto"
    else
        error "No estás en el directorio correcto del proyecto"
        echo "  💡 Navega al directorio raíz de upgraded-happiness"
        return 1
    fi

    # Python y virtual environment
    if [[ -d "upgraded_happiness_venv" ]]; then
        success "Virtual environment encontrado"

        # Verificar activación del venv
        if [[ "$VIRTUAL_ENV" == *"upgraded_happiness_venv"* ]]; then
            success "Virtual environment activo"
        else
            warning "Virtual environment no activo"
            echo "  💡 Ejecuta: source upgraded_happiness_venv/bin/activate"
        fi
    else
        warning "Virtual environment no encontrado"
        echo "  💡 Ejecuta: make setup"
    fi

    # Permisos sudo
    if sudo -n true 2>/dev/null; then
        success "Permisos sudo configurados"
    else
        warning "Permisos sudo no configurados"
        echo "  💡 Ejecuta: ./fix-sudo-permissions.sh"
    fi

    # Verificar archivos clave
    local key_files=("promiscuous_agent.py" "lightweight_ml_detector.py" "scripts/smart_broker.py")
    for file in "${key_files[@]}"; do
        if [[ -f "$file" ]]; then
            success "Archivo encontrado: $file"
        else
            warning "Archivo faltante: $file"
        fi
    done

    echo ""
}

# 2. Verificar procesos en detalle
check_processes() {
    log "🔍 Verificando procesos SCADA..."
    echo "=================================="

    local processes_found=false
    local broker_pid=""
    local ml_pid=""
    local agent_pid=""

    # Buscar procesos específicos
    if broker_pid=$(pgrep -f "smart_broker" 2>/dev/null); then
        success "ZeroMQ Broker encontrado (PID: $broker_pid)"
        processes_found=true

        # Mostrar detalles del proceso
        ps aux | grep -E "smart_broker" | grep -v grep | while read line; do
            echo "  📊 $line"
        done
    else
        error "ZeroMQ Broker NO encontrado"
    fi

    if ml_pid=$(pgrep -f "lightweight_ml_detector" 2>/dev/null); then
        success "ML Detector encontrado (PID: $ml_pid)"
        processes_found=true

        # Mostrar detalles del proceso
        ps aux | grep -E "lightweight_ml_detector" | grep -v grep | while read line; do
            echo "  📊 $line"
        done
    else
        error "ML Detector NO encontrado"
    fi

    if agent_pid=$(pgrep -f "promiscuous_agent" 2>/dev/null); then
        success "Promiscuous Agent encontrado (PID: $agent_pid)"
        processes_found=true

        # Mostrar detalles del proceso
        ps aux | grep -E "promiscuous_agent" | grep -v grep | while read line; do
            echo "  📊 $line"
        done
    else
        error "Promiscuous Agent NO encontrado"
    fi

    if $processes_found; then
        echo ""
        log "📊 Resumen de recursos utilizados:"

        # Calcular memoria total
        local total_memory=0
        for pid in $broker_pid $ml_pid $agent_pid; do
            if [[ -n "$pid" ]]; then
                memory=$(ps -p $pid -o rss= 2>/dev/null | tr -d ' ')
                if [[ -n "$memory" ]]; then
                    total_memory=$((total_memory + memory))
                fi
            fi
        done

        if [[ $total_memory -gt 0 ]]; then
            echo "  💾 Memoria total SCADA: ${total_memory}KB (~$((total_memory/1024))MB)"
        fi
    else
        warning "No se encontraron procesos SCADA activos"
        echo "  💡 Ejecuta: ./quick-start.sh o ./start-scada-platform.sh"
    fi

    echo ""
}

# 3. Verificar conectividad ZeroMQ
check_zeromq() {
    log "🔍 Verificando conectividad ZeroMQ..."
    echo "=================================="

    # Verificar dependencias Python
    if python3 -c "import zmq" 2>/dev/null; then
        success "PyZMQ disponible"

        # Mostrar versión
        zmq_version=$(python3 -c "import zmq; print(zmq.zmq_version())" 2>/dev/null)
        echo "  📋 Versión ZeroMQ: $zmq_version"
    else
        error "PyZMQ no disponible"
        echo "  💡 Ejecuta: make fix-deps"
        return 1
    fi

    # Verificar puertos con conectividad real
    local ports_working=0
    for port in 5555 5556; do
        echo -n "  🔌 Puerto $port: "
        if timeout 5 python3 -c "
import zmq
import sys
try:
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REQ)
    sock.setsockopt(zmq.LINGER, 0)
    sock.connect('tcp://localhost:$port')
    sock.close()
    ctx.term()
    print('${GREEN}✅ RESPONDE${NC}')
    sys.exit(0)
except Exception as e:
    print('${RED}❌ NO RESPONDE${NC} (' + str(e)[:20] + ')')
    sys.exit(1)
" 2>/dev/null; then
            ((ports_working++))
        else
            echo -e "${YELLOW}⚠️ NO RESPONDE (puede ser normal durante inicialización)${NC}"
        fi
    done

    if [[ $ports_working -gt 0 ]]; then
        success "$ports_working/2 puertos ZeroMQ respondiendo"
    else
        warning "Ningún puerto ZeroMQ responde"
        echo "  💡 El broker puede estar inicializándose o no estar ejecutándose"
    fi

    echo ""
}

# 4. Verificar captura de red
check_network_capture() {
    log "🔍 Verificando capacidad de captura de red..."
    echo "=================================="

    # Verificar Scapy
    if python3 -c "from scapy.all import *" 2>/dev/null; then
        success "Scapy disponible"

        # Mostrar versión
        scapy_version=$(python3 -c "from scapy.all import __version__; print(__version__)" 2>/dev/null)
        echo "  📋 Versión Scapy: $scapy_version"
    else
        error "Scapy no disponible"
        echo "  💡 Ejecuta: make fix-deps"
        return 1
    fi

    # Verificar interfaces de red
    echo "🌐 Interfaces de red disponibles:"
    if command -v ip &> /dev/null; then
        interfaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | head -5)
    else
        interfaces=$(ifconfig -a 2>/dev/null | grep "^[a-z]" | awk '{print $1}' | head -5)
    fi

    if [[ -n "$interfaces" ]]; then
        echo "$interfaces" | while read interface; do
            echo "  • $interface"
        done
    else
        warning "No se pudieron detectar interfaces de red"
    fi

    # Verificar permisos para captura promiscua
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if ls /dev/bpf* &>/dev/null; then
            bpf_count=$(ls /dev/bpf* 2>/dev/null | wc -l)
            success "Dispositivos BPF disponibles ($bpf_count)"
        else
            warning "Dispositivos BPF no detectados"
            echo "  💡 Puede necesitar permisos de administrador"
        fi
    else
        # Linux
        if [[ -r /proc/net/dev ]]; then
            success "Acceso a información de red disponible"
        else
            warning "Acceso limitado a información de red"
        fi
    fi

    echo ""
}

# 5. Verificar dependencias ML
check_ml_dependencies() {
    log "🔍 Verificando dependencias de Machine Learning..."
    echo "=================================="

    local ml_libs=("numpy" "pandas" "scikit-learn" "xgboost" "lightgbm")
    local all_ok=true
    local versions=()

    for lib in "${ml_libs[@]}"; do
        if python3 -c "import $lib" 2>/dev/null; then
            success "$lib disponible"

            # Obtener versión
            version=$(python3 -c "import $lib; print($lib.__version__)" 2>/dev/null)
            if [[ -n "$version" ]]; then
                echo "  📋 Versión: $version"
            fi
        else
            error "$lib NO disponible"
            all_ok=false
        fi
    done

    if $all_ok; then
        # Probar entrenamiento básico
        echo "🧠 Probando funcionalidad ML básica..."
        if python3 -c "
from sklearn.ensemble import IsolationForest
import numpy as np
data = np.random.randn(100, 5)
model = IsolationForest()
model.fit(data)
predictions = model.predict(data)
print(f'Entrenamiento exitoso: {len(predictions)} predicciones generadas')
" 2>/dev/null; then
            success "Entrenamiento ML funcional"
        else
            warning "Problemas con entrenamiento ML"
            echo "  💡 Puede ser un problema de dependencias conflictivas"
        fi
    else
        echo "  💡 Ejecuta: make fix-deps para reinstalar dependencias ML"
    fi

    echo ""
}

# 6. Verificar rendimiento del sistema
check_system_performance() {
    log "🔍 Verificando rendimiento del sistema..."
    echo "=================================="

    # CPU
    if command -v top &> /dev/null; then
        cpu_usage=$(top -l 1 -s 0 | grep "CPU usage" | awk '{print $3}' | cut -d'%' -f1 2>/dev/null)
        if [[ -n "$cpu_usage" ]]; then
            echo "  💻 CPU Usage: $cpu_usage%"
            if (( $(echo "$cpu_usage > 80" | bc -l 2>/dev/null || echo 0) )); then
                warning "CPU usage alto"
            else
                success "CPU usage normal"
            fi
        fi
    fi

    # Memoria
    if command -v free &> /dev/null; then
        memory_info=$(free -h | awk '/^Mem:/ {print $3"/"$2}')
        echo "  💾 Memoria: $memory_info"
    elif [[ "$(uname)" == "Darwin" ]]; then
        memory_pressure=$(memory_pressure 2>/dev/null | grep "System-wide memory free percentage" | awk '{print $NF}' || echo "N/A")
        echo "  💾 Memoria libre: $memory_pressure"
    fi

    # Espacio en disco
    disk_usage=$(df -h . | awk 'NR==2 {print $4}')
    echo "  💽 Espacio disponible: $disk_usage"

    # Verificar si hay procesos usando mucha memoria
    echo "🔍 Top procesos SCADA por memoria:"
    ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep | sort -k4 -nr | head -3 | while read line; do
        echo "  📊 $line"
    done

    echo ""
}

# 7. Generar reporte de diagnóstico
generate_report() {
    log "📋 Generando reporte de diagnóstico..."
    echo "=================================="

    # Conteo de componentes
    local broker_count=$(pgrep -f "smart_broker" | wc -l)
    local ml_count=$(pgrep -f "lightweight_ml" | wc -l)
    local agent_count=$(pgrep -f "promiscuous" | wc -l)
    local total_count=$((broker_count + ml_count + agent_count))

    echo -e "${CYAN}📊 RESUMEN DEL DIAGNÓSTICO:${NC}"
    echo "  • ZeroMQ Broker:      $([ $broker_count -gt 0 ] && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
    echo "  • ML Detector:        $([ $ml_count -gt 0 ] && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
    echo "  • Promiscuous Agent:  $([ $agent_count -gt 0 ] && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
    echo ""
    echo -e "${CYAN}📈 Estado general: ${GREEN}$total_count/3${NC} componentes activos"

    # Verificación adicional de conectividad
    local zmq_working=false
    if timeout 3 python3 -c "import zmq; ctx=zmq.Context(); sock=ctx.socket(zmq.REQ); sock.connect('tcp://localhost:5555'); sock.close(); ctx.term()" 2>/dev/null; then
        zmq_working=true
    fi

    echo -e "  • ZeroMQ Conectividad: $([ $zmq_working == true ] && echo "${GREEN}✅ FUNCIONAL${NC}" || echo "${RED}❌ NO FUNCIONAL${NC}")"

    # Clasificación del estado
    if [ $total_count -eq 3 ] && [ $zmq_working == true ]; then
        echo -e "\n${GREEN}🎉 DIAGNÓSTICO: PLATAFORMA COMPLETAMENTE OPERATIVA${NC}"
        platform_status="EXCELENTE"
    elif [ $total_count -eq 3 ]; then
        echo -e "\n${YELLOW}⚠️ DIAGNÓSTICO: PLATAFORMA OPERATIVA CON ADVERTENCIAS${NC}"
        platform_status="BUENO"
    elif [ $total_count -eq 2 ]; then
        echo -e "\n${YELLOW}⚠️ DIAGNÓSTICO: PLATAFORMA PARCIALMENTE OPERATIVA${NC}"
        platform_status="PARCIAL"
    elif [ $total_count -eq 1 ]; then
        echo -e "\n${RED}❌ DIAGNÓSTICO: PLATAFORMA CON PROBLEMAS SIGNIFICATIVOS${NC}"
        platform_status="PROBLEMA"
    else
        echo -e "\n${RED}🚨 DIAGNÓSTICO: PLATAFORMA NO OPERATIVA${NC}"
        platform_status="CRÍTICO"
    fi

    echo ""
    return 0
}

# 8. Sugerir acciones de reparación
suggest_fixes() {
    log "🛠️ Acciones de reparación sugeridas..."
    echo "=================================="

    # Obtener estado actual
    local broker_count=$(pgrep -f "smart_broker" | wc -l)
    local ml_count=$(pgrep -f "lightweight_ml" | wc -l)
    local agent_count=$(pgrep -f "promiscuous" | wc -l)
    local total_count=$((broker_count + ml_count + agent_count))

    echo -e "${CYAN}🔧 RECOMENDACIONES BASADAS EN EL DIAGNÓSTICO:${NC}"
    echo ""

    if [ $total_count -eq 0 ]; then
        echo -e "${RED}🚨 CRÍTICO: Ningún componente activo${NC}"
        echo "     ➡️  1. Ejecuta: ./start-scada-platform.sh"
        echo "     ➡️  2. Si falla, ejecuta: make clean && make setup-production"

    elif [ $total_count -eq 1 ]; then
        echo -e "${RED}⚠️  PROBLEMA: Solo un componente activo${NC}"
        echo "     ➡️  1. Ejecuta: make stop && ./start-scada-platform.sh"
        echo "     ➡️  2. Verifica dependencias: make verify"

    elif [ $total_count -eq 2 ]; then
        echo -e "${YELLOW}⚠️  PARCIAL: Dos componentes activos${NC}"
        if [ $agent_count -eq 0 ]; then
            echo "     ➡️  Falta agente promiscuo: ./fix-sudo-permissions.sh"
        elif [ $broker_count -eq 0 ]; then
            echo "     ➡️  Falta broker: make run-broker"
        elif [ $ml_count -eq 0 ]; then
            echo "     ➡️  Falta ML detector: make run-detector"
        fi
        echo "     ➡️  Alternativa: make stop && ./quick-start.sh"

    else
        echo -e "${GREEN}🎉 EXCELENTE: Todos los componentes activos${NC}"
        echo "     ➡️  Verifica funcionamiento: ./monitor-platform.sh --live"
        echo "     ➡️  Prueba detección: make test-traffic"
    fi

    echo ""
    echo -e "${BLUE}🔧 COMANDOS DE REPARACIÓN COMUNES:${NC}"
    echo ""
    echo "  ${YELLOW}📋 Diagnóstico:${NC}"
    echo "     ./troubleshoot-scada.sh      # Este script"
    echo "     ./check-ports.sh             # Verificar conectividad"
    echo ""
    echo "  ${YELLOW}🚀 Inicio/Reinicio:${NC}"
    echo "     ./quick-start.sh             # Inicio rápido"
    echo "     ./start-scada-platform.sh    # Setup completo"
    echo "     make stop                    # Parar todo"
    echo ""
    echo "  ${YELLOW}🔧 Reparación:${NC}"
    echo "     make fix-deps                # Arreglar dependencias"
    echo "     ./fix-sudo-permissions.sh    # Arreglar permisos sudo"
    echo "     make clean && make setup     # Reset completo"
    echo ""
    echo "  ${YELLOW}📊 Monitoreo:${NC}"
    echo "     ./monitor-platform.sh --live # Monitor en tiempo real"
    echo "     make test-traffic            # Probar funcionalidad"
    echo ""

    echo -e "${GREEN}🎯 VERIFICACIÓN POST-REPARACIÓN:${NC}"
    echo "  1. ./troubleshoot-scada.sh     # Ejecutar este diagnóstico otra vez"
    echo "  2. ./check-ports.sh            # Verificar conectividad específica"
    echo "  3. make test-traffic           # Probar detección de tráfico"
    echo ""
}

# Función principal
main() {
    print_banner

    log "Iniciando diagnóstico completo de la plataforma SCADA..."
    echo ""

    # Ejecutar todas las verificaciones
    check_environment
    check_processes
    check_zeromq
    check_network_capture
    check_ml_dependencies
    check_system_performance
    generate_report
    suggest_fixes

    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        DIAGNÓSTICO COMPLETADO                               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    log "Diagnóstico completo finalizado"
}

# Manejar argumentos de línea de comandos
case "${1:-}" in
    --help|-h)
        echo "Uso: $0 [opción]"
        echo ""
        echo "Opciones:"
        echo "  --help, -h     Mostrar esta ayuda"
        echo "  --environment  Solo verificar entorno"
        echo "  --processes    Solo verificar procesos"
        echo "  --network      Solo verificar red"
        echo "  --ml           Solo verificar ML"
        echo "  --quick        Diagnóstico rápido"
        echo ""
        exit 0
        ;;
    --environment)
        print_banner
        check_environment
        ;;
    --processes)
        print_banner
        check_processes
        ;;
    --network)
        print_banner
        check_network_capture
        ;;
    --ml)
        print_banner
        check_ml_dependencies
        ;;
    --quick)
        print_banner
        check_processes
        generate_report
        ;;
    *)
        # Ejecutar función principal completa
        main "$@"
        ;;
esac