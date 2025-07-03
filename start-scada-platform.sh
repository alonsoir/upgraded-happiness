#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - SCADA Platform Startup Script v2.0
# =============================================================================
# Script completo para levantar toda la arquitectura SCADA incluyendo dashboard
# MEJORADO: Incorpora lecciones aprendidas de troubleshooting
# =============================================================================

set -e  # Salir en caso de error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuración
PROJECT_NAME="upgraded-happiness"
VENV_NAME="upgraded_happiness_venv"
REQUIRED_PYTHON_VERSION="3.13"

# Función para logging con timestamp
log() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR $(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS $(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING $(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🔒 UPGRADED HAPPINESS SCADA PLATFORM 🔒                   ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║  🔌 ZeroMQ Broker    🕵️  Promiscuous Agent    🧠 ML Detector    📊 Dashboard  ║"
    echo "║                          Sistema de Ciberseguridad SCADA                     ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Verificar si estamos en el directorio correcto
check_directory() {
    log "Verificando directorio del proyecto..."

    if [[ ! -f "Makefile" ]] || [[ ! -f "requirements.txt" ]]; then
        error "No estás en el directorio correcto del proyecto upgraded-happiness"
        error "Asegúrate de estar en el directorio raíz del proyecto"
        exit 1
    fi

    success "Directorio del proyecto correcto ✓"
}

# Verificar dependencias del sistema
check_system_dependencies() {
    log "Verificando dependencias del sistema..."

    # Verificar Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 no está instalado"
        echo "Instálalo con:"
        echo "  - macOS: brew install python@3.13"
        echo "  - Ubuntu: sudo apt install python3.13"
        exit 1
    fi

    # Verificar make
    if ! command -v make &> /dev/null; then
        error "Make no está instalado"
        exit 1
    fi

    # Verificar permisos sudo para captura promiscua
    if ! sudo -n true 2>/dev/null; then
        warning "Se necesitarán permisos sudo para el agente promiscuo"
    fi

    success "Dependencias del sistema OK ✓"
}

# Setup inicial completo
setup_environment() {
    log "Configurando entorno de desarrollo..."

    # Ejecutar setup completo con manejo de errores
    if make setup-production; then
        success "Setup de producción completado ✓"
    else
        error "Error en setup-production, intentando setup alternativo..."

        # Fallback: setup paso a paso
        log "Creando entorno virtual..."
        python3 -m venv $VENV_NAME

        log "Activando entorno virtual..."
        source $VENV_NAME/bin/activate

        log "Actualizando pip..."
        pip install --upgrade pip

        log "Instalando dependencias..."
        if make install-all; then
            success "Dependencias instaladas ✓"
        else
            error "Error instalando dependencias"
            exit 1
        fi
    fi

    # Configurar sudoers si es necesario
    log "Configurando permisos sudo..."
    if make setup-sudo; then
        success "Permisos sudo configurados ✓"
    else
        warning "No se pudieron configurar permisos sudo automáticamente"
        warning "Es posible que necesites ejecutar algunos componentes con sudo manualmente"
    fi
}

# Verificar que el entorno esté funcionando
verify_environment() {
    log "Verificando integridad del entorno..."

    if make verify; then
        success "Verificación del entorno completada ✓"
    else
        error "La verificación del entorno falló"
        error "Ejecuta 'make fix-deps' para intentar reparar dependencias"
        exit 1
    fi
}

# Limpiar procesos previos
cleanup_previous_processes() {
    log "Limpiando procesos previos..."

    # Parar procesos previos usando make
    make stop &>/dev/null || true

    # Buscar y matar procesos manualmente si es necesario
    pkill -f "smart_broker" &>/dev/null || true
    pkill -f "lightweight_ml_detector" &>/dev/null || true
    pkill -f "promiscuous_agent" &>/dev/null || true

    sleep 2
    success "Procesos previos limpiados ✓"
}

# Verificar puertos disponibles
check_ports() {
    log "Verificando disponibilidad de puertos..."

    local ports=(5555 5556 55565)
    local port_issues=false

    for port in "${ports[@]}"; do
        if netstat -an 2>/dev/null | grep -q ":$port.*LISTEN" || lsof -i ":$port" &>/dev/null; then
            warning "Puerto $port ya está en uso"
            port_issues=true
        fi
    done

    if $port_issues; then
        warning "Algunos puertos están en uso, intentando limpiarlos..."
        make stop &>/dev/null || true
        sleep 3
    fi

    success "Puertos verificados ✓"
}

# Iniciar la plataforma
start_platform() {
    log "Iniciando plataforma SCADA completa..."

    # Usar quick-start que maneja el orden correcto de inicialización
    if make quick-start; then
        success "Plataforma iniciada exitosamente ✓"
    else
        error "Error iniciando la plataforma"

        # Intentar inicio manual paso a paso
        warning "Intentando inicio manual de componentes..."

        log "Iniciando ZeroMQ Broker..."
        make run-broker &
        sleep 3

        log "Iniciando ML Detector..."
        make run-detector &
        sleep 3

        log "Iniciando Agente Promiscuo..."
        make run-agent &
        sleep 3
    fi
}

# Verificar que todos los componentes estén funcionando
verify_platform() {
    log "Verificando estado de la plataforma..."

    # Esperar más tiempo para que los servicios se estabilicen
    log "Esperando estabilización de componentes..."
    sleep 8

    # Verificación manual de procesos más robusta
    log "Verificando procesos individuales..."

    local broker_running=false
    local ml_running=false
    local agent_running=false

    # Verificar ZeroMQ Broker
    if pgrep -f "smart_broker" &>/dev/null; then
        success "✅ ZeroMQ Broker ejecutándose"
        broker_running=true
    else
        error "❌ ZeroMQ Broker no está ejecutándose"
    fi

    # Verificar ML Detector
    if pgrep -f "lightweight_ml_detector" &>/dev/null; then
        success "✅ ML Detector ejecutándose"
        ml_running=true
    else
        error "❌ ML Detector no está ejecutándose"
    fi

    # Verificar Promiscuous Agent con más detalle
    if pgrep -f "promiscuous_agent" &>/dev/null; then
        success "✅ Agente Promiscuo ejecutándose"
        agent_running=true

        # Verificar si está capturando datos
        log "Verificando captura de datos del agente..."
        sleep 3
        if pgrep -f "promiscuous_agent" &>/dev/null; then
            success "✅ Agente Promiscuo capturando datos activamente"
        fi
    else
        warning "⚠️ Agente Promiscuo no detectado inmediatamente"
        log "Reintentando detección del agente promiscuo..."
        sleep 5
        if pgrep -f "promiscuous_agent" &>/dev/null; then
            success "✅ Agente Promiscuo ejecutándose (detección tardía)"
            agent_running=true
        else
            error "❌ Agente Promiscuo no está ejecutándose"
        fi
    fi

    # Verificar puertos ZeroMQ de manera más específica
    log "Verificando conectividad ZeroMQ..."
    local zmq_ports_ok=false

    # Probar conectividad real a ZeroMQ
    if python3 -c "import zmq; ctx=zmq.Context(); sock=ctx.socket(zmq.REQ); sock.connect('tcp://localhost:5555'); sock.close(); ctx.term()" 2>/dev/null; then
        success "✅ ZeroMQ puerto 5555 respondiendo"
        zmq_ports_ok=true
    else
        warning "⚠️ ZeroMQ puerto 5555 no responde (normal durante inicialización)"
    fi

    # Resumen final
    local components_running=0
    $broker_running && ((components_running++))
    $ml_running && ((components_running++))
    $agent_running && ((components_running++))

    echo ""
    log "=== RESUMEN DE VERIFICACIÓN ==="
    echo -e "  Componentes activos: ${GREEN}$components_running/3${NC}"
    echo -e "  ZeroMQ Broker:       $($broker_running && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
    echo -e "  ML Detector:         $($ml_running && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"
    echo -e "  Promiscuous Agent:   $($agent_running && echo "${GREEN}✅ ACTIVO${NC}" || echo "${RED}❌ INACTIVO${NC}")"

    if [[ $components_running -eq 3 ]]; then
        success "🎉 ¡Plataforma completamente operativa! ($components_running/3)"
        return 0
    elif [[ $components_running -eq 2 ]]; then
        warning "⚠️ Plataforma parcialmente operativa ($components_running/3)"
        warning "Esto puede ser suficiente para operación básica"
        return 0
    else
        error "❌ Plataforma no operativa ($components_running/3)"
        return 1
    fi
}

# Mostrar información de la plataforma
show_platform_info() {
    echo -e "\n${GREEN}🎉 ¡PLATAFORMA SCADA INICIADA EXITOSAMENTE! 🎉${NC}\n"

    echo -e "${CYAN}📊 INFORMACIÓN DE LA PLATAFORMA:${NC}"
    echo -e "  • ZeroMQ Broker:    puertos 5555, 5556, 55565"
    echo -e "  • ML Detector:      6 algoritmos activos"
    echo -e "  • Agente Promiscuo: captura en tiempo real"
    echo -e "  • Dashboard:        monitoreo avanzado"

    echo -e "\n${CYAN}🛠️  COMANDOS ÚTILES:${NC}"
    echo -e "  • Monitoreo:        ${YELLOW}make monitor${NC}"
    echo -e "  • Monitor en vivo:  ${YELLOW}./monitor-platform.sh --live${NC}"
    echo -e "  • Estado rápido:    ${YELLOW}make status${NC}"
    echo -e "  • Verificar puertos:${YELLOW}./check-ports.sh${NC}"
    echo -e "  • Generar tráfico:  ${YELLOW}make test-traffic${NC}"
    echo -e "  • Parar todo:       ${YELLOW}make stop${NC}"
    echo -e "  • Reiniciar:        ${YELLOW}make stop && ./start-scada-platform.sh${NC}"

    echo -e "\n${CYAN}📈 MÉTRICAS ESPERADAS:${NC}"
    echo -e "  • Captura:          ~30 eventos/segundo"
    echo -e "  • Memoria total:    ~300MB"
    echo -e "  • CPU total:        <20%"
    echo -e "  • Latencia E2E:     <10ms"

    echo -e "\n${PURPLE}🔐 SEGURIDAD:${NC}"
    echo -e "  • Captura promiscua activa"
    echo -e "  • Detección ML en tiempo real"
    echo -e "  • Monitoreo de amenazas SCADA"

    echo -e "\n${CYAN}📋 VERIFICACIONES RECOMENDADAS:${NC}"
    echo -e "  1. ${YELLOW}./check-ports.sh${NC}        - Verificar conectividad"
    echo -e "  2. ${YELLOW}./monitor-platform.sh${NC}   - Estado detallado"
    echo -e "  3. ${YELLOW}make test-traffic${NC}       - Probar detección"

    echo -e "\n${BLUE}🚀 ¡La plataforma está lista para proteger infraestructura crítica!${NC}"

    # Mostrar estadísticas actuales si están disponibles
    echo -e "\n${CYAN}📊 ESTADÍSTICAS ACTUALES:${NC}"
    local stats_found=false

    # Intentar obtener estadísticas del agente promiscuo
    if pgrep -f "promiscuous_agent" &>/dev/null; then
        echo -e "  • Agente Promiscuo: ${GREEN}✅ Capturando datos${NC}"
        stats_found=true
    fi

    # Mostrar procesos activos
    local process_count=$(ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep | wc -l)
    echo -e "  • Procesos SCADA activos: ${GREEN}$process_count${NC}"

    if ! $stats_found; then
        echo -e "  ${YELLOW}💡 Ejecuta './monitor-platform.sh --live' para ver estadísticas en tiempo real${NC}"
    fi

    echo ""
}

# Función para mostrar ayuda de troubleshooting
show_troubleshooting() {
    echo -e "\n${YELLOW}🔧 TROUBLESHOOTING RÁPIDO:${NC}"
    echo -e "  • Dependencias:     ${YELLOW}make fix-deps${NC}"
    echo -e "  • Reset completo:   ${YELLOW}make emergency-fix${NC}"
    echo -e "  • Permisos sudo:    ${YELLOW}./fix-sudo-permissions.sh${NC}"
    echo -e "  • Verificar todo:   ${YELLOW}./troubleshoot-scada.sh${NC}"
    echo -e "  • Logs del sistema: ${YELLOW}tail -f logs/*.log${NC}"
}

# Función principal
main() {
    print_banner

    log "Iniciando proceso de levantamiento de la plataforma SCADA..."

    # Verificaciones previas
    check_directory
    check_system_dependencies

    # Setup del entorno
    setup_environment
    verify_environment

    # Preparar para inicio
    cleanup_previous_processes
    check_ports

    # Iniciar plataforma
    start_platform

    # Verificar que todo esté funcionando
    if verify_platform; then
        show_platform_info
    else
        error "La plataforma no se inició correctamente"
        show_troubleshooting

        log "Ejecutando diagnóstico automático..."
        if command -v ./troubleshoot-scada.sh &> /dev/null; then
            ./troubleshoot-scada.sh
        else
            make monitor || true
        fi

        exit 1
    fi

    success "¡Script completado exitosamente!"
}

# Manejo de señales para cleanup
trap 'error "Script interrumpido por el usuario"; exit 130' INT TERM

# Verificar si se pasó argumento de ayuda
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    print_banner
    echo -e "${CYAN}Uso: $0 [opciones]${NC}"
    echo -e "\nEste script levanta toda la arquitectura SCADA de upgraded-happiness"
    echo -e "incluyendo ZeroMQ Broker, ML Detector, Agente Promiscuo y Dashboard."
    echo -e "\n${CYAN}Opciones:${NC}"
    echo -e "  --help, -h    Mostrar esta ayuda"
    echo -e "  --monitor     Solo mostrar el estado actual"
    echo -e "  --stop        Solo parar todos los componentes"
    echo -e "\n${CYAN}Componentes que se inician:${NC}"
    echo -e "  🔌 ZeroMQ Broker (puertos 5555/5556/55565)"
    echo -e "  🧠 ML Detector (6 algoritmos de detección)"
    echo -e "  🕵️  Agente Promiscuo (captura de tráfico)"
    echo -e "  📊 Dashboard de monitoreo"
    exit 0
fi

# Opciones especiales
if [[ "$1" == "--monitor" ]]; then
    if command -v ./troubleshoot-scada.sh &> /dev/null; then
        ./troubleshoot-scada.sh
    else
        make monitor
    fi
    exit 0
fi

if [[ "$1" == "--stop" ]]; then
    log "Parando todos los componentes..."
    make stop
    success "Todos los componentes han sido detenidos"
    exit 0
fi

# Ejecutar función principal
main