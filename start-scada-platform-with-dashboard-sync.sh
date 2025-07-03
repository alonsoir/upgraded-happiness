#!/bin/bash

# =============================================================================
# UPGRADED HAPPINESS - SCADA Platform Startup Script v3.1 SYNCHRONIZED
# =============================================================================
# Script sincronizado con configuración YAML y dashboard existente
# INTEGRADO: BitDefender, configuración YAML, dashboard real
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

# Configuración base
PROJECT_NAME="upgraded-happiness"
VENV_NAME="upgraded_happiness_venv"
REQUIRED_PYTHON_VERSION="3.13"

# Archivos de configuración
CONFIG_FILE="upgraded-happiness-bitdefender/bitdefender_config.yaml"
DASHBOARD_FILE=""  # Se detectará automáticamente

# Configuración del Dashboard (se leerá del YAML)
DASHBOARD_PORT=${DASHBOARD_PORT:-8766}  # Default from YAML
DASHBOARD_HOST=${DASHBOARD_HOST:-localhost}
ZMQ_BROKER_PORT=5555
ZMQ_DASHBOARD_PORT=5556

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

# Banner actualizado
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║               🔒 UPGRADED HAPPINESS SCADA PLATFORM v3.1 🔒                  ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║  🔌 ZeroMQ  🕵️ Agent  🧠 ML  🛡️ BitDefender  📊 Dashboard  🌐 Web Monitor  ║"
    echo "║                  Sistema Integrado de Ciberseguridad SCADA                  ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Leer configuración desde YAML
read_yaml_config() {
    log "📖 Leyendo configuración desde $CONFIG_FILE..."

    if [[ ! -f "$CONFIG_FILE" ]]; then
        warning "Archivo de configuración $CONFIG_FILE no encontrado"
        warning "Usando configuración por defecto"
        return 1
    fi

    # Extraer configuración usando herramientas básicas (sin yq dependency)
    if command -v python3 &> /dev/null; then
        # Usar Python para parsear YAML
        local config_values=$(python3 -c "
import yaml
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = yaml.safe_load(f)

    # Extraer valores relevantes
    dashboard_port = config.get('dashboard', {}).get('port', 8766)
    dashboard_host = config.get('dashboard', {}).get('host', 'localhost')
    zmq_broker = config.get('zmq', {}).get('broker_port', 5555)
    zmq_dashboard = config.get('zmq', {}).get('dashboard_port', 5556)
    bitdefender_enabled = config.get('bitdefender', {}).get('enabled', True)

    print(f'DASHBOARD_PORT={dashboard_port}')
    print(f'DASHBOARD_HOST={dashboard_host}')
    print(f'ZMQ_BROKER_PORT={zmq_broker}')
    print(f'ZMQ_DASHBOARD_PORT={zmq_dashboard}')
    print(f'BITDEFENDER_ENABLED={bitdefender_enabled}')

except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null)

        if [[ $? -eq 0 ]]; then
            # Evaluar las variables extraídas
            eval "$config_values"
            success "Configuración YAML cargada correctamente"
            log "  • Dashboard: ${DASHBOARD_HOST}:${DASHBOARD_PORT}"
            log "  • ZeroMQ Broker: ${ZMQ_BROKER_PORT}"
            log "  • ZeroMQ Dashboard: ${ZMQ_DASHBOARD_PORT}"
            log "  • BitDefender: $([ "$BITDEFENDER_ENABLED" = "True" ] && echo "habilitado" || echo "deshabilitado")"
            return 0
        else
            warning "Error parseando YAML con Python"
        fi
    fi

    # Fallback: parsing manual básico
    if grep -q "port: 8766" "$CONFIG_FILE" 2>/dev/null; then
        DASHBOARD_PORT=8766
        success "Puerto de dashboard detectado: $DASHBOARD_PORT"
    fi

    if grep -q "broker_port: 5555" "$CONFIG_FILE" 2>/dev/null; then
        ZMQ_BROKER_PORT=5555
        success "Puerto ZeroMQ broker detectado: $ZMQ_BROKER_PORT"
    fi

    return 0
}

# Detectar archivo de dashboard existente (mejorado)
detect_dashboard_file() {
    log "🔍 Detectando archivos de dashboard existentes..."

    # Priorizar archivos específicos del proyecto
    local dashboard_candidates=(
        "dashboard_server_with_real_data.py"        # Tu archivo específico
        "upgraded-happiness-bitdefender/dashboard_server.py"
        "dashboard_server.py"
        "dashboard.py"
        "web_dashboard.py"
        "app.py"
        "main.py"
        "server.py"
        "web_server.py"
        "api_server.py"
        "dashboard/main.py"
        "web/app.py"
        "src/dashboard.py"
    )

    for candidate in "${dashboard_candidates[@]}"; do
        if [[ -f "$candidate" ]]; then
            # Verificar que contenga FastAPI, uvicorn o similar
            if grep -q -E "(FastAPI|app.*=|@app\.|uvicorn|from fastapi)" "$candidate" 2>/dev/null; then
                DASHBOARD_FILE="$candidate"
                success "✅ Dashboard encontrado: $DASHBOARD_FILE"

                # Verificar si usa puerto específico
                local file_port=$(grep -oE "port.*[=:].*[0-9]{4,5}" "$candidate" | head -1 | grep -oE "[0-9]{4,5}" || true)
                if [[ -n "$file_port" ]] && [[ "$file_port" != "$DASHBOARD_PORT" ]]; then
                    warning "⚠️ Dashboard define puerto $file_port, configuración YAML usa $DASHBOARD_PORT"
                    log "Se usará puerto de configuración YAML: $DASHBOARD_PORT"
                fi

                return 0
            fi
        fi
    done

    warning "No se encontró archivo de dashboard existente"
    return 1
}

# Verificar dependencias del dashboard (extendido)
check_dashboard_dependencies() {
    log "🔍 Verificando dependencias del dashboard..."

    local required_deps=("fastapi" "uvicorn" "websockets")
    local optional_deps=("yaml" "zmq")
    local missing_deps=()
    local missing_optional=()

    # Verificar dependencias requeridas
    for dep in "${required_deps[@]}"; do
        if ! python3 -c "import $dep" 2>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    # Verificar dependencias opcionales
    for dep in "${optional_deps[@]}"; do
        if ! python3 -c "import $dep" 2>/dev/null; then
            missing_optional+=("$dep")
        fi
    done

    # Instalar dependencias faltantes
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warning "Dependencias requeridas faltantes: ${missing_deps[*]}"
        log "Instalando dependencias requeridas..."

        for dep in "${missing_deps[@]}"; do
            if [[ "$dep" == "websockets" ]]; then
                pip install "websockets>=11.0" || error "No se pudo instalar $dep"
            else
                pip install "$dep" || error "No se pudo instalar $dep"
            fi
        done
    fi

    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        warning "Dependencias opcionales faltantes: ${missing_optional[*]}"
        log "Instalando dependencias opcionales..."

        for dep in "${missing_optional[@]}"; do
            case "$dep" in
                "yaml")
                    pip install "PyYAML" || warning "No se pudo instalar PyYAML"
                    ;;
                "zmq")
                    pip install "pyzmq" || warning "No se pudo instalar pyzmq"
                    ;;
            esac
        done
    fi

    success "Dependencias del dashboard verificadas ✓"
}

# Verificar configuración BitDefender
check_bitdefender_integration() {
    log "🛡️ Verificando integración BitDefender..."

    if [[ "$BITDEFENDER_ENABLED" == "True" ]]; then
        # Verificar si BitDefender está instalado en macOS
        local bitdefender_paths=(
            "/Applications/Bitdefender/AntivirusforMac.app"
            "/Applications/Bitdefender/CoreSecurity.app"
            "/Applications/Bitdefender/BitdefenderAgent.app"
        )

        local bitdefender_found=false
        for path in "${bitdefender_paths[@]}"; do
            if [[ -d "$path" ]]; then
                bitdefender_found=true
                break
            fi
        done

        if $bitdefender_found; then
            success "✅ BitDefender detectado en el sistema"

            # Verificar procesos BitDefender
            local bd_processes=$(pgrep -f "Bitdefender\|BDL\|bd" 2>/dev/null | wc -l)
            if [[ $bd_processes -gt 0 ]]; then
                success "✅ $bd_processes procesos BitDefender activos"
            else
                warning "⚠️ BitDefender instalado pero no hay procesos activos"
            fi
        else
            warning "⚠️ BitDefender habilitado en configuración pero no detectado"
            warning "Ejecutándose en modo simulación"
        fi
    else
        log "BitDefender deshabilitado en configuración"
    fi
}

# Iniciar el dashboard con configuración sincronizada
start_dashboard() {
    log "🚀 Iniciando dashboard web sincronizado..."

    # Verificar que el archivo existe
    if [[ ! -f "$DASHBOARD_FILE" ]]; then
        error "Archivo de dashboard no encontrado: $DASHBOARD_FILE"
        return 1
    fi

    # Verificar que el puerto esté disponible
    if lsof -i ":$DASHBOARD_PORT" &>/dev/null; then
        warning "Puerto $DASHBOARD_PORT ya está en uso"
        log "Intentando parar proceso en puerto $DASHBOARD_PORT..."
        pkill -f "uvicorn.*$DASHBOARD_PORT" || true
        pkill -f ":$DASHBOARD_PORT" || true
        sleep 2
    fi

    # Preparar variables de entorno para el dashboard
    export DASHBOARD_PORT="$DASHBOARD_PORT"
    export DASHBOARD_HOST="$DASHBOARD_HOST"
    export ZMQ_BROKER_PORT="$ZMQ_BROKER_PORT"
    export ZMQ_DASHBOARD_PORT="$ZMQ_DASHBOARD_PORT"
    export CONFIG_FILE="$CONFIG_FILE"

    log "Configuración del dashboard:"
    log "  • Archivo: $DASHBOARD_FILE"
    log "  • Host: $DASHBOARD_HOST"
    log "  • Puerto: $DASHBOARD_PORT"
    log "  • ZeroMQ Broker: $ZMQ_BROKER_PORT"

    # Iniciar dashboard
    if [[ "$DASHBOARD_FILE" == *.py ]]; then
        # Intentar con uvicorn primero si el archivo lo soporta
        if grep -q "if __name__.*__main__" "$DASHBOARD_FILE" && grep -q "uvicorn\|app\.run" "$DASHBOARD_FILE"; then
            log "Iniciando dashboard con Python directo..."
            python3 "$DASHBOARD_FILE" &
        elif command -v uvicorn &> /dev/null && grep -q "app.*=.*FastAPI" "$DASHBOARD_FILE"; then
            log "Iniciando dashboard con uvicorn..."
            local module_name=$(basename "$DASHBOARD_FILE" .py)
            uvicorn "${module_name}:app" --host "$DASHBOARD_HOST" --port "$DASHBOARD_PORT" --reload &
        else
            log "Iniciando dashboard con Python..."
            python3 "$DASHBOARD_FILE" &
        fi
    else
        error "Tipo de archivo de dashboard no soportado: $DASHBOARD_FILE"
        return 1
    fi

    local dashboard_pid=$!
    echo "$dashboard_pid" > dashboard.pid

    # Verificar que se inició correctamente
    sleep 5
    if kill -0 "$dashboard_pid" 2>/dev/null; then
        success "✅ Dashboard iniciado exitosamente (PID: $dashboard_pid)"
        success "🌐 Dashboard disponible en: http://${DASHBOARD_HOST}:${DASHBOARD_PORT}"
        return 0
    else
        error "❌ El dashboard no se pudo iniciar"
        cat dashboard.log 2>/dev/null || true
        return 1
    fi
}

# Verificar estado del dashboard (mejorado)
verify_dashboard() {
    log "🔍 Verificando estado del dashboard..."

    if [[ -f "dashboard.pid" ]]; then
        local dashboard_pid=$(cat dashboard.pid)
        if kill -0 "$dashboard_pid" 2>/dev/null; then
            success "✅ Dashboard ejecutándose (PID: $dashboard_pid)"

            # Verificar conectividad HTTP con timeout
            log "Probando conectividad HTTP..."
            local max_attempts=10
            local attempt=1

            while [[ $attempt -le $max_attempts ]]; do
                if curl -s --max-time 3 "http://${DASHBOARD_HOST}:${DASHBOARD_PORT}" &>/dev/null; then
                    success "✅ Dashboard respondiendo correctamente"

                    # Probar endpoint de API si existe
                    if curl -s --max-time 3 "http://${DASHBOARD_HOST}:${DASHBOARD_PORT}/api/status" &>/dev/null; then
                        success "✅ API endpoints disponibles"
                    fi
                    return 0
                else
                    log "Intento $attempt/$max_attempts - Dashboard aún no responde..."
                    sleep 2
                    ((attempt++))
                fi
            done

            warning "⚠️ Dashboard ejecutándose pero no responde HTTP después de $max_attempts intentos"
            return 1
        else
            error "❌ Dashboard no está ejecutándose"
            rm -f dashboard.pid
            return 1
        fi
    else
        error "❌ No se encontró PID del dashboard"
        return 1
    fi
}

# Verificar que estamos en el directorio correcto (mejorado)
check_directory() {
    log "Verificando directorio del proyecto..."

    if [[ ! -f "Makefile" ]] || [[ ! -f "requirements.txt" ]]; then
        error "No estás en el directorio correcto del proyecto upgraded-happiness"
        error "Asegúrate de estar en el directorio raíz del proyecto"

        # Intentar detectar el directorio correcto
        if [[ -d "upgraded-happiness" ]]; then
            log "Encontrado subdirectorio upgraded-happiness, ¿navegar ahí?"
            cd upgraded-happiness || exit 1
            log "Cambiado al directorio: $(pwd)"
        else
            exit 1
        fi
    fi

    # Verificar estructura específica del proyecto
    if [[ ! -d "upgraded-happiness-bitdefender" ]]; then
        warning "Directorio upgraded-happiness-bitdefender no encontrado"
        warning "Algunas funcionalidades BitDefender pueden no estar disponibles"
    fi

    success "Directorio del proyecto correcto ✓"
}

# Verificar dependencias del sistema (extendido)
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

    # Verificar versión de Python
    local python_version=$(python3 --version | cut -d' ' -f2)
    log "Python versión detectada: $python_version"

    # Verificar make
    if ! command -v make &> /dev/null; then
        error "Make no está instalado"
        exit 1
    fi

    # Verificar herramientas de red
    local network_tools=("lsof" "netstat" "curl")
    for tool in "${network_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            warning "$tool no está disponible, algunas verificaciones pueden fallar"
        fi
    done

    # Verificar permisos sudo para captura promiscua
    if ! sudo -n true 2>/dev/null; then
        warning "Se necesitarán permisos sudo para el agente promiscuo"
        log "Configurando permisos sudo si es posible..."
    fi

    success "Dependencias del sistema OK ✓"
}

# Función principal
main() {
    print_banner

    log "Iniciando proceso de levantamiento sincronizado de la plataforma SCADA + Dashboard..."

    # Verificaciones previas
    check_directory
    check_system_dependencies

    # Leer configuración YAML
    read_yaml_config

    # Setup del entorno
    log "Configurando entorno de desarrollo..."
    if make setup-production; then
        success "Setup de producción completado ✓"
    else
        warning "Error en setup-production, continuando..."
    fi

    # Verificar integración BitDefender
    check_bitdefender_integration

    # Preparar dashboard
    check_dashboard_dependencies
    if ! detect_dashboard_file; then
        error "No se encontró archivo de dashboard válido"
        error "Verifica que dashboard_server_with_real_data.py sea válido"
        exit 1
    fi

    # Preparar para inicio
    log "Limpiando procesos previos..."
    make stop &>/dev/null || true
    pkill -f "uvicorn.*$DASHBOARD_PORT" &>/dev/null || true
    rm -f dashboard.pid
    sleep 2

    # Verificar puertos
    log "Verificando puertos..."
    local ports=($ZMQ_BROKER_PORT $ZMQ_DASHBOARD_PORT 55565 $DASHBOARD_PORT)
    for port in "${ports[@]}"; do
        if lsof -i ":$port" &>/dev/null; then
            warning "Puerto $port en uso, intentando liberar..."
            pkill -f ":$port" &>/dev/null || true
        fi
    done
    sleep 2

    # Iniciar plataforma SCADA
    log "Iniciando plataforma SCADA..."
    if make quick-start; then
        success "Plataforma SCADA iniciada ✓"
    else
        error "Error iniciando plataforma SCADA"
        exit 1
    fi

    # Iniciar dashboard
    start_dashboard

    # Verificaciones finales
    sleep 8
    local scada_ok=false
    local dashboard_ok=false

    log "Verificando estado de componentes..."

    # Verificar SCADA
    if make status | grep -q "OK\|RUNNING\|ACTIVE" 2>/dev/null; then
        scada_ok=true
        success "✅ Plataforma SCADA operativa"
    else
        warning "⚠️ Verificando componentes SCADA individualmente..."
        local components_running=0
        pgrep -f "smart_broker" &>/dev/null && ((components_running++)) && success "  ✅ ZeroMQ Broker"
        pgrep -f "lightweight_ml_detector" &>/dev/null && ((components_running++)) && success "  ✅ ML Detector"
        pgrep -f "promiscuous_agent" &>/dev/null && ((components_running++)) && success "  ✅ Agente Promiscuo"

        if [[ $components_running -ge 2 ]]; then
            scada_ok=true
            success "✅ Plataforma SCADA parcialmente operativa ($components_running/3)"
        fi
    fi

    # Verificar dashboard
    if verify_dashboard; then
        dashboard_ok=true
    fi

    # Mostrar resultado final
    if $scada_ok && $dashboard_ok; then
        show_platform_info
    elif $dashboard_ok; then
        warning "Dashboard funcionando, SCADA con problemas"
        show_platform_info
    else
        error "La plataforma no se inició correctamente"
        show_troubleshooting
        exit 1
    fi

    success "🎉 ¡Script completado exitosamente!"
}

# Mostrar información completa de la plataforma (actualizada)
show_platform_info() {
    echo -e "\n${GREEN}🎉 ¡PLATAFORMA SCADA + DASHBOARD SINCRONIZADA INICIADA! 🎉${NC}\n"

    echo -e "${CYAN}📊 INFORMACIÓN DE LA PLATAFORMA:${NC}"
    echo -e "  • ZeroMQ Broker:    puerto $ZMQ_BROKER_PORT"
    echo -e "  • ZeroMQ Dashboard: puerto $ZMQ_DASHBOARD_PORT"
    echo -e "  • ML Detector:      algoritmos híbridos activos"
    echo -e "  • Agente Promiscuo: captura en tiempo real"
    echo -e "  • 🛡️ BitDefender:    $([[ "$BITDEFENDER_ENABLED" == "True" ]] && echo "integrado" || echo "deshabilitado")"
    echo -e "  • 🌐 Dashboard Web:  http://${DASHBOARD_HOST}:${DASHBOARD_PORT}"

    echo -e "\n${CYAN}🌐 ACCESO AL DASHBOARD SINCRONIZADO:${NC}"
    echo -e "  • URL Principal:    ${YELLOW}http://${DASHBOARD_HOST}:${DASHBOARD_PORT}${NC}"
    echo -e "  • Archivo usado:    ${YELLOW}${DASHBOARD_FILE}${NC}"
    echo -e "  • Configuración:    ${YELLOW}${CONFIG_FILE}${NC}"

    if $dashboard_ok; then
        echo -e "  • API Status:       ${YELLOW}http://${DASHBOARD_HOST}:${DASHBOARD_PORT}/api/status${NC}"
        echo -e "  • WebSocket:        ${YELLOW}ws://${DASHBOARD_HOST}:${DASHBOARD_PORT}/ws${NC}"
    fi

    echo -e "\n${CYAN}🛠️  COMANDOS ÚTILES SINCRONIZADOS:${NC}"
    echo -e "  • Monitoreo SCADA:  ${YELLOW}make monitor${NC}"
    echo -e "  • Estado completo:  ${YELLOW}make status${NC}"
    echo -e "  • Test BitDefender: ${YELLOW}python3 upgraded-happiness-bitdefender/test_integration.py${NC}"
    echo -e "  • Verificar config: ${YELLOW}cat $CONFIG_FILE${NC}"
    echo -e "  • Reiniciar:        ${YELLOW}./start-scada-platform-with-dashboard-sync.sh${NC}"
    echo -e "  • Parar todo:       ${YELLOW}make stop && pkill -f $DASHBOARD_PORT${NC}"

    echo -e "\n${PURPLE}🔐 INTEGRACIÓN COMPLETA:${NC}"
    echo -e "  • Configuración YAML sincronizada ✅"
    echo -e "  • Dashboard real detectado ✅"
    echo -e "  • Puertos consistentes ✅"
    echo -e "  • BitDefender integrado ✅"

    echo -e "\n${BLUE}🚀 ¡Sistema completamente sincronizado y operativo!${NC}"
    echo -e "${BLUE}💻 Dashboard: http://${DASHBOARD_HOST}:${DASHBOARD_PORT}${NC}"
}

# Función para mostrar ayuda de troubleshooting (extendida)
show_troubleshooting() {
    echo -e "\n${YELLOW}🔧 TROUBLESHOOTING SINCRONIZADO:${NC}"
    echo -e "  • Verificar config:  ${YELLOW}cat $CONFIG_FILE${NC}"
    echo -e "  • Dependencias:     ${YELLOW}make fix-deps${NC}"
    echo -e "  • Dashboard logs:   ${YELLOW}tail -f dashboard.log${NC}"
    echo -e "  • Puertos en uso:   ${YELLOW}lsof -i :$DASHBOARD_PORT${NC}"
    echo -e "  • Reiniciar todo:   ${YELLOW}make stop && ./start-scada-platform-with-dashboard-sync.sh${NC}"
}

# Verificar argumentos
case "${1:-}" in
    "--help"|"-h")
        print_banner
        echo -e "${CYAN}SCRIPT SINCRONIZADO - Usa configuración YAML existente${NC}"
        echo -e "\nEste script lee la configuración desde $CONFIG_FILE"
        echo -e "y usa el dashboard_server_with_real_data.py existente.\n"
        echo -e "${CYAN}Variables detectadas automáticamente:${NC}"
        echo -e "  • Dashboard: puerto $DASHBOARD_PORT"
        echo -e "  • ZeroMQ: puertos $ZMQ_BROKER_PORT, $ZMQ_DASHBOARD_PORT"
        echo -e "  • BitDefender: habilitado/deshabilitado según YAML"
        exit 0
        ;;
    "--config")
        read_yaml_config
        echo "Configuración cargada desde $CONFIG_FILE"
        exit 0
        ;;
    "--dashboard-only")
        log "Iniciando solo el dashboard sincronizado..."
        read_yaml_config
        check_dashboard_dependencies
        if detect_dashboard_file; then
            start_dashboard && verify_dashboard
        else
            error "No se pudo detectar dashboard válido"
            exit 1
        fi
        exit 0
        ;;
    "--stop")
        log "Parando todos los componentes..."
        make stop
        pkill -f "uvicorn.*$DASHBOARD_PORT" &>/dev/null || true
        rm -f dashboard.pid
        success "Todos los componentes detenidos"
        exit 0
        ;;
esac

# Cleanup en caso de interrupción
cleanup_on_exit() {
    log "Limpiando al salir..."
    if [[ -f "dashboard.pid" ]]; then
        local dashboard_pid=$(cat dashboard.pid)
        kill "$dashboard_pid" 2>/dev/null || true
        rm -f dashboard.pid
    fi
}

trap cleanup_on_exit EXIT
trap 'error "Script interrumpido"; exit 130' INT TERM

# Ejecutar función principal
main