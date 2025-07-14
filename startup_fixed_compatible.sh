#!/bin/bash
# startup_fixed_complete.sh
# Script de inicio completo y funcional para upgraded-happiness

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Función para convertir a minúsculas (compatible)
to_lower() {
    echo "$1" | tr '[:upper:]' '[:lower:]'
}

# Función para verificar puerto
check_port() {
    local port=$1
    local description=$2
    local max_attempts=15
    local attempt=1

    log "Verificando puerto $port ($description)..."

    while [ $attempt -le $max_attempts ]; do
        if netstat -tulpn 2>/dev/null | grep ":$port " > /dev/null; then
            success "Puerto $port activo"
            return 0
        fi

        if [ $attempt -eq 1 ]; then
            log "Esperando puerto $port..."
        fi

        sleep 1
        attempt=$((attempt + 1))
    done

    error "Puerto $port no disponible después de $max_attempts segundos"
    return 1
}

# Función para limpiar procesos
cleanup_processes() {
    log "Limpiando procesos existentes..."

    pkill -f "firewall_agent.py" 2>/dev/null || true
    pkill -f "ml_detector_with_persistence.py" 2>/dev/null || true
    pkill -f "real_zmq_dashboard_with_firewall.py" 2>/dev/null || true
    pkill -f "promiscuous_agent.py" 2>/dev/null || true

    sleep 2

    for port in 5559 5560 5561 5562 8000; do
        local pid=$(lsof -ti:$port 2>/dev/null || echo "")
        if [ ! -z "$pid" ]; then
            warning "Puerto $port ocupado por PID $pid, liberando..."
            kill -9 $pid 2>/dev/null || true
        fi
    done

    success "Limpieza completada"
}

# Función para verificar dependencias
check_dependencies() {
    log "Verificando dependencias..."

    if ! command -v python3 &> /dev/null; then
        error "Python3 no encontrado"
        exit 1
    fi

    local files=(
        "firewall_agent.py"
        "ml_detector_with_persistence.py"
        "real_zmq_dashboard_with_firewall.py"
        "promiscuous_agent.py"
        "enhanced_agent_config.json"
    )

    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            error "Archivo requerido no encontrado: $file"
            exit 1
        fi
    done

    if ! sudo -n true 2>/dev/null; then
        warning "Se requieren permisos sudo para el promiscuous agent"
    fi

    success "Dependencias verificadas"
}

# Función para iniciar componente
start_component() {
    local script=$1
    local description=$2
    local port=$3
    local is_sudo=$4
    local config_file=$5

    log "Iniciando $description..."

    local cmd="python3 $script"
    if [ ! -z "$config_file" ]; then
        cmd="$cmd $config_file"
    fi

    if [ "$is_sudo" = "true" ]; then
        cmd="sudo $cmd"
    fi

    # Crear directorio de logs
    mkdir -p logs

    # Generar nombre de archivo de log (compatible)
    local log_name=$(to_lower "$description")
    local log_file="logs/${log_name}.log"
    local pid_file="logs/${log_name}.pid"

    # Iniciar componente en background
    nohup $cmd > "$log_file" 2>&1 &
    local pid=$!

    echo $pid > "$pid_file"

    # Verificar que el proceso se inició
    sleep 1
    if ! kill -0 $pid 2>/dev/null; then
        error "$description falló al iniciar"
        if [ -f "$log_file" ]; then
            tail -n 10 "$log_file"
        fi
        return 1
    fi

    success "$description iniciado (PID: $pid)"

    # Verificar puerto si se especifica
    if [ ! -z "$port" ]; then
        if check_port $port "$description"; then
            return 0
        else
            error "$description no está escuchando en puerto $port"
            return 1
        fi
    fi

    return 0
}

# Función para verificar argumentos del dashboard
fix_dashboard_args() {
    log "Verificando argumentos del dashboard..."

    mkdir -p logs
    if python3 real_zmq_dashboard_with_firewall.py --help 2>&1 | grep -q "\--config"; then
        success "Dashboard acepta --config"
        echo "--config dashboard_config.json" > logs/dashboard_args.txt
    else
        warning "Dashboard no acepta --config, usando argumento posicional"
        echo "dashboard_config.json" > logs/dashboard_args.txt
    fi
}

# Función principal
main() {
    echo -e "${BLUE}"
    echo "🚀 UPGRADED-HAPPINESS STARTUP SCRIPT (Complete)"
    echo "================================================"
    echo -e "${NC}"

    check_dependencies
    cleanup_processes
    fix_dashboard_args

    log "Iniciando componentes en orden correcto..."

    # 1. Firewall Agent
    if ! start_component "firewall_agent.py" "Firewall-Agent" "5562" "false"; then
        error "No se pudo iniciar Firewall Agent"
        exit 1
    fi

    sleep 2

    # 2. ML Detector
    if ! start_component "ml_detector_with_persistence.py" "ML-Detector" "5559" "false"; then
        error "No se pudo iniciar ML Detector"
        exit 1
    fi

    if check_port "5560" "ML Detector publisher"; then
        success "ML Detector configurado correctamente"
    fi

    sleep 2

    # 3. Dashboard
    dashboard_args=$(cat logs/dashboard_args.txt)
    if ! start_component "real_zmq_dashboard_with_firewall.py" "Dashboard" "8000" "false" "$dashboard_args"; then
        error "No se pudo iniciar Dashboard"
        exit 1
    fi

    sleep 3

    # 4. Promiscuous Agent
    if ! start_component "promiscuous_agent.py" "Promiscuous-Agent" "" "true" "enhanced_agent_config.json"; then
        error "No se pudo iniciar Promiscuous Agent"
        exit 1
    fi

    # Verificación final
    log "Verificando sistema completo..."

    local all_ports_ok=true
    for port in 5559 5560 5561 5562 8000; do
        if ! netstat -tulpn 2>/dev/null | grep ":$port " > /dev/null; then
            error "Puerto $port no está activo"
            all_ports_ok=false
        fi
    done

    if [ "$all_ports_ok" = "true" ]; then
        echo -e "${GREEN}"
        echo "🎉 ¡SISTEMA INICIADO EXITOSAMENTE!"
        echo "================================="
        echo "🔥 Firewall Agent: ✅ (Puerto 5562)"
        echo "🤖 ML Detector: ✅ (Puertos 5559, 5560)"
        echo "📊 Dashboard: ✅ (Puerto 8000)"
        echo "🕵️  Promiscuous Agent: ✅"
        echo ""
        echo "🌐 Dashboard Web: http://localhost:8000"
        echo "📊 Logs: ls logs/*.log"
        echo "📋 PIDs: ls logs/*.pid"
        echo ""
        echo "Para parar: ./stop_system.sh"
        echo -e "${NC}"

        # Crear script de parada
        create_stop_script

        # Mostrar PIDs
        show_pids

        # Crear script de monitoreo
        create_monitor_script

    else
        error "Sistema iniciado con errores. Verifica los logs."
        show_error_logs
        exit 1
    fi
}

# Función para crear script de parada
create_stop_script() {
    cat > stop_system.sh << 'EOF'
#!/bin/bash
echo "🛑 Parando sistema upgraded-happiness..."

# Leer PIDs de archivos
for pid_file in logs/*.pid; do
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        component=$(basename "$pid_file" .pid)

        if kill -0 "$pid" 2>/dev/null; then
            echo "Parando $component (PID: $pid)..."
            kill "$pid"
        fi

        rm -f "$pid_file"
    fi
done

# Forzar si es necesario
sleep 2
pkill -f "firewall_agent.py" 2>/dev/null || true
pkill -f "ml_detector_with_persistence.py" 2>/dev/null || true
pkill -f "real_zmq_dashboard_with_firewall.py" 2>/dev/null || true
sudo pkill -f "promiscuous_agent.py" 2>/dev/null || true

echo "✅ Sistema detenido"
EOF

    chmod +x stop_system.sh
    success "Script de parada creado: ./stop_system.sh"
}

# Función para mostrar PIDs
show_pids() {
    echo ""
    log "PIDs de componentes activos:"
    for pid_file in logs/*.pid; do
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            component=$(basename "$pid_file" .pid)
            if kill -0 "$pid" 2>/dev/null; then
                echo "  📍 $component: PID $pid ✅"
            else
                echo "  ❌ $component: PID $pid (no activo)"
            fi
        fi
    done
}

# Función para mostrar logs de error
show_error_logs() {
    echo ""
    error "Últimas líneas de logs con errores:"
    for log_file in logs/*.log; do
        if [ -f "$log_file" ]; then
            echo ""
            echo "--- $(basename "$log_file") ---"
            tail -n 5 "$log_file" 2>/dev/null || echo "No se pudo leer el log"
        fi
    done
}

# Función para crear script de monitoreo
create_monitor_script() {
    cat > monitor_system.sh << 'EOF'
#!/bin/bash
echo "📊 Monitor del Sistema upgraded-happiness"
echo "========================================"

while true; do
    clear
    echo "📊 Monitor del Sistema - $(date)"
    echo "================================"

    echo ""
    echo "🔄 Procesos activos:"
    for pid_file in logs/*.pid; do
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            component=$(basename "$pid_file" .pid)
            if kill -0 "$pid" 2>/dev/null; then
                echo "  ✅ $component (PID: $pid)"
            else
                echo "  ❌ $component (PID: $pid) - NO ACTIVO"
            fi
        fi
    done

    echo ""
    echo "🌐 Puertos:"
    for port in 5559 5560 5561 5562 8000; do
        if netstat -tulpn 2>/dev/null | grep ":$port " > /dev/null; then
            echo "  ✅ Puerto $port"
        else
            echo "  ❌ Puerto $port"
        fi
    done

    echo ""
    echo "📜 Logs recientes:"
    tail -n 1 logs/*.log 2>/dev/null | while read line; do
        echo "  $line"
    done

    echo ""
    echo "Presiona Ctrl+C para salir..."
    sleep 5
done
EOF

    chmod +x monitor_system.sh
    success "Script de monitoreo creado: ./monitor_system.sh"
}

# Ejecutar main
main "$@"