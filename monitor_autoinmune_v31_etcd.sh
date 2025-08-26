#!/bin/bash

# =============================================================================
# 🧬 Monitor Avanzado - Sistema Autoinmune Digital v3.1 ETCD
# =============================================================================
# Compatible con macOS bash - Sin arrays asociativos
# Versión optimizada para componentes ETCD v3.1 + protobuf
# =============================================================================

# Colores y formato
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'
DIM='\033[2m'

# Configuración
REFRESH_INTERVAL=5
LOG_DIR="logs"
PIDS_DIR=".pids"

# Función para obtener CPU de proceso (más robusta)
get_cpu_usage() {
    local process_pattern="$1"
    local cpu_val=$(ps aux | grep -E "$process_pattern" | grep -v grep | head -1 | awk '{print $3}')
    # Verificar si es un número válido
    if [[ "$cpu_val" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo "$cpu_val"
    else
        echo "0.0"
    fi
}

# Función para obtener memoria de proceso
get_mem_usage() {
    local process_pattern="$1"
    local mem_val=$(ps aux | grep -E "$process_pattern" | grep -v grep | head -1 | awk '{print $4}')
    # Verificar si es un número válido
    if [[ "$mem_val" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo "$mem_val"
    else
        echo "0.0"
    fi
}

# Función para verificar si un proceso está activo (más robusta)
is_process_active() {
    local process_pattern="$1"
    # Usar ps aux | grep que es más compatible y robusto que pgrep
    ps aux | grep -E "$process_pattern" | grep -v grep >/dev/null 2>&1
}

# Función para obtener uptime de proceso (mejorada)
get_process_uptime() {
    local process_pattern="$1"
    local pid=$(ps aux | grep -E "$process_pattern" | grep -v grep | head -1 | awk '{print $2}')
    if [ -n "$pid" ] && [[ "$pid" =~ ^[0-9]+$ ]]; then
        local uptime_seconds=$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ' | head -1)
        echo "${uptime_seconds:-0}"
    else
        echo "0"
    fi
}

# Función para mostrar estado de salud con colores
show_health_status() {
    local value="$1"
    local threshold_good="$2"
    local threshold_warning="$3"
    local unit="$4"

    # Usar awk para comparaciones de flotantes (compatible con macOS)
    local is_good=$(awk "BEGIN {print ($value < $threshold_good)}")
    local is_warning=$(awk "BEGIN {print ($value < $threshold_warning)}")

    if [ "$is_good" = "1" ]; then
        echo -e "${GREEN}${value}${unit}${NC}"
    elif [ "$is_warning" = "1" ]; then
        echo -e "${YELLOW}${value}${unit}${NC}"
    else
        echo -e "${RED}${value}${unit}${NC}"
    fi
}

# Función para mostrar barras de progreso visual
show_progress_bar() {
    local value="$1"
    local max_value="$2"
    local bar_length=15

    # Calcular con awk (más compatible)
    local filled=$(awk "BEGIN {printf \"%.0f\", $value * $bar_length / $max_value}")

    # Asegurar que filled no sea negativo o mayor que bar_length
    if [ "$filled" -lt "0" ]; then filled=0; fi
    if [ "$filled" -gt "$bar_length" ]; then filled=$bar_length; fi

    local empty=$((bar_length - filled))

    printf "["
    for ((i=1; i<=filled; i++)); do printf "█"; done
    for ((i=1; i<=empty; i++)); do printf "░"; done
    printf "]"
}

# Función para verificar puerto específico
check_port() {
    local port="$1"
    lsof -i ":$port" >/dev/null 2>&1
}

# Función para verificar ETCD
check_etcd() {
    lsof -i ":2379" >/dev/null 2>&1
}

# Función para obtener información de componente ETCD v3.1
get_component_info() {
    local component_type="$1"

    case "$component_type" in
        "etcd")
            echo "etcd|🔐 ETCD Cluster|2379"
            ;;
        "sniffer")
            echo "evolutionary_sniffer_standalone|📡 Evolutionary Sniffer v3.1 ETCD|raw"
            ;;
        "optimizer")
            echo "zmq_performance_optimizer|⚡ ZMQ Performance Optimizer|consumer"
            ;;
        "geoip")
            echo "geoip_enricher_v31_etcd|🌍 GeoIP Enricher v3.1 ETCD|5560"
            ;;
        "ml")
            echo "lightweight_ml_detector_tricapa_v31_etcd|🤖 ML Detector Tricapa v3.1 ETCD|5580"
            ;;
        "scheduler")
            echo "scheduler_firewall_v31_etcd|🧠 Scheduler Firewall v3.1 ETCD|5570"
            ;;
        "firewall")
            echo "simple_firewall_agent_v31_etcd|🛡️  Firewall Agent v3.1 ETCD|5583"
            ;;
        "dashboard")
            echo "dashboard_v31_etcd|📊 Dashboard SCADA v3.1 ETCD|8080"
            ;;
    esac
}

# Función principal de monitoreo
monitor_system() {
    while true; do
        clear

        # Header elegante
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                🧬 SISTEMA AUTOINMUNE DIGITAL v3.1 ETCD                      ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║ ${WHITE}$(date +'%A, %d %B %Y - %H:%M:%S %Z')${CYAN}                                         ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # Variables de estado para cada componente (nueva secuencia)
        local components="etcd sniffer geoip ml scheduler firewall dashboard"
        local optional_components="optimizer"

        # Estado general del sistema
        echo -e "${BOLD}${PURPLE}📊 ESTADO GENERAL DEL SISTEMA ETCD v3.1${NC}"
        echo -e "${PURPLE}════════════════════════════════════════════════════════${NC}"

        local total_cpu=0
        local total_mem=0
        local active_components=0
        local total_components=7  # Sin contar optimizer que es opcional

        # Verificar ETCD primero (crítico)
        local etcd_status=""
        if check_etcd; then
            etcd_status="${GREEN}✅ ETCD ACTIVO${NC}"
        else
            etcd_status="${RED}❌ ETCD OFFLINE${NC}"
        fi

        for component in $components; do
            local component_info=$(get_component_info "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)

            if is_process_active "$pattern"; then
                ((active_components++))
                local cpu=$(get_cpu_usage "$pattern")
                local mem=$(get_mem_usage "$pattern")
                total_cpu=$(awk "BEGIN {print $total_cpu + $cpu}")
                total_mem=$(awk "BEGIN {print $total_mem + $mem}")
            fi
        done

        # Mostrar resumen general
        local health_percentage=$((active_components * 100 / total_components))
        echo -e "🎯 Estado General: $(show_health_status "$health_percentage" "80" "60" "%") ($active_components/$total_components componentes activos)"
        echo -e "🔐 ETCD Status: $etcd_status"
        echo -e "🔥 CPU Total: $(show_health_status "$total_cpu" "50" "100" "%") $(show_progress_bar "$total_cpu" "200")"
        echo -e "💾 RAM Total: $(show_health_status "$total_mem" "10" "20" "%") $(show_progress_bar "$total_mem" "30")"
        echo ""

        # Análisis detallado por componente
        echo -e "${BOLD}${YELLOW}🔍 PIPELINE ETCD v3.1 - ANÁLISIS DETALLADO${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        echo ""

        for component in $components; do
            local component_info=$(get_component_info "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)
            local name=$(echo "$component_info" | cut -d'|' -f2)
            local port=$(echo "$component_info" | cut -d'|' -f3)

            printf "%-35s" "$name"

            if [ "$component" = "etcd" ]; then
                if check_etcd; then
                    printf "${GREEN}●${NC} ACTIVO   "
                    printf "🔐 ETCD  "
                    printf "⏱️  ${GRAY}cluster${NC}"
                    printf "  🌐 $port"
                else
                    printf "${RED}●${NC} OFFLINE  "
                    printf "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                fi
            elif is_process_active "$pattern"; then
                local cpu=$(get_cpu_usage "$pattern")
                local mem=$(get_mem_usage "$pattern")
                local uptime=$(get_process_uptime "$pattern")

                printf "${GREEN}●${NC} ACTIVO   "
                printf "CPU$(show_progress_bar "$cpu" "100") $(show_health_status "$cpu" "30" "70" "%%")  "
                printf "RAM$(show_health_status "$mem" "5" "15" "%%")  "
                printf "⏱️  ${GRAY}${uptime}${NC}"

                # Verificar puerto específico (si no es raw o consumer)
                if [[ "$port" != "raw" && "$port" != "consumer" ]]; then
                    if check_port "$port"; then
                        printf "  🌐 $port"
                    else
                        printf "  ${RED}✗${NC} $port"
                    fi
                else
                    printf "  🔧 $port"
                fi
            else
                printf "${RED}●${NC} OFFLINE  "
                printf "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            fi
            echo ""
        done

        # Componentes opcionales
        echo -e "${BOLD}${GRAY}📋 COMPONENTES OPCIONALES${NC}"
        echo -e "${GRAY}═══════════════════════════════════════${NC}"

        for component in $optional_components; do
            local component_info=$(get_component_info "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)
            local name=$(echo "$component_info" | cut -d'|' -f2)
            local port=$(echo "$component_info" | cut -d'|' -f3)

            printf "%-35s" "$name"

            if is_process_active "$pattern"; then
                local cpu=$(get_cpu_usage "$pattern")
                local mem=$(get_mem_usage "$pattern")
                printf "${BLUE}●${NC} ACTIVO   "
                printf "CPU$(show_health_status "$cpu" "30" "70" "%%") RAM$(show_health_status "$mem" "5" "15" "%%")  🔧 $port"
            else
                printf "${GRAY}●${NC} OFFLINE  "
                printf "${DIM}(opcional - no requerido para operación)${NC}"
            fi
            echo ""
        done

        echo ""

        # Pipeline de datos visual ETCD v3.1
        echo -e "${BOLD}${CYAN}🔄 PIPELINE DATOS ETCD v3.1 + PROTOBUF${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo ""

        # Crear representación visual del pipeline
        local pipeline_status=""
        for component in $components; do
            local component_info=$(get_component_info "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)

            if [ "$component" = "etcd" ]; then
                if check_etcd; then
                    pipeline_status="${pipeline_status}${GREEN}●${NC}"
                else
                    pipeline_status="${pipeline_status}${RED}●${NC}"
                fi
            elif is_process_active "$pattern"; then
                pipeline_status="${pipeline_status}${GREEN}●${NC}"
            else
                pipeline_status="${pipeline_status}${RED}●${NC}"
            fi

            if [ "$component" != "dashboard" ]; then
                pipeline_status="${pipeline_status} ${GRAY}→${NC} "
            fi
        done

        echo -e "🔐 ETCD ${GRAY}→${NC} 📡 Sniffer ${GRAY}→${NC} 🌍 GeoIP ${GRAY}→${NC} 🤖 ML Tricapa ${GRAY}→${NC} 🧠 Scheduler ${GRAY}→${NC} 🛡️  Firewall ${GRAY}→${NC} 📊 Dashboard"
        echo -e "   $pipeline_status"
        echo ""
        echo -e "${CYAN}🔐 Cifrado ETCD:${NC} AES-256-GCM + LZ4 automático en todos los canales"
        echo -e "${CYAN}📡 Protobuf:${NC} v3.1.0 exclusivo con campos nativos node_id + timestamp"
        echo ""

        # Métricas de rendimiento ETCD
        echo -e "${BOLD}${BLUE}📈 MÉTRICAS DE RENDIMIENTO ETCD v3.1${NC}"
        echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

        # Buscar métricas en logs ETCD
        local throughput="N/A"
        local latency="N/A"
        local processed_events="N/A"
        local blocked_ips="N/A"
        local etcd_operations="N/A"
        local crypto_operations="N/A"

        if [ -d "$LOG_DIR" ]; then
            # Throughput
            local throughput_raw=$(find "$LOG_DIR" -name "*.log" -exec tail -10 {} \; 2>/dev/null | grep -o "[0-9]\+\.[0-9]/s" | tail -1)
            if [ -n "$throughput_raw" ]; then
                throughput="$throughput_raw"
            fi

            # Latencia pipeline
            local latency_raw=$(find "$LOG_DIR" -name "*ml*" -exec tail -5 {} \; 2>/dev/null | grep -o "pipeline_latency[: ]*[0-9]\+\.[0-9]*" | tail -1 | grep -o "[0-9]\+\.[0-9]*")
            if [ -n "$latency_raw" ]; then
                latency="${latency_raw}ms"
            fi

            # Eventos procesados
            local events_raw=$(find "$LOG_DIR" -name "*.log" -exec tail -10 {} \; 2>/dev/null | grep -o "events_processed[: ]*[0-9]\+" | tail -1 | grep -o "[0-9]\+")
            if [ -n "$events_raw" ]; then
                processed_events="$events_raw"
            fi

            # Operaciones ETCD crypto
            local crypto_raw=$(find "$LOG_DIR" -name "*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "crypto_operations[: ]*[0-9]\+" | tail -1 | grep -o "[0-9]\+")
            if [ -n "$crypto_raw" ]; then
                crypto_operations="$crypto_raw"
            fi

            # IPs bloqueadas
            local blocked_raw=$(find "$LOG_DIR" -name "*firewall*.log" -exec tail -10 {} \; 2>/dev/null | grep -c "blocked\|bloqueada\|BLOCK_IP" 2>/dev/null)
            if [[ ! "$blocked_raw" =~ ^[0-9]+$ ]]; then
                blocked_raw=0
            fi
            if [ "$blocked_raw" -gt "0" ]; then
                blocked_ips="$blocked_raw"
            fi
        fi

        printf "%-30s %s\n" "⚡ Throughput:" "$throughput"
        printf "%-30s %s\n" "⏱️  Pipeline Latency:" "$latency"
        printf "%-30s %s\n" "📊 Eventos procesados:" "$processed_events"
        printf "%-30s %s\n" "🔐 Operaciones crypto ETCD:" "$crypto_operations"
        printf "%-30s %s\n" "🚫 IPs bloqueadas:" "$blocked_ips"
        echo ""

        # Análisis de red ETCD
        echo -e "${BOLD}${PURPLE}🌐 ANÁLISIS DE RED ETCD v3.1${NC}"
        echo -e "${PURPLE}═══════════════════════════════════════════════${NC}"

        # Puertos ETCD + ZeroMQ activos
        local etcd_port_active=0
        local zmq_ports=0

        if check_etcd; then
            etcd_port_active=1
        fi

        zmq_ports=$(netstat -an 2>/dev/null | grep -E "LISTEN.*:(55[0-9][0-9]|8080)" | wc -l | tr -d ' ')
        if [[ ! "$zmq_ports" =~ ^[0-9]+$ ]]; then
            zmq_ports=0
        fi

        printf "%-30s " "🔐 Puerto ETCD (2379):"
        if [ "$etcd_port_active" -eq "1" ]; then
            echo -e "${GREEN}ACTIVO${NC} ✅"
        else
            echo -e "${RED}OFFLINE${NC} ❌"
        fi

        printf "%-30s " "🔌 Puertos ZeroMQ:"
        if [ "$zmq_ports" -gt "4" ]; then
            echo -e "${GREEN}$zmq_ports activos${NC} ✅"
        elif [ "$zmq_ports" -gt "0" ]; then
            echo -e "${YELLOW}$zmq_ports activos${NC} ⚠️"
        else
            echo -e "${RED}$zmq_ports activos${NC} ❌"
        fi

        # Conexiones activas
        local active_connections=$(netstat -an 2>/dev/null | grep "ESTABLISHED" | wc -l | tr -d ' ')
        if [[ ! "$active_connections" =~ ^[0-9]+$ ]]; then
            active_connections=0
        fi
        printf "%-30s " "🔗 Conexiones activas:"
        echo -e "$(show_health_status "$active_connections" "100" "200" "")"

        echo ""

        # Alertas y recomendaciones ETCD
        echo -e "${BOLD}${RED}🚨 ALERTAS Y RECOMENDACIONES ETCD v3.1${NC}"
        echo -e "${RED}════════════════════════════════════════════════════════════${NC}"

        local alerts=0

        # Verificar ETCD crítico
        if ! check_etcd; then
            echo -e "${RED}⚠️  CRÍTICO:${NC} ETCD cluster offline - Sistema no operacional"
            ((alerts++))
        fi

        # Verificar componentes offline
        if [ "$active_components" -lt "$total_components" ]; then
            echo -e "${RED}⚠️  CRÍTICO:${NC} $((total_components - active_components)) componente(s) v3.1 ETCD offline"
            ((alerts++))
        fi

        # Verificar alta CPU
        local high_cpu=$(awk "BEGIN {print ($total_cpu > 150)}")
        if [ "$high_cpu" = "1" ]; then
            echo -e "${RED}⚠️  CRÍTICO:${NC} Alta carga de CPU (${total_cpu}%)"
            ((alerts++))
        fi

        # Verificar puertos ZeroMQ
        if [ "$zmq_ports" -eq "0" ]; then
            echo -e "${YELLOW}⚠️  ADVERTENCIA:${NC} Sin puertos ZeroMQ activos - Pipeline desconectado"
            ((alerts++))
        fi

        # Verificar logs de errores ETCD recientes
        if [ -d "$LOG_DIR" ]; then
            local recent_errors=$(find "$LOG_DIR" -name "*.log" -newermt "-60 seconds" -exec grep -l -i "error\|exception\|failed\|crypto.*error" {} \; 2>/dev/null | wc -l | tr -d ' ')
            if [[ ! "$recent_errors" =~ ^[0-9]+$ ]]; then
                recent_errors=0
            fi
            if [ "$recent_errors" -gt "0" ]; then
                echo -e "${YELLOW}⚠️  ADVERTENCIA:${NC} $recent_errors archivo(s) con errores ETCD recientes"
                ((alerts++))
            fi
        fi

        if [ "$alerts" -eq "0" ]; then
            echo -e "${GREEN}✅ SISTEMA ETCD v3.1 OPERACIONAL${NC} - Pipeline crypto funcionando correctamente"
        fi

        echo ""

        # Footer con controles actualizados
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║ ${WHITE}🎮 CONTROLES:${NC} ${GRAY}Ctrl+C para salir${NC} ${CYAN}│${NC} ${WHITE}📊 Dashboard v3.1:${NC} ${BLUE}http://localhost:8080${NC} ${CYAN}        ║${NC}"
        echo -e "${CYAN}║ ${WHITE}🔐 ETCD:${NC} ${BLUE}localhost:2379${NC} ${CYAN}│${NC} ${WHITE}📡 Protobuf:${NC} ${BLUE}v3.1.0 exclusivo${NC} ${CYAN}                    ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"

        # Esperar antes del siguiente refresh
        sleep $REFRESH_INTERVAL
    done
}

# Función de ayuda actualizada
show_help() {
    echo "🧬 Monitor Sistema Autoinmune Digital v3.1 ETCD"
    echo "==============================================="
    echo ""
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help          Mostrar esta ayuda"
    echo "  -i, --interval N    Intervalo de refresh en segundos (default: 5)"
    echo "  -s, --status        Mostrar estado una vez y salir"
    echo ""
    echo "Componentes monitoreados (secuencia ETCD v3.1):"
    echo "  🔐 ETCD Cluster (puerto 2379) - CRÍTICO"
    echo "  📡 Evolutionary Sniffer v3.1 ETCD"
    echo "  🌍 GeoIP Enricher v3.1 ETCD (puerto 5560)"
    echo "  🤖 ML Detector Tricapa v3.1 ETCD (puerto 5580)"
    echo "  🧠 Scheduler Firewall v3.1 ETCD (puerto 5570)"
    echo "  🛡️  Firewall Agent v3.1 ETCD (puerto 5583)"
    echo "  📊 Dashboard SCADA v3.1 ETCD (puerto 8080)"
    echo ""
    echo "Componentes opcionales:"
    echo "  ⚡ ZMQ Performance Optimizer"
    echo ""
    echo "Ejemplos:"
    echo "  $0                  # Monitor en tiempo real ETCD v3.1"
    echo "  $0 -i 10           # Refresh cada 10 segundos"
    echo "  $0 -s              # Estado único"
}

# Verificar dependencias
check_dependencies() {
    local missing=0

    for cmd in ps grep awk netstat lsof; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "❌ Comando requerido no encontrado: $cmd"
            ((missing++))
        fi
    done

    if [ "$missing" -gt "0" ]; then
        echo "⚠️  Instala las dependencias faltantes para un funcionamiento completo"
        echo ""
    fi

    # Verificar si ETCD está disponible
    if ! check_etcd; then
        echo "⚠️  ADVERTENCIA: ETCD cluster no detectado en puerto 2379"
        echo "   El sistema ETCD v3.1 requiere ETCD para operar"
        echo ""
    fi
}

# Función principal
main() {
    local mode="monitor"

    # Parsear argumentos
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--interval)
                if [[ -n $2 && $2 =~ ^[0-9]+$ ]]; then
                    REFRESH_INTERVAL=$2
                    shift 2
                else
                    echo "❌ Error: -i requiere un número válido"
                    exit 1
                fi
                ;;
            -s|--status)
                mode="status"
                shift
                ;;
            *)
                echo "❌ Opción desconocida: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Verificar dependencias
    check_dependencies

    # Ejecutar modo seleccionado
    case $mode in
        "monitor")
            echo "🚀 Iniciando monitor ETCD v3.1 en tiempo real..."
            echo "⏱️  Intervalo de refresh: ${REFRESH_INTERVAL}s"
            echo "🔐 Verificando ETCD cluster..."
            echo "🛑 Presiona Ctrl+C para salir"
            echo ""
            sleep 2
            monitor_system
            ;;
        "status")
            # Para modo status, ejecutar una vez y salir después de mostrar info
            clear
            echo "🧬 ESTADO ACTUAL DEL SISTEMA AUTOINMUNE DIGITAL v3.1 ETCD"
            echo "=========================================================="
            echo ""

            # Verificar ETCD primero
            if check_etcd; then
                echo -e "🔐 ETCD Cluster: ${GREEN}✅ ACTIVO${NC}"
            else
                echo -e "🔐 ETCD Cluster: ${RED}❌ OFFLINE${NC} - Sistema no operacional"
            fi
            echo ""

            local components="sniffer geoip ml scheduler firewall dashboard"
            local active_components=0

            for component in $components; do
                local component_info=$(get_component_info "$component")
                local pattern=$(echo "$component_info" | cut -d'|' -f1)
                local name=$(echo "$component_info" | cut -d'|' -f2)

                printf "%-35s" "$name"
                if is_process_active "$pattern"; then
                    local cpu=$(get_cpu_usage "$pattern")
                    local mem=$(get_mem_usage "$pattern")
                    printf "${GREEN}✅ ACTIVO${NC} (CPU: ${cpu}%%, RAM: ${mem}%%)\n"
                    ((active_components++))
                else
                    printf "${RED}❌ OFFLINE${NC}\n"
                fi
            done

            echo ""
            echo "📊 Resumen: $active_components/6 componentes v3.1 ETCD activos"
            echo ""
            echo "🔧 Para monitor completo: $0"
            echo "📊 Dashboard v3.1 ETCD: http://localhost:8080"
            echo "🔐 ETCD cluster: localhost:2379"
            ;;
    esac
}

# Manejar señales
trap 'echo -e "\n\n${YELLOW}🛑 Monitor ETCD v3.1 detenido por el usuario${NC}"; exit 0' INT TERM

# Ejecutar función principal
main "$@"