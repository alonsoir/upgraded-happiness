#!/bin/bash

# =============================================================================
# 🧬 Monitor Avanzado - Sistema Autoinmune Digital v2.0
# =============================================================================
# Compatible con macOS bash - Sin arrays asociativos
# Versión optimizada para máxima compatibilidad
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

# Función para obtener información de componente
get_component_info() {
    local component_type="$1"

    case "$component_type" in
        "promiscuous")
            echo "promiscuous_agent|🕵️  Promiscuous Agent|5559"
            ;;
        "geoip")
            echo "geoip_enricher|🌍 GeoIP Enricher|5560"
            ;;
        "ml")
            echo "lightweight_ml_detector|🤖 ML Detector|5561"
            ;;
        "dashboard")
            echo "real_zmq_dashboard_with_firewall|📊 Dashboard|8080"
            ;;
        "firewall")
            echo "simple_firewall_agent|🛡️  Firewall Agent|5562"
            ;;
    esac
}
# Variable para rango de horas a considerar logs "recientes"
LOG_MAX_AGE_HOURS=24

# Función que lista logs recientes y obtiene métricas solo de ellos
process_recent_logs_metrics() {
    local recent_logs
    recent_logs=$(find "$LOG_DIR" -type f -name "*.log" -mtime -$((LOG_MAX_AGE_HOURS/24)) 2>/dev/null)

    if [ -z "$recent_logs" ]; then
        echo "⚠️ No se detectaron logs modificados en las últimas $LOG_MAX_AGE_HOURS horas."
        throughput="N/A"
        latency="N/A"
        processed_events="N/A"
        blocked_ips="N/A"
        return
    fi

    # Procesar métricas sobre logs recientes
    throughput=$(grep -h -oE "[0-9]+\.[0-9]+/s" $recent_logs 2>/dev/null | tail -1)
    latency=$(grep -h -oE "[0-9]+\.[0-9]*ms" $recent_logs 2>/dev/null | tail -1)
    processed_events=$(grep -h -oE "Procesados[: ]*[0-9]+" $recent_logs 2>/dev/null | tail -1 | grep -oE "[0-9]+")
    blocked_ips=$(grep -h -cE "bloqueada|blocked|denied" $(echo "$recent_logs" | grep firewall) 2>/dev/null)

    # Validaciones básicas
    [ -z "$throughput" ] && throughput="N/A"
    [ -z "$latency" ] && latency="N/A"
    [ -z "$processed_events" ] && processed_events="N/A"
    [ -z "$blocked_ips" ] && blocked_ips="0"
}


# Función para contar puertos ZeroMQ activos (5500-6000 + 8080)
count_zmq_ports() {
    local count=$(lsof -iTCP 2>/dev/null \
        | grep -E ':(5500|5[5-9][0-9]|60[0-0])|:8080' \
        | grep -v "CLOSE_WAIT" \
        | awk '{print $9}' \
        | grep -oE '[0-9]+$' \
        | sort -u \
        | wc -l)

    if [ "$count" -gt 0 ]; then
        echo -e "${GREEN}🧠 Puertos ZeroMQ activos: $count${NC}"
    else
        echo -e "${RED}🧠 Puertos ZeroMQ activos: $count${NC}"
    fi
}

# Función principal de monitoreo
monitor_system() {
    while true; do
        clear

        # Header elegante
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    🧬 SISTEMA AUTOINMUNE DIGITAL v2.0                       ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║ ${WHITE}$(date +'%A, %d %B %Y - %H:%M:%S %Z')${CYAN}                                         ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # Variables de estado para cada componente
        local components="promiscuous geoip ml dashboard firewall"

        # Estado general del sistema
        echo -e "${BOLD}${PURPLE}📊 ESTADO GENERAL DEL SISTEMA${NC}"
        echo -e "${PURPLE}════════════════════════════════════════${NC}"

        local total_cpu=0
        local total_mem=0
        local active_components=0
        local total_components=5

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
        echo -e "🔥 CPU Total: $(show_health_status "$total_cpu" "50" "100" "%") $(show_progress_bar "$total_cpu" "200")"
        echo -e "💾 RAM Total: $(show_health_status "$total_mem" "10" "20" "%") $(show_progress_bar "$total_mem" "30")"
        echo ""

        # Análisis detallado por componente
        echo -e "${BOLD}${YELLOW}🔍 ANÁLISIS DETALLADO DE COMPONENTES${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        echo ""

        for component in $components; do
            local component_info=$(get_component_info "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)
            local name=$(echo "$component_info" | cut -d'|' -f2)
            local port=$(echo "$component_info" | cut -d'|' -f3)

            printf "%-25s" "$name"

            if is_process_active "$pattern"; then
                local cpu=$(get_cpu_usage "$pattern")
                local mem=$(get_mem_usage "$pattern")
                local uptime=$(get_process_uptime "$pattern")

                printf "${GREEN}●${NC} ACTIVO   "
                printf "CPU$(show_progress_bar "$cpu" "100") $(show_health_status "$cpu" "30" "70" "%%")  "
                printf "RAM$(show_health_status "$mem" "5" "15" "%%")  "
                printf "⏱️  ${GRAY}${uptime}${NC}"

                # Verificar puerto específico
                if check_port "$port"; then
                    printf "  🌐 $port"
                else
                    printf "  ${RED}✗${NC} $port"
                fi

            else
                printf "${RED}●${NC} OFFLINE  "
                printf "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            fi
            echo ""
        done

        echo ""

        # Pipeline de datos visual
        echo -e "${BOLD}${CYAN}🔄 PIPELINE DE DATOS${NC}"
        echo -e "${CYAN}═══════════════════════════════════════${NC}"
        echo ""

        # Crear representación visual del pipeline
        local pipeline_status=""
        for component in $components; do
            local component_info=$(get_component_info "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)

            if is_process_active "$pattern"; then
                pipeline_status="${pipeline_status}${GREEN}●${NC}"
            else
                pipeline_status="${pipeline_status}${RED}●${NC}"
            fi

            if [ "$component" != "firewall" ]; then
                pipeline_status="${pipeline_status} ${GRAY}→${NC} "
            fi
        done

        echo -e "📡 Captura ${GRAY}→${NC} 🌍 GeoIP ${GRAY}→${NC} 🤖 ML ${GRAY}→${NC} 📊 Dashboard ${GRAY}→${NC} 🛡️  Firewall"
        echo -e "   $pipeline_status"
        echo ""

        # Métricas de rendimiento
        echo -e "${BOLD}${BLUE}📈 MÉTRICAS DE RENDIMIENTO${NC}"
        echo -e "${BLUE}════════════════════════════════════════════${NC}"

        # Buscar métricas en logs
        local throughput="N/A"
        local latency="N/A"
        local processed_events="N/A"
        local blocked_ips="N/A"

        if [ -d "$LOG_DIR" ]; then
        # Aquí llamas a:
          process_recent_logs_metrics
        fi

        printf "%-25s %s\n" "⚡ Throughput:" "$throughput"
        printf "%-25s %s\n" "⏱️  Latencia promedio:" "$latency"
        printf "%-25s %s\n" "📊 Eventos procesados:" "$processed_events"
        printf "%-25s %s\n" "🚫 IPs bloqueadas:" "$blocked_ips"
        echo ""

        # Análisis de red
        echo -e "${BOLD}${PURPLE}🌐 ANÁLISIS DE RED${NC}"
        echo -e "${PURPLE}═══════════════════════════════════════${NC}"

        # Puertos ZeroMQ activos (mejorado)
        local zmq_ports=$(lsof -iTCP 2>/dev/null \
        | grep -E ':(5500|5[5-9][0-9]|60[0-0])|:8080' \
        | grep -v "CLOSE_WAIT" \
        | awk '{print $9}' \
        | grep -oE '[0-9]+$' \
        | sort -u \
        | wc -l)
        # Validar que zmq_ports es un número
        if [[ ! "$zmq_ports" =~ ^[0-9]+$ ]]; then
            zmq_ports=0
        fi
        printf "%-25s " "🔌 Puertos ZeroMQ:"
        if [ "$zmq_ports" -gt 0 ]; then
          echo -e "${GREEN}$zmq_ports activos${NC} ✅"
        else
          echo -e "${RED}$zmq_ports activos${NC} ❌"
        fi


        # Conexiones activas (mejorado)
        local active_connections=$(netstat -an 2>/dev/null | grep "ESTABLISHED" | wc -l | tr -d ' ')
        # Validar que active_connections es un número
        if [[ ! "$active_connections" =~ ^[0-9]+$ ]]; then
            active_connections=0
        fi
        printf "%-25s " "🔗 Conexiones activas:"
        echo -e "$(show_health_status "$active_connections" "100" "200" "")"

        echo ""

        # Alertas y recomendaciones
        echo -e "${BOLD}${RED}🚨 ALERTAS Y RECOMENDACIONES${NC}"
        echo -e "${RED}════════════════════════════════════════════════${NC}"

        local alerts=0

        # Verificar componentes offline
        if [ "$active_components" -lt "$total_components" ]; then
            echo -e "${RED}⚠️  CRÍTICO:${NC} $((total_components - active_components)) componente(s) offline"
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
            echo -e "${YELLOW}⚠️  ADVERTENCIA:${NC} Sin puertos ZeroMQ activos"
            ((alerts++))
        fi

        # Verificar logs de errores recientes
        if [ -d "$LOG_DIR" ]; then
            local recent_errors=$(find "$LOG_DIR" -name "*.log" -newermt "-60 seconds" -exec grep -l -i "error\|exception\|failed" {} \; 2>/dev/null | wc -l | tr -d ' ')
            # Asegurar que recent_errors es un número válido
            if [[ ! "$recent_errors" =~ ^[0-9]+$ ]]; then
                recent_errors=0
            fi
            if [ "$recent_errors" -gt "0" ]; then
                echo -e "${YELLOW}⚠️  ADVERTENCIA:${NC} $recent_errors archivo(s) con errores recientes"
                ((alerts++))
            fi
        fi

        if [ "$alerts" -eq "0" ]; then
            echo -e "${GREEN}✅ SISTEMA OPERACIONAL${NC} - No se detectaron problemas críticos"
        fi

        echo ""

        # Footer con controles
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║ ${WHITE}🎮 CONTROLES:${NC} ${GRAY}Ctrl+C para salir${NC} ${CYAN}│${NC} ${WHITE}📊 Dashboard:${NC} ${BLUE}http://localhost:8080${NC} ${CYAN}            ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"

        # Esperar antes del siguiente refresh
        sleep $REFRESH_INTERVAL
    done
}

# Función de ayuda
show_help() {
    echo "🧬 Monitor Sistema Autoinmune Digital v2.0"
    echo "=========================================="
    echo ""
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help          Mostrar esta ayuda"
    echo "  -i, --interval N    Intervalo de refresh en segundos (default: 5)"
    echo "  -s, --status        Mostrar estado una vez y salir"
    echo ""
    echo "Ejemplos:"
    echo "  $0                  # Monitor en tiempo real"
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
            echo "🚀 Iniciando monitor en tiempo real..."
            echo "⏱️  Intervalo de refresh: ${REFRESH_INTERVAL}s"
            echo "🛑 Presiona Ctrl+C para salir"
            echo ""
            sleep 2
            monitor_system
            ;;
        "status")
            # Para modo status, ejecutar una vez y salir después de mostrar info
            clear
            echo "🧬 ESTADO ACTUAL DEL SISTEMA AUTOINMUNE DIGITAL v2.0"
            echo "====================================================="
            echo ""

            local components="promiscuous geoip ml dashboard firewall"
            local active_components=0

            for component in $components; do
                local component_info=$(get_component_info "$component")
                local pattern=$(echo "$component_info" | cut -d'|' -f1)
                local name=$(echo "$component_info" | cut -d'|' -f2)

                printf "%-25s" "$name"
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
            echo "📊 Resumen: $active_components/5 componentes activos"
            echo ""
            echo "🔧 Para monitor completo: $0"
            echo "📊 Dashboard: http://localhost:8080"
            ;;
    esac
}

# Manejar señales
trap 'echo -e "\n\n${YELLOW}🛑 Monitor detenido por el usuario${NC}"; exit 0' INT TERM

# Ejecutar función principal
main "$@"