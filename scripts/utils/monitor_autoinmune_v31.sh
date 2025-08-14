#!/bin/bash

# =============================================================================
# 🧬 Monitor Avanzado V3.1 - Sistema Autoinmune Digital v3.1
# =============================================================================
# Compatible con macOS bash - Versión V3.1 evolutiva
# Monitorea pipeline V3.1: evolutionary_sniffer → geoip_enricher → ml_detector_tricapa → scheduler → firewall_agent → dashboard
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

# Función para obtener información de componente V3.1
get_component_info_v31() {
    local component_type="$1"

    case "$component_type" in
        "evolutionary_sniffer")
            echo "evolutionary_sniffer_v31|🕵️  Evolutionary Sniffer V3.1|5559"
            ;;
        "geoip")
            echo "geoip_enricher_v31|🌍 GeoIP Enricher V3.1|5560"
            ;;
        "ml_tricapa")
            echo "lightweight_ml_detector_tricapa_v31|🤖 ML Detector Tricapa V3.1|5561"
            ;;
        "scheduler")
            echo "scheduler-firewall|🎯 Scheduler Firewall|5562"
            ;;
        "firewall_agent")
            echo "simple_firewall_agent_v31|🛡️  Firewall Agent V3.1|5562"
            ;;
        "dashboard")
            echo "dashboard_v31|📊 Dashboard V3.1|8080"
            ;;
    esac
}

# Función principal de monitoreo V3.1
monitor_system_v31() {
    while true; do
        clear

        # Header elegante V3.1
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                🧬 SISTEMA AUTOINMUNE DIGITAL V3.1 EVOLUTIVO                ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║ ${WHITE}$(date +'%A, %d %B %Y - %H:%M:%S %Z')${CYAN}                                         ║${NC}"
        echo -e "${CYAN}║ ${PURPLE}Pipeline V3.1: evolutionary_sniffer → geoip → ml_tricapa → scheduler → firewall → dashboard${CYAN} ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # Variables de estado para cada componente V3.1
        local components_v31="evolutionary_sniffer geoip ml_tricapa scheduler firewall_agent dashboard"

        # Estado general del sistema V3.1
        echo -e "${BOLD}${PURPLE}📊 ESTADO GENERAL SISTEMA V3.1${NC}"
        echo -e "${PURPLE}════════════════════════════════════════${NC}"

        local total_cpu=0
        local total_mem=0
        local active_components=0
        local total_components=6

        for component in $components_v31; do
            local component_info=$(get_component_info_v31 "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)

            if is_process_active "$pattern"; then
                ((active_components++))
                local cpu=$(get_cpu_usage "$pattern")
                local mem=$(get_mem_usage "$pattern")
                total_cpu=$(awk "BEGIN {print $total_cpu + $cpu}")
                total_mem=$(awk "BEGIN {print $total_mem + $mem}")
            fi
        done

        # Mostrar resumen general V3.1
        local health_percentage=$((active_components * 100 / total_components))
        echo -e "🎯 Estado V3.1: $(show_health_status "$health_percentage" "80" "60" "%") ($active_components/$total_components componentes activos)"
        echo -e "🔥 CPU Total: $(show_health_status "$total_cpu" "50" "100" "%") $(show_progress_bar "$total_cpu" "200")"
        echo -e "💾 RAM Total: $(show_health_status "$total_mem" "10" "20" "%") $(show_progress_bar "$total_mem" "30")"
        echo ""

        # Análisis detallado por componente V3.1
        echo -e "${BOLD}${YELLOW}🔍 ANÁLISIS DETALLADO COMPONENTES V3.1${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        echo ""

        for component in $components_v31; do
            local component_info=$(get_component_info_v31 "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)
            local name=$(echo "$component_info" | cut -d'|' -f2)
            local port=$(echo "$component_info" | cut -d'|' -f3)

            printf "%-35s" "$name"

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

        # Pipeline de datos visual V3.1
        echo -e "${BOLD}${CYAN}🔄 PIPELINE DE DATOS V3.1${NC}"
        echo -e "${CYAN}═══════════════════════════════════════${NC}"
        echo ""

        # Crear representación visual del pipeline V3.1
        local pipeline_status=""
        for component in $components_v31; do
            local component_info=$(get_component_info_v31 "$component")
            local pattern=$(echo "$component_info" | cut -d'|' -f1)

            if is_process_active "$pattern"; then
                pipeline_status="${pipeline_status}${GREEN}●${NC}"
            else
                pipeline_status="${pipeline_status}${RED}●${NC}"
            fi

            if [ "$component" != "dashboard" ]; then
                pipeline_status="${pipeline_status} ${GRAY}→${NC} "
            fi
        done

        echo -e "🕵️  Evolutionary Sniffer ${GRAY}→${NC} 🌍 GeoIP V3.1 ${GRAY}→${NC} 🤖 ML Tricapa ${GRAY}→${NC} 🎯 Scheduler ${GRAY}→${NC} 🛡️  Firewall ${GRAY}→${NC} 📊 Dashboard V3.1"
        echo -e "   $pipeline_status"
        echo ""

        # Métricas de rendimiento V3.1
        echo -e "${BOLD}${BLUE}📈 MÉTRICAS RENDIMIENTO V3.1${NC}"
        echo -e "${BLUE}════════════════════════════════════════════${NC}"

        # Buscar métricas en logs V3.1
        local throughput="N/A"
        local latency="N/A"
        local processed_events="N/A"
        local blocked_ips="N/A"
        local ensemble_confidence="N/A"

        if [ -d "$LOG_DIR" ]; then
            # Throughput
            local throughput_raw=$(find "$LOG_DIR" -name "*_v31.log" -exec tail -10 {} \; 2>/dev/null | grep -o "[0-9]\+\.[0-9]/s" | tail -1)
            if [ -n "$throughput_raw" ]; then
                throughput="$throughput_raw"
            fi

            # Latencia V3.1 (pipeline_latency)
            local latency_raw=$(find "$LOG_DIR" -name "*_v31.log" -exec tail -10 {} \; 2>/dev/null | grep -o "pipeline_latency[: ]*[0-9]\+\.[0-9]*ms" | tail -1 | grep -o "[0-9]\+\.[0-9]*ms")
            if [ -n "$latency_raw" ]; then
                latency="$latency_raw"
            fi

            # Eventos procesados V3.1
            local events_raw=$(find "$LOG_DIR" -name "*dashboard_v31*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "Events:[: ]*[0-9]\+" | tail -1 | grep -o "[0-9]\+")
            if [ -n "$events_raw" ]; then
                processed_events="$events_raw"
            fi

            # Ensemble confidence V3.1
            local confidence_raw=$(find "$LOG_DIR" -name "*ml_detector_tricapa_v31*.log" -exec tail -5 {} \; 2>/dev/null | grep -o "ensemble_confidence[: ]*[0-9]\+\.[0-9]*" | tail -1 | grep -o "[0-9]\+\.[0-9]*")
            if [ -n "$confidence_raw" ]; then
                ensemble_confidence="${confidence_raw}%"
            fi

            # IPs bloqueadas V3.1
            local blocked_raw=$(find "$LOG_DIR" -name "*firewall*v31*.log" -exec tail -10 {} \; 2>/dev/null | grep -c "blocked\|denied\|BLOCK_IP" 2>/dev/null)
            if [[ ! "$blocked_raw" =~ ^[0-9]+$ ]]; then
                blocked_raw=0
            fi
            if [ "$blocked_raw" -gt "0" ]; then
                blocked_ips="$blocked_raw"
            fi
        fi

        printf "%-30s %s\n" "⚡ Throughput V3.1:" "$throughput"
        printf "%-30s %s\n" "⏱️  Pipeline Latency:" "$latency"
        printf "%-30s %s\n" "📊 Eventos Procesados:" "$processed_events"
        printf "%-30s %s\n" "🧠 Ensemble Confidence:" "$ensemble_confidence"
        printf "%-30s %s\n" "🚫 IPs Bloqueadas:" "$blocked_ips"
        echo ""

        # Análisis de red V3.1
        echo -e "${BOLD}${PURPLE}🌐 ANÁLISIS DE RED V3.1${NC}"
        echo -e "${PURPLE}═══════════════════════════════════════${NC}"

        # Puertos ZeroMQ V3.1 activos
        local zmq_ports=$(netstat -an 2>/dev/null | grep -E "LISTEN.*:(555[0-9]|556[0-9]|8080|5580)" | wc -l | tr -d ' ')
        if [[ ! "$zmq_ports" =~ ^[0-9]+$ ]]; then
            zmq_ports=0
        fi
        printf "%-25s " "🔌 Puertos ZeroMQ V3.1:"
        if [ "$zmq_ports" -gt "4" ]; then
            echo -e "${GREEN}$zmq_ports activos${NC} ✅"
        elif [ "$zmq_ports" -gt "0" ]; then
            echo -e "${YELLOW}$zmq_ports activos${NC} ⚠️"
        else
            echo -e "${RED}$zmq_ports activos${NC} ❌"
        fi

        # Dashboard V3.1 específico
        printf "%-25s " "📊 Dashboard V3.1:"
        if check_port "8080" && is_process_active "dashboard_v31"; then
            echo -e "${GREEN}OPERATIVO${NC} 🎯 http://localhost:8080"
        else
            echo -e "${RED}OFFLINE${NC} ❌"
        fi

        # Protobuf V3.1 status
        printf "%-25s " "🔒 Protobuf V3.1:"
        if [ -f "protocols/current/network_security_clean_v31_pb2.py" ]; then
            echo -e "${GREEN}COMPILADO${NC} ✅"
        else
            echo -e "${RED}FALTA${NC} ❌"
        fi

        echo ""

        # Alertas y recomendaciones V3.1
        echo -e "${BOLD}${RED}🚨 ALERTAS Y RECOMENDACIONES V3.1${NC}"
        echo -e "${RED}════════════════════════════════════════════════${NC}"

        local alerts=0

        # Verificar componentes offline V3.1
        if [ "$active_components" -lt "$total_components" ]; then
            echo -e "${RED}⚠️  CRÍTICO V3.1:${NC} $((total_components - active_components)) componente(s) V3.1 offline"
            ((alerts++))
        fi

        # Verificar alta CPU
        local high_cpu=$(awk "BEGIN {print ($total_cpu > 150)}")
        if [ "$high_cpu" = "1" ]; then
            echo -e "${RED}⚠️  CRÍTICO:${NC} Alta carga de CPU (${total_cpu}%)"
            ((alerts++))
        fi

        # Verificar puertos ZeroMQ V3.1
        if [ "$zmq_ports" -eq "0" ]; then
            echo -e "${YELLOW}⚠️  ADVERTENCIA V3.1:${NC} Sin puertos ZeroMQ V3.1 activos"
            ((alerts++))
        fi

        # Verificar dashboard V3.1 específico
        if ! is_process_active "dashboard_v31"; then
            echo -e "${YELLOW}⚠️  ADVERTENCIA:${NC} Dashboard V3.1 no está activo"
            ((alerts++))
        fi

        # Verificar logs de errores recientes V3.1
        if [ -d "$LOG_DIR" ]; then
            local recent_errors=$(find "$LOG_DIR" -name "*_v31.log" -newermt "-60 seconds" -exec grep -l -i "error\|exception\|failed" {} \; 2>/dev/null | wc -l | tr -d ' ')
            if [[ ! "$recent_errors" =~ ^[0-9]+$ ]]; then
                recent_errors=0
            fi
            if [ "$recent_errors" -gt "0" ]; then
                echo -e "${YELLOW}⚠️  ADVERTENCIA V3.1:${NC} $recent_errors archivo(s) V3.1 con errores recientes"
                ((alerts++))
            fi
        fi

        if [ "$alerts" -eq "0" ]; then
            echo -e "${GREEN}✅ SISTEMA V3.1 OPERACIONAL${NC} - No se detectaron problemas críticos"
        fi

        echo ""

        # Footer con controles V3.1
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║ ${WHITE}🎮 CONTROLES V3.1:${NC} ${GRAY}Ctrl+C para salir${NC} ${CYAN}│${NC} ${WHITE}📊 Dashboard V3.1:${NC} ${BLUE}http://localhost:8080${NC} ${CYAN}     ║${NC}"
        echo -e "${CYAN}║ ${WHITE}🔧 Pipeline:${NC} ${GREEN}make start_v31${NC} ${CYAN}│${NC} ${WHITE}🛑 Parada:${NC} ${RED}make stop-nuclear${NC} ${CYAN}                    ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"

        # Esperar antes del siguiente refresh
        sleep $REFRESH_INTERVAL
    done
}

# Función de ayuda V3.1
show_help() {
    echo "🧬 Monitor Sistema Autoinmune Digital V3.1"
    echo "=========================================="
    echo ""
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help          Mostrar esta ayuda"
    echo "  -i, --interval N    Intervalo de refresh en segundos (default: 5)"
    echo "  -s, --status        Mostrar estado una vez y salir"
    echo ""
    echo "Componentes V3.1 monitoreados:"
    echo "  🕵️  evolutionary_sniffer_v31.py      - Puerto 5559"
    echo "  🌍 geoip_enricher_v31.py           - Puerto 5560"
    echo "  🤖 lightweight_ml_detector_tricapa_v31.py - Puerto 5561"
    echo "  🎯 scheduler-firewall.py            - Orquestador"
    echo "  🛡️  simple_firewall_agent_v31.py    - Puerto 5562"
    echo "  📊 dashboard_v31.py                 - Puerto 8080"
    echo ""
    echo "Ejemplos:"
    echo "  $0                  # Monitor V3.1 en tiempo real"
    echo "  $0 -i 10           # Refresh cada 10 segundos"
    echo "  $0 -s              # Estado único V3.1"
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
            echo "🚀 Iniciando monitor V3.1 en tiempo real..."
            echo "⏱️  Intervalo de refresh: ${REFRESH_INTERVAL}s"
            echo "🛑 Presiona Ctrl+C para salir"
            echo ""
            sleep 2
            monitor_system_v31
            ;;
        "status")
            # Para modo status V3.1, ejecutar una vez y salir después de mostrar info
            clear
            echo "🧬 ESTADO ACTUAL DEL SISTEMA AUTOINMUNE DIGITAL V3.1"
            echo "====================================================="
            echo ""

            local components_v31="evolutionary_sniffer geoip ml_tricapa scheduler firewall_agent dashboard"
            local active_components=0

            for component in $components_v31; do
                local component_info=$(get_component_info_v31 "$component")
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
            echo "📊 Resumen V3.1: $active_components/6 componentes activos"
            echo ""
            echo "🔧 Para monitor completo V3.1: $0"
            echo "📊 Dashboard V3.1: http://localhost:8080"
            echo "🚀 Iniciar V3.1: make start_v31"
            ;;
    esac
}

# Manejar señales
trap 'echo -e "\n\n${YELLOW}🛑 Monitor V3.1 detenido por el usuario${NC}"; exit 0' INT TERM

# Ejecutar función principal
main "$@"