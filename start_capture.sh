#!/bin/bash
# Script de inicio completo para captura de tráfico normal
# Promiscuous Agent v2 + Traffic Generator

echo "🚀 SISTEMA DE CAPTURA DE TRÁFICO NORMAL"
echo "========================================"
echo "Para entrenar modelos con advanced-trainer.py"
echo ""

# Verificar que estamos en el directorio correcto
if [ ! -f "promiscuous_agent_v2.py" ]; then
    echo "❌ Error: promiscuous_agent_v2.py no encontrado"
    echo "   Ejecuta este script desde el directorio del proyecto"
    exit 1
fi

# Verificar archivos necesarios
echo "🔍 Verificando archivos necesarios..."

required_files=(
    "promiscuous_agent_v2.py"
    "geoip_enricher_v2.py"
    "geodata/GeoLite2-City.mmdb"
    "geodata/GeoLite2-Country.mmdb"
    "geodata/GeoLite2-ASN-Test.mmdb"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        echo "  ❌ $file - FALTANTE"
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo ""
    echo "❌ Faltan archivos críticos:"
    printf '   %s\n' "${missing_files[@]}"
    echo ""
    echo "💡 Soluciones:"
    echo "   - Para geodata/GeoLite2-*.mmdb: Descargar desde MaxMind"
    echo "     https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "   - Para scripts: Verificar que están en el directorio"
    echo "   - Ejecutar: python verify_setup.py (verificación completa)"
    echo ""
    echo "🔧 Para el archivo ASN específicamente:"
    echo "   - Si tienes GeoLite2-ASN.mmdb, renómbralo a GeoLite2-ASN-Test.mmdb"
    echo "   - O descarga la versión correcta desde MaxMind"
    exit 1
fi

# Verificar permisos de root
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "⚠️  Este script necesita permisos de root para captura de paquetes"
    echo "   Relanzando con sudo..."
    exec sudo "$0" "$@"
fi

echo "✅ Verificaciones completadas"
echo ""

# Función para iniciar el agente en background
start_agent() {
    echo "🎯 Iniciando Promiscuous Agent v2..."

    # Crear logs directory
    mkdir -p logs

    # Iniciar agente en background
    python3 promiscuous_agent_v2.py \
        --interface auto \
        --output normal_traffic.csv \
        > logs/agent.log 2>&1 &

    AGENT_PID=$!
    echo "🔄 Agente iniciado con PID: $AGENT_PID"

    # Verificar que inició correctamente
    sleep 3
    if ! kill -0 $AGENT_PID 2>/dev/null; then
        echo "❌ Error: El agente no se inició correctamente"
        echo "   Revisar logs/agent.log para más detalles"
        tail -20 logs/agent.log
        exit 1
    fi

    echo "✅ Agente funcionando correctamente"
    return 0
}

# Función para iniciar generador de tráfico
start_traffic_generator() {
    local mode=${1:-"auto"}

    echo ""
    echo "🌐 Iniciando generador de tráfico..."

    if [ ! -f "websites_database.csv" ]; then
        echo "⚠️  websites_database.csv no encontrado, usando script bash..."

        if [ -f "quick_traffic.sh" ]; then
            chmod +x quick_traffic.sh
            echo "🚀 Ejecutando generador bash en modo $mode..."

            case $mode in
                "turbo")
                    ./quick_traffic.sh --turbo &
                    ;;
                "test")
                    ./quick_traffic.sh --test &
                    ;;
                *)
                    ./quick_traffic.sh --auto &
                    ;;
            esac

            TRAFFIC_PID=$!
            echo "🔄 Generador bash iniciado con PID: $TRAFFIC_PID"
        else
            echo "❌ No se encontró generador de tráfico"
            return 1
        fi
    else
        echo "🐍 Usando generador Python avanzado..."

        case $mode in
            "turbo")
                python3 traffic_generator.py --mode turbo --duration 10 &
                ;;
            "test")
                python3 traffic_generator.py --mode single --batch-size 20 &
                ;;
            *)
                python3 traffic_generator.py --mode continuous --batch-size 30 --interval 5 &
                ;;
        esac

        TRAFFIC_PID=$!
        echo "🔄 Generador Python iniciado con PID: $TRAFFIC_PID"
    fi

    return 0
}

# Función para monitorear progreso
monitor_progress() {
    echo ""
    echo "📊 MONITOREO EN TIEMPO REAL"
    echo "============================"
    echo "Presiona Ctrl+C para parar la captura"
    echo ""

    # Contadores
    local last_lines=0
    local start_time=$(date +%s)

    while true; do
        sleep 10

        # Verificar que el agente sigue ejecutándose
        if ! kill -0 $AGENT_PID 2>/dev/null; then
            echo "⚠️  El agente se detuvo inesperadamente"
            break
        fi

        # Estadísticas del CSV
        if [ -f "normal_traffic.csv" ]; then
            current_lines=$(wc -l < normal_traffic.csv)
            flows=$((current_lines - 1))  # -1 por el header

            if [ $flows -gt 0 ]; then
                new_flows=$((flows - last_lines))
                elapsed=$(($(date +%s) - start_time))
                rate=$(echo "scale=1; $flows / $elapsed" | bc -l 2>/dev/null || echo "0")

                echo "📈 Flujos capturados: $flows (+$new_flows) | Tasa: $rate flujos/s"

                # Mostrar sample de países si hay datos
                if [ $flows -gt 10 ]; then
                    countries=$(tail -n 20 normal_traffic.csv | cut -d',' -f21 | sort | uniq -c | sort -nr | head -5)
                    echo "🌍 Países recientes: $(echo "$countries" | tr '\n' ' ')"
                fi

                last_lines=$flows
            else
                echo "⏳ Esperando primeros flujos..."
            fi
        else
            echo "⏳ Esperando archivo CSV..."
        fi

        # Verificar si ya tenemos suficientes datos
        if [ -f "normal_traffic.csv" ]; then
            lines=$(wc -l < normal_traffic.csv)
            if [ $lines -gt 5000 ]; then
                echo ""
                echo "🎉 ¡Dataset básico completado! (5000+ flujos)"
                echo "💡 Puedes parar ahora con Ctrl+C o seguir para más datos"
            elif [ $lines -gt 15000 ]; then
                echo ""
                echo "🏆 ¡Dataset excelente! (15000+ flujos)"
                echo "🎯 Recomendado parar y usar con advanced-trainer.py"
            fi
        fi
    done
}

# Función de limpieza
cleanup() {
    echo ""
    echo "🧹 Limpiando procesos..."

    # Parar agente
    if [ ! -z "$AGENT_PID" ]; then
        kill -TERM $AGENT_PID 2>/dev/null
        sleep 2
        kill -KILL $AGENT_PID 2>/dev/null
        echo "🛑 Agente detenido"
    fi

    # Parar generador de tráfico
    if [ ! -z "$TRAFFIC_PID" ]; then
        kill -TERM $TRAFFIC_PID 2>/dev/null
        sleep 1
        kill -KILL $TRAFFIC_PID 2>/dev/null
        echo "🛑 Generador de tráfico detenido"
    fi

    # Estadísticas finales
    if [ -f "normal_traffic.csv" ]; then
        lines=$(wc -l < normal_traffic.csv)
        flows=$((lines - 1))
        size=$(du -h normal_traffic.csv | cut -f1)

        echo ""
        echo "📊 ESTADÍSTICAS FINALES"
        echo "======================="
        echo "📁 Archivo: normal_traffic.csv"
        echo "📈 Flujos capturados: $flows"
        echo "💾 Tamaño: $size"

        if [ $flows -gt 1000 ]; then
            echo "✅ Dataset listo para advanced-trainer.py"
        else
            echo "⚠️  Dataset pequeño, considera capturar más datos"
        fi
    fi

    echo ""
    echo "👋 Captura finalizada"
    exit 0
}

# Configurar trap para limpieza
trap cleanup INT TERM

# Función principal
main() {
    local mode="auto"

    # Procesar argumentos
    case "$1" in
        "--turbo")
            mode="turbo"
            echo "🚀 Modo TURBO activado (captura acelerada)"
            ;;
        "--test")
            mode="test"
            echo "🧪 Modo TEST activado (captura breve)"
            ;;
        "--help"|"-h")
            echo "Uso: $0 [--turbo|--test|--help]"
            echo ""
            echo "Opciones:"
            echo "  --turbo    Captura acelerada con tráfico masivo"
            echo "  --test     Captura de prueba (pocos minutos)"
            echo "  --help     Mostrar esta ayuda"
            exit 0
            ;;
        "")
            echo "🎯 Modo NORMAL activado (captura estándar)"
            ;;
        *)
            echo "❌ Opción desconocida: $1"
            echo "   Usa --help para ver opciones disponibles"
            exit 1
            ;;
    esac

    echo ""
    echo "🚀 Iniciando sistema de captura en modo: $mode"
    echo ""

    # Iniciar componentes
    start_agent
    sleep 2  # Dar tiempo al agente para inicializar

    start_traffic_generator "$mode"
    sleep 3  # Dar tiempo al generador para inicializar

    # Monitorear progreso
    monitor_progress
}

# Mostrar información inicial
echo "💡 Este script:"
echo "   1. Inicia el agente de captura de paquetes"
echo "   2. Genera tráfico hacia sitios web mundiales"
echo "   3. Monitorea el progreso en tiempo real"
echo "   4. Crea normal_traffic.csv para advanced-trainer.py"
echo ""

# Ejecutar script principal
main "$@"