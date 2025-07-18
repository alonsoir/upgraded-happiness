#!/bin/bash
# Test del Pipeline Completo: promiscuous_agent → geoip_enricher → consumer

echo "🔗 TEST PIPELINE COMPLETO - UPGRADED HAPPINESS"
echo "=" * 70
echo "Pipeline: promiscuous_agent → geoip_enricher → consumer"
echo "Puertos: 5559 (promiscuous→geoip) | 5560 (geoip→consumer)"
echo ""

# Función para limpiar procesos
cleanup() {
    echo ""
    echo "🧹 Limpiando procesos..."
    sudo pkill -f "promiscuous_agent.py" 2>/dev/null || true
    pkill -f "geoip_enricher.py" 2>/dev/null || true
    pkill -f "zmq_consumer_test" 2>/dev/null || true

    # Limpiar puertos
    sudo lsof -t -i :5559 | xargs sudo kill -9 2>/dev/null || true
    sudo lsof -t -i :5560 | xargs sudo kill -9 2>/dev/null || true

    sleep 2
}

# Verificar archivos necesarios
check_files() {
    echo "📁 Verificando archivos necesarios..."

    local missing=0

    for file in "promiscuous_agent.py" "enhanced_agent_config.json" \
               "geoip_enricher.py" "geoip_enricher_config.json" \
               "zmq_consumer_test_from_promiscuous.py" \
               "zmq_consumer_test_from_geoip.py"; do
        if [ ! -f "$file" ]; then
            echo "❌ Archivo faltante: $file"
            missing=1
        else
            echo "✅ $file"
        fi
    done

    if [ $missing -eq 1 ]; then
        echo ""
        echo "❌ Faltan archivos necesarios. No se puede continuar."
        exit 1
    fi

    echo "✅ Todos los archivos presentes"
}

# Verificar configuraciones
test_configs() {
    echo ""
    echo "📄 Validando configuraciones..."

    echo "Testing promiscuous_agent config..."
    python promiscuous_agent.py --test-config enhanced_agent_config.json || exit 1

    echo "Testing geoip_enricher config..."
    python geoip_enricher.py --test-config geoip_enricher_config.json || exit 1

    echo "✅ Configuraciones válidas"
}

# Test manual (3 terminales)
test_manual() {
    echo ""
    echo "🎯 MODO MANUAL - 3 TERMINALES"
    echo "=" * 40
    echo ""
    echo "TERMINAL 1 - Consumer final:"
    echo "cd $(pwd)"
    echo "python zmq_consumer_test_from_geoip.py"
    echo ""
    echo "TERMINAL 2 - GeoIP Enricher:"
    echo "cd $(pwd)"
    echo "python geoip_enricher.py geoip_enricher_config.json"
    echo ""
    echo "TERMINAL 3 - Promiscuous Agent:"
    echo "cd $(pwd)"
    echo "sudo python promiscuous_agent.py enhanced_agent_config.json"
    echo ""
    echo "🎯 ORDEN DE ARRANQUE:"
    echo "1. Arrancar Terminal 1 (consumer)"
    echo "2. Arrancar Terminal 2 (geoip_enricher)"
    echo "3. Arrancar Terminal 3 (promiscuous_agent)"
    echo ""
    echo "✅ RESULTADO ESPERADO:"
    echo "- Terminal 1: Eventos con coordenadas geográficas"
    echo "- Terminal 2: Logs de enriquecimiento GeoIP"
    echo "- Terminal 3: Captura de paquetes sin warnings"
}

# Test automático
test_automatic() {
    echo ""
    echo "🤖 MODO AUTOMÁTICO"
    echo "=" * 40

    cleanup

    echo ""
    echo "🚀 Arrancando pipeline en background..."

    # Terminal 1: Consumer
    echo "📡 Arrancando consumer..."
    python zmq_consumer_test_from_geoip.py > consumer_output.log 2>&1 &
    CONSUMER_PID=$!
    sleep 2

    # Terminal 2: GeoIP Enricher
    echo "🌍 Arrancando geoip_enricher..."
    python geoip_enricher.py geoip_enricher_config.json > geoip_output.log 2>&1 &
    GEOIP_PID=$!
    sleep 3

    # Terminal 3: Promiscuous Agent
    echo "📦 Arrancando promiscuous_agent..."
    sudo python promiscuous_agent.py enhanced_agent_config.json > promiscuous_output.log 2>&1 &
    PROMISCUOUS_PID=$!

    echo ""
    echo "📊 PIDs: Consumer=$CONSUMER_PID | GeoIP=$GEOIP_PID | Promiscuous=$PROMISCUOUS_PID"
    echo ""
    echo "⏱️ Dejando correr el pipeline por 30 segundos..."

    # Monitor por 30 segundos
    for i in {1..30}; do
        echo -n "."
        sleep 1
    done
    echo ""

    echo ""
    echo "🔍 Verificando resultados..."

    # Verificar logs
    echo ""
    echo "📊 RESULTADOS DEL CONSUMER:"
    if [ -f "consumer_output.log" ]; then
        tail -10 consumer_output.log
    else
        echo "❌ No se generó consumer_output.log"
    fi

    echo ""
    echo "📊 RESULTADOS DEL GEOIP ENRICHER:"
    if [ -f "geoip_output.log" ]; then
        tail -10 geoip_output.log
    else
        echo "❌ No se generó geoip_output.log"
    fi

    echo ""
    echo "📊 RESULTADOS DEL PROMISCUOUS AGENT:"
    if [ -f "promiscuous_output.log" ]; then
        tail -10 promiscuous_output.log
    else
        echo "❌ No se generó promiscuous_output.log"
    fi

    # Cleanup
    cleanup

    echo ""
    echo "📄 Logs guardados en:"
    echo "   - consumer_output.log"
    echo "   - geoip_output.log"
    echo "   - promiscuous_output.log"
}

# Test paso a paso
test_step_by_step() {
    echo ""
    echo "👣 MODO PASO A PASO"
    echo "=" * 40

    cleanup

    echo ""
    echo "PASO 1: Arrancar consumer (simulando ml_detector)"
    echo "Presiona ENTER para continuar..."
    read

    python zmq_consumer_test_from_geoip.py &
    CONSUMER_PID=$!
    echo "📡 Consumer arrancado (PID: $CONSUMER_PID)"
    sleep 2

    echo ""
    echo "PASO 2: Arrancar geoip_enricher"
    echo "Presiona ENTER para continuar..."
    read

    python geoip_enricher.py geoip_enricher_config.json &
    GEOIP_PID=$!
    echo "🌍 GeoIP Enricher arrancado (PID: $GEOIP_PID)"
    sleep 3

    echo ""
    echo "PASO 3: Arrancar promiscuous_agent"
    echo "Presiona ENTER para continuar..."
    read

    sudo python promiscuous_agent.py enhanced_agent_config.json &
    PROMISCUOUS_PID=$!
    echo "📦 Promiscuous Agent arrancado (PID: $PROMISCUOUS_PID)"

    echo ""
    echo "🎯 Pipeline completo funcionando!"
    echo "   Monitorea los outputs en tiempo real"
    echo "   Presiona ENTER para detener..."
    read

    cleanup
}

# Menú principal
main_menu() {
    echo ""
    echo "🎯 SELECCIONA MODO DE TEST:"
    echo "1) Manual (3 terminales separadas)"
    echo "2) Automático (background + logs)"
    echo "3) Paso a paso (interactivo)"
    echo "4) Solo validar archivos y configs"
    echo "5) Salir"
    echo ""
    echo -n "Opción [1-5]: "
    read choice

    case $choice in
        1) test_manual ;;
        2) test_automatic ;;
        3) test_step_by_step ;;
        4) echo "✅ Solo validación completada" ;;
        5) echo "👋 Bye!"; exit 0 ;;
        *) echo "❌ Opción inválida"; main_menu ;;
    esac
}

# Ejecución principal
echo "🔍 Validación inicial..."
check_files
test_configs

# Trap para cleanup en caso de Ctrl+C
trap cleanup EXIT

main_menu

echo ""
echo "✅ Test completado"