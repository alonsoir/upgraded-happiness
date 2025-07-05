#!/bin/bash
# 🚀 Script de corrección rápida para el problema de procesos que se cierran

echo "🚀 CORRECCIÓN RÁPIDA DEL SISTEMA SCADA"
echo "======================================"

# Crear directorios necesarios
echo "📁 Creando directorios necesarios..."
mkdir -p logs static .pids

# Función para crear archivos si no existen
create_file_if_missing() {
    local filename="$1"
    local description="$2"

    if [ ! -f "$filename" ]; then
        echo "❌ Falta $filename ($description)"
        echo "💡 Necesitas crear este archivo manualmente"
        return 1
    else
        echo "✅ $filename existe"
        return 0
    fi
}

echo ""
echo "🔍 VERIFICANDO ARCHIVOS CRÍTICOS:"
echo "================================="

# Verificar archivos principales
missing_files=0
create_file_if_missing "simple_broker.py" "Broker simple ZeroMQ" || ((missing_files++))
create_file_if_missing "enhanced_protobuf_gis_dashboard.py" "Dashboard GIS" || ((missing_files++))
create_file_if_missing "ip_geolocator.py" "Geolocalizador IP" || ((missing_files++))
create_file_if_missing "promiscuous_agent.py" "Agente promiscuo" || ((missing_files++))

echo ""
if [ $missing_files -eq 0 ]; then
    echo "✅ Todos los archivos necesarios están presentes"
else
    echo "❌ Faltan $missing_files archivos críticos"
    echo ""
    echo "🔧 SOLUCIÓN:"
    echo "============"
    echo "1. Copia los archivos Python que te proporcioné"
    echo "2. Guárdalos con los nombres exactos mostrados arriba"
    echo "3. Ejecuta este script nuevamente"
    echo ""
    echo "📝 ARCHIVOS A CREAR:"
    echo "==================="
    [ ! -f "simple_broker.py" ] && echo "• simple_broker.py - Copia el contenido del 'Simple Broker Corregido'"
    [ ! -f "enhanced_protobuf_gis_dashboard.py" ] && echo "• enhanced_protobuf_gis_dashboard.py - Dashboard GIS"
    [ ! -f "ip_geolocator.py" ] && echo "• ip_geolocator.py - Servicio de geolocalización"
    exit 1
fi

echo ""
echo "🧪 PROBANDO EJECUCIÓN INDIVIDUAL:"
echo "================================="

# Función para probar un script Python
test_python_script() {
    local script="$1"
    local description="$2"

    echo "🔍 Probando $script ($description)..."

    if python3 -m py_compile "$script" 2>/dev/null; then
        echo "✅ $script - Sintaxis correcta"
        return 0
    else
        echo "❌ $script - Error de sintaxis"
        python3 -m py_compile "$script"
        return 1
    fi
}

# Probar sintaxis de los archivos Python
syntax_errors=0
test_python_script "simple_broker.py" "Broker" || ((syntax_errors++))
test_python_script "enhanced_protobuf_gis_dashboard.py" "Dashboard" || ((syntax_errors++))
test_python_script "ip_geolocator.py" "Geolocalizador" || ((syntax_errors++))

if [ $syntax_errors -gt 0 ]; then
    echo ""
    echo "❌ Hay $syntax_errors archivos con errores de sintaxis"
    echo "💡 Revisa los errores mostrados arriba"
    exit 1
fi

echo ""
echo "🌐 VERIFICANDO PUERTOS:"
echo "======================"

check_port() {
    local port="$1"
    local description="$2"

    if lsof -i :$port >/dev/null 2>&1; then
        echo "⚠️ Puerto $port ($description) está ocupado"
        echo "   Proceso: $(lsof -ti :$port | head -1 | xargs ps -p 2>/dev/null | tail -1)"
        return 1
    else
        echo "✅ Puerto $port ($description) está libre"
        return 0
    fi
}

check_port 5559 "Broker input"
check_port 5560 "Broker output"
check_port 8000 "Dashboard GIS"

echo ""
echo "🔧 INICIANDO SISTEMA DE PRUEBA:"
echo "==============================="

# Parar cualquier proceso previo
echo "🛑 Parando procesos previos..."
pkill -f "simple_broker.py" 2>/dev/null || true
pkill -f "enhanced_protobuf_gis_dashboard.py" 2>/dev/null || true
sudo pkill -f "promiscuous_agent.py" 2>/dev/null || true
sleep 2

# Función para iniciar componente con verificación
start_component() {
    local script="$1"
    local description="$2"
    local logfile="$3"
    local use_sudo="$4"

    echo "🚀 Iniciando $description..."

    if [ "$use_sudo" = "true" ]; then
        sudo nohup python3 "$script" > "logs/$logfile" 2>&1 &
    else
        nohup python3 "$script" > "logs/$logfile" 2>&1 &
    fi

    local pid=$!
    echo $pid > ".pids/$logfile.pid"

    # Esperar un poco y verificar
    sleep 3

    if kill -0 $pid 2>/dev/null; then
        echo "✅ $description iniciado correctamente (PID: $pid)"
        echo "📋 Log: logs/$logfile"
        return 0
    else
        echo "❌ $description falló al iniciar"
        echo "📋 Error log:"
        tail -5 "logs/$logfile" 2>/dev/null || echo "No hay log disponible"
        return 1
    fi
}

# Iniciar componentes en orden
start_component "simple_broker.py" "Simple Broker" "broker.out" false
start_component "enhanced_protobuf_gis_dashboard.py" "Dashboard GIS" "dashboard.out" false

# El agente promiscuo requiere sudo y puede fallar si no hay permisos
echo ""
echo "🔐 AGENTE PROMISCUO (requiere sudo):"
echo "===================================="
echo "⚠️ El agente promiscuo requiere permisos de sudo"
echo "💡 Si falla, es normal - el resto del sistema puede funcionar"

if start_component "promiscuous_agent.py" "Agente Promiscuo" "agent.out" true; then
    echo "✅ Agente promiscuo iniciado correctamente"
else
    echo "⚠️ Agente promiscuo falló (esperado si no hay permisos sudo)"
fi

echo ""
echo "📊 ESTADO FINAL DEL SISTEMA:"
echo "============================"

# Verificar qué está corriendo
echo "Procesos SCADA activos:"
ps aux | grep -E "(simple_broker|enhanced_protobuf|promiscuous_agent)" | grep -v grep || echo "❌ No hay procesos SCADA activos"

echo ""
echo "Puertos ocupados:"
netstat -an 2>/dev/null | grep -E "(5559|5560|8000)" || echo "❌ No hay puertos SCADA ocupados"

echo ""
echo "🌐 URLs DISPONIBLES:"
echo "==================="
echo "📊 Dashboard GIS: http://localhost:8000"
echo "📋 API Stats: http://localhost:8000/api/stats"
echo "🔍 Health Check: http://localhost:8000/health"

echo ""
echo "📋 COMANDOS ÚTILES:"
echo "=================="
echo "# Ver logs en tiempo real:"
echo "tail -f logs/*.out"
echo ""
echo "# Parar todo:"
echo "make stop"
echo ""
echo "# Ver estado:"
echo "make status"
echo ""
echo "# Abrir dashboard:"
echo "open http://localhost:8000  # macOS"
echo "xdg-open http://localhost:8000  # Linux"

echo ""
echo "✅ CORRECCIÓN COMPLETADA"
echo "========================"
echo "Si ves procesos activos y puertos ocupados, el sistema debería estar funcionando."
echo "Abre http://localhost:8000 para ver el dashboard."