#!/bin/bash
# 🔍 Diagnóstico rápido del problema de procesos

echo "🔍 DIAGNÓSTICO RÁPIDO DEL PROBLEMA"
echo "=================================="

echo ""
echo "📁 1. VERIFICANDO ARCHIVOS PYTHON EXISTENTES:"
echo "=============================================="
echo "Archivos Python en el directorio:"
ls -la *.py 2>/dev/null || echo "❌ No hay archivos .py en el directorio raíz"

echo ""
echo "📂 2. VERIFICANDO ESTRUCTURA DE DIRECTORIOS:"
echo "============================================"
echo "Directorios importantes:"
ls -la | grep -E "(logs|static|scripts|src)" || echo "⚠️ Algunos directorios pueden faltar"

echo ""
echo "📋 3. VERIFICANDO LOGS DE ERROR:"
echo "==============================="
if [ -d "logs" ]; then
    echo "Logs disponibles:"
    ls -la logs/
    echo ""
    echo "Últimas líneas de cada log:"
    for log in logs/*.out; do
        if [ -f "$log" ]; then
            echo "--- $log ---"
            tail -n 5 "$log" 2>/dev/null
            echo ""
        fi
    done
else
    echo "❌ Directorio 'logs' no existe"
fi

echo ""
echo "🔍 4. VERIFICANDO PROCESOS ACTIVOS:"
echo "==================================="
echo "Procesos Python relacionados con SCADA:"
ps aux | grep -E "(python.*broker|python.*dashboard|python.*agent|python.*promiscuous)" | grep -v grep || echo "❌ No hay procesos SCADA activos"

echo ""
echo "🌐 5. VERIFICANDO PUERTOS:"
echo "========================="
echo "Puertos SCADA ocupados:"
netstat -an 2>/dev/null | grep -E "(5555|5556|5559|5560|8000|8766)" || echo "❌ No hay puertos SCADA ocupados"

echo ""
echo "📊 6. RESUMEN DEL DIAGNÓSTICO:"
echo "============================="
# Verificar archivos críticos
missing_files=()
for file in "simple_broker.py" "enhanced_protobuf_gis_dashboard.py" "ip_geolocator.py" "promiscuous_agent.py"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -eq 0 ]; then
    echo "✅ Todos los archivos Python necesarios existen"
else
    echo "❌ Archivos Python faltantes:"
    for file in "${missing_files[@]}"; do
        echo "   - $file"
    done
fi

# Verificar si hay procesos corriendo
if pgrep -f "python.*broker\|python.*dashboard\|python.*agent" > /dev/null; then
    echo "✅ Hay procesos SCADA corriendo"
else
    echo "❌ No hay procesos SCADA corriendo"
fi

# Verificar si hay puertos ocupados
if netstat -an 2>/dev/null | grep -E "(5555|5556|5559|5560|8000|8766)" > /dev/null; then
    echo "✅ Hay puertos SCADA ocupados"
else
    echo "❌ No hay puertos SCADA ocupados"
fi

echo ""
echo "🎯 PRÓXIMOS PASOS RECOMENDADOS:"
echo "==============================="
if [ ${#missing_files[@]} -gt 0 ]; then
    echo "1. Crear los archivos Python faltantes"
    echo "2. Verificar dependencias en los archivos existentes"
    echo "3. Probar ejecución individual de cada componente"
else
    echo "1. Revisar logs de error detalladamente"
    echo "2. Probar ejecución individual con debug"
    echo "3. Verificar permisos de archivos"
fi

echo ""
echo "⚡ COMANDOS DE PRUEBA INDIVIDUAL:"
echo "================================"
echo "# Probar broker individual:"
echo "python simple_broker.py"
echo ""
echo "# Probar dashboard individual:"
echo "python enhanced_protobuf_gis_dashboard.py"
echo ""
echo "# Probar agente individual (requiere sudo):"
echo "sudo python promiscuous_agent.py"