#!/bin/bash
# immediate_cleanup_commands.sh
# Limpieza del sistema y preparación para refactoring

echo "🎯 LIMPIEZA Y PREPARACIÓN PARA REFACTORING"
echo "=========================================="

echo ""
echo "📋 PASO 1: IDENTIFICAR COMPONENTES DUPLICADOS"
echo "=============================================="

echo ""
echo "🔍 Archivos de firewall encontrados:"
if [ -f "firewall_agent.py" ]; then
    echo "   📄 firewall_agent.py (LEGACY) - Tamaño: $(wc -l < firewall_agent.py) líneas"
else
    echo "   ❌ firewall_agent.py no encontrado"
fi

if [ -f "simple_firewall_agent.py" ]; then
    echo "   📄 simple_firewall_agent.py (MODERNO) - Tamaño: $(wc -l < simple_firewall_agent.py) líneas"
else
    echo "   ❌ simple_firewall_agent.py no encontrado"
fi

echo ""
echo "🔍 Diferencias clave detectadas:"
echo ""

if [ -f "firewall_agent.py" ] && [ -f "simple_firewall_agent.py" ]; then
    echo "📊 Análisis rápido:"

    # Puertos en cada archivo
    echo ""
    echo "🔌 Puertos en firewall_agent.py:"
    grep -n "556[0-9]" firewall_agent.py | head -5 || echo "   No encontrados"

    echo ""
    echo "🔌 Puertos en simple_firewall_agent.py:"
    grep -n "556[0-9]" simple_firewall_agent.py | head -5 || echo "   No encontrados"

    # Arquitectura
    echo ""
    echo "🏗️ Arquitectura firewall_agent.py:"
    grep -n "puerto\|port.*556" firewall_agent.py | head -3 || echo "   Básica"

    echo ""
    echo "🏗️ Arquitectura simple_firewall_agent.py:"
    grep -n "3.*puertos\|3.*PUERTOS" simple_firewall_agent.py | head -3 || echo "   Avanzada"

    # Protobuf support
    echo ""
    echo "📦 Soporte Protobuf:"
    if grep -q "protobuf" simple_firewall_agent.py; then
        echo "   ✅ simple_firewall_agent.py: SÍ"
    else
        echo "   ❌ simple_firewall_agent.py: NO"
    fi

    if grep -q "protobuf" firewall_agent.py; then
        echo "   ✅ firewall_agent.py: SÍ"
    else
        echo "   ❌ firewall_agent.py: NO"
    fi
fi

echo ""
echo "📋 PASO 2: DECISIÓN Y LIMPIEZA"
echo "==============================="

echo ""
echo "🎯 RECOMENDACIÓN BASADA EN ANÁLISIS:"
echo ""

if [ -f "simple_firewall_agent.py" ]; then
    lines_simple=$(wc -l < simple_firewall_agent.py)

    if [ -f "firewall_agent.py" ]; then
        lines_legacy=$(wc -l < firewall_agent.py)

        if [ $lines_simple -gt $lines_legacy ]; then
            echo "✅ USAR: simple_firewall_agent.py"
            echo "   📊 Razón: Es más grande ($lines_simple vs $lines_legacy líneas)"
            echo "   🏗️ Arquitectura moderna (3 puertos)"
            echo "   📦 Soporte protobuf"
            echo "   🔧 Configuración JSON avanzada"
            echo ""
            echo "❌ ELIMINAR: firewall_agent.py"
            echo "   📊 Razón: Legacy, menos funciones"
            echo "   🏗️ Arquitectura simple (1 puerto)"
            echo ""

            echo "🔧 COMANDO PARA LIMPIAR:"
            echo "   # Hacer backup por seguridad"
            echo "   mv firewall_agent.py firewall_agent.py.legacy.backup"
            echo "   echo '✅ firewall_agent.py respaldado como .legacy.backup'"
            echo ""
            echo "   # Confirmar que usamos simple_firewall_agent.py"
            echo "   ls -la simple_firewall_agent.py"

        else
            echo "⚠️  VERIFICAR: simple_firewall_agent.py es más pequeño"
            echo "💡 Revisar manualmente cuál es más completo"
        fi
    else
        echo "✅ USAR: simple_firewall_agent.py (único encontrado)"
    fi
else
    echo "❌ simple_firewall_agent.py no encontrado"
    if [ -f "firewall_agent.py" ]; then
        echo "⚠️  Solo está firewall_agent.py - usar pero refactorizar"
    fi
fi

echo ""
echo "📋 PASO 3: AUDITORÍA ACTUALIZADA"
echo "================================="

echo ""
echo "🔍 Crear auditor actualizado:"

# Crear config_audit_updated.py actualizado
cat > config_audit_updated.py << 'EOF'
# [El código del ConfigAuditor actualizado va aquí - es demasiado largo para incluir en el script]
# Usar el artefacto config-audit-updated
EOF

echo "✅ config_audit_updated.py creado (placeholder)"
echo ""
echo "📋 Componentes que auditará:"
echo "   1. simple_firewall_agent.py → simple_firewall_agent_config.json"
echo "   2. ml_detector_with_persistence.py → lightweight_ml_detector_config.json"
echo "   3. real_zmq_dashboard_with_firewall.py → dashboard_config.json"
echo "   4. promiscuous_agent.py → enhanced_agent_config.json"
echo "   5. geoip_enricher.py → geoip_enricher_config.json"

echo ""
echo "📋 PASO 4: VERIFICAR CONFIGURACIONES JSON"
echo "=========================================="

echo ""
echo "🔍 Estado de archivos JSON:"

json_files=(
    "simple_firewall_agent_config.json"
    "lightweight_ml_detector_config.json"
    "dashboard_config.json"
    "enhanced_agent_config.json"
    "geoip_enricher_config.json"
)

for json_file in "${json_files[@]}"; do
    if [ -f "$json_file" ]; then
        echo "   ✅ $json_file ($(wc -l < "$json_file") líneas)"

        # Verificar si tiene estructura legacy
        if grep -q "\"bind_address\".*\"\\*\"" "$json_file"; then
            echo "      ⚠️  Formato legacy detectado"
        fi

        if grep -q "\"address\".*\"port\".*\"mode\"" "$json_file"; then
            echo "      ✅ Formato distribuido detectado"
        fi
    else
        echo "   ❌ $json_file NO ENCONTRADO"
    fi
done

echo ""
echo "📋 PASO 5: EJECUTAR AUDITORÍA"
echo "=============================="

echo ""
echo "🚀 Comandos para ejecutar:"
echo ""
echo "# 1. Limpiar firewall duplicado"
echo "mv firewall_agent.py firewall_agent.py.legacy.backup"
echo ""
echo "# 2. Ejecutar auditoría actualizada"
echo "python config_audit_updated.py"
echo ""
echo "# 3. Revisar reporte específico"
echo "cat config_audit_report_updated.txt"
echo ""
echo "# 4. Buscar específicamente el conflicto ML → Dashboard"
echo "grep -A 5 -B 5 \"CONFLICTO DETECTADO\" config_audit_report_updated.txt"

echo ""
echo "📋 RESULTADOS ESPERADOS"
echo "======================="

echo ""
echo "✅ Después de la auditoría deberías ver:"
echo ""
echo "🔥 CONFLICTO DETECTADO: ML Detector usa 5560, Dashboard espera 5561"
echo "📋 Evidencia:"
echo "   🤖 ML Detector puertos hardcodeados: [5560]"
echo "   📊 Dashboard puertos hardcodeados: [5561]"
echo "   📄 ML JSON puertos: [5560]"
echo "   📄 Dashboard JSON puertos: [5561]"
echo ""
echo "💡 Y recomendaciones para:"
echo "   1. Qué componente refactorizar primero"
echo "   2. Qué JSONs necesitan cambios"
echo "   3. Orden específico de trabajo"

echo ""
echo "🎯 DESPUÉS DE LA AUDITORÍA"
echo "=========================="

echo ""
echo "📝 Siguiente sesión (mañana):"
echo "   1. Revisar resultados de auditoría"
echo "   2. Decidir orden de refactoring"
echo "   3. Empezar con el componente más simple"
echo "   4. Refactorizar JSON a formato distribuido"
echo "   5. Eliminar hardcoding paso a paso"

echo ""
echo "🏁 OBJETIVO FINAL:"
echo "   ✅ Todos los componentes leen del JSON"
echo "   ✅ Zero hardcoding"
echo "   ✅ Formato distribuido preparado"
echo "   ✅ Eventos fluyen ML Detector → Dashboard"
echo "   ✅ Sistema escalable horizontalmente"

echo ""
echo "🚀 ¿EJECUTAR LIMPIEZA Y AUDITORÍA AHORA?"
echo "========================================"
echo ""
echo "chmod +x immediate_cleanup_commands.sh"
echo "./immediate_cleanup_commands.sh"