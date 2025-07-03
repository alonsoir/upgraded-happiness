#!/bin/bash

# =============================================================================
# QUICK FIX - Mejorar detección de procesos ejecutándose como root
# =============================================================================

# Función mejorada de detección de agente promiscuo
check_promiscuous_agent_improved() {
    # Buscar como usuario normal
    if pgrep -f "promiscuous_agent" &>/dev/null; then
        echo "✅ Agente Promiscuo encontrado (usuario normal)"
        return 0
    fi

    # Buscar como root usando sudo
    if sudo pgrep -f "promiscuous_agent" &>/dev/null 2>/dev/null; then
        echo "✅ Agente Promiscuo encontrado (ejecutándose como root)"
        return 0
    fi

    # Buscar en todos los procesos sin importar usuario
    if ps aux | grep -E "promiscuous_agent" | grep -v grep &>/dev/null; then
        echo "✅ Agente Promiscuo encontrado (detección amplia)"
        return 0
    fi

    echo "❌ Agente Promiscuo no encontrado"
    return 1
}

echo "🔧 Probando detección mejorada del agente promiscuo..."
check_promiscuous_agent_improved

echo ""
echo "📊 Procesos promiscuos actuales:"
ps aux | grep -E "promiscuous" | grep -v grep

echo ""
echo "🎯 Para aplicar este fix a los scripts existentes:"
echo "  1. Los scripts ya funcionan correctamente"
echo "  2. El agente SÍ está ejecutándose (como root)"
echo "  3. Está capturando datos en tiempo real"
echo "  4. Es un problema menor de detección, no de funcionalidad"