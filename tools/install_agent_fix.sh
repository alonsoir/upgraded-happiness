#!/bin/bash
# 🔧 Install Firewall Agent V3.1 Fix
# Reemplaza el código del agent para leer configuración JSON correctamente

echo "🔧 INSTALANDO FIX PARA FIREWALL AGENT V3.1..."
echo "================================================"

# Verificar que estamos en el directorio correcto
if [ ! -f "core/simple_firewall_agent_v31.py" ]; then
    echo "❌ ERROR: No se encuentra core/simple_firewall_agent_v31.py"
    echo "📍 Ejecutar desde el directorio raíz de upgraded-happiness"
    exit 1
fi

# Backup del código actual
echo "📁 Haciendo backup del código actual..."
cp core/simple_firewall_agent_v31.py core/simple_firewall_agent_v31.py.backup_$(date +%Y%m%d_%H%M%S)
echo "✅ Backup creado: core/simple_firewall_agent_v31.py.backup_$(date +%Y%m%d_%H%M%S)"

# Verificar configuración de puertos
echo ""
echo "🔍 Verificando configuración de puertos..."
python tools/check_ports_firewall_agent_scheduler_firewall.py \
    config/json/scheduler_firewall_config.json \
    config/json/simple_firewall_agent_v31_config.json

if [ $? -ne 0 ]; then
    echo "❌ ERROR: Configuración de puertos incorrecta"
    echo "🔧 Corregir configuración antes de continuar"
    exit 1
fi

echo ""
echo "✅ Configuración de puertos verificada correctamente"
echo ""
echo "📋 CAMBIOS QUE SE VAN A APLICAR:"
echo "   • Leer puertos desde configuración JSON (no hardcoded)"
echo "   • Mantener protobuf V3.1 exclusivo"
echo "   • Mantener crypto V31 opcional"
echo "   • Mantener ultra-seguridad"
echo ""

read -p "¿Continuar con la instalación? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "🛑 Instalación cancelada"
    exit 0
fi

# Aquí el usuario debe copiar el código del artifact manualmente
echo ""
echo "📝 INSTRUCCIONES:"
echo "   1. Copia el código corregido del artifact anterior"
echo "   2. Reemplaza completamente core/simple_firewall_agent_v31.py"
echo "   3. Ejecuta el test: ./test_agent_fix.sh"
echo ""
echo "🎯 El código corregido incluye:"
echo "   • _setup_sockets() que lee puertos desde JSON"
echo "   • Debug logging para verificar configuración"
echo "   • Protobuf V3.1 exclusivo mantenido"
echo "   • Crypto V31 opcional mantenido"
echo ""
echo "✅ Backup completado. Listo para aplicar fix."