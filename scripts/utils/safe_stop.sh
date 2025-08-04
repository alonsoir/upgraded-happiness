#!/bin/bash
echo "🛑 Deteniendo sistema SCADA de forma segura..."

# Lista completa de procesos Python relacionados con SCADA
echo "🔍 Matando todos los procesos Python del proyecto..."
pkill -f "lightweight_ml_detector.py" 2>/dev/null || true
pkill -f "ml_detector_with_persistence.py" 2>/dev/null || true  
pkill -f "real_zmq_dashboard_with_firewall.py" 2>/dev/null || true
pkill -f "firewall_agent.py" 2>/dev/null || true
pkill -f "promiscuous_agent.py" 2>/dev/null || true
sudo pkill -f "promiscuous_agent.py" 2>/dev/null || true
pkill -f "generate_gps_traffic.py" 2>/dev/null || true

sleep 3

# Verificación final
remaining=$(ps aux | grep -E "(lightweight_ml|ml_detector|dashboard.*firewall|firewall_agent|promiscuous_agent)" | grep -v grep | grep python)

if [ -z "$remaining" ]; then
    echo "✅ Sistema completamente detenido"
else
    echo "⚠️ Procesos aún ejecutándose:"
    echo "$remaining"
    echo "💀 Forzando terminación..."
    killall Python 2>/dev/null || true
fi

echo "🎯 Parada completada"
