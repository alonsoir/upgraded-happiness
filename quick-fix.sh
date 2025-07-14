#!/bin/bash
# quick_fix.sh - Solución rápida para upgraded-happiness

# 1. Script para parar procesos (ya que no tienes make emergency-stop)
echo "🛑 Parando procesos duplicados..."

# Parar todos los procesos relacionados
pkill -f "firewall_agent.py" 2>/dev/null || true
pkill -f "ml_detector_with_persistence.py" 2>/dev/null || true
pkill -f "real_zmq_dashboard_with_firewall.py" 2>/dev/null || true
sudo pkill -f "promiscuous_agent.py" 2>/dev/null || true

sleep 3

# 2. Limpiar puertos ocupados
echo "🧹 Limpiando puertos..."
for port in 5559 5560 5561 5562 8000; do
    pid=$(lsof -ti:$port 2>/dev/null || echo "")
    if [ ! -z "$pid" ]; then
        echo "Liberando puerto $port (PID: $pid)"
        kill -9 $pid 2>/dev/null || true
    fi
done

echo "✅ Limpieza completada"

# 3. Verificar que no quedan procesos
echo "🔍 Verificando procesos restantes..."
ps aux | grep -E "(firewall|ml_detector|dashboard|promiscuous)" | grep -v grep

echo ""
echo "📋 Para verificar el dashboard:"
echo "   curl http://localhost:8000"
echo "   o abrir: http://localhost:8000"