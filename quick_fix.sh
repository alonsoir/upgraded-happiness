#!/bin/bash
echo "🛑 Parando procesos duplicados..."

pkill -f "firewall_agent.py" 2>/dev/null || true
pkill -f "ml_detector_with_persistence.py" 2>/dev/null || true
pkill -f "real_zmq_dashboard_with_firewall.py" 2>/dev/null || true
sudo pkill -f "promiscuous_agent.py" 2>/dev/null || true

sleep 3

for port in 5559 5560 5561 5562 8000; do
    pid=$(lsof -ti:$port 2>/dev/null || echo "")
    if [ ! -z "$pid" ]; then
        echo "Liberando puerto $port (PID: $pid)"
        kill -9 $pid 2>/dev/null || true
    fi
done

echo "✅ Limpieza completada"
ps aux | grep -E "(firewall|ml_detector|dashboard|promiscuous)" | grep -v grep
