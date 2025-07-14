#!/bin/bash
# port_fix.sh - Fix del mismatch de puertos

echo "🔧 FIX DEL MISMATCH DE PUERTOS"
echo "=============================="

echo "🔍 Problema identificado:"
echo "   ML Detector envía en puerto 5560"
echo "   Dashboard escucha en puerto 5561"
echo "   ¡Los eventos se pierden en el vacío!"

echo ""
echo "🛠️  Aplicando fix..."

# Backup del archivo original
cp real_zmq_dashboard_with_firewall.py real_zmq_dashboard_with_firewall.py.backup
echo "✅ Backup creado: real_zmq_dashboard_with_firewall.py.backup"

# Fix 1: Cambiar puerto de eventos de 5561 a 5560
sed -i.bak 's/"events_input_port": 5561/"events_input_port": 5560/g' real_zmq_dashboard_with_firewall.py
echo "✅ Cambiado events_input_port de 5561 → 5560"

# Fix 2: Actualizar comentarios y documentación
sed -i.bak 's/Puerto 5561: Eventos del ML/Puerto 5560: Eventos del ML/g' real_zmq_dashboard_with_firewall.py
sed -i.bak 's/puerto 5561/puerto 5560/g' real_zmq_dashboard_with_firewall.py
sed -i.bak 's/5561: Eventos del ML/5560: Eventos del ML/g' real_zmq_dashboard_with_firewall.py

echo "✅ Actualizados comentarios y documentación"

# Fix 3: Actualizar configuración de firewall para usar puertos correctos
# Dashboard → 5561 → Firewall (esto debe quedarse igual)
echo "✅ Configuración de firewall mantenida (5561→5562→5563)"

echo ""
echo "🔍 Verificando cambios..."
grep -n "events_input_port.*556" real_zmq_dashboard_with_firewall.py | head -3

echo ""
echo "✅ FIX APLICADO CORRECTAMENTE"
echo "=============================="
echo "📊 Nuevo flujo:"
echo "   Promiscuous → 5559 → ML Detector → 5560 → Dashboard ✅"
echo "   Dashboard → 5561 → Firewall Agent ✅"
echo ""
echo "🚀 Para probar:"
echo "   1. python3 ml_detector_with_persistence.py &"
echo "   2. python3 real_zmq_dashboard_with_firewall.py &"
echo "   3. Abrir http://localhost:8000"
echo ""
echo "🔄 Para restaurar backup si hay problemas:"
echo "   mv real_zmq_dashboard_with_firewall.py.backup real_zmq_dashboard_with_firewall.py"
