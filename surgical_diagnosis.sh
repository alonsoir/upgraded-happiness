#!/bin/bash
# surgical_diagnosis.sh - Diagnóstico quirúrgico del problema ZMQ

echo "🔬 DIAGNÓSTICO QUIRÚRGICO ZMQ"
echo "============================="

# 1. Liberar puerto 5561 problemático
echo "🔓 1. Liberando puerto 5561..."
pid=$(lsof -ti:5561 2>/dev/null || echo "")
if [ ! -z "$pid" ]; then
    echo "   Matando proceso en puerto 5561: PID $pid"
    kill -9 $pid 2>/dev/null || true
else
    echo "   Puerto 5561 libre"
fi

# 2. Verificar patrones ZMQ en el código
echo ""
echo "🔍 2. Analizando patrones ZMQ en el código..."

echo ""
echo "📄 ML Detector patterns:"
grep -n "zmq\." ml_detector_with_persistence.py | grep -E "(PUSH|PULL|PUB|SUB)" | head -10

echo ""
echo "📄 Dashboard patterns:"
grep -n "zmq\." real_zmq_dashboard_with_firewall.py | grep -E "(PUSH|PULL|PUB|SUB)" | head -10

echo ""
echo "📄 Puertos en ML Detector:"
grep -n "556[0-9]" ml_detector_with_persistence.py

echo ""
echo "📄 Puertos en Dashboard:"
grep -n "556[0-9]" real_zmq_dashboard_with_firewall.py

# 3. Test directo del ML Detector
echo ""
echo "🧪 3. TEST DIRECTO DEL ML DETECTOR"
echo "================================="

# Iniciar ML Detector en background
echo "🤖 Iniciando ML Detector..."
python3 ml_detector_with_persistence.py &
ML_PID=$!
echo "   PID: $ML_PID"

sleep 3

# Verificar que está corriendo
if kill -0 $ML_PID 2>/dev/null; then
    echo "✅ ML Detector iniciado correctamente"

    # Test 1: Enviar evento
    echo ""
    echo "📤 Enviando evento de prueba..."
    python3 -c "
import zmq, json, time
context = zmq.Context()
socket = context.socket(zmq.PUSH)
socket.connect('tcp://localhost:5559')
test_event = {
    'timestamp': time.time(),
    'src_ip': '192.168.1.99',
    'dst_ip': '10.0.0.99',
    'src_port': 9999,
    'dst_port': 80,
    'protocol': 'TCP',
    'surgical_test': True
}
socket.send_string(json.dumps(test_event))
print('✅ Evento enviado al ML Detector')
socket.close()
context.term()
"

    # Test 2: Escuchar output por 5 segundos
    echo ""
    echo "👂 Escuchando output del ML Detector por 5 segundos..."
    timeout 5 python3 -c "
import zmq, time
context = zmq.Context()

# Probar ambos patrones: PULL y SUB
print('Probando PULL...')
try:
    socket = context.socket(zmq.PULL)
    socket.connect('tcp://localhost:5560')
    socket.setsockopt(zmq.RCVTIMEO, 2000)
    msg = socket.recv_string()
    print('✅ PULL recibió:', msg[:100])
    socket.close()
except Exception as e:
    print('❌ PULL falló:', str(e))
    socket.close()

print('Probando SUB...')
try:
    socket = context.socket(zmq.SUB)
    socket.connect('tcp://localhost:5560')
    socket.setsockopt(zmq.SUBSCRIBE, b'')
    socket.setsockopt(zmq.RCVTIMEO, 2000)
    msg = socket.recv_string()
    print('✅ SUB recibió:', msg[:100])
    socket.close()
except Exception as e:
    print('❌ SUB falló:', str(e))
    socket.close()

context.term()
" || echo "⏰ Timeout - ML Detector no está enviando output"

    # Matar ML Detector
    kill $ML_PID 2>/dev/null || true

else
    echo "❌ ML Detector falló al iniciar"
fi

# 4. Verificar configuración de sockets en el código
echo ""
echo "🔍 4. VERIFICANDO CONFIGURACIÓN DE SOCKETS"
echo "=========================================="

echo ""
echo "📄 ML Detector - configuración de sockets:"
grep -A 5 -B 5 "bind\|connect" ml_detector_with_persistence.py | grep -A 5 -B 5 "556"

echo ""
echo "📄 Dashboard - configuración de sockets:"
grep -A 5 -B 5 "bind\|connect" real_zmq_dashboard_with_firewall.py | grep -A 5 -B 5 "556"

# 5. Verificar si hay lógica de envío en ML Detector
echo ""
echo "🔍 5. VERIFICANDO LÓGICA DE ENVÍO EN ML DETECTOR"
echo "=============================================="

echo "📄 Buscando 'send' en ML Detector:"
grep -n -A 3 -B 3 "send" ml_detector_with_persistence.py | head -20

echo ""
echo "📄 Buscando loops principales:"
grep -n -A 5 "while\|for.*in\|def.*process\|def.*run" ml_detector_with_persistence.py | head -20

# 6. Verificar estado de puertos
echo ""
echo "🌐 6. ESTADO ACTUAL DE PUERTOS"
echo "=============================="
for port in 5559 5560 5561 5562 8000; do
    if netstat -an 2>/dev/null | grep ":$port " > /dev/null; then
        echo "✅ Puerto $port: ACTIVO"
    else
        echo "❌ Puerto $port: INACTIVO"
    fi
done

echo ""
echo "✅ DIAGNÓSTICO COMPLETADO"
echo "========================"
echo "💡 Revisa la salida para identificar:"
echo "   1. Si ML Detector está configurado para enviar output"
echo "   2. Si usa PUSH vs PUB en puerto 5560"
echo "   3. Si Dashboard usa PULL vs SUB en puerto 5560"
echo "   4. Si hay lógica de envío en el loop principal del ML Detector"