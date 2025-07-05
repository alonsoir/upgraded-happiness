#!/bin/bash

echo "🚀 QUICK FIX - Reparación rápida del agente promiscuo"
echo "===================================================="

# Verificar que el agente esté ejecutándose
echo "🔍 Verificando procesos activos..."
AGENT_PID=$(ps aux | grep promiscuous_agent.py | grep -v grep | awk '{print $2}')

if [ -n "$AGENT_PID" ]; then
    echo "✅ Agente encontrado (PID: $AGENT_PID)"
    echo "🔍 Verificando actividad ZMQ..."

    # Test rápido de ZMQ
    python3 -c "
import zmq
import time

# Test puertos comunes
ports_to_test = [5555, 5556, 5557, 5558, 5559, 5560]
active_ports = []

for port in ports_to_test:
    try:
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.connect(f'tcp://localhost:{port}')
        socket.setsockopt(zmq.SUBSCRIBE, b'')
        socket.setsockopt(zmq.RCVTIMEO, 1000)

        try:
            message = socket.recv_string()
            print(f'✅ Puerto {port}: ACTIVO - {len(message)} chars')
            active_ports.append(port)
        except zmq.Again:
            print(f'❌ Puerto {port}: Sin datos')
        except Exception as e:
            print(f'❌ Puerto {port}: Error - {e}')
        finally:
            socket.close()
            context.term()
    except Exception as e:
        print(f'❌ Puerto {port}: No accesible')

if not active_ports:
    print('\\n❌ NO SE DETECTÓ ACTIVIDAD ZMQ EN NINGÚN PUERTO')
    print('💡 El agente podría no estar configurado para ZMQ')
else:
    print(f'\\n✅ PUERTOS ACTIVOS: {active_ports}')
"

else
    echo "❌ Agente no está ejecutándose"
    echo "💡 Ejecutar: sudo python3 promiscuous_agent.py"
    exit 1
fi

echo ""
echo "🔧 POSIBLES SOLUCIONES:"
echo "1. Restart del agente:"
echo "   pkill -f promiscuous_agent.py"
echo "   sudo python3 promiscuous_agent.py"

echo ""
echo "2. Verificar configuración ZMQ del agente:"
echo "   grep -n 'zmq\|ZMQ' promiscuous_agent.py"

echo ""
echo "3. Verificar logs del sistema:"
echo "   sudo tail -f /var/log/syslog | grep promiscuous"

echo ""
echo "4. Ejecutar diagnóstico completo:"
echo "   python3 zmq_agent_debugger.py"

echo ""
echo "5. Test manual de captura:"
echo "   sudo tcpdump -i any -c 10"

# Crear bridge temporal como backup
echo ""
echo "🌉 CREANDO BRIDGE TEMPORAL DE RESPALDO..."
cat > temp_bridge.py << 'EOF'
#!/usr/bin/env python3
import zmq
import asyncio
import json
import signal
from datetime import datetime

async def emergency_bridge():
    context = zmq.Context()

    # Intentar conectar a diferentes puertos donde podría estar el agente
    possible_ports = [5555, 5556, 5557, 5558, 5559]
    active_port = None

    for port in possible_ports:
        try:
            test_socket = context.socket(zmq.SUB)
            test_socket.connect(f"tcp://localhost:{port}")
            test_socket.setsockopt(zmq.SUBSCRIBE, b"")
            test_socket.setsockopt(zmq.RCVTIMEO, 1000)

            message = test_socket.recv_string()
            print(f"✅ Datos encontrados en puerto {port}")
            active_port = port
            test_socket.close()
            break
        except:
            test_socket.close()
            continue

    if not active_port:
        print("❌ No se encontraron datos en ningún puerto")
        print("💡 Verificar que promiscuous_agent.py esté enviando a ZMQ")
        return

    # Bridge desde puerto activo al dashboard
    print(f"🌉 Bridge {active_port} → 5560")

    subscriber = context.socket(zmq.SUB)
    subscriber.connect(f"tcp://localhost:{active_port}")
    subscriber.setsockopt(zmq.SUBSCRIBE, b"")

    publisher = context.socket(zmq.PUB)
    publisher.bind("tcp://*:5560")

    count = 0
    while True:
        try:
            message = subscriber.recv_string(zmq.NOBLOCK)
            await publisher.send_string(message)
            count += 1
            if count % 50 == 0:
                print(f"📊 {count} eventos | {datetime.now().strftime('%H:%M:%S')}")
        except zmq.Again:
            await asyncio.sleep(0.01)

if __name__ == "__main__":
    print("🌉 Emergency Bridge - Buscando datos del agente...")
    try:
        asyncio.run(emergency_bridge())
    except KeyboardInterrupt:
        print("\n👋 Bridge detenido")
EOF

echo "✅ Bridge temporal creado: temp_bridge.py"
echo ""
echo "📋 ORDEN DE EJECUCIÓN RECOMENDADO:"
echo "Terminal 1: sudo python3 promiscuous_agent.py"
echo "Terminal 2: python3 temp_bridge.py"
echo "Terminal 3: python3 hybrid_dashboard.py"