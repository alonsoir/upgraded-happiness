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
