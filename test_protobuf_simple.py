#!/usr/bin/env python3
"""
Prueba rápida para verificar que protobuf funciona
"""

import sys
import os

# Agregar ruta actual al PYTHONPATH
sys.path.insert(0, os.getcwd())

print("🧪 PROBANDO IMPORTACIONES...")
print("=" * 40)

# Probar protobuf
try:
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado correctamente")

    # Crear instancia de prueba
    event = network_event_pb2.NetworkEvent()
    event.event_id = "test_123"
    event.source_ip = "192.168.1.1"
    event.target_ip = "192.168.1.2"
    event.agent_id = "test-agent"
    print("✅ NetworkEvent creado exitosamente")

    # Probar serialización
    data = event.SerializeToString()
    print(f"✅ Serialización OK: {len(data)} bytes")

    # Probar deserialización
    event2 = network_event_pb2.NetworkEvent()
    event2.ParseFromString(data)
    print(f"✅ Deserialización OK: event_id = {event2.event_id}")

except Exception as e:
    print(f"❌ Error con protobuf: {e}")
    import traceback

    traceback.print_exc()

# Probar scapy
try:
    from scapy.all import IP, TCP, UDP

    print("✅ Scapy importado correctamente")
except Exception as e:
    print(f"❌ Error con scapy: {e}")

# Probar zmq
try:
    import zmq

    print("✅ ZMQ importado correctamente")
except Exception as e:
    print(f"❌ Error con zmq: {e}")

print("=" * 40)
print("🎯 RESULTADO: ", end="")

# Verificar si todo está bien
try:
    from src.protocols.protobuf import network_event_pb2
    from scapy.all import IP, TCP
    import zmq

    print("✅ TODAS LAS IMPORTACIONES FUNCIONAN")
    print("\\n🚀 Puedes ejecutar:")
    print("   python agent_scapy_fixed.py")
    print("   python -m src.agents.agent_scapy")
except:
    print("❌ AÚN HAY PROBLEMAS")