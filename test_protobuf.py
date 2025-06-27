#!/usr/bin/env python3
"""
Script de prueba para verificar que protobuf funciona correctamente
"""

import sys
import os

# Agregar el directorio raíz al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.protocols.protobuff import network_event_pb2

    print("✓ Importación de protobuf exitosa")

    # Verificar que la clase NetworkEvent existe
    if hasattr(network_event_pb2, 'NetworkEvent'):
        print("✓ Clase NetworkEvent encontrada")

        # Crear una instancia de prueba
        event = network_event_pb2.NetworkEvent()
        event.event_id = "test_001"
        event.timestamp = 1234567890
        event.source_ip = "192.168.1.1"
        event.target_ip = "192.168.1.2"
        event.agent_id = "test-agent"

        print("✓ Instancia de NetworkEvent creada exitosamente")
        print(f"Event ID: {event.event_id}")
        print(f"Source IP: {event.source_ip}")

        # Serializar para probar
        serialized = event.SerializeToString()
        print(f"✓ Serialización exitosa: {len(serialized)} bytes")

    else:
        print("✗ Clase NetworkEvent NO encontrada")
        print("Atributos disponibles:", dir(network_event_pb2))

except ImportError as e:
    print(f"✗ Error de importación: {e}")
except Exception as e:
    print(f"✗ Error: {e}")

# Verificar scapy
try:
    from scapy.all import IP, TCP

    print("✓ Importación de scapy exitosa")
except ImportError as e:
    print(f"✗ Error importando scapy: {e}")
    print("Instala scapy: pip install scapy")