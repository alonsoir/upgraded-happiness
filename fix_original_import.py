#!/usr/bin/env python3
"""
Script para corregir la importación en el archivo agent_scapy.py original
"""

import os

file_path = "src/agents/agent_scapy.py"

if os.path.exists(file_path):
    # Leer archivo
    with open(file_path, 'r') as f:
        content = f.read()

    # Corregir la importación
    old_import = "from src.protocols.protobuff import network_event_pb2"
    new_import = "from src.protocols.protobuf import network_event_pb2"

    if old_import in content:
        content = content.replace(old_import, new_import)

        # Escribir archivo corregido
        with open(file_path, 'w') as f:
            f.write(content)

        print(f"✅ Archivo {file_path} corregido")
        print(f"   Cambiado: protobuff -> protobuf")
    else:
        print(f"⚠️  No se encontró la importación problemática en {file_path}")
        print("   Puede que ya esté corregido o tenga un formato diferente")
else:
    print(f"❌ No se encontró el archivo: {file_path}")