#!/usr/bin/env python3
"""verify_imports.py - Verificar que las importaciones funcionan correctamente"""

import os
import sys

print("🔍 Verificando estructura del proyecto...")
print(f"📁 Directorio actual: {os.getcwd()}")
print(f"📁 Python path: {sys.path[:3]}...")  # Mostrar solo los primeros 3

# Verificar si existe protocols/
if os.path.exists("protocols/protobuf"):
    print("✅ Encontrado: protocols/protobuf/")
    # Listar archivos
    files = os.listdir("protocols/protobuf")
    for f in files:
        if f.endswith("_pb2.py"):
            print(f"   📄 {f}")
elif os.path.exists("src/protocols/protobuf"):
    print("✅ Encontrado: src/protocols/protobuf/")
    files = os.listdir("src/protocols/protobuf")
    for f in files:
        if f.endswith("_pb2.py"):
            print(f"   📄 {f}")
else:
    print("❌ No se encontró protocols/protobuf/ ni src/protocols/protobuf/")

# Intentar importar
try:
    from protocols.protobuf import network_event_extended_v3_pb2

    print("✅ Importación exitosa desde protocols.protobuf")
except ImportError as e:
    print(f"❌ Error importando desde protocols.protobuf: {e}")

try:
    from src.protocols.protobuf import network_event_extended_v3_pb2

    print("✅ Importación exitosa desde src.protocols.protobuf")
except ImportError as e:
    print(f"❌ Error importando desde src.protocols.protobuf: {e}")