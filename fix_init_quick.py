#!/usr/bin/env python3
"""
Corrección rápida para src/protocols/__init__.py
"""

import os
import shutil


def fix_init_file():
    """Corregir el archivo __init__.py inmediatamente"""

    init_file = "src/protocols/__init__.py"

    # Hacer backup
    backup_file = f"{init_file}.backup"
    shutil.copy2(init_file, backup_file)
    print(f"✅ Backup creado: {backup_file}")

    # Contenido corregido
    corrected_content = '''"""Protocols package - Serialization implementations"""
from .protobuf.protobuf_serializer import ProtobufEventSerializer
from .protobuf import network_event_pb2

__all__ = [
    'ProtobufEventSerializer',
    'network_event_pb2',
]
'''

    # Escribir contenido corregido
    with open(init_file, 'w') as f:
        f.write(corrected_content)

    print(f"✅ Archivo corregido: {init_file}")
    print("Cambios realizados:")
    print("  - protobuff -> protobuf")
    print("  - **all** -> __all__")
    print("  - Agregado network_event_pb2 a __all__")

    print(f"\n📝 Contenido nuevo:")
    print("=" * 50)
    print(corrected_content)
    print("=" * 50)


if __name__ == "__main__":
    print("🚀 CORRECCIÓN RÁPIDA DE __init__.py")
    fix_init_file()
    print("\n🧪 Ahora ejecuta: python test_protobuf_simple.py")