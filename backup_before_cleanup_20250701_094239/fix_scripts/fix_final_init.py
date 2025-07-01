#!/usr/bin/env python3
"""
Corrección final para src/protocols/__init__.py
"""

import os
import shutil


def fix_protocols_init_final():
    """Crear un __init__.py que solo importe lo que existe"""

    init_file = "src/protocols/__init__.py"

    # Hacer backup
    backup_file = f"{init_file}.backup_final"
    shutil.copy2(init_file, backup_file)
    print(f"✅ Backup creado: {backup_file}")

    # Contenido que solo importa lo que realmente existe
    working_content = '''"""Protocols package - Network event protocols"""

# Importar solo lo que existe
from .protobuf import network_event_pb2

__all__ = ['network_event_pb2']
'''

    # Escribir el contenido funcional
    with open(init_file, "w") as f:
        f.write(working_content)

    print(f"✅ Archivo corregido: {init_file}")
    print("📝 Contenido funcional:")
    print("=" * 50)
    print(working_content)
    print("=" * 50)


def ensure_protobuf_init():
    """Asegurar que src/protocols/protobuf/__init__.py tenga contenido"""

    protobuf_init = "src/protocols/protobuf/__init__.py"

    # Verificar si está vacío
    if os.path.exists(protobuf_init):
        with open(protobuf_init, "r") as f:
            content = f.read().strip()

        if not content:  # Archivo vacío
            protobuf_content = '''"""Protobuf protocols package"""

from . import network_event_pb2

__all__ = ['network_event_pb2']
'''
            with open(protobuf_init, "w") as f:
                f.write(protobuf_content)
            print(f"✅ Contenido agregado a: {protobuf_init}")
        else:
            print(f"✅ Ya tiene contenido: {protobuf_init}")


if __name__ == "__main__":
    print("🎯 CORRECCIÓN FINAL DE IMPORTACIONES")
    print("=" * 50)

    # Paso 1: Corregir src/protocols/__init__.py
    fix_protocols_init_final()

    # Paso 2: Asegurar que protobuf/__init__.py tenga contenido
    ensure_protobuf_init()

    print(f"\n🧪 LISTO PARA PROBAR:")
    print("   python test_protobuf_simple.py")
    print("   python agent_scapy_fixed.py")
