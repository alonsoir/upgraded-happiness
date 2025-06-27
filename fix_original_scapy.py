#!/usr/bin/env python3
"""
Script para corregir la importación en agent_scapy.py original
"""

import os
import re


def fix_agent_scapy():
    """Corregir el archivo agent_scapy.py original"""

    file_path = "src/agents/agent_scapy.py"

    if not os.path.exists(file_path):
        print(f"❌ No se encontró el archivo: {file_path}")
        return False

    # Leer el archivo
    with open(file_path, 'r') as f:
        content = f.read()

    print(f"📝 Contenido actual del archivo:")
    print("=" * 50)
    # Mostrar las primeras líneas para diagnóstico
    lines = content.split('\n')
    for i, line in enumerate(lines[:10]):
        print(f"{i + 1:2d}: {line}")
    print("=" * 50)

    # Buscar y corregir todas las variaciones de importación incorrecta
    patterns_to_fix = [
        (r'from src\.protocols\.protobuff import', 'from src.protocols.protobuf import'),
        (r'import src\.protocols\.protobuff\.', 'import src.protocols.protobuf.'),
        (r'src\.protocols\.protobuff\.', 'src.protocols.protobuf.'),
    ]

    original_content = content
    changes_made = []

    for pattern, replacement in patterns_to_fix:
        if re.search(pattern, content):
            content = re.sub(pattern, replacement, content)
            changes_made.append(f"  ✅ {pattern} -> {replacement}")

    # Verificar si se hicieron cambios
    if content != original_content:
        # Guardar el archivo corregido
        with open(file_path, 'w') as f:
            f.write(content)

        print(f"\\n✅ Archivo {file_path} corregido:")
        for change in changes_made:
            print(change)

        print(f"\\n📝 Contenido corregido:")
        print("=" * 50)
        lines = content.split('\n')
        for i, line in enumerate(lines[:10]):
            print(f"{i + 1:2d}: {line}")
        print("=" * 50)

        return True
    else:
        print(f"\\n⚠️  No se encontraron patrones de importación incorrecta")
        print("El archivo puede que ya esté corregido o tenga un formato diferente")
        return False


if __name__ == "__main__":
    print("🔧 Corrigiendo importaciones en agent_scapy.py...")
    success = fix_agent_scapy()

    if success:
        print("\\n🎉 ¡Corrección completada!")
        print("\\nAhora puedes usar:")
        print("  python -m src.agents.agent_scapy")
        print("  sudo python -m src.agents.agent_scapy")
    else:
        print("\\n🤔 Revisa manualmente el archivo src/agents/agent_scapy.py")
        print("Busca líneas que contengan 'protobuff' y cámbialas por 'protobuf'")