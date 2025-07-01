#!/usr/bin/env python3
"""
Script para corregir el error en protobuf_serializer.py
"""

import os
import re


def fix_protobuf_serializer():
    """Corrige el error en el archivo protobuf_serializer.py"""

    filepath = "src/protocols/protobuff/protobuf_serializer.py"

    if not os.path.exists(filepath):
        print(f"❌ No se encontró el archivo {filepath}")
        return False

    # Leer el archivo
    with open(filepath, "r") as f:
        content = f.read()

    # Buscar y corregir el error específico
    # El problema está en que _populate_struct recibe 'event' en lugar de 'event_dict'

    # Pattern para encontrar la línea problemática
    pattern = r"await self\._populate_struct\(struct, event\)"
    replacement = "await self._populate_struct(struct, event_dict)"

    if re.search(pattern, content):
        content = re.sub(pattern, replacement, content)
        print("✅ Corregido: _populate_struct ahora recibe event_dict")
    else:
        print("⚠️  No se encontró el patrón exacto, buscando variaciones...")

        # Buscar la función _to_protobuf y asegurarse de que use event_dict
        pattern2 = r"(await self\._populate_struct\(struct,\s*)(\w+)\)"
        match = re.search(pattern2, content)
        if match and match.group(2) != "event_dict":
            content = re.sub(pattern2, r"\1event_dict)", content)
            print(
                f"✅ Corregido: _populate_struct ahora recibe event_dict (era {match.group(2)})"
            )

    # Guardar el archivo corregido
    with open(filepath, "w") as f:
        f.write(content)

    print(f"✅ Archivo {filepath} actualizado")
    return True


if __name__ == "__main__":
    print("🔧 Corrigiendo protobuf_serializer.py...")
    if fix_protobuf_serializer():
        print("✅ Corrección completada!")
        print("\n📝 Próximos pasos:")
        print("   1. Ejecuta: pytest tests/unit/test_protobuf_research_complete.py -v")
        print("   2. O ejecuta: python tests/unit/test_protobuf_research_complete.py")
