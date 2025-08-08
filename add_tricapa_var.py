#!/usr/bin/env python3
"""
ARCHIVO: add_tricapa_var.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Fix súper simple - solo añadir la variable tricapa_dir faltante
"""

from pathlib import Path


def add_tricapa_variable():
    """Añade solo la variable tricapa_dir faltante"""
    file_path = Path("core/scapy_to_ml_features.py")

    print("🔧 AÑADIENDO VARIABLE tricapa_dir FALTANTE")
    print("=" * 45)

    # Leer contenido
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Verificar si ya existe
    if 'tricapa_dir' in content and 'tricapa_dir =' in content:
        print("✅ Variable tricapa_dir ya existe")
        return

    # Buscar la línea específica de models_dir en __init__
    lines = content.split('\n')
    new_lines = []
    added = False

    for i, line in enumerate(lines):
        new_lines.append(line)

        # Buscar la línea exacta donde se usa models_dir en __init__
        if 'def __init__' in line:
            # Buscar las siguientes líneas para encontrar models_dir
            for j in range(i + 1, min(i + 20, len(lines))):
                if 'models_dir' in lines[j] and '=' in lines[j]:
                    # Encontrar la indentación correcta
                    indent = len(lines[j]) - len(lines[j].lstrip())
                    tricapa_line = ' ' * indent + 'tricapa_dir = f"{models_dir}/production/tricapa"'

                    # Insertar después de la línea models_dir
                    new_lines.append(tricapa_line)
                    print(f"  ✅ Añadida tricapa_dir después de línea {j + 1}: {lines[j].strip()}")
                    added = True
                    break
            break

    if added:
        # Escribir el archivo actualizado
        new_content = '\n'.join(new_lines)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print("🎉 VARIABLE AÑADIDA EXITOSAMENTE")
        print("🧪 PROBAR AHORA:")
        print("   sudo python3 core/scapy_to_ml_features.py")
    else:
        print("❌ No se pudo encontrar dónde añadir la variable")
        print("📋 Mostrar líneas relevantes:")
        for i, line in enumerate(lines):
            if 'models_dir' in line:
                print(f"   Línea {i + 1}: {line.strip()}")


if __name__ == "__main__":
    add_tricapa_variable()