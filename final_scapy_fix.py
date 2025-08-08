#!/usr/bin/env python3
"""
ARCHIVO: final_scapy_fix.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Solución definitiva para scapy_to_ml_features.py
"""


def final_scapy_fix():
    """Arregla definitivamente el archivo scapy_to_ml_features.py"""
    print("🔧 FIX DEFINITIVO SCAPY_TO_ML_FEATURES")
    print("=" * 45)

    # Restaurar desde backup .bak primero
    try:
        with open("core/scapy_to_ml_features.py.bak", 'r') as f:
            content = f.read()
        print("✅ Backup .bak restaurado")
    except:
        # Si no hay .bak, intentar con el archivo actual
        with open("core/scapy_to_ml_features.py", 'r') as f:
            content = f.read()
        print("⚠️  Usando archivo actual (no hay .bak)")

    # Insertar línea correctamente después de def __init__
    lines = content.split('\n')

    for i, line in enumerate(lines):
        if 'def __init__(self, models_dir="./models"):' in line:
            # Insertar la línea tricapa_dir después de def __init__
            lines.insert(i + 1, '        tricapa_dir = f"{models_dir}/production/tricapa"')
            print(f"✅ Línea tricapa_dir insertada después de línea {i + 1}")
            break

    # Escribir archivo corregido
    with open("core/scapy_to_ml_features.py", 'w') as f:
        f.write('\n'.join(lines))

    print("🎉 ARCHIVO CORREGIDO DEFINITIVAMENTE")
    print("🧪 PROBAR AHORA:")
    print("   sudo python3 core/scapy_to_ml_features.py")


if __name__ == "__main__":
    final_scapy_fix()