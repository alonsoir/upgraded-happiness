#!/usr/bin/env python3
"""
ARCHIVO: direct_scapy_fix.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Solución directa para scapy_to_ml_features.py SIN verificación estricta

ESTRATEGIA SIMPLE:
1. Leer archivo
2. Aplicar cambios específicos
3. ESCRIBIR SIN VERIFICACIÓN ESTRICTA
4. Probar inmediatamente
"""

import shutil
from pathlib import Path
from datetime import datetime


def direct_scapy_fix():
    """Fix directo sin verificación compleja"""
    file_path = Path("core/scapy_to_ml_features.py")

    # Backup rápido
    timestamp = datetime.now().strftime('%H%M%S')
    backup_file = f"core/scapy_to_ml_features.py.backup_{timestamp}"
    shutil.copy2(file_path, backup_file)
    print(f"📦 Backup: {backup_file}")

    # Leer contenido
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    print("🔧 Aplicando cambios directos...")

    changes_made = 0

    # 1. Añadir tricapa_dir (buscar patrón específico de models_dir)
    if 'tricapa_dir' not in content:
        # Buscar línea que define models_dir y añadir tricapa_dir después
        lines = content.split('\n')
        new_lines = []

        for line in lines:
            new_lines.append(line)
            # Si encontramos la definición de models_dir, añadir tricapa_dir después
            if 'models_dir = ' in line and 'str(' in line:
                indent = len(line) - len(line.lstrip())
                tricapa_line = ' ' * indent + 'tricapa_dir = f"{models_dir}/production/tricapa"'
                new_lines.append(tricapa_line)
                print(f"  ✅ Añadida tricapa_dir después de: {line.strip()}")
                changes_made += 1
                break

        content = '\n'.join(new_lines)

    # 2. Cambios específicos de f-strings (más directo)
    replacements = [
        ("f'{models_dir}/ddos_random_forest.joblib'", "f'{tricapa_dir}/ddos_random_forest.joblib'"),
        ("f'{models_dir}/ddos_lightgbm.joblib'", "f'{tricapa_dir}/ddos_lightgbm.joblib'"),
        ("f'{models_dir}/ransomware_random_forest.joblib'", "f'{tricapa_dir}/ransomware_random_forest.joblib'"),
        ("f'{models_dir}/ransomware_lightgbm.joblib'", "f'{tricapa_dir}/ransomware_lightgbm.joblib'")
    ]

    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            print(f"  ✅ {old} → {new}")
            changes_made += 1

    # 3. ESCRIBIR INMEDIATAMENTE (sin verificación compleja)
    if changes_made > 0:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"\n🎉 CAMBIOS APLICADOS DIRECTAMENTE")
        print(f"✅ Total cambios: {changes_made}")
        print(f"💾 Backup: {backup_file}")
        print(f"\n🧪 PROBAR INMEDIATAMENTE:")
        print(f"   sudo python3 core/scapy_to_ml_features.py")

    else:
        print("❌ No se detectaron cambios necesarios")


if __name__ == "__main__":
    print("🔧 FIX DIRECTO SCAPY - SIN VERIFICACIÓN ESTRICTA")
    print("=" * 50)
    direct_scapy_fix()