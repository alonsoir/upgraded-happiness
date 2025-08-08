#!/usr/bin/env python3
"""
ARCHIVO: suppress_sklearn_warnings.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Script para suprimir warnings de sklearn en los archivos core

WARNINGS A ELIMINAR:
- sklearn/utils/validation.py: X does not have valid feature names
- Parallel jobs warnings de RandomForest
"""

import re
from pathlib import Path


def add_warning_suppression():
    """Añade supresión de warnings a los archivos core"""

    files_to_update = [
        "core/complete_ml_pipeline.py",
        "core/scapy_monitor_complete_pipeline.py",
        "core/scapy_to_ml_features.py"
    ]

    # Código para suprimir warnings
    warning_suppression = '''
# Suprimir warnings de sklearn
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message="X does not have valid feature names")
warnings.filterwarnings("ignore", message=".*Parallel.*")
'''

    print("🔇 SUPRIMIENDO WARNINGS SKLEARN")
    print("=" * 40)

    for file_path in files_to_update:
        path = Path(file_path)
        if not path.exists():
            print(f"⚠️  {file_path} no encontrado")
            continue

        print(f"🔄 Procesando: {file_path}")

        # Leer contenido
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Verificar si ya tiene supresión
        if 'warnings.filterwarnings("ignore"' in content:
            print(f"  ✅ Ya tiene supresión de warnings")
            continue

        # Buscar después de imports
        lines = content.split('\n')
        insert_index = 0

        # Encontrar el lugar después de los imports
        for i, line in enumerate(lines):
            if (line.strip().startswith('import ') or
                    line.strip().startswith('from ') or
                    line.strip() == '' or
                    line.strip().startswith('#')):
                insert_index = i + 1
            else:
                break

        # Insertar supresión de warnings
        lines.insert(insert_index, warning_suppression)

        # Escribir archivo actualizado
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        print(f"  ✅ Warnings suprimidos en {path.name}")

    print("\n🎉 WARNINGS SUPRIMIDOS EN TODOS LOS ARCHIVOS")
    print("🧪 Probar sin warnings:")
    print("   python3 core/complete_ml_pipeline.py")
    print("   sudo python3 core/scapy_monitor_complete_pipeline.py")
    print("   sudo python3 core/scapy_to_ml_features.py")


if __name__ == "__main__":
    add_warning_suppression()