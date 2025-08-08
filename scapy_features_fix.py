#!/usr/bin/env python3
"""
ARCHIVO: scapy_features_fix.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Fix específico para scapy_to_ml_features.py

PROBLEMA ESPECÍFICO:
- scapy_to_ml_features.py busca modelos DDOS/Ransomware en f'{models_dir}/modelo.joblib'
- Pero ahora están en models/production/tricapa/

SOLUCIÓN:
- Añadir variable tricapa_dir
- Cambiar f-strings específicos para DDOS/Ransomware: models_dir → tricapa_dir
"""

import shutil
from pathlib import Path
from datetime import datetime


class ScapyFeaturesFix:
    def __init__(self):
        self.file_path = Path("core/scapy_to_ml_features.py")
        self.backup_dir = Path("core_backups_scapy")

        # Modelos que deben usar tricapa_dir
        self.tricapa_models = [
            "ddos_random_forest.joblib",
            "ddos_lightgbm.joblib",
            "ransomware_random_forest.joblib",
            "ransomware_lightgbm.joblib"
        ]

    def create_backup(self):
        """Crea backup específico"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f"scapy_fix_{timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)

        backup_file = backup_subdir / self.file_path.name
        shutil.copy2(self.file_path, backup_file)

        print(f"📦 Backup creado: {backup_file}")
        return backup_file

    def analyze_and_fix(self):
        """Analiza y aplica fix específico para scapy_to_ml_features.py"""
        print(f"🔍 Procesando: {self.file_path}")

        with open(self.file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        changes_made = 0
        tricapa_dir_added = False

        for i, line in enumerate(lines):
            # 1. Añadir tricapa_dir después de models_dir
            if 'models_dir = ' in line and 'tricapa_dir' not in ''.join(lines):
                new_lines.append(line)
                # Detectar indentación de la línea actual
                indent = len(line) - len(line.lstrip())
                tricapa_line = ' ' * indent + f'tricapa_dir = f"{{{line.strip().split("=")[0].strip()}}}/production/tricapa"\n'
                new_lines.append(tricapa_line)
                print(f"  ✅ Línea {i + 1}: Añadida variable tricapa_dir")
                tricapa_dir_added = True
                changes_made += 1
                continue

            # 2. Cambiar f-strings específicos para modelos tricapa
            if "f'{models_dir}/" in line:
                # Verificar si la línea contiene alguno de los modelos tricapa
                line_has_tricapa_model = any(model.replace('.joblib', '') in line for model in self.tricapa_models)

                if line_has_tricapa_model:
                    # Reemplazar models_dir con tricapa_dir para esta línea
                    new_line = line.replace("f'{models_dir}/", "f'{tricapa_dir}/")
                    new_lines.append(new_line)
                    print(f"  ✅ Línea {i + 1}: {line.strip()} → {new_line.strip()}")
                    changes_made += 1
                else:
                    # Mantener models_dir para otros modelos
                    new_lines.append(line)
                    print(f"  ⏸️  Línea {i + 1}: Mantenida (no es modelo tricapa)")
                continue

            # 3. Mantener todas las demás líneas sin cambios
            new_lines.append(line)

        return new_lines, changes_made, tricapa_dir_added

    def verify_changes(self, lines):
        """Verifica que los cambios sean correctos"""
        content = ''.join(lines)

        # Verificaciones específicas para f-strings
        tricapa_dir_exists = 'tricapa_dir = f"' in content
        tricapa_usage_ddos = "f'{tricapa_dir}/ddos_" in content
        tricapa_usage_ransomware = "f'{tricapa_dir}/ransomware_" in content
        models_dir_remaining = content.count("f'{models_dir}/ddos_") + content.count("f'{models_dir}/ransomware_")

        print("\n🔍 Verificación de cambios:")
        print(f"  ✅ tricapa_dir variable definida: {tricapa_dir_exists}")
        print(f"  ✅ DDOS usa tricapa_dir: {tricapa_usage_ddos}")
        print(f"  ✅ Ransomware usa tricapa_dir: {tricapa_usage_ransomware}")
        print(f"  🎯 F-strings problemáticos restantes: {models_dir_remaining}")

        # Éxito si tricapa_dir existe, se usa para DDOS/Ransomware, y no quedan f-strings problemáticos
        success = tricapa_dir_exists and tricapa_usage_ddos and tricapa_usage_ransomware and models_dir_remaining == 0

        return success

    def run_scapy_fix(self):
        """Ejecuta la solución específica para scapy_to_ml_features.py"""
        print("🔧 FIX ESPECÍFICO SCAPY_TO_ML_FEATURES")
        print("=" * 45)
        print("🎯 Objetivo: Arreglar f-strings para modelos DDOS/Ransomware")
        print("📁 Archivo: scapy_to_ml_features.py")
        print()

        # Crear backup
        backup_file = self.create_backup()

        # Procesar archivo
        new_lines, changes, tricapa_added = self.analyze_and_fix()

        # Verificar cambios
        verification_success = self.verify_changes(new_lines)

        if verification_success and changes > 0:
            # Escribir archivo corregido
            try:
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)

                print(f"\n🎉 FIX SCAPY APLICADO EXITOSAMENTE")
                print("=" * 45)
                print(f"✅ Cambios aplicados: {changes}")
                print(f"✅ tricapa_dir añadida: {tricapa_added}")
                print(f"💾 Backup: {backup_file}")
                print()
                print("🧪 VERIFICAR INMEDIATAMENTE:")
                print("   sudo python3 core/scapy_to_ml_features.py")
                print()
                print("✅ ESPERADO:")
                print("   • 4 modelos DDOS/Ransomware deben cargar")
                print("   • 🤖 Modelos cargados: [ddos_rf, ddos_lgb, ransomware_rf, ransomware_lgb]")
                print("   • Sin errores 'No such file or directory'")

            except Exception as e:
                print(f"❌ Error escribiendo archivo: {e}")
                print(f"🔙 Restaurando backup...")
                shutil.copy2(backup_file, self.file_path)

        else:
            print("❌ La verificación falló o no se hicieron cambios.")
            print(f"📊 Cambios detectados: {changes}")
            print("🔙 Archivo mantenido sin cambios.")

            if changes > 0:
                print("\n🔍 DEBUG - Contenido con cambios:")
                content = ''.join(new_lines)
                if 'tricapa_dir' in content:
                    print("   ✅ tricapa_dir encontrada en contenido")
                if "f'{tricapa_dir}/" in content:
                    print("   ✅ f-strings tricapa_dir encontrados")


if __name__ == "__main__":
    fixer = ScapyFeaturesFix()
    fixer.run_scapy_fix()