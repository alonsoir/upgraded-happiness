#!/usr/bin/env python3
"""
ARCHIVO: simple_pipeline_fix.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Solución robusta y simple para complete_ml_pipeline.py

ESTRATEGIA SIMPLE:
1. Añadir TRICAPA_DIR variable
2. Reemplazar TODAS las líneas "model_path = MODELS_DIR / filename"
3. Verificar manualmente contexto para evitar cambios incorrectos
"""

import shutil
from pathlib import Path
from datetime import datetime


class SimplePipelineFix:
    def __init__(self):
        self.file_path = Path("core/complete_ml_pipeline.py")
        self.backup_dir = Path("core_backups_simple")

    def create_backup(self):
        """Crea backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f"simple_fix_{timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)

        backup_file = backup_subdir / self.file_path.name
        shutil.copy2(self.file_path, backup_file)

        print(f"📦 Backup creado: {backup_file}")
        return backup_file

    def analyze_and_fix(self):
        """Analiza línea por línea y aplica cambios"""
        print(f"🔍 Procesando línea por línea: {self.file_path}")

        with open(self.file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        changes_made = 0
        tricapa_dir_added = False

        for i, line in enumerate(lines):
            # 1. Añadir TRICAPA_DIR después de PRODUCTION_DIR
            if 'PRODUCTION_DIR = ' in line and 'TRICAPA_DIR' not in ''.join(lines):
                new_lines.append(line)
                new_lines.append('TRICAPA_DIR = PRODUCTION_DIR / "tricapa"\n')
                print(f"  ✅ Línea {i + 1}: Añadida variable TRICAPA_DIR")
                tricapa_dir_added = True
                changes_made += 1
                continue

            # 2. Cambiar líneas problemáticas en contexto correcto
            if 'model_path = MODELS_DIR / filename' in line:
                # Verificar contexto: ¿estamos en la sección correcta?
                context_lines = lines[max(0, i - 10):i + 5]  # 10 líneas antes, 5 después
                context_text = ''.join(context_lines)

                # Si encontramos level2_models en el contexto, es la línea que queremos cambiar
                if 'level2_models' in context_text or 'ddos_' in context_text or 'ransomware_' in context_text:
                    new_line = line.replace('MODELS_DIR', 'TRICAPA_DIR')
                    new_lines.append(new_line)
                    print(f"  ✅ Línea {i + 1}: {line.strip()} → {new_line.strip()}")
                    changes_made += 1
                else:
                    # Mantener sin cambios si no estamos seguros del contexto
                    new_lines.append(line)
                    print(f"  ⏸️  Línea {i + 1}: Mantenida sin cambios (contexto no level2)")
                continue

            # 3. Mantener todas las demás líneas sin cambios
            new_lines.append(line)

        return new_lines, changes_made, tricapa_dir_added

    def verify_changes(self, lines):
        """Verifica que los cambios sean correctos"""
        content = ''.join(lines)

        # Verificaciones
        tricapa_dir_exists = 'TRICAPA_DIR = PRODUCTION_DIR / "tricapa"' in content
        tricapa_usage = 'model_path = TRICAPA_DIR / filename' in content
        models_dir_remaining = content.count('model_path = MODELS_DIR / filename')
        production_dir_preserved = 'model_path = PRODUCTION_DIR / filename' in content

        print("\n🔍 Verificación de cambios:")
        print(f"  ✅ TRICAPA_DIR variable definida: {tricapa_dir_exists}")
        print(f"  ✅ Uso de TRICAPA_DIR encontrado: {tricapa_usage}")
        print(f"  ✅ PRODUCTION_DIR preservado: {production_dir_preserved}")
        print(f"  🎯 Líneas MODELS_DIR restantes: {models_dir_remaining}")

        # Éxito si TRICAPA_DIR existe, se usa, y quedan pocas/ninguna línea problemática
        success = tricapa_dir_exists and tricapa_usage and models_dir_remaining <= 1

        return success

    def run_simple_fix(self):
        """Ejecuta la solución simple y robusta"""
        print("🔧 SOLUCIÓN SIMPLE Y ROBUSTA")
        print("=" * 40)
        print("🎯 Estrategia: Procesamiento línea por línea")
        print("📁 Archivo: complete_ml_pipeline.py")
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

                print(f"\n🎉 SOLUCIÓN APLICADA EXITOSAMENTE")
                print("=" * 40)
                print(f"✅ Cambios aplicados: {changes}")
                print(f"✅ TRICAPA_DIR añadida: {tricapa_added}")
                print(f"💾 Backup: {backup_file}")
                print()
                print("🧪 VERIFICAR INMEDIATAMENTE:")
                print("   python3 core/complete_ml_pipeline.py")
                print()
                print("✅ ESPERADO:")
                print("   • Los 4 modelos DDOS/Ransomware deben cargar")
                print("   • Total: 7 modelos activos (en lugar de 3)")

            except Exception as e:
                print(f"❌ Error escribiendo archivo: {e}")
                print(f"🔙 Restaurando backup...")
                shutil.copy2(backup_file, self.file_path)

        else:
            print("❌ La verificación falló o no se hicieron cambios.")
            print(f"📊 Cambios detectados: {changes}")
            print("🔙 Archivo mantenido sin cambios.")


if __name__ == "__main__":
    fixer = SimplePipelineFix()
    fixer.run_simple_fix()