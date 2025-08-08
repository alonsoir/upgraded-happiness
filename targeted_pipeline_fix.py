#!/usr/bin/env python3
"""
ARCHIVO: targeted_pipeline_fix.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Solución quirúrgica para complete_ml_pipeline.py

PROBLEMA ESPECÍFICO:
- Nivel 2 (DDOS/Ransomware) busca modelos en MODELS_DIR/
- Pero ahora están en TRICAPA_DIR/

SOLUCIÓN:
- Cambiar línea específica: MODELS_DIR → TRICAPA_DIR para nivel 2
- Añadir variable TRICAPA_DIR si no existe
"""

import re
import shutil
from pathlib import Path
from datetime import datetime


class TargetedPipelineFix:
    def __init__(self):
        self.file_path = Path("core/complete_ml_pipeline.py")
        self.backup_dir = Path("core_backups_targeted")

    def create_backup(self):
        """Crea backup específico"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f"targeted_fix_{timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)

        backup_file = backup_subdir / self.file_path.name
        shutil.copy2(self.file_path, backup_file)

        print(f"📦 Backup creado: {backup_file}")
        return backup_file

    def analyze_current_content(self):
        """Analiza contenido actual"""
        print(f"🔍 Analizando: {self.file_path}")

        with open(self.file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Buscar problema específico
        level2_pattern = r'model_path = MODELS_DIR / filename.*?# Para nivel 2'
        level2_match = re.search(level2_pattern, content, re.DOTALL)

        # Buscar si TRICAPA_DIR ya existe
        tricapa_exists = 'TRICAPA_DIR' in content

        # Buscar línea problemática específica
        problem_line_pattern = r'model_path = MODELS_DIR / filename(?!\s*# Para nivel 3)'
        problem_matches = list(re.finditer(problem_line_pattern, content))

        print(f"✅ TRICAPA_DIR ya existe: {tricapa_exists}")
        print(f"🎯 Líneas problemáticas encontradas: {len(problem_matches)}")

        return {
            'content': content,
            'tricapa_exists': tricapa_exists,
            'problem_matches': problem_matches,
            'needs_fix': len(problem_matches) > 0
        }

    def apply_targeted_fix(self, content):
        """Aplica la solución quirúrgica específica"""
        print("🔧 Aplicando solución quirúrgica...")

        changes_made = 0

        # 1. Añadir TRICAPA_DIR si no existe
        if 'TRICAPA_DIR' not in content:
            # Buscar después de PRODUCTION_DIR = ...
            production_pattern = r'(PRODUCTION_DIR = .*?)(\n)'
            match = re.search(production_pattern, content)
            if match:
                insertion_point = match.end()
                tricapa_line = "TRICAPA_DIR = PRODUCTION_DIR / \"tricapa\"\n"
                content = content[:insertion_point] + tricapa_line + content[insertion_point:]
                print("  ✅ Variable TRICAPA_DIR añadida")
                changes_made += 1

        # 2. Arreglar el problema específico de nivel 2
        # Buscar el bloque de level2_models y cambiar solo esa línea

        # Patrón más específico para el bloque level2
        level2_block_pattern = r'(level2_models = \[.*?\].*?for model_name, filename in level2_models:.*?try:.*?)(model_path = MODELS_DIR / filename)(.*?except.*?Nivel 2)'

        match = re.search(level2_block_pattern, content, re.DOTALL)
        if match:
            before_line = match.group(1)
            problem_line = match.group(2)
            after_line = match.group(3)

            # Reemplazar solo esa línea específica
            fixed_line = "model_path = TRICAPA_DIR / filename"

            new_block = before_line + fixed_line + after_line
            content = content.replace(match.group(0), new_block)

            print(f"  ✅ Línea nivel 2 corregida: {problem_line} → {fixed_line}")
            changes_made += 1

        # 3. Verificar que nivel 3 sigue usando PRODUCTION_DIR (correcto)
        level3_pattern = r'level3_models.*?model_path = PRODUCTION_DIR / filename'
        if re.search(level3_pattern, content, re.DOTALL):
            print("  ✅ Nivel 3 mantiene PRODUCTION_DIR (correcto)")

        return content, changes_made

    def verify_fix(self, content):
        """Verifica que la solución sea correcta"""
        print("🔍 Verificando solución aplicada...")

        # Verificar TRICAPA_DIR existe
        tricapa_exists = 'TRICAPA_DIR = PRODUCTION_DIR / "tricapa"' in content

        # Verificar nivel 2 usa TRICAPA_DIR
        level2_fixed = 'model_path = TRICAPA_DIR / filename' in content

        # Verificar nivel 3 sigue usando PRODUCTION_DIR
        level3_intact = 'model_path = PRODUCTION_DIR / filename' in content

        # Contar líneas problemáticas restantes
        remaining_problems = len(re.findall(r'model_path = MODELS_DIR / filename', content))

        print(f"  ✅ TRICAPA_DIR definida: {tricapa_exists}")
        print(f"  ✅ Nivel 2 usa TRICAPA_DIR: {level2_fixed}")
        print(f"  ✅ Nivel 3 usa PRODUCTION_DIR: {level3_intact}")
        print(f"  🎯 Problemas restantes: {remaining_problems}")

        success = tricapa_exists and level2_fixed and level3_intact and remaining_problems == 0

        return success

    def run_targeted_fix(self):
        """Ejecuta la solución quirúrgica"""
        print("🔧 SOLUCIÓN QUIRÚRGICA PIPELINE TRICAPA")
        print("=" * 50)
        print("🎯 Objetivo: Arreglar carga de modelos Nivel 2 (DDOS/Ransomware)")
        print("📁 Archivo: complete_ml_pipeline.py")
        print()

        # Crear backup
        backup_file = self.create_backup()

        # Analizar estado actual
        analysis = self.analyze_current_content()

        if not analysis['needs_fix']:
            print("✅ No se detectaron problemas. El archivo ya está correcto.")
            return

        # Aplicar solución
        fixed_content, changes = self.apply_targeted_fix(analysis['content'])

        # Verificar solución
        verification_success = self.verify_fix(fixed_content)

        if verification_success and changes > 0:
            # Escribir archivo corregido
            try:
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)

                print(f"\n🎉 SOLUCIÓN APLICADA EXITOSAMENTE")
                print("=" * 50)
                print(f"✅ Cambios aplicados: {changes}")
                print(f"💾 Backup disponible: {backup_file}")
                print()
                print("🎯 SOLUCIÓN ESPECÍFICA:")
                print("  • TRICAPA_DIR variable añadida")
                print("  • Nivel 2 (DDOS/Ransomware): MODELS_DIR → TRICAPA_DIR")
                print("  • Nivel 3 (Internal/Web): Mantiene PRODUCTION_DIR")
                print()
                print("🧪 VERIFICAR FUNCIONAMIENTO:")
                print("   python3 core/complete_ml_pipeline.py")
                print()
                print("✅ ESPERADO: Los 7 modelos deberían cargar correctamente")

            except Exception as e:
                print(f"❌ Error escribiendo archivo: {e}")
                print(f"🔙 Restaurando backup...")
                shutil.copy2(backup_file, self.file_path)

        else:
            print("❌ La verificación falló. No se aplicaron cambios.")
            print("🔙 Archivo mantenido sin cambios.")


if __name__ == "__main__":
    fixer = TargetedPipelineFix()
    fixer.run_targeted_fix()