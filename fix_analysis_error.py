#!/usr/bin/env python3
"""
fix_analysis_error.py - Arreglar TypeError en comprehensive_pipeline_analysis.py
Error: can only concatenate list (not "NoneType") to list
"""

import re
from pathlib import Path


def fix_analysis_script():
    script_file = Path("comprehensive_pipeline_analysis.py")

    if not script_file.exists():
        print("❌ Script no encontrado")
        return False

    try:
        with open(script_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Backup
        backup_path = script_file.with_suffix('.py.backup')
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"💾 Backup creado: {backup_path}")

        # Arreglar el error: asegurar que todas las funciones retornen listas
        fixes = []

        # Fix 1: analyze_fleet_configuration debe retornar lista
        if 'return fleet_issues' in content:
            content = content.replace(
                'return fleet_issues',
                'return fleet_issues if fleet_issues else []'
            )
            fixes.append("✅ analyze_fleet_configuration retorna lista")

        # Fix 2: analyze_dashboard_role_confusion debe retornar lista
        if 'return role_issues' in content:
            content = content.replace(
                'return role_issues',
                'return role_issues if role_issues else []'
            )
            fixes.append("✅ analyze_dashboard_role_confusion retorna lista")

        # Fix 3: Inicializar listas vacías por defecto
        init_fix = '''        fleet_issues = self.analyze_fleet_configuration()
        if fleet_issues is None:
            fleet_issues = []

        # 7. Analizar rol del dashboard (nuevo)
        role_issues = self.analyze_dashboard_role_confusion()
        if role_issues is None:
            role_issues = []'''

        if '# 6. Analizar fleet específicamente' in content:
            old_section = '''        # 6. Analizar fleet específicamente
        fleet_issues = self.analyze_fleet_configuration()

        # 7. Analizar rol del dashboard (nuevo)
        role_issues = self.analyze_dashboard_role_confusion()'''

            content = content.replace(old_section, init_fix)
            fixes.append("✅ Inicialización segura de listas")

        # Guardar
        with open(script_file, 'w', encoding='utf-8') as f:
            f.write(content)

        print("🔧 Arreglos aplicados:")
        for fix in fixes:
            print(f"   {fix}")

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    print("🔧 Arreglando TypeError en análisis...")

    if fix_analysis_script():
        print("\n✅ Error corregido!")
        print("\n🚀 Ahora ejecuta:")
        print("   python3 comprehensive_pipeline_analysis.py")
    else:
        print("\n❌ No se pudo arreglar")