#!/usr/bin/env python3
"""
ARCHIVO: core_tricapa_updater.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Actualizador conservador para core/ con rutas tricapa

Script conservador que actualiza SOLO las rutas de modelos en los 3 archivos core
SIN tocar lightweight_ml_detector.py ni cambiar lógica del pipeline

OBJETIVO: Que los experimentos actuales funcionen con la nueva organización tricapa
ESTRATEGIA: Cambios mínimos, máxima compatibilidad
"""

import os
import re
import shutil
from pathlib import Path
from datetime import datetime


class CoreTricapaUpdater:
    def __init__(self):
        self.core_dir = Path("core")
        self.backup_dir = Path("core_backups")

        # Archivos a actualizar (NO lightweight_ml_detector.py)
        self.target_files = [
            "complete_ml_pipeline.py",
            "scapy_monitor_complete_pipeline.py",
            "scapy_to_ml_features.py"
        ]

        # Mapeo de rutas: antiguas → nuevas (tricapa)
        self.path_mappings = {
            # Modelos principales DDOS/Ransomware
            '"models/ddos_random_forest.joblib"': '"models/production/tricapa/ddos_random_forest.joblib"',
            "'models/ddos_random_forest.joblib'": "'models/production/tricapa/ddos_random_forest.joblib'",
            '"models/ddos_lightgbm.joblib"': '"models/production/tricapa/ddos_lightgbm.joblib"',
            "'models/ddos_lightgbm.joblib'": "'models/production/tricapa/ddos_lightgbm.joblib'",

            '"models/ransomware_random_forest.joblib"': '"models/production/tricapa/ransomware_random_forest.joblib"',
            "'models/ransomware_random_forest.joblib'": "'models/production/tricapa/ransomware_random_forest.joblib'",
            '"models/ransomware_lightgbm.joblib"': '"models/production/tricapa/ransomware_lightgbm.joblib"',
            "'models/ransomware_lightgbm.joblib'": "'models/production/tricapa/ransomware_lightgbm.joblib'",

            # Modelo CICDS2017 (Nivel 1)
            '"models/rf_production_cicids.joblib"': '"models/production/tricapa/rf_production_cicids.joblib"',
            "'models/rf_production_cicids.joblib'": "'models/production/tricapa/rf_production_cicids.joblib'",

            # Detectores normales (Nivel 2)
            '"models/web_normal_detector.joblib"': '"models/production/tricapa/web_normal_detector.joblib"',
            "'models/web_normal_detector.joblib'": "'models/production/tricapa/web_normal_detector.joblib'",
            '"models/internal_normal_detector.joblib"': '"models/production/tricapa/internal_normal_detector.joblib"',
            "'models/internal_normal_detector.joblib'": "'models/production/tricapa/internal_normal_detector.joblib'",

            # Variantes con rutas relativas
            '"../models/ddos_random_forest.joblib"': '"../models/production/tricapa/ddos_random_forest.joblib"',
            "'../models/ddos_random_forest.joblib'": "'../models/production/tricapa/ddos_random_forest.joblib'",
            '"./models/ddos_random_forest.joblib"': '"./models/production/tricapa/ddos_random_forest.joblib"',

            # Archivos de métricas
            '"models/ddos_random_forest_metrics.json"': '"models/production/tricapa/ddos_random_forest_metrics.json"',
            '"models/ransomware_random_forest_metrics.json"': '"models/production/tricapa/ransomware_random_forest_metrics.json"',

            # Scalers
            '"models/rf_production_cicids_scaler.joblib"': '"models/production/tricapa/rf_production_cicids_scaler.joblib"',
            '"models/web_normal_detector_scaler.joblib"': '"models/production/tricapa/web_normal_detector_scaler.joblib"',
            '"models/internal_normal_detector_scaler.joblib"': '"models/production/tricapa/internal_normal_detector_scaler.joblib"',
        }

        # Patrones regex para detectar carga dinámica de modelos
        self.dynamic_patterns = [
            r'f["\']models/.*?\.joblib["\']',  # f-strings
            r'os\.path\.join\(["\']models["\'].*?\)',  # os.path.join
            r'Path\(["\']models["\'].*?\)',  # pathlib
            r'model_path\s*=.*?["\']models/.*?["\']',  # variables model_path
        ]

    def create_backup_structure(self):
        """Crea estructura de backups"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f"backup_{timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)

        print(f"📦 Creando backups en: {backup_subdir}")
        return backup_subdir

    def analyze_file(self, file_path):
        """Analiza un archivo para detectar cargas de modelos"""
        print(f"\n🔍 Analizando: {file_path}")

        if not file_path.exists():
            print(f"⚠️  Archivo no encontrado: {file_path}")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Buscar coincidencias directas
            direct_matches = []
            for old_path, new_path in self.path_mappings.items():
                if old_path in content:
                    direct_matches.append((old_path, new_path))

            # Buscar patrones dinámicos
            dynamic_matches = []
            for pattern in self.dynamic_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    dynamic_matches.extend(matches)

            if direct_matches:
                print(f"  ✅ Encontradas {len(direct_matches)} rutas directas para actualizar")
                for old, new in direct_matches:
                    print(f"    {old} → {new}")

            if dynamic_matches:
                print(f"  🔧 Encontrados {len(dynamic_matches)} patrones dinámicos:")
                for match in dynamic_matches:
                    print(f"    {match}")
                print("    ⚠️  Revisar manualmente patrones dinámicos")

            if not direct_matches and not dynamic_matches:
                print("  ℹ️  No se encontraron referencias a modelos")

            return {
                'content': content,
                'direct_matches': direct_matches,
                'dynamic_matches': dynamic_matches
            }

        except Exception as e:
            print(f"  ❌ Error leyendo archivo: {e}")
            return None

    def update_file(self, file_path, analysis, backup_dir):
        """Actualiza un archivo con las nuevas rutas"""
        if not analysis or not analysis['direct_matches']:
            print(f"  ℹ️  Sin actualizaciones necesarias para {file_path.name}")
            return False

        print(f"  🔄 Actualizando {file_path.name}...")

        # Crear backup
        backup_file = backup_dir / file_path.name
        shutil.copy2(file_path, backup_file)
        print(f"    💾 Backup: {backup_file}")

        # Aplicar cambios
        content = analysis['content']
        changes_made = 0

        for old_path, new_path in analysis['direct_matches']:
            if old_path in content:
                content = content.replace(old_path, new_path)
                changes_made += 1
                print(f"    ✅ {old_path} → {new_path}")

        # Escribir archivo actualizado
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            print(f"    🎯 {changes_made} cambios aplicados")
            return True

        except Exception as e:
            print(f"    ❌ Error escribiendo archivo: {e}")
            # Restaurar backup
            shutil.copy2(backup_file, file_path)
            print(f"    🔙 Backup restaurado")
            return False

    def add_tricapa_header(self, file_path):
        """Añade header informativo sobre migración tricapa"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Verificar si ya tiene header
            if "MIGRADO TRICAPA" in content:
                return

            header = f'''"""
MIGRADO TRICAPA - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==================================================

✅ Actualizado para usar modelos en models/production/tricapa/
🏗️ Arquitectura tricapa: 3 niveles, 7 modelos especializados
🔄 Conserva lógica original, solo actualiza rutas

NIVELES:
🔴 Nivel 1: rf_production_cicids (CICDS2017)
🟡 Nivel 2: web/internal_normal_detector 
🟢 Nivel 3: ddos/ransomware específicos

⚠️  NO modificar sin validar con sistema tricapa completo
"""

'''

            # Insertar header después de imports/docstrings existentes
            lines = content.split('\n')
            insert_pos = 0

            # Buscar después de imports y docstrings
            for i, line in enumerate(lines):
                if (line.strip().startswith('import ') or
                        line.strip().startswith('from ') or
                        line.strip().startswith('"""') or
                        line.strip().startswith("'''") or
                        line.strip() == '' or
                        line.strip().startswith('#')):
                    insert_pos = i + 1
                else:
                    break

            lines.insert(insert_pos, header)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))

            print(f"    📋 Header tricapa añadido")

        except Exception as e:
            print(f"    ⚠️  Error añadiendo header: {e}")

    def generate_update_report(self, results):
        """Genera reporte de actualización"""
        report_path = Path("core_tricapa_update_report.md")

        report_content = f"""# Reporte Actualización Core → Tricapa

**Fecha**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Objetivo**: Actualizar rutas de modelos en core/ para arquitectura tricapa

## 📊 Resumen

"""

        updated_files = 0
        total_changes = 0

        for file_name, result in results.items():
            if result['updated']:
                updated_files += 1
                total_changes += result['changes']

        report_content += f"- **Archivos analizados**: {len(results)}\n"
        report_content += f"- **Archivos actualizados**: {updated_files}\n"
        report_content += f"- **Total cambios**: {total_changes}\n\n"

        ## Detalles por archivo
        report_content += "## 📁 Detalles por Archivo\n\n"

        for file_name, result in results.items():
            report_content += f"### {file_name}\n"
            if result['updated']:
                report_content += f"✅ **Actualizado** - {result['changes']} cambios\n"
                if result['changes_detail']:
                    for change in result['changes_detail']:
                        report_content += f"- {change}\n"
            else:
                report_content += "ℹ️  Sin cambios necesarios\n"
            report_content += "\n"

        report_content += f"""## 🚀 Próximos Pasos

1. **Verificar funcionamiento**: Probar pipeline con nuevas rutas
2. **Validar modelos**: Confirmar carga correcta de los 7 modelos tricapa  
3. **Ejecutar tests**: Comprobar compatibilidad con datasets existentes
4. **Integrar v3.1**: Preparar para protobuf unificado

## 📂 Estructura Tricapa

```
models/production/tricapa/
├── 🔴 rf_production_cicids.joblib           # Nivel 1
├── 🟡 web_normal_detector.joblib            # Nivel 2  
├── 🟡 internal_normal_detector.joblib       # Nivel 2
├── 🟢 ddos_random_forest.joblib            # Nivel 3
├── 🟢 ddos_lightgbm.joblib                 # Nivel 3
├── 🟢 ransomware_random_forest.joblib      # Nivel 3
└── 🟢 ransomware_lightgbm.joblib           # Nivel 3
```

---
*Generado automáticamente por core_tricapa_updater.py*
"""

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        print(f"\n📋 Reporte generado: {report_path}")

    def run_conservative_update(self):
        """Ejecuta actualización conservadora de core/"""
        print("🔧 ACTUALIZACIÓN CONSERVADORA CORE → TRICAPA")
        print("=" * 60)
        print("🎯 Objetivo: Actualizar SOLO rutas, mantener lógica")
        print("⚠️  NO toca: lightweight_ml_detector.py")
        print()

        # Crear backups
        backup_dir = self.create_backup_structure()

        # Resultados
        results = {}

        # Procesar cada archivo
        for file_name in self.target_files:
            file_path = self.core_dir / file_name

            # Analizar
            analysis = self.analyze_file(file_path)
            if not analysis:
                results[file_name] = {'updated': False, 'changes': 0, 'changes_detail': []}
                continue

            # Actualizar
            updated = self.update_file(file_path, analysis, backup_dir)

            if updated:
                # Añadir header
                self.add_tricapa_header(file_path)

                changes_detail = [f"{old} → {new}" for old, new in analysis['direct_matches']]
                results[file_name] = {
                    'updated': True,
                    'changes': len(analysis['direct_matches']),
                    'changes_detail': changes_detail
                }
            else:
                results[file_name] = {'updated': False, 'changes': 0, 'changes_detail': []}

        # Reporte final
        print("\n🎉 ACTUALIZACIÓN CONSERVADORA COMPLETADA")
        print("=" * 60)

        updated_count = sum(1 for r in results.values() if r['updated'])
        total_changes = sum(r['changes'] for r in results.values())

        print(f"✅ Archivos actualizados: {updated_count}/{len(self.target_files)}")
        print(f"🔧 Total cambios aplicados: {total_changes}")
        print(f"📦 Backups en: {backup_dir}")

        if updated_count > 0:
            print("\n🚀 ARCHIVOS LISTOS PARA TRICAPA:")
            for file_name, result in results.items():
                if result['updated']:
                    print(f"   ✅ {file_name} - {result['changes']} cambios")

        # Generar reporte
        self.generate_update_report(results)

        print(f"\n📋 Verificar funcionamiento:")
        print(f"   python3 core/complete_ml_pipeline.py")
        print(f"   python3 core/scapy_monitor_complete_pipeline.py")
        print(f"   python3 core/scapy_to_ml_features.py")

        print(f"\n🎯 Próximo: Crear rama y probar integración tricapa")


if __name__ == "__main__":
    updater = CoreTricapaUpdater()
    updater.run_conservative_update()