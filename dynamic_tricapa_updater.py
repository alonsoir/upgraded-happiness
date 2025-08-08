#!/usr/bin/env python3
"""
ARCHIVO: dynamic_tricapa_updater.py
FECHA CREACIÓN: 8 de agosto de 2025
DESCRIPCIÓN: Actualizador inteligente para construcción dinámica de rutas tricapa

Script inteligente que detecta y actualiza patrones de construcción dinámica de rutas
hacia la nueva estructura models/production/tricapa/

PATRONES DETECTADOS:
- MODELS_DIR / filename
- PRODUCTION_DIR / filename
- f'{models_dir}/filename'
- Variables de directorio construcción dinámica

OBJETIVO: Actualizar lógica de directorios sin romper funcionalidad
"""

import os
import re
import shutil
import ast
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple


class DynamicTricapaUpdater:
    def __init__(self):
        self.core_dir = Path("core")
        self.backup_dir = Path("core_backups_dynamic")

        # Archivos a actualizar
        self.target_files = [
            "complete_ml_pipeline.py",
            "scapy_monitor_complete_pipeline.py",
            "scapy_to_ml_features.py"
        ]

        # Modelos que ahora están en tricapa/
        self.tricapa_models = {
            "ddos_random_forest.joblib",
            "ddos_lightgbm.joblib",
            "ransomware_random_forest.joblib",
            "ransomware_lightgbm.joblib",
            "internal_normal_detector.joblib",
            "web_normal_detector.joblib",
            "rf_production_cicids.joblib",
            # Incluir scalers y metadata
            "ddos_random_forest_metrics.json",
            "ddos_lightgbm_metrics.json",
            "ransomware_random_forest_metrics.json",
            "ransomware_lightgbm_metrics.json",
            "internal_normal_detector_scaler.joblib",
            "internal_normal_detector_metadata.json",
            "web_normal_detector_scaler.joblib",
            "web_normal_detector_metadata.json",
            "rf_production_cicids_scaler.joblib"
        }

        # Patrones a buscar y reemplazar
        self.replacement_patterns = [
            # Construcción directa con MODELS_DIR
            {
                'pattern': r'MODELS_DIR\s*/\s*["\']([^"\']+)["\']',
                'description': 'MODELS_DIR / "filename"',
                'replace_func': self.replace_models_dir_path
            },
            # Construcción directa con PRODUCTION_DIR
            {
                'pattern': r'PRODUCTION_DIR\s*/\s*["\']([^"\']+)["\']',
                'description': 'PRODUCTION_DIR / "filename"',
                'replace_func': self.replace_production_dir_path
            },
            # F-strings con models_dir
            {
                'pattern': r'f["\']([^"\']*\{models_dir\}/[^"\']*)["\']',
                'description': 'f"{models_dir}/filename"',
                'replace_func': self.replace_fstring_models_dir
            },
            # Construcción con Path() y join
            {
                'pattern': r'Path\(["\']models["\'].*?\)\s*/\s*["\']([^"\']+)["\']',
                'description': 'Path("models") / "filename"',
                'replace_func': self.replace_path_construction
            }
        ]

    def should_use_tricapa(self, filename: str) -> bool:
        """Determina si un modelo debe usar ruta tricapa"""
        return any(filename.startswith(model.split('.')[0]) or filename == model
                   for model in self.tricapa_models)

    def replace_models_dir_path(self, match: re.Match) -> str:
        """Reemplaza MODELS_DIR / filename según corresponda"""
        filename = match.group(1)
        if self.should_use_tricapa(filename):
            return f'TRICAPA_DIR / "{filename}"'
        else:
            return match.group(0)  # Sin cambios

    def replace_production_dir_path(self, match: re.Match) -> str:
        """Reemplaza PRODUCTION_DIR / filename según corresponda"""
        filename = match.group(1)
        if self.should_use_tricapa(filename):
            return f'TRICAPA_DIR / "{filename}"'
        else:
            return match.group(0)  # Sin cambios

    def replace_fstring_models_dir(self, match: re.Match) -> str:
        """Reemplaza f-strings con models_dir"""
        original_fstring = match.group(1)
        # Extraer filename de patterns como {models_dir}/filename
        filename_match = re.search(r'\{models_dir\}/([^}\'\"]+)', original_fstring)
        if filename_match:
            filename = filename_match.group(1)
            if self.should_use_tricapa(filename):
                # Reemplazar con tricapa_dir
                new_fstring = original_fstring.replace('{models_dir}', '{tricapa_dir}')
                return f'f"{new_fstring}"'
        return match.group(0)  # Sin cambios

    def replace_path_construction(self, match: re.Match) -> str:
        """Reemplaza construcciones Path() complejas"""
        filename = match.group(1)
        if self.should_use_tricapa(filename):
            return f'TRICAPA_DIR / "{filename}"'
        else:
            return match.group(0)  # Sin cambios

    def add_tricapa_dir_variable(self, content: str) -> Tuple[str, bool]:
        """Añade variable TRICAPA_DIR después de PRODUCTION_DIR"""

        # Buscar donde se define PRODUCTION_DIR
        production_dir_pattern = r'(PRODUCTION_DIR\s*=\s*.*?)(\n)'
        match = re.search(production_dir_pattern, content)

        if match:
            # Verificar si TRICAPA_DIR ya existe
            if 'TRICAPA_DIR' in content:
                return content, False

            # Añadir TRICAPA_DIR después de PRODUCTION_DIR
            insertion_point = match.end()
            tricapa_line = "TRICAPA_DIR = PRODUCTION_DIR / \"tricapa\"\n"

            new_content = (content[:insertion_point] +
                           tricapa_line +
                           content[insertion_point:])

            return new_content, True

        return content, False

    def add_tricapa_dir_variable_for_fstrings(self, content: str) -> Tuple[str, bool]:
        """Añade variable tricapa_dir para f-strings"""

        # Buscar donde se define models_dir para f-strings
        models_dir_pattern = r'(models_dir\s*=\s*.*?)(\n)'
        match = re.search(models_dir_pattern, content)

        if match:
            # Verificar si tricapa_dir ya existe
            if 'tricapa_dir' in content:
                return content, False

            # Añadir tricapa_dir después de models_dir
            insertion_point = match.end()
            tricapa_line = '        tricapa_dir = f"{models_dir}/production/tricapa"\n'

            new_content = (content[:insertion_point] +
                           tricapa_line +
                           content[insertion_point:])

            return new_content, True

        return content, False

    def analyze_file_dynamic(self, file_path: Path) -> Dict:
        """Análisis profundo de patrones dinámicos"""
        print(f"\n🔍 Análisis dinámico: {file_path.name}")

        if not file_path.exists():
            print(f"⚠️  Archivo no encontrado: {file_path}")
            return {'content': '', 'matches': [], 'needs_tricapa_dir': False}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            all_matches = []

            # Buscar cada patrón
            for pattern_info in self.replacement_patterns:
                pattern = pattern_info['pattern']
                description = pattern_info['description']

                matches = list(re.finditer(pattern, content))
                if matches:
                    print(f"  🎯 Encontrado patrón '{description}': {len(matches)} coincidencias")
                    for match in matches:
                        filename = match.group(1) if match.groups() else "N/A"
                        should_update = self.should_use_tricapa(filename)
                        all_matches.append({
                            'pattern_info': pattern_info,
                            'match': match,
                            'filename': filename,
                            'should_update': should_update,
                            'original': match.group(0)
                        })

                        status = "✅ ACTUALIZAR" if should_update else "⏸️  MANTENER"
                        print(f"    {status}: {match.group(0)} (archivo: {filename})")

            # Determinar si necesita TRICAPA_DIR
            needs_tricapa_dir = any(m['should_update'] for m in all_matches)

            if not all_matches:
                print(f"  ℹ️  Sin patrones dinámicos detectados")

            return {
                'content': content,
                'matches': all_matches,
                'needs_tricapa_dir': needs_tricapa_dir
            }

        except Exception as e:
            print(f"  ❌ Error leyendo archivo: {e}")
            return {'content': '', 'matches': [], 'needs_tricapa_dir': False}

    def update_file_dynamic(self, file_path: Path, analysis: Dict, backup_dir: Path) -> bool:
        """Actualiza archivo con patrones dinámicos"""

        if not analysis['matches']:
            print(f"  ℹ️  Sin actualizaciones dinámicas para {file_path.name}")
            return False

        print(f"  🔄 Actualizando patrones dinámicos en {file_path.name}...")

        # Crear backup
        backup_file = backup_dir / file_path.name
        shutil.copy2(file_path, backup_file)
        print(f"    💾 Backup: {backup_file}")

        content = analysis['content']
        changes_made = 0

        # Añadir TRICAPA_DIR si es necesario
        if analysis['needs_tricapa_dir']:
            content, added = self.add_tricapa_dir_variable(content)
            if added:
                print(f"    ✅ Variable TRICAPA_DIR añadida")
                changes_made += 1

            # Para f-strings, también añadir tricapa_dir
            content, added_fstring = self.add_tricapa_dir_variable_for_fstrings(content)
            if added_fstring:
                print(f"    ✅ Variable tricapa_dir añadida para f-strings")
                changes_made += 1

        # Aplicar reemplazos (en orden inverso para no afectar posiciones)
        matches_to_update = [m for m in analysis['matches'] if m['should_update']]
        matches_to_update.sort(key=lambda x: x['match'].start(), reverse=True)

        for match_info in matches_to_update:
            match = match_info['match']
            pattern_info = match_info['pattern_info']
            replace_func = pattern_info['replace_func']

            # Aplicar función de reemplazo
            replacement = replace_func(match)

            if replacement != match.group(0):
                # Realizar reemplazo
                start, end = match.span()
                content = content[:start] + replacement + content[end:]
                changes_made += 1
                print(f"    ✅ {match.group(0)} → {replacement}")

        # Escribir archivo actualizado
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            print(f"    🎯 {changes_made} cambios dinámicos aplicados")
            return True

        except Exception as e:
            print(f"    ❌ Error escribiendo archivo: {e}")
            # Restaurar backup
            shutil.copy2(backup_file, file_path)
            print(f"    🔙 Backup restaurado")
            return False

    def create_backup_structure(self):
        """Crea estructura de backups para actualizaciones dinámicas"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f"dynamic_backup_{timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)

        print(f"📦 Creando backups dinámicos en: {backup_subdir}")
        return backup_subdir

    def generate_dynamic_report(self, results: Dict):
        """Genera reporte de actualización dinámica"""
        report_path = Path("dynamic_tricapa_update_report.md")

        report_content = f"""# Reporte Actualización Dinámica Core → Tricapa

**Fecha**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Objetivo**: Actualizar construcción dinámica de rutas para arquitectura tricapa

## 📊 Resumen

"""

        updated_files = sum(1 for r in results.values() if r['updated'])
        total_changes = sum(r['changes'] for r in results.values())
        total_patterns = sum(len(r.get('matches', [])) for r in results.values())

        report_content += f"- **Archivos analizados**: {len(results)}\n"
        report_content += f"- **Archivos actualizados**: {updated_files}\n"
        report_content += f"- **Patrones detectados**: {total_patterns}\n"
        report_content += f"- **Cambios aplicados**: {total_changes}\n\n"

        # Detalles por archivo
        report_content += "## 📁 Detalles por Archivo\n\n"

        for file_name, result in results.items():
            report_content += f"### {file_name}\n"
            if result['updated']:
                report_content += f"✅ **Actualizado** - {result['changes']} cambios dinámicos\n"
                if result.get('patterns_found'):
                    report_content += "**Patrones actualizados**:\n"
                    for pattern in result['patterns_found']:
                        report_content += f"- {pattern}\n"
            else:
                report_content += "ℹ️  Sin patrones dinámicos que actualizar\n"
            report_content += "\n"

        report_content += f"""## 🔧 Cambios Realizados

### Variables Añadidas:
- `TRICAPA_DIR = PRODUCTION_DIR / "tricapa"` (para Path objects)
- `tricapa_dir = f"{{models_dir}}/production/tricapa"` (para f-strings)

### Patrones Actualizados:
- `MODELS_DIR / "modelo.joblib"` → `TRICAPA_DIR / "modelo.joblib"`
- `PRODUCTION_DIR / "modelo.joblib"` → `TRICAPA_DIR / "modelo.joblib"`  
- `f"{{models_dir}}/modelo.joblib"` → `f"{{tricapa_dir}}/modelo.joblib"`

## 🚀 Próximos Pasos

1. **Probar pipeline actualizado**: Verificar carga correcta de modelos tricapa
2. **Validar funcionalidad**: Ejecutar tests con datasets conocidos
3. **Confirmar rutas**: Verificar que todos los modelos se cargan desde tricapa/
4. **Documentar cambios**: Actualizar documentación del pipeline

## 📂 Estructura Tricapa Utilizada

```
models/production/tricapa/
├── 🔴 rf_production_cicids.joblib           # Nivel 1 - CICDS2017
├── 🟡 web_normal_detector.joblib            # Nivel 2 - Web context  
├── 🟡 internal_normal_detector.joblib       # Nivel 2 - Internal context
├── 🟢 ddos_random_forest.joblib            # Nivel 3 - DDOS específico
├── 🟢 ddos_lightgbm.joblib                 # Nivel 3 - DDOS específico
├── 🟢 ransomware_random_forest.joblib      # Nivel 3 - Ransomware específico
└── 🟢 ransomware_lightgbm.joblib           # Nivel 3 - Ransomware específico
```

---
*Generado automáticamente por dynamic_tricapa_updater.py*
"""

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        print(f"\n📋 Reporte dinámico generado: {report_path}")

    def run_dynamic_update(self):
        """Ejecuta actualización dinámica completa"""
        print("🔧 ACTUALIZACIÓN DINÁMICA CORE → TRICAPA")
        print("=" * 60)
        print("🎯 Objetivo: Actualizar construcción dinámica de rutas")
        print("🔍 Patrones: MODELS_DIR/, PRODUCTION_DIR/, f-strings")
        print("📦 Modelos objetivo: tricapa/ (7 modelos principales)")
        print()

        # Crear backups
        backup_dir = self.create_backup_structure()

        # Resultados
        results = {}

        # Procesar cada archivo
        for file_name in self.target_files:
            file_path = self.core_dir / file_name

            # Análisis dinámico
            analysis = self.analyze_file_dynamic(file_path)

            if not analysis['matches']:
                results[file_name] = {
                    'updated': False,
                    'changes': 0,
                    'patterns_found': []
                }
                continue

            # Actualizar dinámicamente
            updated = self.update_file_dynamic(file_path, analysis, backup_dir)

            if updated:
                patterns_found = [m['original'] + " → " + m['pattern_info']['replace_func'](m['match'])
                                  for m in analysis['matches'] if m['should_update']]
                results[file_name] = {
                    'updated': True,
                    'changes': len([m for m in analysis['matches'] if m['should_update']]),
                    'patterns_found': patterns_found,
                    'matches': analysis['matches']
                }
            else:
                results[file_name] = {
                    'updated': False,
                    'changes': 0,
                    'patterns_found': []
                }

        # Reporte final
        print("\n🎉 ACTUALIZACIÓN DINÁMICA COMPLETADA")
        print("=" * 60)

        updated_count = sum(1 for r in results.values() if r['updated'])
        total_changes = sum(r['changes'] for r in results.values())

        print(f"✅ Archivos actualizados: {updated_count}/{len(self.target_files)}")
        print(f"🔧 Cambios dinámicos aplicados: {total_changes}")
        print(f"📦 Backups en: {backup_dir}")

        if updated_count > 0:
            print("\n🚀 ARCHIVOS CON PATRONES DINÁMICOS ACTUALIZADOS:")
            for file_name, result in results.items():
                if result['updated']:
                    print(f"   ✅ {file_name} - {result['changes']} patrones actualizados")
                    print(f"      Variables añadidas: TRICAPA_DIR, tricapa_dir")

        # Generar reporte
        self.generate_dynamic_report(results)

        print(f"\n🧪 Verificar funcionamiento:")
        print(f"   python3 core/complete_ml_pipeline.py")
        print(f"   python3 core/scapy_monitor_complete_pipeline.py")
        print(f"   python3 core/scapy_to_ml_features.py")

        print(f"\n🎯 Los archivos ahora buscan modelos en:")
        print(f"   models/production/tricapa/ (para los 7 modelos principales)")
        print(f"   models/production/ (para otros modelos legacy)")


if __name__ == "__main__":
    updater = DynamicTricapaUpdater()
    updater.run_dynamic_update()