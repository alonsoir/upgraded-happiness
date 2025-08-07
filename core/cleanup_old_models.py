#!/usr/bin/env python3
"""
🧹 UPGRADED HAPPINESS - Limpieza Inteligente de Modelos

PROBLEMA: 40+ archivos de modelos sin organización clara
SOLUCIÓN:
1. Identificar modelos por importancia y fecha
2. Archivar modelos obsoletos
3. Mantener solo modelos de producción y mejores
4. Crear estructura organizada

Autor: Alonso Rodriguez
Fecha: Agosto 7, 2025
"""

import os
import sys
import json
import joblib
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import pandas as pd

# Configuración
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
MODELS_DIR = PROJECT_ROOT / "models"
OPTIMIZED_MODELS_DIR = PROJECT_ROOT / "optimized_models"


def print_header():
    """Imprime header del script"""
    print("=" * 80)
    print("🧹 UPGRADED HAPPINESS - LIMPIEZA INTELIGENTE DE MODELOS")
    print("Organizando 40+ archivos de modelos para fácil mantenimiento")
    print("=" * 80)


def analyze_model_inventory():
    """Analiza el inventario actual de modelos"""
    print("📊 Analizando inventario de modelos...")

    # Estructuras para clasificar archivos
    models_info = {
        'production': [],  # Modelos de producción actuales
        'optimized': [],  # Modelos optimizados
        'historical': [],  # Modelos históricos por fecha
        'specialized': [],  # Modelos especializados
        'backup': [],  # Archivos de respaldo
        'metadata': [],  # Archivos de metadatos/configuración
        'unknown': []  # Archivos no clasificados
    }

    # Obtener todos los archivos en models/
    all_files = list(MODELS_DIR.rglob("*"))
    all_files = [f for f in all_files if f.is_file()]

    print(f"   📁 Total archivos encontrados: {len(all_files)}")

    # Clasificar archivos
    for file_path in all_files:
        file_info = analyze_file(file_path)

        # Clasificar según patrones
        if any(x in file_path.name for x in ['ddos_', 'ransomware_']):
            if 'Aug  7' in str(file_path.stat().st_mtime) or file_path.stat().st_mtime > 1723008000:  # Aug 7, 2025
                models_info['production'].append(file_info)
            else:
                models_info['historical'].append(file_info)
        elif 'optimized' in file_path.name:
            models_info['optimized'].append(file_info)
        elif any(x in file_path.name for x in ['production', 'sniffer', 'cicids']):
            models_info['specialized'].append(file_info)
        elif any(x in file_path.name for x in ['normal_', 'detector_', 'behavior']):
            models_info['specialized'].append(file_info)
        elif file_path.name.startswith('model_2025'):
            models_info['historical'].append(file_info)
        elif file_path.name.endswith(('.json', '.txt')):
            models_info['metadata'].append(file_info)
        elif 'archive' in str(file_path) or 'backup' in str(file_path):
            models_info['backup'].append(file_info)
        else:
            models_info['unknown'].append(file_info)

    # Mostrar clasificación
    for category, files in models_info.items():
        if files:
            print(f"   📂 {category.upper()}: {len(files)} archivos")
            for file_info in files[:3]:  # Mostrar primeros 3
                print(f"      • {file_info['name']} ({file_info['size_mb']:.1f}MB)")
            if len(files) > 3:
                print(f"      ... y {len(files) - 3} más")

    return models_info


def analyze_file(file_path):
    """Analiza un archivo individual"""
    stat = file_path.stat()

    file_info = {
        'path': file_path,
        'name': file_path.name,
        'size_mb': stat.st_size / (1024 * 1024),
        'modified': datetime.fromtimestamp(stat.st_mtime),
        'category': 'unknown',
        'importance': 0,  # 0=low, 1=medium, 2=high, 3=critical
        'keep': True
    }

    # Determinar importancia basada en nombre y fecha
    name = file_path.name.lower()

    # Modelos críticos (no tocar)
    if any(x in name for x in ['ddos_lightgbm.joblib', 'ddos_random_forest.joblib']) and 'Aug  7' in str(stat.st_mtime):
        file_info['importance'] = 3
        file_info['category'] = 'production_critical'
    # Modelos optimizados recientes
    elif 'optimized' in name and 'final' in name:
        file_info['importance'] = 3
        file_info['category'] = 'optimized_critical'
    # Modelos de producción
    elif any(x in name for x in ['production', 'sniffer_compatible']):
        file_info['importance'] = 2
        file_info['category'] = 'production_stable'
    # Modelos especializados útiles
    elif any(x in name for x in ['detector', 'behavior']) and stat.st_size > 1024 * 1024:  # >1MB
        file_info['importance'] = 2
        file_info['category'] = 'specialized_useful'
    # Metadatos importantes
    elif name.endswith(('.json')) and any(x in name for x in ['metrics', 'metadata', 'summary']):
        file_info['importance'] = 1
        file_info['category'] = 'metadata_useful'
    # Modelos históricos grandes (posible archivo)
    elif stat.st_size > 5 * 1024 * 1024 and any(x in name for x in ['model_2025', 'rf_']):  # >5MB
        file_info['importance'] = 0
        file_info['category'] = 'historical_archive'
        file_info['keep'] = False  # Candidato para archivo
    # Archivos pequeños o duplicados
    elif stat.st_size < 1024:  # <1KB
        file_info['importance'] = 0
        file_info['category'] = 'small_file'

    return file_info


def create_organized_structure():
    """Crea estructura organizada para modelos"""
    print("📁 Creando estructura organizada...")

    # Estructura propuesta
    new_structure = {
        'current': MODELS_DIR / "current",  # Modelos actuales en uso
        'optimized': MODELS_DIR / "optimized",  # Modelos optimizados
        'production': MODELS_DIR / "production",  # Modelos estables de producción
        'archive': MODELS_DIR / "archive",  # Modelos históricos archivados
        'backup': MODELS_DIR / "backup",  # Respaldos automáticos
        'metadata': MODELS_DIR / "metadata",  # Configuraciones y metadatos
        'temp': MODELS_DIR / "temp"  # Archivos temporales
    }

    # Crear directorios
    for dir_name, dir_path in new_structure.items():
        dir_path.mkdir(exist_ok=True)
        print(f"   ✅ {dir_name}/")

    return new_structure


def organize_models(models_info, new_structure):
    """Organiza modelos según su clasificación"""
    print("🔄 Organizando modelos...")

    # Mapeo de categorías a directorios
    category_mapping = {
        'production_critical': 'current',
        'optimized_critical': 'optimized',
        'production_stable': 'production',
        'specialized_useful': 'production',
        'metadata_useful': 'metadata',
        'historical_archive': 'archive',
        'small_file': 'temp'
    }

    moved_files = defaultdict(list)
    kept_files = []

    # Procesar cada categoría
    for category, files in models_info.items():
        for file_info in files:

            # Determinar destino
            file_category = file_info.get('category', 'unknown')
            target_dir = category_mapping.get(file_category)

            if not target_dir:
                # Mantener en ubicación actual si no sabemos dónde ponerlo
                kept_files.append(file_info)
                continue

            # Obtener paths
            source_path = file_info['path']
            target_path = new_structure[target_dir] / source_path.name

            # Evitar conflictos de nombres
            counter = 1
            while target_path.exists():
                name_parts = source_path.name.rsplit('.', 1)
                if len(name_parts) == 2:
                    target_path = new_structure[target_dir] / f"{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    target_path = new_structure[target_dir] / f"{source_path.name}_{counter}"
                counter += 1

            # Mover archivo
            try:
                if file_info['importance'] >= 2:
                    # Archivos importantes: copiar (no mover) por seguridad
                    shutil.copy2(source_path, target_path)
                    moved_files[target_dir].append(f"📋 {source_path.name} (copied)")
                else:
                    # Archivos menos críticos: mover
                    shutil.move(str(source_path), str(target_path))
                    moved_files[target_dir].append(f"📁 {source_path.name}")

            except Exception as e:
                print(f"   ⚠️ Error moviendo {source_path.name}: {e}")
                kept_files.append(file_info)

    # Mostrar resultados
    print("\n📊 Resultados de organización:")
    for dir_name, files in moved_files.items():
        print(f"   📂 {dir_name}/ ({len(files)} archivos)")
        for file_desc in files[:5]:  # Mostrar primeros 5
            print(f"      {file_desc}")
        if len(files) > 5:
            print(f"      ... y {len(files) - 5} más")

    if kept_files:
        print(f"   📋 Mantenidos en ubicación original: {len(kept_files)} archivos")

    return moved_files


def create_inventory_report(new_structure):
    """Crea reporte de inventario después de la organización"""
    print("📋 Creando reporte de inventario...")

    report = {
        "cleanup_date": datetime.now().isoformat(),
        "directories": {},
        "recommendations": [],
        "critical_models": []
    }

    # Analizar cada directorio
    for dir_name, dir_path in new_structure.items():
        if not dir_path.exists():
            continue

        files = list(dir_path.glob("*"))
        total_size = sum(f.stat().st_size for f in files if f.is_file())

        dir_info = {
            "file_count": len([f for f in files if f.is_file()]),
            "total_size_mb": total_size / (1024 * 1024),
            "files": []
        }

        for file_path in files:
            if file_path.is_file():
                file_stat = file_path.stat()
                dir_info["files"].append({
                    "name": file_path.name,
                    "size_mb": file_stat.st_size / (1024 * 1024),
                    "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                })

        report["directories"][dir_name] = dir_info

        # Identificar modelos críticos
        if dir_name in ['current', 'optimized']:
            for file_info in dir_info["files"]:
                if file_info["name"].endswith('.joblib'):
                    report["critical_models"].append({
                        "location": f"{dir_name}/{file_info['name']}",
                        "size_mb": file_info["size_mb"]
                    })

    # Generar recomendaciones
    archive_size = report["directories"].get("archive", {}).get("total_size_mb", 0)
    if archive_size > 50:  # >50MB en archivo
        report["recommendations"].append(
            f"Considerar comprimir directorio archive/ ({archive_size:.1f}MB)"
        )

    temp_files = report["directories"].get("temp", {}).get("file_count", 0)
    if temp_files > 10:
        report["recommendations"].append(
            f"Limpiar archivos temporales ({temp_files} archivos en temp/)"
        )

    # Guardar reporte
    report_path = MODELS_DIR / "cleanup_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"   ✅ Reporte guardado: {report_path}")
    return report


def show_cleanup_summary(report, moved_files):
    """Muestra resumen final de la limpieza"""
    print("\n" + "=" * 80)
    print("📊 RESUMEN DE LIMPIEZA COMPLETADA")
    print("=" * 80)

    # Estadísticas generales
    total_files = sum(dir_info["file_count"] for dir_info in report["directories"].values())
    total_size = sum(dir_info["total_size_mb"] for dir_info in report["directories"].values())

    print(f"📁 Total archivos organizados: {total_files}")
    print(f"💾 Tamaño total: {total_size:.1f}MB")
    print()

    # Estructura nueva
    print("📂 ESTRUCTURA ORGANIZADA:")
    for dir_name, dir_info in report["directories"].items():
        if dir_info["file_count"] > 0:
            print(f"   {dir_name}/  ({dir_info['file_count']} archivos, {dir_info['total_size_mb']:.1f}MB)")
    print()

    # Modelos críticos
    if report["critical_models"]:
        print("🏆 MODELOS CRÍTICOS (USAR ESTOS):")
        for model in report["critical_models"][:5]:  # Mostrar primeros 5
            print(f"   ✅ {model['location']} ({model['size_mb']:.1f}MB)")
    print()

    # Recomendaciones
    if report["recommendations"]:
        print("💡 RECOMENDACIONES:")
        for rec in report["recommendations"]:
            print(f"   • {rec}")
    print()

    # Comandos útiles
    print("🔧 COMANDOS ÚTILES:")
    print("   # Usar modelos organizados")
    print("   python core/use_current_models.py")
    print()
    print("   # Ver reporte completo")
    print("   cat models/cleanup_report.json | python -m json.tool")
    print()
    print("   # Limpiar archivos temporales")
    print("   rm -rf models/temp/*")
    print()

    print("✅ LIMPIEZA COMPLETADA - Estructura organizada y lista")
    print("=" * 80)


def main():
    """Función principal"""
    print_header()

    try:
        # Verificar que existe el directorio models
        if not MODELS_DIR.exists():
            print(f"❌ No se encontró directorio de modelos: {MODELS_DIR}")
            return 1

        # Paso 1: Analizar inventario actual
        models_info = analyze_model_inventory()

        # Paso 2: Crear estructura organizada
        new_structure = create_organized_structure()

        # Paso 3: Organizar modelos
        moved_files = organize_models(models_info, new_structure)

        # Paso 4: Crear reporte de inventario
        report = create_inventory_report(new_structure)

        # Paso 5: Mostrar resumen
        show_cleanup_summary(report, moved_files)

        return 0

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)