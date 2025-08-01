#!/usr/bin/env python3
"""
Project Cleanup & Organization Audit
Analiza todos los scripts generados y categoriza por valor para la RELEASE
"""

import os
import glob
import subprocess
from datetime import datetime
from pathlib import Path


def analyze_project_files():
    """Analiza todos los archivos del proyecto y los categoriza"""

    print("🧹 PROJECT CLEANUP & ORGANIZATION AUDIT")
    print("🎯 Objetivo: Preparar para RELEASE manteniendo solo lo valioso")
    print("=" * 70)

    # Obtener todos los archivos Python
    python_files = glob.glob("*.py")

    categories = {
        'CORE_PRODUCTION': {
            'description': '🏆 Scripts CORE para PRODUCCIÓN (MANTENER)',
            'files': [],
            'criteria': 'Sistema ML funcional, pipeline principal'
        },
        'VALUABLE_TOOLS': {
            'description': '🔧 Herramientas VALIOSAS (MANTENER & ORGANIZAR)',
            'files': [],
            'criteria': 'Utilidades para entrenamiento, análisis, validación'
        },
        'DEBUGGING_LEGACY': {
            'description': '🐛 Scripts de DEBUGGING (ARCHIVAR)',
            'files': [],
            'criteria': 'Usados solo para encontrar problemas específicos'
        },
        'EXPERIMENTAL': {
            'description': '🧪 EXPERIMENTAL/TESTING (EVALUAR)',
            'files': [],
            'criteria': 'Experimentos, pruebas, versiones anteriores'
        },
        'DEPRECATED': {
            'description': '🗑️ DEPRECATED (ELIMINAR)',
            'files': [],
            'criteria': 'Obsoletos, superados por versiones mejores'
        }
    }

    # Categorización basada en nombres y propósito
    file_categorization = {
        # CORE PRODUCTION - Lo que realmente funciona
        'fixed_service_sniffer.py': 'CORE_PRODUCTION',
        'sniffer_compatible_retrainer.py': 'CORE_PRODUCTION',

        # VALUABLE TOOLS - Herramientas útiles
        'cicids_traditional_processor.py': 'VALUABLE_TOOLS',
        'cicids_retrainer.py': 'VALUABLE_TOOLS',
        'unsw_audit.py': 'VALUABLE_TOOLS',

        # DEBUGGING LEGACY - Usados para debugging específico
        'debug_ml_network_sniffer.py': 'DEBUGGING_LEGACY',
        'auto_detect_ml_network_sniffer.py': 'DEBUGGING_LEGACY',
        'fixed_ml_network_sniffer.py': 'DEBUGGING_LEGACY',

        # EXPERIMENTAL - Experimentos durante desarrollo
        'cicids_kaggle_processor.py': 'EXPERIMENTAL',
        'advanced_trainer.py': 'EXPERIMENTAL',
        'advanced_trainer_no_dns.py': 'EXPERIMENTAL',

        # DEPRECATED - Versiones anteriores superadas
        'real_time_ml_network_sniffer.py': 'DEPRECATED',
        'threat-sniffer.py': 'DEPRECATED',
        'initial_trainer_models.py': 'DEPRECATED',
    }

    print("📊 CATEGORIZACIÓN DE ARCHIVOS:")
    print()

    # Categorizar archivos encontrados
    for py_file in python_files:
        file_size = os.path.getsize(py_file) / 1024  # KB
        mod_time = datetime.fromtimestamp(os.path.getmtime(py_file))

        # Determinar categoría
        category = file_categorization.get(py_file, 'EXPERIMENTAL')
        categories[category]['files'].append({
            'name': py_file,
            'size_kb': file_size,
            'modified': mod_time,
            'lines': count_lines(py_file)
        })

    # Mostrar resultados por categoría
    for cat_name, cat_info in categories.items():
        if cat_info['files']:
            print(f"{cat_info['description']}")
            print(f"Criterio: {cat_info['criteria']}")

            for file_info in sorted(cat_info['files'], key=lambda x: x['modified'], reverse=True):
                print(f"   📄 {file_info['name']:<35} "
                      f"({file_info['size_kb']:>6.1f}KB, "
                      f"{file_info['lines']:>4d} líneas, "
                      f"{file_info['modified'].strftime('%m/%d %H:%M')})")
            print()

    return categories


def count_lines(filename):
    """Cuenta líneas de código en un archivo"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return sum(1 for line in f if line.strip())
    except:
        return 0


def analyze_models_and_data():
    """Analiza modelos y datos generados"""

    print("🤖 ANÁLISIS DE MODELOS Y DATOS:")
    print("=" * 40)

    # Modelos
    model_files = glob.glob("models/*.joblib")
    if model_files:
        print("📊 MODELOS ENCONTRADOS:")
        for model in sorted(model_files):
            size_mb = os.path.getsize(model) / (1024 * 1024)
            mod_time = datetime.fromtimestamp(os.path.getmtime(model))

            # Categorizar modelos
            if 'sniffer_compatible' in model:
                status = "🏆 PRODUCTION READY"
            elif 'cicids' in model:
                status = "✅ CLEAN DATA"
            elif 'final' in model:
                status = "❌ CORRUPTED DATA"
            else:
                status = "🧪 EXPERIMENTAL"

            print(f"   {status:<20} {os.path.basename(model):<40} "
                  f"({size_mb:>5.1f}MB, {mod_time.strftime('%m/%d %H:%M')})")

    # Datos
    data_files = glob.glob("*.csv")
    if data_files:
        print("\n📈 DATASETS ENCONTRADOS:")
        for data in sorted(data_files):
            if os.path.getsize(data) > 1024 * 1024:  # > 1MB
                size_mb = os.path.getsize(data) / (1024 * 1024)
                mod_time = datetime.fromtimestamp(os.path.getmtime(data))

                # Categorizar datasets
                if 'cicids_2017_processed' in data:
                    status = "🏆 CLEAN & PROCESSED"
                elif 'UNSW' in data:
                    status = "❌ CORRUPTED"
                else:
                    status = "📊 DATA"

                print(f"   {status:<20} {os.path.basename(data):<40} "
                      f"({size_mb:>6.1f}MB, {mod_time.strftime('%m/%d %H:%M')})")

    print()


def generate_cleanup_recommendations():
    """Genera recomendaciones de limpieza específicas"""

    print("💡 RECOMENDACIONES DE LIMPIEZA:")
    print("=" * 40)

    recommendations = {
        "MANTENER & ORGANIZAR": [
            "fixed_service_sniffer.py → core/ml_sniffer.py",
            "sniffer_compatible_retrainer.py → tools/model_trainer.py",
            "cicids_traditional_processor.py → tools/dataset_processor.py",
            "models/rf_production_sniffer_compatible.joblib → models/production/",
            "cicids_2017_processed.csv → data/clean/"
        ],

        "ARCHIVAR (no eliminar todavía)": [
            "debug_ml_network_sniffer.py → archive/debugging/",
            "fixed_ml_network_sniffer.py → archive/debugging/",
            "unsw_audit.py → archive/analysis/",
            "models/rf_production_final.joblib → archive/corrupted_models/"
        ],

        "EVALUAR PARA ELIMINACIÓN": [
            "advanced_trainer*.py → posible eliminación",
            "initial_trainer_models.py → posible eliminación",
            "threat-sniffer.py → posible eliminación",
            "UNSW-NB15.csv → eliminar (corrupto)"
        ],

        "CREAR ESTRUCTURA NUEVA": [
            "core/ → código principal de producción",
            "tools/ → herramientas de desarrollo/entrenamiento",
            "models/production/ → modelos listos para release",
            "data/clean/ → datasets limpios y validados",
            "archive/ → código legacy pero valioso",
            "docs/ → documentación de lecciones aprendidas"
        ]
    }

    for category, items in recommendations.items():
        print(f"\n{category}:")
        for item in items:
            print(f"   ✅ {item}")

    print()


def generate_next_steps():
    """Genera pasos siguientes hacia la RELEASE"""

    print("🚀 PRÓXIMOS PASOS HACIA LA RELEASE:")
    print("=" * 40)

    next_steps = [
        "1. 🧹 LIMPIEZA INMEDIATA:",
        "   - Crear estructura de directorios organizada",
        "   - Mover archivos según recomendaciones",
        "   - Eliminar código claramente obsoleto",
        "",
        "2. 🔧 REFINAMIENTO TÉCNICO:",
        "   - Optimizar fixed_service_sniffer.py para producción",
        "   - Mejorar logging y monitoring",
        "   - Configuraciones externalizadas",
        "",
        "3. 📚 DOCUMENTACIÓN:",
        "   - README completo del proyecto",
        "   - Lecciones aprendidas (timestamps, datasets, etc.)",
        "   - Guía de despliegue",
        "",
        "4. 🧪 TESTING & VALIDACIÓN:",
        "   - Suite de tests automatizados",
        "   - Validación con tráfico real diverso",
        "   - Benchmarks de performance",
        "",
        "5. 🚀 PREPARACIÓN RELEASE:",
        "   - Containerización (Docker)",
        "   - CI/CD pipeline",
        "   - Configuración de producción",
        "",
        "6. 📊 MONITORING & OBSERVABILITY:",
        "   - Métricas de sistema",
        "   - Alerting inteligente",
        "   - Dashboards de monitoreo"
    ]

    for step in next_steps:
        print(step)

    print()


def main():
    """Función principal del audit"""

    print(f"Ejecutado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Directorio: {os.getcwd()}")
    print()

    # Ejecutar análisis
    categories = analyze_project_files()
    analyze_models_and_data()
    generate_cleanup_recommendations()
    generate_next_steps()

    print("🎯 RESUMEN:")
    print(f"   - Hito INCREÍBLE logrado: Sistema ML funcional ✅")
    print(f"   - Próximo objetivo: Organizar para RELEASE 🚀")
    print(f"   - Estado: Listo para limpieza y refinamiento 💪")

    print("\n" + "=" * 70)
    print("🏆 ¡EXCELENTE TRABAJO, ALONSO!")
    print("   El sistema funciona, ahora vamos por la RELEASE perfecta.")
    print("=" * 70)


if __name__ == "__main__":
    main()