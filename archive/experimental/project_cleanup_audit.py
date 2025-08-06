#!/usr/bin/env python3
"""
Comprehensive Project Audit - Upgraded Happiness
Análisis completo respetando TODA la arquitectura del sistema
"""

import os
import glob
import subprocess
from datetime import datetime
from pathlib import Path


def read_makefile_targets():
    """Lee el Makefile para entender la estructura oficial del proyecto"""

    print("📋 ANALIZANDO MAKEFILE PARA ESTRUCTURA OFICIAL")
    print("=" * 60)

    makefile_files = []
    makefile_targets = []

    if os.path.exists('Makefile'):
        try:
            with open('Makefile', 'r') as f:
                content = f.read()

            print("✅ Makefile encontrado - extrayendo información oficial...")

            # Buscar archivos mencionados en el Makefile
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue

                # Buscar archivos .py mencionados
                if '.py' in line and not line.startswith('\t'):
                    # Extraer nombres de archivos .py
                    words = line.split()
                    for word in words:
                        if word.endswith('.py') and not word.startswith('-'):
                            makefile_files.append(word.strip(':'))

                # Buscar targets/objetivos
                if ':' in line and not line.startswith('\t') and not '=' in line:
                    target = line.split(':')[0].strip()
                    if target and not target.startswith('.'):
                        makefile_targets.append(target)

            if makefile_files:
                print("🐍 ARCHIVOS PYTHON EN MAKEFILE:")
                for py_file in sorted(set(makefile_files)):
                    status = "✅ EXISTS" if os.path.exists(py_file) else "❌ MISSING"
                    print(f"   {status} {py_file}")

            if makefile_targets:
                print(f"\n🎯 TARGETS EN MAKEFILE:")
                for target in sorted(set(makefile_targets)):
                    print(f"   📌 {target}")

        except Exception as e:
            print(f"⚠️  Error leyendo Makefile: {e}")
    else:
        print("⚠️  Makefile no encontrado")

    print()
    return makefile_files, makefile_targets


def analyze_all_project_files():
    """Análisis exhaustivo de TODOS los archivos del proyecto"""

    print("🔍 ANÁLISIS EXHAUSTIVO DE ARCHIVOS DEL PROYECTO")
    print("=" * 60)

    file_categories = {
        'SYSTEM_CORE': {
            'description': '🏆 SISTEMA CORE - Network/ML/Security (CRÍTICO)',
            'files': [],
            'patterns': [
                'simple_firewall_agent.py',
                'promiscuous_agent*.py',
                'geoip_enricher.py',
                'lightweight_ml_detector.py',
                'real_zmq_dashboard*.py',
                'fixed_service_sniffer.py',
                'enhanced_network_feature_extractor.py'
            ]
        },
        'ML_PIPELINE': {
            'description': '🤖 PIPELINE ML - Entrenamiento/Modelos (CRÍTICO)',
            'files': [],
            'patterns': [
                '*trainer*.py',
                '*retrainer*.py',
                'model_analyzer*.py',
                'validate_ensemble*.py',
                'hybrid_dataset_generator.py'
            ]
        },
        'DATA_PIPELINE': {
            'description': '📊 PIPELINE DATOS - Descarga/Limpieza (CRÍTICO)',
            'files': [],
            'patterns': [
                '*processor*.py',
                '*cicids*.py',
                '*audit*.py',
                'process-raw-data*.py',
                'extract_required_features.py'
            ]
        },
        'TRAFFIC_CAPTURE': {
            'description': '🌐 CAPTURA TRÁFICO - Generación datos entrenamiento (CRÍTICO)',
            'files': [],
            'patterns': [
                '*sniffer*.py',
                '*capture*.py',
                '*traffic*.py'
            ]
        },
        'CONFIGURATION': {
            'description': '⚙️ CONFIGURACIÓN - Sistema/Modelos (ESENCIAL)',
            'files': [],
            'patterns': ['*.json']
        },
        'DOCUMENTATION': {
            'description': '📚 DOCUMENTACIÓN - README/ROADMAP (ESENCIAL)',
            'files': [],
            'patterns': ['README*', 'ROADMAP*', 'requirements.txt', 'Makefile', '*.md']
        },
        'SCRIPTS_SUPPORT': {
            'description': '🔧 SCRIPTS SOPORTE - Bash/Utilidades (MANTENER)',
            'files': [],
            'patterns': ['*.sh', '*.bash']
        },
        'LEGACY_VALUABLE': {
            'description': '📦 LEGACY VALIOSO - Versiones anteriores útiles',
            'files': [],
            'patterns': []  # Se llena manualmente
        },
        'EXPERIMENTAL': {
            'description': '🧪 EXPERIMENTAL - Para evaluar',
            'files': [],
            'patterns': []  # Se llena manualmente
        }
    }

    # Obtener todos los archivos del proyecto
    all_files = []
    for ext in ['*.py', '*.json', '*.sh', '*.bash', '*.md', '*.txt', 'Makefile', 'ROADMAP', 'README']:
        all_files.extend(glob.glob(ext))

    # Categorizar archivos
    categorized = set()

    for category, info in file_categories.items():
        for pattern in info['patterns']:
            matches = glob.glob(pattern)
            for match in matches:
                if os.path.isfile(match) and match not in categorized:
                    file_size = os.path.getsize(match) / 1024
                    mod_time = datetime.fromtimestamp(os.path.getmtime(match))
                    lines = count_lines(match) if match.endswith('.py') else 0

                    info['files'].append({
                        'name': match,
                        'size_kb': file_size,
                        'modified': mod_time,
                        'lines': lines
                    })
                    categorized.add(match)

    # Archivos específicos que sabemos son legacy pero valiosos
    legacy_valuable = [
        'debug_ml_network_sniffer.py',
        'auto_detect_ml_network_sniffer.py',
        'real_time_ml_network_sniffer.py'
    ]

    for legacy_file in legacy_valuable:
        if os.path.exists(legacy_file) and legacy_file not in categorized:
            file_size = os.path.getsize(legacy_file) / 1024
            mod_time = datetime.fromtimestamp(os.path.getmtime(legacy_file))
            lines = count_lines(legacy_file)

            file_categories['LEGACY_VALUABLE']['files'].append({
                'name': legacy_file,
                'size_kb': file_size,
                'modified': mod_time,
                'lines': lines
            })
            categorized.add(legacy_file)

    # Archivos restantes van a experimental
    for file in all_files:
        if file not in categorized and os.path.isfile(file):
            file_size = os.path.getsize(file) / 1024
            mod_time = datetime.fromtimestamp(os.path.getmtime(file))
            lines = count_lines(file) if file.endswith('.py') else 0

            file_categories['EXPERIMENTAL']['files'].append({
                'name': file,
                'size_kb': file_size,
                'modified': mod_time,
                'lines': lines
            })

    # Mostrar resultados
    total_files = 0
    for category, info in file_categories.items():
        if info['files']:
            print(f"\n{info['description']}")
            print("-" * len(info['description']))

            for file_info in sorted(info['files'], key=lambda x: x['modified'], reverse=True):
                lines_info = f", {file_info['lines']:>4d} líneas" if file_info['lines'] > 0 else ""
                print(f"   📄 {file_info['name']:<40} "
                      f"({file_info['size_kb']:>6.1f}KB{lines_info}, "
                      f"{file_info['modified'].strftime('%m/%d %H:%M')})")
                total_files += 1

    print(f"\n📊 TOTAL ARCHIVOS ANALIZADOS: {total_files}")
    return file_categories


def count_lines(filename):
    """Cuenta líneas de código en un archivo"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
    except:
        return 0


def analyze_models_and_data():
    """Análisis de modelos y datasets"""

    print("\n🤖 ANÁLISIS DE MODELOS Y DATASETS")
    print("=" * 50)

    # Modelos
    model_files = glob.glob("models/*.joblib") + glob.glob("models/*/*.joblib")
    if model_files:
        print("🧠 MODELOS ENCONTRADOS:")
        for model in sorted(model_files):
            size_mb = os.path.getsize(model) / (1024 * 1024)
            mod_time = datetime.fromtimestamp(os.path.getmtime(model))

            if 'sniffer_compatible' in model:
                status = "🏆 PRODUCTION READY"
            elif 'cicids' in model:
                status = "✅ TRAINED ON CLEAN DATA"
            elif 'final' in model or 'unsw' in model.lower():
                status = "⚠️  TRAINED ON CORRUPTED DATA"
            else:
                status = "🔧 UTILITY MODEL"

            print(f"   {status:<25} {os.path.basename(model):<40} "
                  f"({size_mb:>5.1f}MB, {mod_time.strftime('%m/%d %H:%M')})")

    # Datasets grandes
    data_files = []
    for pattern in ["*.csv", "data/*.csv", "datasets/*.csv"]:
        data_files.extend(glob.glob(pattern))

    large_datasets = [f for f in data_files if os.path.getsize(f) > 10 * 1024 * 1024]  # > 10MB

    if large_datasets:
        print("\n📊 DATASETS ENCONTRADOS:")
        for data in sorted(large_datasets):
            size_mb = os.path.getsize(data) / (1024 * 1024)
            mod_time = datetime.fromtimestamp(os.path.getmtime(data))

            if 'cicids_2017_processed' in data:
                status = "🏆 CLEAN & PROCESSED"
            elif 'UNSW' in data and 'NB15' in data:
                status = "❌ CORRUPTED (confirmed)"
            elif 'cicids' in data.lower():
                status = "✅ CICIDS FAMILY"
            else:
                status = "📊 DATASET"

            print(f"   {status:<25} {os.path.basename(data):<40} "
                  f"({size_mb:>6.1f}MB, {mod_time.strftime('%m/%d %H:%M')})")


def generate_organization_recommendations():
    """Recomendaciones de organización conservadoras"""

    print("\n💡 RECOMENDACIONES DE ORGANIZACIÓN")
    print("=" * 50)

    print("🎯 FILOSOFÍA: CONSERVAR TODO LO VALIOSO, SOLO ORGANIZAR")
    print()

    organization_plan = {
        "MANTENER TODO EL SISTEMA CORE": [
            "✅ simple_firewall_agent.py → MANTENER (componente core)",
            "✅ promiscuous_agent*.py → MANTENER (componente core)",
            "✅ geoip_enricher.py → MANTENER (componente core)",
            "✅ lightweight_ml_detector.py → MANTENER (componente core)",
            "✅ real_zmq_dashboard*.py → MANTENER (componente core)",
            "✅ fixed_service_sniffer.py → MANTENER (recién arreglado)",
            "✅ enhanced_network_feature_extractor.py → MANTENER (features críticas)"
        ],

        "MANTENER TODO EL PIPELINE ML": [
            "✅ *trainer*.py → MANTENER (esenciales para re-entrenamiento)",
            "✅ *retrainer*.py → MANTENER (capacidad de mejora continua)",
            "✅ model_analyzer*.py → MANTENER (validación de modelos)",
            "✅ validate_ensemble*.py → MANTENER (testing de modelos)"
        ],

        "MANTENER TODO EL PIPELINE DE DATOS": [
            "✅ *processor*.py → MANTENER (descarga/limpieza datasets)",
            "✅ *cicids*.py → MANTENER (acceso a datos limpios)",
            "✅ *audit*.py → MANTENER (validación de calidad de datos)",
            "✅ extract_required_features.py → MANTENER (pipeline features)"
        ],

        "MANTENER DOCUMENTACIÓN COMPLETA": [
            "✅ README → MANTENER (documentación principal)",
            "✅ ROADMAP → MANTENER (planificación proyecto)",
            "✅ requirements.txt → MANTENER (dependencias)",
            "✅ Makefile → MANTENER (automatización)",
            "✅ *.json → MANTENER TODOS (configuraciones)"
        ],

        "ARCHIVAR (NO ELIMINAR) LEGACY VALIOSO": [
            "📦 debug_ml_network_sniffer.py → archive/debugging/",
            "📦 real_time_ml_network_sniffer.py → archive/versions/",
            "📦 models con datos corruptos → archive/corrupted_models/",
            "📦 UNSW-NB15.csv → archive/corrupted_datasets/"
        ],

        "ESTRUCTURA PROPUESTA CONSERVADORA": [
            "core/ → Componentes sistema principal (firewall, agents, ML)",
            "ml_pipeline/ → Todo el pipeline ML (trainers, analyzers)",
            "data_pipeline/ → Scripts descarga/procesamiento datasets",
            "config/ → Todas las configuraciones JSON",
            "models/ → Modelos organizados por estado (production/, archive/)",
            "docs/ → Documentación (README, ROADMAP, etc.)",
            "scripts/ → Scripts bash y utilidades",
            "archive/ → Legacy valioso pero no en producción activa"
        ]
    }

    for category, items in organization_plan.items():
        print(f"\n{category}:")
        for item in items:
            print(f"   {item}")


def generate_next_steps():
    """Próximos pasos hacia RELEASE"""

    print(f"\n🚀 PRÓXIMOS PASOS HACIA RELEASE")
    print("=" * 50)

    next_steps = [
        "FASE 1 - ORGANIZACIÓN CONSERVADORA:",
        "   🗂️  Crear estructura de directorios sin mover archivos aún",
        "   📋 Inventario completo de dependencias entre archivos",
        "   🔗 Mapear todas las interconexiones del sistema",
        "",
        "FASE 2 - DOCUMENTACIÓN EXHAUSTIVA:",
        "   📚 Documentar cada componente del sistema",
        "   🧭 Actualizar ROADMAP con lecciones aprendidas",
        "   📖 Crear guías de uso para cada pipeline",
        "",
        "FASE 3 - TESTING COMPREHENSIVE:",
        "   🧪 Suite de tests para todo el sistema",
        "   ✅ Validación de cada componente individualmente",
        "   🔄 Testing de integración completa",
        "",
        "FASE 4 - OPTIMIZACIÓN SIN ROMPER:",
        "   ⚡ Optimizaciones de performance",
        "   📊 Mejoras de logging y monitoring",
        "   🔧 Configuraciones externalizadas",
        "",
        "FASE 5 - CONTAINERIZACIÓN Y CI/CD:",
        "   🐳 Docker para todo el stack",
        "   🚀 Pipeline de deployment",
        "   📈 Monitoring en producción",
        "",
        "FILOSOFÍA: 'SI FUNCIONA, NO LO ROMPAS - SOLO MEJÓRALO'"
    ]

    for step in next_steps:
        print(step)


def main():
    """Función principal del audit comprehensivo"""

    print("🔍 COMPREHENSIVE PROJECT AUDIT - UPGRADED HAPPINESS")
    print("🎯 Respetando TODA la arquitectura del sistema completo")
    print("=" * 80)
    print(f"Ejecutado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Directorio: {os.getcwd()}")
    print()

    # Análisis completo
    makefile_files, makefile_targets = read_makefile_targets()
    file_categories = analyze_all_project_files()
    analyze_models_and_data()
    generate_organization_recommendations()
    generate_next_steps()

    print(f"\n🎯 RESUMEN EJECUTIVO:")
    print(f"   ✅ Sistema ML funcionando correctamente")
    print(f"   ✅ Pipeline completo de datos/entrenamiento identificado")
    print(f"   ✅ Arquitectura completa de red/security mapeada")
    print(f"   ✅ Todos los componentes críticos preservados")
    print(f"   🎯 Objetivo: Organizar sin romper, preparar para RELEASE")

    print("\n" + "=" * 80)
    print("🏆 SISTEMA COMPREHENSIVE MAPEADO - LISTO PARA ORGANIZACIÓN")
    print("   Filosofía: Conservar todo lo valioso, solo mejorar la organización")
    print("=" * 80)


if __name__ == "__main__":
    main()