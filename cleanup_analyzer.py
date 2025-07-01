#!/usr/bin/env python3
"""
Analizador de Limpieza Inteligente - Upgraded Happiness
=====================================================
Identifica qué consolidar, qué eliminar y qué conservar
"""

import os
import re
from pathlib import Path
from collections import defaultdict
import hashlib
import json


def get_file_hash(file_path):
    """Calcula hash MD5 de un archivo para detectar duplicados"""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None


def analyze_project_for_cleanup():
    """Análisis completo para estrategia de limpieza"""

    print("🔍 ANÁLISIS COMPLETO PARA LIMPIEZA QUIRÚRGICA")
    print("=" * 60)

    root = Path(".")

    # Categorías de archivos
    categories = {
        'fix_scripts': [],
        'backup_files': [],
        'test_files': [],
        'temp_files': [],
        'core_files': [],
        'config_files': [],
        'duplicates': defaultdict(list),
        'large_files': [],
        'empty_files': []
    }

    # Patrones para clasificar archivos
    patterns = {
        'fix_scripts': re.compile(r'^fix_.*\.py$'),
        'backup_files': re.compile(r'.*\.(backup|bak|old|orig|copy|\.quick)$'),
        'temp_files': re.compile(r'^(temp_|tmp_|test_.*|.*_temp|.*_tmp)'),
        'duplicates_suffix': re.compile(r'.*_\d+\.py$'),
        'version_files': re.compile(r'.*_v\d+.*\.py$'),
    }

    # Archivos core esenciales (ya validados por tests)
    core_files = {
        'system_orchestrator.py',
        'lightweight_ml_detector.py',
        'promiscuous_agent.py'
    }

    # Recopilar todos los archivos Python
    all_files = list(root.glob("**/*.py"))

    print(f"📁 Archivos Python encontrados: {len(all_files)}")
    print("\n🏷️  CLASIFICANDO ARCHIVOS...")

    # Hashes para detectar duplicados exactos
    file_hashes = {}

    for file_path in all_files:
        if file_path.is_file():
            file_name = file_path.name
            file_size = file_path.stat().st_size
            file_hash = get_file_hash(file_path)

            # Clasificar por categorías
            if file_name in core_files:
                categories['core_files'].append((file_path, file_size))
            elif patterns['fix_scripts'].match(file_name):
                categories['fix_scripts'].append((file_path, file_size))
            elif patterns['backup_files'].match(str(file_path)):
                categories['backup_files'].append((file_path, file_size))
            elif patterns['temp_files'].match(file_name):
                categories['temp_files'].append((file_path, file_size))
            elif file_path.parts[0] == 'tests' or 'test' in file_name:
                categories['test_files'].append((file_path, file_size))
            elif file_name.endswith('.yaml') or file_name.endswith('.json'):
                categories['config_files'].append((file_path, file_size))

            # Detectar duplicados por hash
            if file_hash:
                if file_hash in file_hashes:
                    categories['duplicates'][file_hash].append((file_path, file_size))
                else:
                    file_hashes[file_hash] = (file_path, file_size)

            # Archivos grandes (>50KB)
            if file_size > 50000:
                categories['large_files'].append((file_path, file_size))

            # Archivos vacíos
            if file_size == 0:
                categories['empty_files'].append((file_path, file_size))

    # Convertir duplicados a lista final
    final_duplicates = []
    for file_hash, files in categories['duplicates'].items():
        if len(files) > 1:
            # Agregar el original también
            original = file_hashes[file_hash]
            all_dupes = [original] + files
            final_duplicates.append(all_dupes)

    categories['duplicates'] = final_duplicates

    return categories


def analyze_fix_scripts(fix_scripts):
    """Analiza contenido de scripts fix para consolidación"""

    print("\n🔧 ANÁLISIS DETALLADO DE SCRIPTS FIX")
    print("-" * 40)

    script_analysis = {}

    for file_path, size in fix_scripts:
        print(f"\n📜 {file_path.name} ({size / 1024:.1f}KB)")

        try:
            with open(file_path, 'r') as f:
                content = f.read()

            analysis = {
                'size': size,
                'lines': len(content.splitlines()),
                'functions': len(re.findall(r'^def ', content, re.MULTILINE)),
                'classes': len(re.findall(r'^class ', content, re.MULTILINE)),
                'imports': len(re.findall(r'^import |^from .* import', content, re.MULTILINE)),
                'has_main': '__name__ == "__main__"' in content,
                'keywords': []
            }

            # Buscar palabras clave para entender propósito
            keywords = ['scapy', 'protobuf', 'import', 'patch', 'fix', 'init', 'final']
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    analysis['keywords'].append(keyword)

            script_analysis[file_path.name] = analysis

            print(f"   📊 {analysis['lines']} líneas, {analysis['functions']} funciones, {analysis['classes']} clases")
            print(f"   🏷️  Keywords: {', '.join(analysis['keywords'])}")

        except Exception as e:
            print(f"   ❌ Error leyendo archivo: {e}")
            script_analysis[file_path.name] = {'error': str(e)}

    return script_analysis


def generate_cleanup_strategy(categories, script_analysis):
    """Genera estrategia de limpieza basada en análisis"""

    print("\n" + "=" * 60)
    print("🎯 ESTRATEGIA DE LIMPIEZA RECOMENDADA")
    print("=" * 60)

    # Calcular espacios a liberar
    backup_size = sum(size for _, size in categories['backup_files'])
    temp_size = sum(size for _, size in categories['temp_files'])
    duplicate_size = sum(sum(size for _, size in group[1:]) for group in categories['duplicates'])
    empty_size = len(categories['empty_files'])

    total_cleanup = backup_size + temp_size + duplicate_size

    print(f"\n💾 ESPACIO A LIBERAR:")
    print(f"   📦 Backups: {backup_size / 1024:.1f}KB ({len(categories['backup_files'])} archivos)")
    print(f"   🗑️  Temporales: {temp_size / 1024:.1f}KB ({len(categories['temp_files'])} archivos)")
    print(f"   👥 Duplicados: {duplicate_size / 1024:.1f}KB ({len(categories['duplicates'])} grupos)")
    print(f"   📄 Vacíos: {empty_size} archivos")
    print(f"   🎯 TOTAL: {total_cleanup / 1024:.1f}KB")

    print(f"\n🔧 SCRIPTS FIX A CONSOLIDAR:")
    fix_total_size = sum(size for _, size in categories['fix_scripts'])
    print(f"   📜 {len(categories['fix_scripts'])} scripts ({fix_total_size / 1024:.1f}KB total)")

    for file_path, size in categories['fix_scripts']:
        analysis = script_analysis.get(file_path.name, {})
        keywords = analysis.get('keywords', [])
        print(f"   • {file_path.name} - {', '.join(keywords) if keywords else 'general'}")

    print(f"\n✅ ARCHIVOS CORE (MANTENER):")
    for file_path, size in categories['core_files']:
        print(f"   🔒 {file_path.name} ({size / 1024:.1f}KB)")

    # Plan de acción
    action_plan = {
        'immediate_delete': {
            'backup_files': [str(f) for f, _ in categories['backup_files']],
            'temp_files': [str(f) for f, _ in categories['temp_files']],
            'empty_files': [str(f) for f, _ in categories['empty_files']],
            'duplicates': [[str(f) for f, _ in group[1:]] for group in categories['duplicates']]
        },
        'consolidate': {
            'fix_scripts': [str(f) for f, _ in categories['fix_scripts']]
        },
        'preserve': {
            'core_files': [str(f) for f, _ in categories['core_files']],
            'test_files': [str(f) for f, _ in categories['test_files']],
            'config_files': [str(f) for f, _ in categories['config_files']]
        }
    }

    return action_plan


def main():
    """Ejecuta análisis completo y genera estrategia"""

    categories = analyze_project_for_cleanup()
    script_analysis = analyze_fix_scripts(categories['fix_scripts'])
    action_plan = generate_cleanup_strategy(categories, script_analysis)

    # Guardar plan de acción
    with open('cleanup_action_plan.json', 'w') as f:
        json.dump(action_plan, f, indent=2)

    print(f"\n📋 Plan de acción guardado en: cleanup_action_plan.json")
    print("\n🚀 PRÓXIMO PASO:")
    print("   python cleanup_executor.py  # Ejecutar limpieza segura")

    return action_plan


if __name__ == "__main__":
    main()