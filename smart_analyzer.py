#!/usr/bin/env python3
"""
Analizador INTELIGENTE y LIGERO
==============================
Solo captura lo esencial, ignora ruido
"""

import os
from pathlib import Path
from collections import defaultdict
import re

class SmartAnalyzer:
    def __init__(self, project_root="."):
        self.project_root = Path(project_root)
        
        # Directorios a IGNORAR
        self.ignore_dirs = {
            'venv', 'env', '__pycache__', '.git', 'node_modules', 
            'upgraded_happiness_venv', 'upgraded-happiness-bitdefender/venv',
            '.pytest_cache', 'tests_consolidated'
        }
        
        # Extensiones a IGNORAR
        self.ignore_extensions = {'.pyc', '.pyo', '.log', '.tmp', '.cache'}
    
    def quick_scan(self):
        """Escaneo rápido y ligero"""
        print("🔍 Escaneo RÁPIDO del proyecto...")
        
        results = {
            'fix_scripts': [],
            'backup_files': [],
            'essential_files': [],
            'duplicate_candidates': [],
            'large_files': [],
            'summary': {}
        }
        
        all_python_files = []
        file_sizes = []
        
        # Escaneo inteligente
        for file_path in self.project_root.rglob("*.py"):
            # Ignorar directorios específicos
            if any(ignore_dir in str(file_path) for ignore_dir in self.ignore_dirs):
                continue
                
            # Ignorar extensiones específicas
            if file_path.suffix in self.ignore_extensions:
                continue
            
            rel_path = str(file_path.relative_to(self.project_root))
            file_size = file_path.stat().st_size
            file_sizes.append(file_size)
            
            # Categorizar por nombre/patrón
            if re.match(r'fix_.*\.py$', file_path.name):
                results['fix_scripts'].append({
                    'path': rel_path,
                    'size': file_size,
                    'name': file_path.name
                })
            elif '.backup' in file_path.name or '.quick' in file_path.name:
                results['backup_files'].append({
                    'path': rel_path,
                    'size': file_size
                })
            elif file_path.name in [
                'system_orchestrator.py', 
                'lightweight_ml_detector.py',
                'promiscuous_agent.py'
            ]:
                results['essential_files'].append({
                    'path': rel_path,
                    'size': file_size,
                    'lines': self._count_lines(file_path)
                })
            
            # Detectar archivos grandes (>100KB)
            if file_size > 100000:
                results['large_files'].append({
                    'path': rel_path,
                    'size': file_size,
                    'size_mb': round(file_size / 1024 / 1024, 2)
                })
            
            all_python_files.append(rel_path)
        
        # Resumen estadístico
        results['summary'] = {
            'total_python_files': len(all_python_files),
            'fix_scripts_count': len(results['fix_scripts']),
            'backup_files_count': len(results['backup_files']),
            'essential_files_count': len(results['essential_files']),
            'large_files_count': len(results['large_files']),
            'total_size_mb': round(sum(file_sizes) / 1024 / 1024, 2),
            'avg_file_size_kb': round(sum(file_sizes) / len(file_sizes) / 1024, 2) if file_sizes else 0
        }
        
        return results
    
    def _count_lines(self, file_path):
        """Cuenta líneas de código (sin generar contenido masivo)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return len(f.readlines())
        except:
            return 0
    
    def print_concise_report(self, results):
        """Reporte conciso y útil"""
        print("\n" + "="*50)
        print("📊 ANÁLISIS INTELIGENTE - UPGRADED HAPPINESS")
        print("="*50)
        
        s = results['summary']
        print(f"\n📈 RESUMEN:")
        print(f"   Total archivos Python: {s['total_python_files']}")
        print(f"   Scripts fix_*: {s['fix_scripts_count']}")
        print(f"   Archivos backup: {s['backup_files_count']}")
        print(f"   Archivos esenciales: {s['essential_files_count']}")
        print(f"   Archivos grandes (>100KB): {s['large_files_count']}")
        print(f"   Tamaño total: {s['total_size_mb']} MB")
        
        print(f"\n🔧 SCRIPTS FIX DETECTADOS:")
        for script in results['fix_scripts'][:10]:  # Solo primeros 10
            size_kb = round(script['size'] / 1024, 1)
            print(f"   📜 {script['name']} ({size_kb}KB)")
        
        if len(results['fix_scripts']) > 10:
            print(f"   ... y {len(results['fix_scripts']) - 10} más")
        
        print(f"\n🗑️  ARCHIVOS BACKUP DETECTADOS:")
        total_backup_size = sum(f['size'] for f in results['backup_files'])
        print(f"   {len(results['backup_files'])} archivos ({round(total_backup_size/1024/1024, 1)} MB)")
        
        print(f"\n⚡ ARCHIVOS ESENCIALES:")
        for essential in results['essential_files']:
            size_kb = round(essential['size'] / 1024, 1)
            print(f"   ✅ {Path(essential['path']).name} ({size_kb}KB, {essential['lines']} líneas)")
        
        if results['large_files']:
            print(f"\n📁 ARCHIVOS GRANDES:")
            for large in results['large_files'][:5]:  # Solo primeros 5
                print(f"   📦 {Path(large['path']).name} ({large['size_mb']} MB)")
        
        print(f"\n🎯 RECOMENDACIONES INMEDIATAS:")
        
        # Calcular ahorros potenciales
        backup_savings = round(sum(f['size'] for f in results['backup_files']) / 1024 / 1024, 1)
        fix_consolidation = len(results['fix_scripts'])
        
        print(f"   1. 🗑️  Eliminar backups: Liberar {backup_savings} MB")
        print(f"   2. 🔧 Consolidar {fix_consolidation} scripts fix_* en 1 módulo")
        print(f"   3. 📊 Enfocar en {len(results['essential_files'])} archivos esenciales")
        
        if results['large_files']:
            print(f"   4. 📁 Revisar {len(results['large_files'])} archivos grandes")
        
        print("\n" + "="*50)
        
        return {
            'backup_savings_mb': backup_savings,
            'fix_scripts_to_consolidate': fix_consolidation,
            'essential_files': len(results['essential_files'])
        }

def main():
    analyzer = SmartAnalyzer()
    results = analyzer.quick_scan()
    recommendations = analyzer.print_concise_report(results)
    
    print(f"\n💡 SIGUIENTE PASO RECOMENDADO:")
    if recommendations['backup_savings_mb'] > 5:
        print(f"   Eliminar backups para liberar {recommendations['backup_savings_mb']} MB")
    elif recommendations['fix_scripts_to_consolidate'] > 10:
        print(f"   Consolidar {recommendations['fix_scripts_to_consolidate']} scripts fix_*")
    else:
        print(f"   Enfocar en archivos esenciales para desarrollo")
    
    return recommendations

if __name__ == "__main__":
    main()
