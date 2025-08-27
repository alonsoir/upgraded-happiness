#!/usr/bin/env python3
"""
🧬 Upgraded Happiness V3.1 - ETCD Client Extractor
================================================================================
Extrae y analiza los clientes ETCD de cada componente según la secuencia de arranque
"""

import os
import re
import ast
import json
from pathlib import Path


class ETCDClientExtractor:
    def __init__(self):
        self.components = [
            {
                'name': 'EVOLUTIONARY_SNIFFER',
                'script': 'core/evolutionary_sniffer_standalone.py',
                'config': 'config/json/sniffer_config.json',
                'step': '#1'
            },
            {
                'name': 'ZMQ_PERFORMANCE_OPTIMIZER',
                'script': 'zmq_performance_optimizer.py',
                'config': 'config/json/sniffer_config.json',
                'step': '#2 (Opcional)'
            },
            {
                'name': 'GEOIP_ENRICHER',
                'script': 'core/geoip_enricher_v31_etcd.py',
                'config': 'config/json/geoip_config.json',
                'step': '#3'
            },
            {
                'name': 'ML_DETECTOR',
                'script': 'core/lightweight_ml_detector_tricapa_v31_etcd.py',
                'config': 'config/json/ml_detector_config.json',
                'step': '#4'
            },
            {
                'name': 'SCHEDULER_FIREWALL',
                'script': 'core/scheduler_firewall_v31_etcd.py',
                'config': 'config/json/scheduler_firewall_config.json',
                'additional_config': 'config/json/firewall_rules.json',
                'step': '#5'
            },
            {
                'name': 'FIREWALL_AGENT',
                'script': 'core/simple_firewall_agent_v31_etcd.py',
                'config': 'config/json/simple_firewall_agent_config.json',
                'additional_config': 'config/json/firewall_rules.json',
                'step': '#6'
            },
            {
                'name': 'DASHBOARD',
                'script': 'core/dashboard_v31_etcd.py',
                'config': 'config/json/dashboard_config.json',
                'additional_config': 'config/json/firewall_rules.json',
                'step': '#7'
            }
        ]

    def extract_etcd_code(self, filepath):
        """Extrae código relacionado con ETCD de un archivo Python"""
        if not os.path.exists(filepath):
            return {
                'exists': False,
                'etcd_imports': [],
                'etcd_classes': [],
                'etcd_functions': [],
                'upload_methods': [],
                'config_uploads': []
            }

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Buscar imports relacionados con ETCD
            etcd_imports = re.findall(r'^(?:from|import).*etcd.*$', content, re.MULTILINE | re.IGNORECASE)

            # Buscar clases relacionadas con ETCD
            etcd_classes = re.findall(r'class\s+\w*[Ee]tcd\w*.*?:', content)

            # Buscar funciones relacionadas con ETCD
            etcd_functions = re.findall(r'def\s+\w*etcd\w*\(.*?\):', content, re.IGNORECASE)

            # Buscar métodos de upload/put a ETCD
            upload_patterns = [
                r'\.put\(.*?\)',
                r'upload.*etcd',
                r'etcd.*upload',
                r'send.*etcd',
                r'etcd.*put'
            ]
            upload_methods = []
            for pattern in upload_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                upload_methods.extend(matches)

            # Buscar líneas específicas de subida de configuración
            config_upload_patterns = [
                r'.*\.put\(.*config.*\)',
                r'.*upload.*json.*',
                r'.*etcd.*json.*',
                r'.*put.*\(.*\.json.*\)'
            ]
            config_uploads = []
            for pattern in config_upload_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                config_uploads.extend(matches)

            return {
                'exists': True,
                'etcd_imports': etcd_imports,
                'etcd_classes': etcd_classes,
                'etcd_functions': etcd_functions,
                'upload_methods': upload_methods[:10],  # Limitar para no saturar
                'config_uploads': config_uploads[:10]
            }

        except Exception as e:
            return {
                'exists': True,
                'error': str(e),
                'etcd_imports': [],
                'etcd_classes': [],
                'etcd_functions': [],
                'upload_methods': [],
                'config_uploads': []
            }

    def extract_etcd_client_class(self, filepath):
        """Extrae la clase completa del cliente ETCD"""
        if not os.path.exists(filepath):
            return None

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Buscar clase que contenga "etcd" o "ETCD"
            pattern = r'class\s+\w*[Ee]tcd\w*[^:]*:.*?(?=\nclass|\nif __name__|\Z)'
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)

            if match:
                return match.group(0)[:2000]  # Primeros 2000 caracteres

            return None

        except Exception as e:
            return f"Error: {str(e)}"

    def check_config_file_references(self, filepath):
        """Verifica qué archivos de configuración se referencian en el script"""
        if not os.path.exists(filepath):
            return []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Buscar referencias a archivos JSON
            json_refs = re.findall(r'["\']([^"\']*\.json)["\']', content)
            return list(set(json_refs))  # Eliminar duplicados

        except Exception as e:
            return [f"Error: {str(e)}"]

    def analyze_components(self):
        """Analiza todos los componentes"""
        print("🧬 Upgraded Happiness V3.1 - ETCD Client Analysis")
        print("=" * 80)
        print("Analizando clientes ETCD según la secuencia de arranque...")
        print()

        results = {}

        for component in self.components:
            print(f"📋 {component['step']} - {component['name']}")
            print(f"   📄 Script: {component['script']}")
            print(f"   ⚙️  Config: {component['config']}")
            if component.get('additional_config'):
                print(f"   ➕ Additional: {component['additional_config']}")

            # Extraer información del cliente ETCD
            etcd_info = self.extract_etcd_code(component['script'])

            if not etcd_info['exists']:
                print("   ❌ Script no existe")
                results[component['name']] = {'status': 'missing', 'script': component['script']}
                continue

            if etcd_info.get('error'):
                print(f"   ❌ Error: {etcd_info['error']}")
                results[component['name']] = {'status': 'error', 'error': etcd_info['error']}
                continue

            # Referencias a archivos de configuración
            config_refs = self.check_config_file_references(component['script'])

            print(f"   🔌 ETCD Imports: {len(etcd_info['etcd_imports'])}")
            for imp in etcd_info['etcd_imports']:
                print(f"      - {imp}")

            print(f"   🏗️  ETCD Classes: {len(etcd_info['etcd_classes'])}")
            for cls in etcd_info['etcd_classes']:
                print(f"      - {cls}")

            print(f"   ⚡ ETCD Functions: {len(etcd_info['etcd_functions'])}")
            for func in etcd_info['etcd_functions']:
                print(f"      - {func}")

            print(f"   📤 Upload Methods: {len(etcd_info['upload_methods'])}")
            for method in etcd_info['upload_methods'][:3]:  # Solo primeros 3
                print(f"      - {method[:60]}...")

            print(f"   📋 Config Uploads: {len(etcd_info['config_uploads'])}")
            for upload in etcd_info['config_uploads'][:3]:  # Solo primeros 3
                print(f"      - {upload[:60]}...")

            print(f"   📁 JSON References: {len(config_refs)}")
            for ref in config_refs:
                if 'json' in ref:
                    print(f"      - {ref}")

            # Determinar estado
            has_etcd_import = len(etcd_info['etcd_imports']) > 0
            has_etcd_class = len(etcd_info['etcd_classes']) > 0
            has_upload_logic = len(etcd_info['upload_methods']) > 0 or len(etcd_info['config_uploads']) > 0

            if has_etcd_import and has_etcd_class and has_upload_logic:
                status = "✅ COMPLETO"
            elif has_etcd_import and (has_etcd_class or has_upload_logic):
                status = "⚠️  PARCIAL"
            else:
                status = "❌ FALTA ETCD"

            print(f"   🎯 Estado: {status}")

            results[component['name']] = {
                'status': 'analyzed',
                'script': component['script'],
                'etcd_imports': len(etcd_info['etcd_imports']),
                'etcd_classes': len(etcd_info['etcd_classes']),
                'upload_methods': len(etcd_info['upload_methods']),
                'config_uploads': len(etcd_info['config_uploads']),
                'config_refs': config_refs,
                'assessment': status
            }

            print("-" * 60)

        return results

    def generate_summary(self, results):
        """Genera resumen del análisis"""
        print()
        print("🎯 RESUMEN DEL ANÁLISIS ETCD")
        print("=" * 50)

        complete = sum(1 for r in results.values()
                       if r.get('assessment') == '✅ COMPLETO')
        partial = sum(1 for r in results.values()
                      if r.get('assessment') == '⚠️  PARCIAL')
        missing = sum(1 for r in results.values()
                      if r.get('assessment') == '❌ FALTA ETCD')
        errors = sum(1 for r in results.values()
                     if r.get('status') in ['missing', 'error'])

        total = len(results)

        print(f"📊 Total componentes: {total}")
        print(f"✅ Completos: {complete}")
        print(f"⚠️  Parciales: {partial}")
        print(f"❌ Faltan ETCD: {missing}")
        print(f"🚫 Errores/Faltantes: {errors}")

        print()
        print("🔧 COMPONENTES QUE REQUIEREN ATENCIÓN:")
        for name, data in results.items():
            if data.get('assessment') in ['⚠️  PARCIAL', '❌ FALTA ETCD'] or data.get('status') in ['missing', 'error']:
                print(f"   {name}: {data.get('assessment', data.get('status', 'Unknown'))}")


if __name__ == "__main__":
    extractor = ETCDClientExtractor()
    results = extractor.analyze_components()
    extractor.generate_summary(results)

    print()
    print("🔍 Para examinar el código específico de cada cliente ETCD:")
    print("   python extract_etcd_clients.py --detail [COMPONENT_NAME]")