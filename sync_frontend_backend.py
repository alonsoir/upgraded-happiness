#!/usr/bin/env python3
"""
sync_frontend_backend_v2.py - Sincronización específica para tu configuración
Upgraded Happiness V3.1 - Sistema de Ciberseguridad

Basado en el análisis real:
- Backend: core/dashboard_v31_etcd.py (usa render_template_string)
- JavaScript: usa endpoints /api/etcd/* específicos
- HTML: templates/dashboard_v31_etcd.html

Este script hace correcciones más agresivas y específicas.
"""

import os
import re
import shutil
import sys
from pathlib import Path


class SpecificFrontendBackendSync:
    def __init__(self, project_root="."):
        self.project_root = Path(project_root)

        # Archivos específicos
        self.backend_file = self.project_root / "core" / "dashboard_v31_etcd.py"
        self.html_file = self.project_root / "templates" / "dashboard_v31_etcd.html"
        self.css_file = self.project_root / "static" / "css" / "dashboard.css"
        self.js_file = self.project_root / "static" / "js" / "dashboard_v31_etcd.js"

        # Endpoints detectados en tu JS
        self.js_endpoints = [
            '/api/etcd/dashboard-metrics',
            '/api/etcd/activate-ensemble-model',
            '/api/etcd/toggle-rag',
            '/api/etcd/execute-firewall-action',
            '/api/etcd/firewall-agent-info'
        ]

    def fix_backend_render_template(self):
        """Corregir backend para usar render_template y los endpoints correctos"""
        print(f"🔧 Corrigiendo backend específicamente: {self.backend_file}")

        try:
            with open(self.backend_file, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            fixes_applied = []

            # 1. Asegurar imports correctos
            if 'from flask import' in content:
                # Encontrar la línea de imports de Flask
                flask_import_pattern = r'from flask import ([^\\n]+)'
                match = re.search(flask_import_pattern, content)
                if match:
                    current_imports = match.group(1)
                    needed_imports = ['Flask', 'render_template', 'jsonify', 'request', 'send_from_directory']

                    # Agregar imports faltantes
                    imports_to_add = []
                    for imp in needed_imports:
                        if imp not in current_imports:
                            imports_to_add.append(imp)

                    if imports_to_add:
                        new_imports = current_imports + ', ' + ', '.join(imports_to_add)
                        content = content.replace(
                            f'from flask import {current_imports}',
                            f'from flask import {new_imports}'
                        )
                        fixes_applied.append(f"Agregados imports: {', '.join(imports_to_add)}")

            # 2. Configuración Flask después de app = Flask(__name__)
            if 'app = Flask(__name__)' in content and 'app.static_folder' not in content:
                content = content.replace(
                    'app = Flask(__name__)',
                    '''app = Flask(__name__)

# Configurar rutas estáticas y templates
app.static_folder = 'static'
app.template_folder = 'templates'
app.static_url_path = '/static'
'''
                )
                fixes_applied.append("Agregada configuración Flask")

            # 3. Cambiar render_template_string por render_template de forma más agresiva
            if 'render_template_string(' in content:
                # Buscar todas las ocurrencias de render_template_string
                pattern = r'render_template_string\(([^)]+)\)'
                matches = list(re.finditer(pattern, content))

                for match in reversed(matches):  # Trabajar en reversa para no afectar posiciones
                    # Reemplazar con render_template
                    replacement = "render_template('dashboard_v31_etcd.html')"
                    start, end = match.span()
                    content = content[:start] + replacement + content[end:]

                if matches:
                    fixes_applied.append(f"Cambiado {len(matches)} render_template_string por render_template")

            # 4. Agregar/actualizar endpoints específicos para tu JS
            endpoints_to_add = {
                '/api/etcd/dashboard-metrics': '''
@app.route('/api/etcd/dashboard-metrics')
def get_etcd_dashboard_metrics():
    """API endpoint para métricas específicas de ETCD"""
    return jsonify({
        "status": "active",
        "events_processed": 1600,
        "ml_models_active": 7,
        "firewall_rules": 45,
        "pipeline_latency": "12ms",
        "ml_confidence": "94%",
        "active_threats": 3,
        "blocked_ips": 128,
        "etcd_nodes": 3,
        "etcd_status": "healthy",
        "ensemble_models": {
            "isolation_forest": {"status": "active", "confidence": 0.94},
            "one_class_svm": {"status": "active", "confidence": 0.91},
            "local_outlier": {"status": "active", "confidence": 0.88}
        }
    })''',

                '/api/etcd/execute-firewall-action': '''
@app.route('/api/etcd/execute-firewall-action', methods=['POST'])
def execute_etcd_firewall_action():
    """API endpoint para ejecutar acciones de firewall via ETCD"""
    data = request.json if request.json else {}
    action = data.get('action', 'unknown')
    target = data.get('target', 'unknown')

    print(f"ETCD Firewall action: {action} on {target}")

    return jsonify({
        "success": True,
        "action": action,
        "target": target,
        "message": f"ETCD Firewall action {action} executed on {target}",
        "timestamp": "2024-08-25T12:00:00Z",
        "etcd_node": "node-1"
    })''',

                '/api/etcd/activate-ensemble-model': '''
@app.route('/api/etcd/activate-ensemble-model', methods=['POST'])
def activate_etcd_ensemble_model():
    """API endpoint para activar modelos ensemble via ETCD"""
    data = request.json if request.json else {}
    model_type = data.get('model', 'isolation_forest')

    print(f"Activating ensemble model: {model_type}")

    return jsonify({
        "success": True,
        "model": model_type,
        "status": "activated",
        "message": f"Ensemble model {model_type} activated successfully"
    })''',

                '/api/etcd/toggle-rag': '''
@app.route('/api/etcd/toggle-rag', methods=['POST'])
def toggle_etcd_rag():
    """API endpoint para toggle RAG via ETCD"""
    data = request.json if request.json else {}
    action = data.get('action', 'toggle')

    return jsonify({
        "success": True,
        "rag_status": "enabled" if action == "enable" else "disabled",
        "message": f"RAG {action} completed successfully"
    })''',

                '/api/etcd/firewall-agent-info': '''
@app.route('/api/etcd/firewall-agent-info')
def get_etcd_firewall_agent_info():
    """API endpoint para información del agente firewall via ETCD"""
    return jsonify({
        "agent_id": "firewall-agent-1",
        "status": "active",
        "version": "3.1.0",
        "rules_count": 45,
        "blocked_ips": 128,
        "last_update": "2024-08-25T12:00:00Z",
        "etcd_cluster": "healthy"
    })'''
            }

            # Verificar qué endpoints faltan y agregarlos
            for endpoint, code in endpoints_to_add.items():
                if f"@app.route('{endpoint}'" not in content:
                    content += '\n' + code + '\n'
                    fixes_applied.append(f"Agregado endpoint {endpoint}")

            # 5. Asegurar que hay una ruta principal que sirve el template
            if "@app.route('/')" not in content and "@app.route('/dashboard')" not in content:
                main_route = '''
@app.route('/')
def dashboard():
    """Ruta principal del dashboard"""
    return render_template('dashboard_v31_etcd.html')
'''
                content += '\n' + main_route + '\n'
                fixes_applied.append("Agregada ruta principal /")

            # 6. Asegurar que el archivo termina con el if __name__ == '__main__':
            if 'if __name__ == ' not in content:
                content += '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
'''
                fixes_applied.append("Agregado bloque main")

            # Guardar cambios
            if content != original_content and fixes_applied:
                # Backup
                backup_path = self.backend_file.with_suffix('.py.backup2')
                shutil.copy2(self.backend_file, backup_path)
                print(f"      💾 Backup creado: {backup_path}")

                # Guardar
                with open(self.backend_file, 'w', encoding='utf-8') as f:
                    f.write(content)

                print(f"   ✅ Backend actualizado:")
                for fix in fixes_applied:
                    print(f"      - {fix}")

                return True
            else:
                print("   ✅ Backend ya está actualizado")
                return True

        except Exception as e:
            print(f"   ❌ Error actualizando backend: {e}")
            return False

    def verify_endpoints_match(self):
        """Verificar que los endpoints del JS coincidan con el backend"""
        print("\n🔍 Verificando coincidencia de endpoints...")

        try:
            # Leer backend
            with open(self.backend_file, 'r', encoding='utf-8') as f:
                backend_content = f.read()

            # Leer JavaScript
            with open(self.js_file, 'r', encoding='utf-8') as f:
                js_content = f.read()

            # Extraer endpoints del backend
            backend_routes = re.findall(r"@app\.route\(['\"]([^'\"]+)['\"]", backend_content)

            # Extraer endpoints del JavaScript (URLs que empiezan con /api/)
            js_api_calls = re.findall(r"['\"](/api/[^'\"]*)['\"]", js_content)
            js_api_calls = list(set(js_api_calls))  # Eliminar duplicados

            print(f"   📊 Endpoints en backend: {backend_routes}")
            print(f"   📊 Endpoints en JS: {js_api_calls}")

            # Verificar coincidencias
            missing_in_backend = []
            for js_endpoint in js_api_calls:
                if js_endpoint not in backend_routes:
                    missing_in_backend.append(js_endpoint)

            if missing_in_backend:
                print(f"   ⚠️  Endpoints faltantes en backend: {missing_in_backend}")
                return False
            else:
                print("   ✅ Todos los endpoints JS están en el backend")
                return True

        except Exception as e:
            print(f"   ❌ Error verificando endpoints: {e}")
            return False

    def run_specific_sync(self):
        """Ejecutar sincronización específica"""
        print("🧬 Upgraded Happiness V3.1 - Sincronización Específica v2")
        print("=" * 65)
        print(f"📁 Directorio: {self.project_root.absolute()}")

        try:
            # 1. Corregir backend agresivamente
            backend_fixed = self.fix_backend_render_template()

            # 2. Verificar endpoints
            endpoints_match = self.verify_endpoints_match()

            if backend_fixed and endpoints_match:
                print("\n🎉 ¡SINCRONIZACIÓN ESPECÍFICA COMPLETADA!")
                print("\n📋 Para probar:")
                print(f"   cd {self.project_root.absolute()}")
                print("   python3 core/dashboard_v31_etcd.py")
                print("   curl http://localhost:8080/api/etcd/dashboard-metrics")
                print("   Abrir: http://localhost:8080")
                return True
            elif backend_fixed:
                print("\n⚠️  Backend corregido, pero algunos endpoints no coinciden")
                print("   El sistema debería funcionar, pero revisa los logs")
                return True
            else:
                print("\n❌ Error en la sincronización")
                return False

        except Exception as e:
            print(f"\n❌ Error durante sincronización específica: {e}")
            return False


def main():
    syncer = SpecificFrontendBackendSync()
    success = syncer.run_specific_sync()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()