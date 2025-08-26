#!/usr/bin/env python3
"""
final_sync_cleanup.py - Limpieza final de endpoints
Completa la sincronización agregando los endpoints faltantes detectados
"""

import re
from pathlib import Path


def add_missing_endpoints():
    backend_file = Path("core/dashboard_v31_etcd.py")

    print("🔧 Agregando endpoints faltantes...")

    try:
        with open(backend_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Agregar endpoint /api/firewall-agent-info (alias sin etcd)
        if "@app.route('/api/firewall-agent-info')" not in content:
            alias_endpoint = '''
@app.route('/api/firewall-agent-info')
def get_firewall_agent_info_alias():
    """Alias para firewall agent info (sin etcd prefix)"""
    return get_etcd_firewall_agent_info()
'''
            content += alias_endpoint
            print("   ✅ Agregado endpoint /api/firewall-agent-info")

        # Agregar endpoint genérico /api/ si es necesario
        if "@app.route('/api/')" not in content:
            api_root = '''
@app.route('/api/')
def api_root():
    """API root endpoint"""
    return jsonify({
        "message": "Upgraded Happiness API v3.1",
        "available_endpoints": [
            "/api/etcd/dashboard-metrics",
            "/api/etcd/execute-firewall-action", 
            "/api/etcd/activate-ensemble-model",
            "/api/etcd/toggle-rag",
            "/api/etcd/firewall-agent-info",
            "/api/metrics",
            "/api/execute-firewall-action",
            "/api/firewall-agent-info"
        ]
    })
'''
            content += api_root
            print("   ✅ Agregado endpoint /api/")

        # Guardar cambios
        with open(backend_file, 'w', encoding='utf-8') as f:
            f.write(content)

        print("✅ Endpoints faltantes agregados")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def verify_complete_sync():
    """Verificación final completa"""
    backend_file = Path("core/dashboard_v31_etcd.py")
    js_file = Path("static/js/dashboard_v31_etcd.js")

    print("\n🔍 Verificación final...")

    try:
        # Leer archivos
        with open(backend_file, 'r') as f:
            backend_content = f.read()
        with open(js_file, 'r') as f:
            js_content = f.read()

        # Extraer endpoints
        backend_routes = set(re.findall(r"@app\.route\(['\"]([^'\"]+)['\"]", backend_content))
        js_api_calls = set(re.findall(r"['\"](/api/[^'\"]*)['\"]", js_content))

        print(f"   📊 Backend endpoints: {len(backend_routes)}")
        print(f"   📊 JS endpoints: {len(js_api_calls)}")

        # Verificar coincidencias
        missing = js_api_calls - backend_routes
        if missing:
            print(f"   ⚠️  Aún faltan: {missing}")
            return False
        else:
            print("   ✅ Todos los endpoints JS están en el backend")
            return True

    except Exception as e:
        print(f"   ❌ Error en verificación: {e}")
        return False


if __name__ == "__main__":
    print("🧬 Upgraded Happiness V3.1 - Limpieza Final")
    print("=" * 50)

    if add_missing_endpoints():
        if verify_complete_sync():
            print("\n🎉 ¡SINCRONIZACIÓN 100% COMPLETA!")
            print("\n📋 Listo para probar:")
            print("   python3 core/dashboard_v31_etcd.py")
            print("   open http://localhost:8080")
        else:
            print("\n⚠️  Casi completo, pequeños ajustes pendientes")
    else:
        print("\n❌ Error en limpieza final")