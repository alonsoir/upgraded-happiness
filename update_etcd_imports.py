#!/usr/bin/env python3
"""
🔄 Update ETCD Imports - Upgraded Happiness V3.1
================================================================================
Actualiza los imports en componentes principales para usar clientes ETCD REALES
"""

import os
import re

# Mapeo de componentes principales a sus clientes ETCD
COMPONENT_IMPORTS = {
    'core/evolutionary_sniffer_standalone.py': {
        'client_name': 'etcd_crypto_client_sniffer_fixed',
        'functions': ['setup_sniffer_crypto', 'get_sniffer_pipeline_key']
    },
    'core/geoip_enricher_v31_etcd.py': {
        'client_name': 'etcd_crypto_client_geoip_fixed',
        'functions': ['setup_geoip_crypto', 'get_geoip_pipeline_key']
    },
    'core/lightweight_ml_detector_tricapa_v31_etcd.py': {
        'client_name': 'etcd_crypto_client_ml_detector_fixed',
        'functions': ['setup_ml_detector_crypto', 'get_ml_detector_pipeline_key']
    },
    'core/scheduler_firewall_v31_etcd.py': {
        'client_name': 'etcd_crypto_client_scheduler_firewall_fixed',
        'functions': ['setup_scheduler_firewall_crypto', 'get_scheduler_firewall_pipeline_key']
    },
    'core/simple_firewall_agent_v31_etcd.py': {
        'client_name': 'etcd_crypto_client_simple_firewall_agent_fixed',
        'functions': ['setup_simple_firewall_agent_crypto', 'get_simple_firewall_agent_pipeline_key']
    },
    'core/dashboard_v31_etcd.py': {
        'client_name': 'etcd_crypto_client_dashboard_fixed',
        'functions': ['setup_dashboard_crypto', 'get_dashboard_pipeline_key']
    }
}


def update_component_imports():
    """Actualiza los imports en todos los componentes principales"""
    print("🔄 Actualizando imports ETCD en componentes principales...")
    print("=" * 60)

    updated_files = []

    for component_path, import_info in COMPONENT_IMPORTS.items():
        if not os.path.exists(component_path):
            print(f"   ⚠️  No encontrado: {component_path}")
            continue

        print(f"📋 Procesando: {component_path}")

        try:
            # Leer el archivo
            with open(component_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content

            # 1. Buscar imports existentes del cliente ETCD
            client_name = import_info['client_name']
            functions = import_info['functions']

            # Patrones de import que pueden existir
            import_patterns = [
                rf'from\s+{re.escape(client_name)}\s+import.*',
                rf'import\s+{re.escape(client_name)}.*',
                rf'from\s+.*{re.escape(client_name.replace("_fixed", ""))}\w*\s+import.*'
            ]

            # Buscar y eliminar imports viejos
            lines = content.split('\n')
            new_lines = []
            import_found = False
            import_line_index = -1

            for i, line in enumerate(lines):
                # Verificar si es un import relacionado con ETCD
                is_etcd_import = False
                for pattern in import_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        is_etcd_import = True
                        import_found = True
                        import_line_index = len(new_lines)
                        print(f"   🔍 Import encontrado en línea {i + 1}: {line.strip()}")
                        break

                if not is_etcd_import:
                    new_lines.append(line)

            # 2. Agregar el import correcto
            if functions:
                new_import = f"from {client_name} import (\n    {',\n    '.join(functions)}\n)"
            else:
                new_import = f"import {client_name}"

            if import_found and import_line_index >= 0:
                # Insertar en el lugar del import viejo
                new_lines.insert(import_line_index, new_import)
                print(f"   ✅ Import actualizado: {new_import.split('(')[0]}...")
            else:
                # Buscar un lugar apropiado para insertar (después de otros imports)
                insert_index = 0
                for i, line in enumerate(new_lines):
                    if line.strip().startswith(('import ', 'from ')) or line.strip().startswith('#'):
                        insert_index = i + 1
                    elif line.strip() == '':
                        continue
                    else:
                        break

                new_lines.insert(insert_index, new_import)
                print(f"   ➕ Import agregado en línea {insert_index + 1}: {new_import.split('(')[0]}...")

            # 3. Escribir el archivo actualizado
            new_content = '\n'.join(new_lines)

            if new_content != original_content:
                # Crear backup
                backup_path = f"{component_path}.backup_imports_{int(__import__('time').time())}"
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)

                # Escribir archivo actualizado
                with open(component_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)

                updated_files.append(component_path)
                print(f"   ✅ Actualizado: {component_path}")
                print(f"   💾 Backup: {backup_path}")
            else:
                print(f"   ℹ️  Sin cambios necesarios: {component_path}")

        except Exception as e:
            print(f"   ❌ Error procesando {component_path}: {e}")

        print("-" * 40)

    return updated_files


def verify_imports():
    """Verifica que los imports sean correctos"""
    print("\n🔍 VERIFICANDO IMPORTS ACTUALIZADOS...")
    print("=" * 50)

    all_good = True

    for component_path, import_info in COMPONENT_IMPORTS.items():
        if not os.path.exists(component_path):
            continue

        print(f"📋 Verificando: {os.path.basename(component_path)}")

        try:
            with open(component_path, 'r', encoding='utf-8') as f:
                content = f.read()

            client_name = import_info['client_name']

            # Verificar que el cliente ETCD esté importado
            if client_name in content:
                print(f"   ✅ Cliente ETCD encontrado: {client_name}")

                # Verificar que las funciones estén importadas
                functions = import_info['functions']
                for func in functions:
                    if func in content:
                        print(f"   ✅ Función encontrada: {func}")
                    else:
                        print(f"   ⚠️  Función no encontrada: {func}")
                        all_good = False
            else:
                print(f"   ❌ Cliente ETCD no encontrado: {client_name}")
                all_good = False

        except Exception as e:
            print(f"   ❌ Error verificando: {e}")
            all_good = False

    return all_good


def main():
    print("🧬 Upgraded Happiness V3.1 - ETCD Import Updater")
    print("=" * 60)
    print("Actualizando imports para usar clientes ETCD REALES...")
    print()

    # Actualizar imports
    updated_files = update_component_imports()

    # Verificar imports
    verification_passed = verify_imports()

    # Resumen final
    print("\n" + "=" * 60)
    print("📊 RESUMEN FINAL:")
    print(f"   📁 Archivos procesados: {len(COMPONENT_IMPORTS)}")
    print(f"   ✅ Archivos actualizados: {len(updated_files)}")
    print(f"   🔍 Verificación: {'✅ PASSED' if verification_passed else '❌ FAILED'}")

    if updated_files:
        print("\n📝 ARCHIVOS ACTUALIZADOS:")
        for file in updated_files:
            print(f"   - {file}")

    print("\n🚀 SIGUIENTE PASO:")
    print("   Probar el pipeline completo con los clientes ETCD REALES")
    print("   etcd &")
    print(
        "   sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json")


if __name__ == "__main__":
    main()