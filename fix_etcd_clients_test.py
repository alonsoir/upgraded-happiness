#!/usr/bin/env python3
"""
fix_etcd_client_tests.py
Fix para el bug en los clientes ETCD generados
"""

import os
import glob


def fix_test_function_bug():
    """Corrige el bug en la función test de todos los clientes ETCD"""

    # Buscar todos los clientes ETCD
    client_files = glob.glob("core/etcd_crypto_client_*_fixed.py")

    print("🔧 Corrigiendo bug en clientes ETCD...")

    for client_file in client_files:
        print(f"   📋 Procesando: {client_file}")

        # Leer el archivo
        with open(client_file, 'r') as f:
            content = f.read()

        # Extraer el nombre del componente del archivo
        if "sniffer" in client_file:
            component_name = "evolutionary_sniffer"
        elif "geoip" in client_file:
            component_name = "geoip_enricher"
        elif "ml_detector" in client_file:
            component_name = "lightweight_ml_detector_tricapa"
        elif "scheduler" in client_file:
            component_name = "scheduler_firewall"
        elif "agent" in client_file:
            component_name = "simple_firewall_agent"
        else:
            component_name = "unknown_component"

        # Reemplazar la línea problemática
        old_line = 'print(f"🧪 Testing {config[\'component_type\']} ETCD client...")'
        new_line = f'print(f"🧪 Testing {component_name} ETCD client...")'

        if old_line in content:
            content = content.replace(old_line, new_line)

            # Escribir el archivo corregido
            with open(client_file, 'w') as f:
                f.write(content)

            print(f"   ✅ Corregido: {client_file}")
        else:
            print(f"   ⚠️  No se encontró el bug en: {client_file}")


if __name__ == "__main__":
    fix_test_function_bug()
    print("\n🎯 CORRECCIÓN COMPLETADA")
    print("✅ Ahora puedes probar los clientes ETCD sin errores")