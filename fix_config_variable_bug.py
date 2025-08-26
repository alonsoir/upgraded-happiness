#!/usr/bin/env python3
"""
Fix para el bug config['component_type'] en clientes ETCD generados
"""

import os
import glob


def fix_config_variable_bug():
    """Corrige el bug de variable config no definida en todos los clientes ETCD"""

    # Mapeo de archivos a nombres de componente
    component_mapping = {
        'etcd_crypto_client_sniffer_fixed.py': 'evolutionary_sniffer',
        'etcd_crypto_client_geoip_fixed.py': 'geoip_enricher',
        'etcd_crypto_client_ml_detector_fixed.py': 'lightweight_ml_detector_tricapa',
        'etcd_crypto_client_scheduler_fixed.py': 'scheduler_firewall',
        'etcd_crypto_client_agent_fixed.py': 'simple_firewall_agent',
        'etcd_crypto_client_dashboard_fixed.py': 'dashboard_scada_v31_etcd'
    }

    print("🔧 Corrigiendo bug config['component_type'] en clientes ETCD...")

    for filename, component_type in component_mapping.items():
        client_file = f"core/{filename}"

        if not os.path.exists(client_file):
            print(f"   ⚠️  No encontrado: {client_file}")
            continue

        print(f"   📋 Procesando: {client_file}")

        # Leer el archivo
        with open(client_file, 'r') as f:
            content = f.read()

        # Buscar TODAS las ocurrencias de config['component_type'] y reemplazarlas
        import re

        # Patrón para encontrar todas las referencias a config['component_type']
        pattern = r"config\['component_type'\]"

        # Encontrar todas las ocurrencias
        matches = re.findall(pattern, content)
        print(f"   🔍 Encontradas {len(matches)} ocurrencias de config['component_type']")

        # Reemplazar TODAS las ocurrencias
        content = re.sub(pattern, f"'{component_type}'", content)

        # También reemplazar variaciones con .title(), .upper(), etc.
        pattern_title = r"config\['component_type'\]\.title\(\)"
        content = re.sub(pattern_title, f"'{component_type.title()}'", content)

        pattern_upper = r"config\['component_type'\]\.upper\(\)"
        content = re.sub(pattern_upper, f"'{component_type.upper()}'", content)

        # Reemplazos específicos adicionales que pueden no estar cubiertos
        specific_replacements = [
            (f'f"❌ Failed to load {{config[\'component_type\']}} config: {{e}}"',
             f'f"❌ Failed to load {component_type} config: {{e}}"'),
            (f'f"✅ {{config[\'component_type\'].title()}} config loaded successfully"',
             f'f"✅ {component_type.title()} config loaded successfully"'),
        ]

        for old_text, new_text in specific_replacements:
            if old_text in content:
                content = content.replace(old_text, new_text)
                modified = True

        # Escribir el archivo corregido si se modificó
        if len(matches) > 0:
            with open(client_file, 'w') as f:
                f.write(content)
            print(f"   ✅ Corregido: {client_file} ({len(matches)} reemplazos)")
        else:
            print(f"   ℹ️  Sin cambios: {client_file}")


if __name__ == "__main__":
    fix_config_variable_bug()
    print("\n🎯 CORRECCIÓN COMPLETADA")
    print("✅ Ahora puedes probar los clientes ETCD sin el bug config['component_type']")