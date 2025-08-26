#!/usr/bin/env python3
"""
🔍 ETCD Client Individual Auditor
================================================================================
Audita un cliente ETCD específico para verificar funcionalidad de upload JSON
"""

import os
import re
import sys
from pathlib import Path


def audit_etcd_client(client_path, component_name):
    """Audita un cliente ETCD específico"""
    print(f"🔍 AUDITANDO CLIENTE ETCD: {component_name}")
    print(f"📄 Archivo: {client_path}")
    print("=" * 60)

    if not os.path.exists(client_path):
        print("❌ ARCHIVO NO EXISTE")
        return False

    try:
        with open(client_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"❌ ERROR LEYENDO ARCHIVO: {e}")
        return False

    # 1. Verificar imports ETCD
    print("🔌 IMPORTS ETCD:")
    etcd_imports = re.findall(r'^(?:from|import).*etcd.*$', content, re.MULTILINE | re.IGNORECASE)
    if etcd_imports:
        for imp in etcd_imports:
            print(f"   ✅ {imp}")
    else:
        print("   ❌ No hay imports ETCD")

    # 2. Verificar clases ETCD
    print("\n🏗️ CLASES:")
    classes = re.findall(r'class\s+(\w+).*?:', content)
    for cls in classes:
        print(f"   📦 {cls}")

    # 3. Verificar funciones públicas
    print("\n⚡ FUNCIONES PÚBLICAS:")
    public_functions = re.findall(r'^(?:async )?def\s+([a-zA-Z][^_]\w*)\(', content, re.MULTILINE)
    for func in public_functions[:10]:  # Limitar salida
        print(f"   🔧 {func}()")

    # 4. CRÍTICO: Buscar funciones de upload JSON
    print("\n📤 FUNCIONES DE UPLOAD JSON:")
    upload_patterns = [
        r'def\s+\w*upload\w*.*json',
        r'def\s+\w*put\w*.*json',
        r'def\s+\w*send\w*.*json',
        r'def\s+\w*register\w*.*json',
        r'def\s+\w*save\w*.*json'
    ]

    upload_found = False
    for pattern in upload_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            upload_found = True
            for match in matches:
                print(f"   ✅ {match}")

    # Buscar también métodos put/upload generales
    general_upload = re.findall(r'def\s+(\w*(?:upload|put|send|register)\w*)\(', content, re.IGNORECASE)
    if general_upload:
        upload_found = True
        print("   📋 Funciones upload generales:")
        for func in general_upload:
            print(f"      🔧 {func}()")

    if not upload_found:
        print("   ❌ NO HAY FUNCIONES DE UPLOAD JSON")

    # 5. Verificar operaciones ETCD put/get
    print("\n🔑 OPERACIONES ETCD:")
    etcd_ops = re.findall(r'\.(?:put|get|delete)\(', content)
    if etcd_ops:
        unique_ops = list(set(etcd_ops))
        for op in unique_ops:
            print(f"   ⚙️ {op}")
    else:
        print("   ❌ No hay operaciones ETCD put/get")

    # 6. Verificar manejo de archivos JSON
    print("\n📁 MANEJO DE ARCHIVOS JSON:")
    json_ops = re.findall(r'(?:open|read|load|dump).*\.json|json\.(?:load|dump)', content, re.IGNORECASE)
    if json_ops:
        for op in list(set(json_ops))[:5]:
            print(f"   📋 {op}")
    else:
        print("   ❌ No maneja archivos JSON")

    # 7. VEREDICTO
    print("\n" + "=" * 60)
    has_etcd = len(etcd_imports) > 0
    has_upload = upload_found
    has_json = len(json_ops) > 0
    has_etcd_ops = len(etcd_ops) > 0

    if has_etcd and has_upload and has_json and has_etcd_ops:
        verdict = "✅ CLIENTE COMPLETO"
    elif has_etcd and has_etcd_ops:
        verdict = "⚠️ PARCIAL - FALTA UPLOAD JSON"
    elif has_etcd:
        verdict = "❌ SOLO TOKENS - NO OPERA ETCD"
    else:
        verdict = "💀 NO ES CLIENTE ETCD"

    print(f"🎯 VEREDICTO: {verdict}")

    # 8. Recomendaciones
    print("\n🛠️ RECOMENDACIONES:")
    if not has_upload:
        print("   ❌ IMPLEMENTAR: upload_config_to_etcd(json_path)")
    if not has_json:
        print("   ❌ IMPLEMENTAR: load_json_file(path)")
    if not has_etcd_ops:
        print("   ❌ IMPLEMENTAR: operaciones etcd put/get")

    return has_etcd and has_upload and has_json and has_etcd_ops


def main():
    if len(sys.argv) != 3:
        print("Uso: python audit_etcd_client.py <client_path> <component_name>")
        print("Ejemplo: python audit_etcd_client.py core/etcd_crypto_client_sniffer_fixed.py SNIFFER")
        return

    client_path = sys.argv[1]
    component_name = sys.argv[2]

    success = audit_etcd_client(client_path, component_name)

    print("\n" + "=" * 60)
    if success:
        print("🎉 CLIENTE ETCD FUNCIONAL")
    else:
        print("🚨 CLIENTE ETCD REQUIERE TRABAJO")


if __name__ == "__main__":
    main()