#!/usr/bin/env python3
"""
Script para diagnosticar versiones de protobuf y otras dependencias
"""

import subprocess
import sys


def run_command(cmd):
    """Ejecutar comando y capturar salida"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return None, str(e)


def check_python_package(package_name):
    """Verificar versión de paquete Python"""
    try:
        import importlib.metadata
        version = importlib.metadata.version(package_name)
        return version
    except:
        try:
            # Fallback para versiones más antiguas
            import pkg_resources
            version = pkg_resources.get_distribution(package_name).version
            return version
        except:
            return "No instalado"


print("=== DIAGNÓSTICO DE VERSIONES ===\n")

# Versión de Python
print(f"Python: {sys.version}")

# Versión de protoc (compilador)
stdout, stderr = run_command("protoc --version")
if stdout:
    print(f"protoc (compilador): {stdout}")
else:
    print(f"protoc: No encontrado o error - {stderr}")

# Versión de protobuf Python
protobuf_version = check_python_package("protobuf")
print(f"protobuf (Python): {protobuf_version}")

# Verificar qué tiene la instalación actual de protobuf
try:
    import google.protobuf

    print(f"google.protobuf ubicación: {google.protobuf.__file__}")

    # Verificar qué atributos tiene
    attrs = dir(google.protobuf)
    has_runtime_version = 'runtime_version' in attrs
    print(f"¿Tiene runtime_version? {has_runtime_version}")

    if not has_runtime_version:
        print("Atributos disponibles en google.protobuf:")
        for attr in sorted(attrs):
            if not attr.startswith('_'):
                print(f"  - {attr}")

except ImportError as e:
    print(f"Error importando google.protobuf: {e}")

# Otros paquetes relevantes
print(f"\nOtras dependencias:")
print(f"zmq: {check_python_package('pyzmq')}")
print(f"scapy: {check_python_package('scapy')}")

print("\n=== RECOMENDACIONES ===")
if protobuf_version == "No instalado":
    print("❌ protobuf no está instalado")
else:
    try:
        from packaging import version

        if version.parse(protobuf_version) < version.parse("4.21.0"):
            print(f"⚠️  protobuf {protobuf_version} es muy antiguo, se recomienda actualizar")
        else:
            print(f"✅ protobuf {protobuf_version} debería ser compatible")
    except:
        print(f"📋 protobuf instalado: {protobuf_version}")