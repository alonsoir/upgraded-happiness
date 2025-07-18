#!/usr/bin/env python3
"""
Script para corregir el conflicto de protobuf en upgraded-happiness
Soluciona el error: duplicate symbol 'network.events.NetworkEvent'
"""

import os
import shutil
import subprocess
import sys


def backup_current_files():
    """Hacer backup de archivos actuales"""
    print("📋 Haciendo backup de archivos actuales...")

    backup_files = [
        'src/protocols/protobuf/network_event_extended.proto',
        'src/protocols/protobuf/network_event_extended_pb2.py'
    ]

    for file in backup_files:
        if os.path.exists(file):
            backup_name = f"{file}.backup"
            shutil.copy2(file, backup_name)
            print(f"   ✅ {file} → {backup_name}")


def create_fixed_protobuf():
    """Crear protobuf con package name corregido"""
    print("🔧 Creando protobuf corregido...")

    proto_content = '''syntax = "proto3";

// ✅ PACKAGE CAMBIADO PARA EVITAR CONFLICTOS
package network.events.extended;

//protoc --python_out=. network_event_extended_fixed.proto

message NetworkEvent {
    string event_id = 1;
    int64 timestamp = 2;
    string source_ip = 3;
    string target_ip = 4;
    int32 packet_size = 5;
    int32 dest_port = 6;
    int32 src_port = 7;
    string agent_id = 8;
    float anomaly_score = 9;
    double latitude = 10;
    double longitude = 11;

    // Campos existentes para eventos enriquecidos cuando alguien trate de usar TOR.
    string event_type = 12;
    float risk_score = 13;
    string description = 14;

    // NUEVOS CAMPOS: Identificador del SO para selección de reglas
    string so_identifier = 15;  // "linux_ufw", "linux_iptables", "windows_firewall", "darwin_pf"

    // NUEVOS CAMPOS: Información adicional del nodo (opcional, solo en primer evento)
    string node_hostname = 16;        // Hostname del nodo
    string os_version = 17;           // "Ubuntu 22.04", "Windows 11", etc.
    string firewall_status = 18;      // "active", "inactive", "unknown"
    string agent_version = 19;        // Versión del agente
    bool is_initial_handshake = 20;   // true solo en el primer evento del nodo
}'''

    # Crear archivo corregido
    fixed_path = 'src/protocols/protobuf/network_event_extended_fixed.proto'
    with open(fixed_path, 'w') as f:
        f.write(proto_content)

    print(f"   ✅ Creado: {fixed_path}")
    return fixed_path


def compile_protobuf(proto_file):
    """Compilar archivo protobuf"""
    print(f"🔧 Compilando {proto_file}...")

    # Cambiar al directorio del protobuf
    proto_dir = os.path.dirname(proto_file)
    proto_name = os.path.basename(proto_file)

    original_dir = os.getcwd()

    try:
        os.chdir(proto_dir)

        # Compilar
        result = subprocess.run([
            'protoc',
            '--python_out=.',
            proto_name
        ], capture_output=True, text=True)

        if result.returncode == 0:
            expected_output = proto_name.replace('.proto', '_pb2.py')
            if os.path.exists(expected_output):
                print(f"   ✅ Compilado: {expected_output}")
                return True
            else:
                print(f"   ❌ No se encontró archivo compilado: {expected_output}")
                return False
        else:
            print(f"   ❌ Error compilando:")
            print(f"   {result.stderr}")
            return False

    finally:
        os.chdir(original_dir)


def update_imports():
    """Actualizar imports en promiscuous_agent.py"""
    print("🔧 Actualizando imports en promiscuous_agent.py...")

    agent_file = 'promiscuous_agent.py'

    if not os.path.exists(agent_file):
        print(f"   ❌ No se encontró {agent_file}")
        return False

    # Leer archivo actual
    with open(agent_file, 'r') as f:
        content = f.read()

    # Realizar reemplazos
    replacements = [
        # Cambiar import del protobuf extendido
        (
            'from src.protocols.protobuf import network_event_extended_pb2',
            'from src.protocols.protobuf import network_event_extended_fixed_pb2 as network_event_extended_pb2'
        ),
        (
            'from protobuf import network_event_extended_pb2',
            'from src.protocols.protobuf import network_event_extended_fixed_pb2 as network_event_extended_pb2'
        ),
        # Backup para diferentes variaciones
        (
            'import network_event_extended_pb2',
            'from src.protocols.protobuf import network_event_extended_fixed_pb2 as network_event_extended_pb2'
        )
    ]

    modified = False
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            modified = True
            print(f"   ✅ Reemplazado: {old}")

    if modified:
        # Crear backup
        shutil.copy2(agent_file, f"{agent_file}.backup")

        # Escribir archivo actualizado
        with open(agent_file, 'w') as f:
            f.write(content)
        print(f"   ✅ Actualizado: {agent_file}")
        return True
    else:
        print(f"   ⚠️  No se encontraron imports para actualizar")
        return False


def clean_old_files():
    """Limpiar archivos problemáticos"""
    print("🧹 Limpiando archivos problemáticos...")

    files_to_remove = [
        'src/protocols/protobuf/network_event_extended_pb2.py',
        'src/protocols/protobuf/__pycache__'
    ]

    for file_path in files_to_remove:
        if os.path.exists(file_path):
            if os.path.isdir(file_path):
                shutil.rmtree(file_path)
                print(f"   ✅ Eliminado directorio: {file_path}")
            else:
                os.remove(file_path)
                print(f"   ✅ Eliminado archivo: {file_path}")


def test_import():
    """Probar que el import funciona"""
    print("🧪 Probando import corregido...")

    try:
        # Test import
        result = subprocess.run([
            sys.executable, '-c',
            'from src.protocols.protobuf import network_event_extended_fixed_pb2; print("✅ Import OK")'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("   ✅ Import test exitoso")
            return True
        else:
            print(f"   ❌ Import test falló:")
            print(f"   {result.stderr}")
            return False

    except Exception as e:
        print(f"   ❌ Error en test: {e}")
        return False


def main():
    """Función principal"""
    print("🔧 Arreglando conflicto de protobuf en upgraded-happiness")
    print("=" * 60)

    # Verificar que estamos en el directorio correcto
    if not os.path.exists('src/protocols/protobuf'):
        print("❌ No se encontró src/protocols/protobuf")
        print("   Ejecutar desde el directorio raíz del proyecto")
        return 1

    steps = [
        ("Backup de archivos", backup_current_files),
        ("Crear protobuf corregido", create_fixed_protobuf),
        ("Compilar protobuf", lambda: compile_protobuf('src/protocols/protobuf/network_event_extended_fixed.proto')),
        ("Limpiar archivos problemáticos", clean_old_files),
        ("Actualizar imports", update_imports),
        ("Test de import", test_import)
    ]

    for step_name, step_func in steps:
        print(f"\n🔄 {step_name}...")
        try:
            if step_func() is False:
                print(f"❌ Falló: {step_name}")
                return 1
        except Exception as e:
            print(f"❌ Error en {step_name}: {e}")
            return 1

    print("\n" + "=" * 60)
    print("🎉 ¡Conflicto de protobuf resuelto!")
    print("\n📋 Cambios realizados:")
    print("   • Creado protobuf con package corregido")
    print("   • Compilado nuevo protobuf")
    print("   • Actualizado imports en promiscuous_agent.py")
    print("   • Limpiado archivos conflictivos")

    print("\n🚀 Próximo paso:")
    print("   sudo python promiscuous_agent.py enhanced_agent_config.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())