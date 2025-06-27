#!/usr/bin/env python3
"""
Parche para agregar auto-discovery a agentes existentes
"""

import os
import shutil
import argparse

def create_autodiscovery_functions():
    """Crear funciones de auto-discovery para agentes"""
    return """
import socket
import zmq
import time

def find_active_broker(start_port=5555, max_attempts=10, timeout_ms=1000):
    """Encontrar un broker ZeroMQ activo para conectarse"""
    context = zmq.Context()

    for port in range(start_port, start_port + max_attempts):
        try:
            # Intentar conexión simple
            socket_test = context.socket(zmq.REQ)
            socket_test.setsockopt(zmq.RCVTIMEO, timeout_ms)
            socket_test.setsockopt(zmq.SNDTIMEO, timeout_ms)
            socket_test.setsockopt(zmq.LINGER, 0)

            broker_address = f"tcp://localhost:{port}"
            socket_test.connect(broker_address)

            # Probar conexión básica
            socket_test.send_string("ping", zmq.NOBLOCK)
            time.sleep(0.1)  # Pequeña pausa

            socket_test.close()
            context.term()

            print(f"✅ Broker encontrado en {broker_address}")
            return broker_address

        except zmq.Again:
            socket_test.close()
            continue
        except Exception:
            socket_test.close()
            continue

    context.term()
    print(f"⚠️  No se encontró broker activo en puertos {start_port}-{start_port + max_attempts - 1}")
    return f"tcp://localhost:{start_port}"  # Fallback al puerto por defecto

def get_broker_address_with_discovery(default_address="tcp://localhost:5555"):
    """Obtener dirección del broker con auto-discovery"""
    # Si se especifica via línea de comandos o args, usar esa
    import sys

    # Buscar --broker en argumentos
    for i, arg in enumerate(sys.argv):
        if arg == "--broker" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        elif arg.startswith("--broker="):
            return arg.split("=", 1)[1]

    # Si no se especifica, usar auto-discovery
    print("🔍 Buscando broker activo...")
    discovered_address = find_active_broker()

    return discovered_address
"""

def patch_agent_file(agent_file, backup=True):
    """Agregar auto-discovery a un archivo de agente"""
    if not os.path.exists(agent_file):
        print(f"❌ Archivo no encontrado: {agent_file}")
        return False

    # Hacer backup
    if backup:
        backup_file = f"{agent_file}.backup"
        shutil.copy2(agent_file, backup_file)
        print(f"📁 Backup creado: {backup_file}")

    # Leer archivo original
    with open(agent_file, 'r') as f:
        content = f.read()

    # Verificar si ya tiene auto-discovery
    if "find_active_broker" in content:
        print(f"⚠️  {agent_file} ya tiene auto-discovery")
        return True

    # Encontrar donde insertar las funciones (después de imports)
    lines = content.split('\n')
    insert_position = 0

    # Buscar última línea de import o primera línea de código
    for i, line in enumerate(lines):
        if line.strip().startswith('import ') or line.strip().startswith('from '):
            insert_position = i + 1
        elif line.strip() and not line.strip().startswith('#'):
            break

    # Insertar funciones de auto-discovery
    autodiscovery_code = create_autodiscovery_functions()
    lines.insert(insert_position, autodiscovery_code)

    # Buscar y modificar línea de broker_address
    for i, line in enumerate(lines):
        if 'broker_address = "tcp://localhost:' in line:
            # Reemplazar con auto-discovery
            indent = len(line) - len(line.lstrip())
            new_line = ' ' * indent + 'broker_address = get_broker_address_with_discovery("tcp://localhost:5555")'
            lines[i] = new_line
            print(f"✅ Línea de broker_address actualizada")
            break

    # Escribir archivo modificado
    modified_content = '\n'.join(lines)

    with open(agent_file, 'w') as f:
        f.write(modified_content)

    print(f"✅ Auto-discovery agregado a {agent_file}")
    return True

def patch_all_agents():
    """Aplicar parche a todos los agentes encontrados"""
    agent_files = [
        "agent_scapy.py",
        "agent_scapy_fixed.py", 
        "promiscuous_agent.py",
        "lightweight_ml_detector.py"
    ]

    patched_count = 0

    for agent_file in agent_files:
        if os.path.exists(agent_file):
            print(f"\n🔧 Aplicando parche a {agent_file}...")
            if patch_agent_file(agent_file):
                patched_count += 1
        else:
            print(f"⚠️  No encontrado: {agent_file}")

    return patched_count

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description="Aplicar parche de auto-discovery a agentes")
    parser.add_argument("--file", help="Archivo específico a patchear")
    parser.add_argument("--all", action="store_true", help="Patchear todos los agentes")
    parser.add_argument("--no-backup", action="store_true", help="No crear backup")

    args = parser.parse_args()

    print("🔧 PARCHE DE AUTO-DISCOVERY PARA AGENTES")
    print("=" * 50)

    if args.file:
        # Patchear archivo específico
        print(f"🎯 Aplicando parche a: {args.file}")
        success = patch_agent_file(args.file, backup=not args.no_backup)
        if success:
            print(f"✅ Parche aplicado exitosamente")
        else:
            print(f"❌ Error aplicando parche")

    elif args.all:
        # Patchear todos los agentes
        print("🎯 Aplicando parche a todos los agentes...")
        patched_count = patch_all_agents()
        print(f"\n📊 RESUMEN:")
        print(f"   ✅ Archivos patcheados: {patched_count}")

        if patched_count > 0:
            print(f"\n🚀 BENEFICIOS DEL AUTO-DISCOVERY:")
            print("   🔌 Conexión automática a brokers disponibles")
            print("   🔄 Reconexión inteligente si cambia el puerto")
            print("   ⚙️  Configuración automática de red") 
            print("   🛡️  Mayor robustez del sistema")

            print(f"\n📝 PRÓXIMOS PASOS:")
            print("   1. python system_orchestrator.py start")
            print("   2. Los agentes se conectarán automáticamente")

    else:
        # Modo interactivo
        print("🎮 MODO INTERACTIVO")
        print("\nOpciones disponibles:")
        print("1. Patchear todos los agentes")
        print("2. Patchear archivo específico")
        print("0. Salir")

        choice = input("\n🎯 Selecciona opción: ").strip()

        if choice == "1":
            patched_count = patch_all_agents()
            print(f"\n✅ {patched_count} agentes patcheados")

        elif choice == "2":
            filename = input("Archivo a patchear: ").strip()
            if filename:
                patch_agent_file(filename)

        elif choice == "0":
            print("👋 ¡Hasta luego!")

        else:
            print("❌ Opción no válida")

if __name__ == "__main__":
    main()
