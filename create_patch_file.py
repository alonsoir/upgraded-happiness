#!/usr/bin/env python3
"""
Script para crear agent_autodiscovery_patch.py
"""

import os

# Contenido del archivo de parche
patch_content = '''#!/usr/bin/env python3
"""
Parche para agregar auto-discovery a agentes existentes
"""

import os
import shutil
import argparse

def create_autodiscovery_functions():
    """Crear funciones de auto-discovery para agentes"""
    return '''
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
        except Exception as e:
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


'''

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

def create_test_script():
    """Crear script de prueba para auto-discovery"""
    test_content = '''  # !/usr/bin/env python3
"""
Script de prueba para auto-discovery de agentes
"""

import sys
import os

# Agregar directorio actual al path
sys.path.insert(0, os.getcwd())


def test_autodiscovery():
    """Probar funcionalidad de auto-discovery"""
    print("🧪 PROBANDO AUTO-DISCOVERY DE AGENTES...")
    print("=" * 50)

    try:
        # Importar funciones desde agente patcheado
        exec(open('agent_scapy_fixed.py').read(), globals())

        # Probar auto-discovery
        print("🔍 Probando find_active_broker...")
        broker_addr = find_active_broker(5555, 5, 500)
        print(f"Resultado: {broker_addr}")

        print("\\n🔍 Probando get_broker_address_with_discovery...")
        discovery_addr = get_broker_address_with_discovery()
        print(f"Resultado: {discovery_addr}")

        print("\\n✅ Pruebas de auto-discovery completadas")

    except Exception as e:
        print(f"❌ Error en prueba: {e}")


if __name__ == "__main__":
    test_autodiscovery()
'''

    with open("test_autodiscovery.py", 'w') as f:
        f.write(test_content)

    os.chmod("test_autodiscovery.py", 0o755)
    print("✅ Script de prueba creado: test_autodiscovery.py")

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description="Aplicar parche de auto-discovery a agentes")
    parser.add_argument("--file", help="Archivo específico a patchear")
    parser.add_argument("--all", action="store_true", help="Patchear todos los agentes")
    parser.add_argument("--test", action="store_true", help="Crear script de prueba")
    parser.add_argument("--no-backup", action="store_true", help="No crear backup")

    args = parser.parse_args()

    print("🔧 PARCHE DE AUTO-DISCOVERY PARA AGENTES")
    print("=" * 50)

    if args.test:
        create_test_script()
        return

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
            print("   3. python test_autodiscovery.py  # Para probar")

    else:
        # Modo interactivo
        print("🎮 MODO INTERACTIVO")
        print("\nOpciones disponibles:")
        print("1. Patchear todos los agentes")
        print("2. Patchear archivo específico")
        print("3. Crear script de prueba")
        print("0. Salir")

        choice = input("\n🎯 Selecciona opción: ").strip()

        if choice == "1":
            patched_count = patch_all_agents()
            print(f"\n✅ {patched_count} agentes patcheados")

        elif choice == "2":
            filename = input("Archivo a patchear: ").strip()
            if filename:
                patch_agent_file(filename)

        elif choice == "3":
            create_test_script()

        elif choice == "0":
            print("👋 ¡Hasta luego!")

        else:
            print("❌ Opción no válida")

if __name__ == "__main__":
    main()
'''


def create_patch_file():
    """Crear el archivo agent_autodiscovery_patch.py"""
    filename = "agent_autodiscovery_patch.py"

    try:
        with open(filename, 'w') as f:
            f.write(patch_content)

        # Hacer ejecutable
        os.chmod(filename, 0o755)

        print(f"✅ Archivo creado: {filename}")
        print(f"✅ Permisos de ejecución configurados")

        # Verificar que se creó correctamente
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"📁 Tamaño: {size:,} bytes")
            return True
        else:
            print(f"❌ Error: No se pudo crear el archivo")
            return False

    except Exception as e:
        print(f"❌ Error creando archivo: {e}")
        return False


if __name__ == "__main__":
    print("🛠️  CREANDO PARCHE DE AUTO-DISCOVERY...")
    print("=" * 50)

    success = create_patch_file()

    if success:
        print(f"\n🎉 ¡Archivo de parche creado exitosamente!")
        print(f"\n🚀 Próximos pasos:")
        print("   1. python agent_autodiscovery_patch.py --all")
        print("   2. python system_orchestrator.py start")
        print("   3. ¡Disfrutar del auto-discovery!")
    else:
        print(f"\n❌ Error creando el archivo de parche")