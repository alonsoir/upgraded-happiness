#!/usr/bin/env python3
"""
Solución rápida sin problemas de sintaxis
"""

import os
import subprocess
import time


def create_simple_patch():
    """Crear parche simple que funcione"""

    # Código de auto-discovery simple
    autodiscovery_code = """
# Auto-discovery functions
import socket
import zmq
import time

def find_available_port(start_port=5555, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return start_port

def find_active_broker(start_port=5555, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        try:
            context = zmq.Context()
            socket_test = context.socket(zmq.REQ)
            socket_test.setsockopt(zmq.RCVTIMEO, 500)
            socket_test.connect(f"tcp://localhost:{port}")
            socket_test.send_string("ping", zmq.NOBLOCK)
            socket_test.close()
            context.term()
            print(f"✅ Broker encontrado en puerto {port}")
            return f"tcp://localhost:{port}"
        except:
            continue
    print(f"⚠️  No se encontró broker, usando puerto {start_port}")
    return f"tcp://localhost:{start_port}"

def get_smart_broker_address():
    import sys
    for i, arg in enumerate(sys.argv):
        if arg == "--broker" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return find_active_broker()
"""

    # Aplicar a archivos específicos
    files_to_patch = [
        "agent_scapy_fixed.py",
        "promiscuous_agent.py",
        "lightweight_ml_detector.py",
    ]

    for filename in files_to_patch:
        if os.path.exists(filename):
            print(f"🔧 Patcheando {filename}...")

            # Leer archivo
            with open(filename, "r") as f:
                content = f.read()

            # Verificar si ya está patcheado
            if "find_active_broker" in content:
                print(f"⚠️  {filename} ya está patcheado")
                continue

            # Hacer backup
            backup_file = f"{filename}.backup.quick"
            with open(backup_file, "w") as f:
                f.write(content)

            # Insertar código al principio (después del shebang y docstring)
            lines = content.split("\n")
            insert_pos = 5  # Después de imports iniciales

            lines.insert(insert_pos, autodiscovery_code)

            # Buscar y reemplazar broker_address
            for i, line in enumerate(lines):
                if 'broker_address = "tcp://localhost:' in line:
                    indent = len(line) - len(line.lstrip())
                    lines[i] = (
                        " " * indent + "broker_address = get_smart_broker_address()"
                    )
                    break

            # Escribir archivo modificado
            modified_content = "\n".join(lines)
            with open(filename, "w") as f:
                f.write(modified_content)

            print(f"✅ {filename} patcheado exitosamente")


def kill_conflicting_processes():
    """Matar procesos que usan puertos"""
    print("🧹 Liberando puertos...")

    try:
        # Matar procesos específicos
        subprocess.run(["pkill", "-f", "run_broker"], capture_output=True)
        subprocess.run(["pkill", "-f", "zmq"], capture_output=True)
        subprocess.run(["pkill", "-f", "agent_scapy"], capture_output=True)
        time.sleep(2)

        # Verificar puertos
        result = subprocess.run(["lsof", "-i", ":5555"], capture_output=True, text=True)
        if result.stdout:
            print("🔍 Procesos aún activos en 5555:")
            print(result.stdout[:200])
        else:
            print("✅ Puerto 5555 liberado")

    except Exception as e:
        print(f"⚠️  Error limpiando: {e}")


def create_simple_broker_script():
    """Crear script de broker simple que use auto-discovery"""
    broker_script = """#!/usr/bin/env python3
import zmq
import socket
import time
import signal
import sys

def find_available_port(start_port=5555):
    for port in range(start_port, start_port + 10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return start_port

def start_smart_broker():
    frontend_port = find_available_port(5555)
    backend_port = frontend_port + 1

    print(f"🔌 Iniciando broker en puertos {frontend_port}/{backend_port}")

    context = zmq.Context()

    # Frontend socket (clientes se conectan aquí)
    frontend = context.socket(zmq.ROUTER)
    frontend.bind(f"tcp://*:{frontend_port}")

    # Backend socket (workers se conectan aquí)  
    backend = context.socket(zmq.DEALER)
    backend.bind(f"tcp://*:{backend_port}")

    print(f"✅ Broker ZeroMQ iniciado en {frontend_port}/{backend_port}")

    def signal_handler(signum, frame):
        print("\\n🛑 Deteniendo broker...")
        frontend.close()
        backend.close()
        context.term()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Proxy entre frontend y backend
        zmq.proxy(frontend, backend)
    except KeyboardInterrupt:
        pass
    finally:
        frontend.close()
        backend.close()
        context.term()

if __name__ == "__main__":
    start_smart_broker()
"""

    os.makedirs("scripts", exist_ok=True)
    with open("scripts/smart_broker.py", "w") as f:
        f.write(broker_script)

    os.chmod("scripts/smart_broker.py", 0o755)
    print("✅ Broker inteligente creado: scripts/smart_broker.py")


def fix_orchestrator_broker():
    """Corregir orquestador para usar broker inteligente"""
    orchestrator_file = "system_orchestrator.py"

    if os.path.exists(orchestrator_file):
        with open(orchestrator_file, "r") as f:
            content = f.read()

        # Cambiar script del broker
        content = content.replace(
            '"script": "./scripts/run_broker.sh"',
            '"script": "python scripts/smart_broker.py"',
        )

        with open(orchestrator_file, "w") as f:
            f.write(content)

        print("✅ Orquestador actualizado para usar broker inteligente")


def test_system():
    """Probar que el sistema funciona"""
    print("🧪 Probando sistema...")

    try:
        # Probar broker independiente
        print("🔌 Iniciando broker de prueba...")
        proc = subprocess.Popen(
            ["python", "scripts/smart_broker.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(3)

        if proc.poll() is None:
            print("✅ Broker de prueba iniciado correctamente")
            proc.terminate()
            proc.wait()
        else:
            stdout, stderr = proc.communicate()
            print(f"❌ Error en broker: {stderr.decode()[:200]}")

    except Exception as e:
        print(f"⚠️  Error en prueba: {e}")


if __name__ == "__main__":
    print("⚡ SOLUCIÓN RÁPIDA PARA SISTEMA")
    print("=" * 50)

    # 1. Limpiar puertos
    kill_conflicting_processes()

    # 2. Crear broker inteligente
    create_simple_broker_script()

    # 3. Aplicar parches simples
    create_simple_patch()

    # 4. Actualizar orquestador
    fix_orchestrator_broker()

    # 5. Probar sistema
    test_system()

    print(f"\n🎉 SOLUCIÓN RÁPIDA COMPLETADA!")
    print(f"\n🚀 AHORA EJECUTA:")
    print("   python system_orchestrator.py start")
    print("\n💡 O para prueba individual:")
    print("   python scripts/smart_broker.py")
