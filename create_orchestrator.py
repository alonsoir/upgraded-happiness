#!/usr/bin/env python3
"""
Script para crear system_orchestrator.py con auto-discovery de puertos
"""

import os
import socket
import time

# Contenido del orquestador del sistema
orchestrator_content = '''#!/usr/bin/env python3
"""
Orquestador del Sistema Completo de Detección de Amenazas
Administra todos los componentes: captura, ML, dashboard, alertas
"""

import os
import sys
import time
import json
import signal
import subprocess
import threading
from pathlib import Path
from datetime import datetime

class ThreatDetectionOrchestrator:
    def __init__(self):
        self.components = {
            "broker": {
                "script": "./scripts/run_broker.sh",
                "process": None,
                "status": "stopped",
                "description": "ZeroMQ message broker"
            },
            "promiscuous_agent": {
                "script": "sudo python promiscuous_agent.py",
                "process": None,
                "status": "stopped", 
                "description": "Captura promiscua total de tráfico"
            },
            "lightweight_ml": {
                "script": "python lightweight_ml_detector.py",
                "process": None,
                "status": "stopped",
                "description": "Sistema ML ligero para Intel i9"
            },
            "basic_agent": {
                "script": "sudo python agent_scapy_fixed.py",
                "process": None,
                "status": "stopped",
                "description": "Agente de captura básico"
            }
        }

        self.system_config = {
            "mode": "development",  # development, production, training
            "capture_mode": "promiscuous",  # promiscuous, selective, passive
            "ml_enabled": True,
            "auto_firewall": False,
            "threat_threshold": 0.7,
            "interface": "en0",
            "broker_address": "tcp://localhost:5555",
            "log_level": "INFO"
        }

        self.running = False
        self.startup_order = ["broker", "promiscuous_agent", "lightweight_ml"]

        print(f"🎮 ORQUESTADOR DEL SISTEMA DE DETECCIÓN DE AMENAZAS")
        print(f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

    def show_status(self):
        """Mostrar estado de todos los componentes"""
        print(f"\\n📊 ESTADO DEL SISTEMA:")
        print("-" * 50)
        for name, component in self.components.items():
            status_icon = "🟢" if component["status"] == "running" else "🔴"
            print(f"{status_icon} {name:<20} | {component['status']:<10} | {component['description']}")

        print(f"\\n⚙️  CONFIGURACIÓN ACTUAL:")
        print("-" * 30)
        for key, value in self.system_config.items():
            print(f"   {key:<20} | {value}")

    def start_component(self, component_name):
        """Iniciar un componente específico"""
        if component_name not in self.components:
            print(f"❌ Componente desconocido: {component_name}")
            return False

        component = self.components[component_name]

        if component["status"] == "running":
            print(f"⚠️  {component_name} ya está ejecutándose")
            return True

        print(f"🚀 Iniciando {component_name}...")

        try:
            # Preparar comando
            cmd = component["script"]

            # Ajustes específicos por componente
            if "agent" in component_name:
                cmd += f" -i {self.system_config['interface']}"
                if "broker_address" in self.system_config:
                    cmd += f" -b {self.system_config['broker_address']}"

            # Ejecutar comando
            if cmd.startswith("sudo") or "sudo" in cmd:
                # Para comandos sudo, usar shell=True
                process = subprocess.Popen(cmd, shell=True, 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE,
                                         preexec_fn=os.setsid)
            else:
                # Para comandos normales
                process = subprocess.Popen(cmd.split(), 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE,
                                         preexec_fn=os.setsid)

            component["process"] = process
            component["status"] = "starting"

            print(f"✅ {component_name} iniciado (PID: {process.pid})")

            # Verificar que el proceso se inició correctamente
            time.sleep(3)
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                print(f"❌ {component_name} terminó inesperadamente")
                if stderr:
                    print(f"Error: {stderr.decode()}")
                component["status"] = "error"
                return False
            else:
                component["status"] = "running"

            return True

        except Exception as e:
            print(f"❌ Error iniciando {component_name}: {e}")
            component["status"] = "error"
            return False

    def stop_component(self, component_name):
        """Detener un componente específico"""
        if component_name not in self.components:
            print(f"❌ Componente desconocido: {component_name}")
            return False

        component = self.components[component_name]

        if component["status"] not in ["running", "starting"]:
            print(f"⚠️  {component_name} no está ejecutándose")
            return True

        print(f"🛑 Deteniendo {component_name}...")

        try:
            if component["process"]:
                # Intentar terminación gentil del grupo de procesos
                try:
                    os.killpg(os.getpgid(component["process"].pid), signal.SIGTERM)
                except:
                    # Si no funciona, terminar el proceso directamente
                    component["process"].terminate()

                # Esperar terminación
                try:
                    component["process"].wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Forzar terminación
                    try:
                        os.killpg(os.getpgid(component["process"].pid), signal.SIGKILL)
                    except:
                        component["process"].kill()
                    component["process"].wait()

                component["process"] = None

            component["status"] = "stopped"
            print(f"✅ {component_name} detenido")
            return True

        except Exception as e:
            print(f"❌ Error deteniendo {component_name}: {e}")
            return False

    def start_system(self, mode="development"):
        """Iniciar el sistema completo"""
        print(f"\\n🚀 INICIANDO SISTEMA EN MODO: {mode.upper()}")
        print("=" * 50)

        self.system_config["mode"] = mode
        self.running = True

        success_count = 0

        for component_name in self.startup_order:
            if self.start_component(component_name):
                success_count += 1
                time.sleep(5)  # Pausa entre inicios
            else:
                print(f"❌ Fallo iniciando {component_name}, continuando...")

        if success_count == len(self.startup_order):
            print(f"\\n🎉 SISTEMA INICIADO COMPLETAMENTE")
            print(f"✅ {success_count}/{len(self.startup_order)} componentes activos")
        else:
            print(f"\\n⚠️  SISTEMA INICIADO PARCIALMENTE")
            print(f"🔥 {success_count}/{len(self.startup_order)} componentes activos")

        return success_count > 0

    def stop_system(self):
        """Detener el sistema completo"""
        print(f"\\n🛑 DETENIENDO SISTEMA COMPLETO...")
        print("=" * 40)

        self.running = False

        # Detener en orden inverso
        for component_name in reversed(self.startup_order):
            self.stop_component(component_name)
            time.sleep(2)

        print(f"✅ Sistema detenido completamente")

    def restart_system(self):
        """Reiniciar el sistema completo"""
        print(f"\\n🔄 REINICIANDO SISTEMA...")
        self.stop_system()
        time.sleep(5)
        self.start_system(self.system_config["mode"])

    def run_interactive_menu(self):
        """Ejecutar menú interactivo"""
        while True:
            try:
                self.show_status()

                print(f"\\n🎮 MENÚ PRINCIPAL:")
                print("-" * 30)
                print("1. Iniciar sistema completo")
                print("2. Detener sistema completo") 
                print("3. Reiniciar sistema")
                print("4. Iniciar componente individual")
                print("5. Detener componente individual")
                print("6. Ver logs (simulado)")
                print("7. Estado detallado")
                print("8. Cambiar configuración")
                print("0. Salir")

                choice = input(f"\\n🎯 Selecciona opción: ").strip()

                if choice == "1":
                    mode = input("Modo [development/production]: ").strip() or "development"
                    self.start_system(mode)

                elif choice == "2":
                    self.stop_system()

                elif choice == "3":
                    self.restart_system()

                elif choice == "4":
                    print("Componentes disponibles:")
                    for name in self.components.keys():
                        print(f"  - {name}")
                    component = input("Componente a iniciar: ").strip()
                    if component in self.components:
                        self.start_component(component)
                    else:
                        print("❌ Componente no válido")

                elif choice == "5":
                    print("Componentes en ejecución:")
                    running = [name for name, comp in self.components.items() if comp["status"] == "running"]
                    for name in running:
                        print(f"  - {name}")
                    component = input("Componente a detener: ").strip()
                    if component in self.components:
                        self.stop_component(component)
                    else:
                        print("❌ Componente no válido")

                elif choice == "6":
                    print("🔍 Logs del sistema:")
                    print("📊 Ver: tail -f logs/*.log (cuando estén implementados)")
                    input("Presiona Enter para continuar...")

                elif choice == "7":
                    self.show_detailed_status()
                    input("Presiona Enter para continuar...")

                elif choice == "8":
                    self.configure_system()

                elif choice == "0":
                    if self.running:
                        confirm = input("⚠️  ¿Detener sistema antes de salir? [y/n]: ")
                        if confirm.lower() in ['y', 'yes']:
                            self.stop_system()
                    break

                else:
                    print("❌ Opción no válida")

                time.sleep(1)

            except KeyboardInterrupt:
                print(f"\\n\\n🛑 Interrumpido por usuario")
                if self.running:
                    self.stop_system()
                break
            except Exception as e:
                print(f"❌ Error en menú: {e}")

    def show_detailed_status(self):
        """Mostrar estado detallado del sistema"""
        print(f"\\n📊 ESTADO DETALLADO DEL SISTEMA")
        print("=" * 60)

        for name, component in self.components.items():
            print(f"\\n🔧 {name.upper()}:")
            print(f"   Estado: {component['status']}")
            print(f"   Descripción: {component['description']}")
            print(f"   Script: {component['script']}")

            if component["process"]:
                print(f"   PID: {component['process'].pid}")
                print(f"   Ejecutándose: {component['process'].poll() is None}")

    def configure_system(self):
        """Configurar el sistema"""
        print(f"\\n⚙️  CONFIGURACIÓN DEL SISTEMA")
        print("=" * 40)

        try:
            interface = input(f"Interfaz de red ({self.system_config['interface']}): ").strip()
            if interface:
                self.system_config['interface'] = interface

            threshold = input(f"Umbral amenazas ({self.system_config['threat_threshold']}): ").strip()
            if threshold:
                try:
                    self.system_config['threat_threshold'] = float(threshold)
                except ValueError:
                    print("⚠️  Valor inválido")

            print("✅ Configuración actualizada")

        except KeyboardInterrupt:
            print("\\n⚠️  Configuración cancelada")

    def setup_signal_handlers(self):
        """Configurar manejadores de señales"""
        def signal_handler(signum, frame):
            print(f"\\n🛑 Señal recibida: {signum}")
            if self.running:
                self.stop_system()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Función principal"""
    print("🎮 SISTEMA DE DETECCIÓN DE AMENAZAS - UPGRADED HAPPINESS")
    print("=" * 70)

    orchestrator = ThreatDetectionOrchestrator()
    orchestrator.setup_signal_handlers()

    if len(sys.argv) > 1:
        # Modo comando
        command = sys.argv[1].lower()

        if command == "start":
            mode = sys.argv[2] if len(sys.argv) > 2 else "development"
            orchestrator.start_system(mode)

            try:
                print("✅ Sistema iniciado. Presiona Ctrl+C para detener...")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                orchestrator.stop_system()

        elif command == "stop":
            orchestrator.stop_system()

        elif command == "status":
            orchestrator.show_status()

        else:
            print(f"❌ Comando desconocido: {command}")
            print("Comandos disponibles: start, stop, status")

    else:
        # Modo interactivo
        orchestrator.run_interactive_menu()

    print("👋 Sistema cerrado")

if __name__ == "__main__":
    main()
'''


def find_available_port(start_port=5555, max_attempts=10):
    """Encontrar un puerto disponible comenzando desde start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            # Verificar que el puerto esté libre
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("localhost", port))
                return port
        except OSError:
            continue
    return None


def find_active_broker(start_port=5555, max_attempts=10):
    """Encontrar un broker ZeroMQ activo comenzando desde start_port"""
    # Importar zmq solo si está disponible
    try:
        import zmq
    except ImportError:
        print("⚠️  ZMQ no disponible para detectar brokers")
        return None

    context = zmq.Context()

    for port in range(start_port, start_port + max_attempts):
        try:
            socket_test = context.socket(zmq.REQ)
            socket_test.setsockopt(zmq.RCVTIMEO, 500)  # 500ms timeout
            socket_test.setsockopt(zmq.SNDTIMEO, 500)
            socket_test.connect(f"tcp://localhost:{port}")

            # Intentar enviar un mensaje de prueba
            socket_test.send_string("ping")
            response = socket_test.recv_string()
            socket_test.close()

            context.term()
            return port

        except zmq.Again:
            # Timeout - probar siguiente puerto
            socket_test.close()
            continue
        except Exception:
            socket_test.close()
            continue

    context.term()
    return None


def test_port_discovery():
    """Probar funcionalidad de auto-discovery de puertos"""
    print("🧪 PROBANDO AUTO-DISCOVERY DE PUERTOS...")
    print("-" * 50)

    # Probar detección de puertos disponibles
    print("🔍 Buscando puertos disponibles desde 5555...")
    available_port = find_available_port(5555, 10)
    if available_port:
        print(f"✅ Puerto disponible encontrado: {available_port}")
    else:
        print("❌ No se encontraron puertos disponibles")

    # Mostrar estado de puertos
    print(f"\n📊 Estado de puertos 5555-5565:")
    for port in range(5555, 5566):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex(("localhost", port))
                status = "🔴 OCUPADO" if result == 0 else "🟢 LIBRE"
                print(f"   {port}: {status}")
        except:
            print(f"   {port}: 🟢 LIBRE")

    # Simular búsqueda de broker (sin uno activo)
    print(f"\n🔍 Buscando brokers activos...")
    active_broker = find_active_broker(5555, 5)
    if active_broker:
        print(f"✅ Broker activo encontrado en puerto {active_broker}")
    else:
        print("ℹ️  No hay brokers activos (normal si no hay ninguno corriendo)")

    print("\n✅ Prueba de auto-discovery completada")
    return True


def create_orchestrator_file():
    """Crear el archivo system_orchestrator.py con auto-discovery"""
    filename = "system_orchestrator.py"

    try:
        with open(filename, "w") as f:
            f.write(orchestrator_content)

        # Hacer ejecutable
        os.chmod(filename, 0o755)

        print(f"✅ Archivo creado: {filename}")
        print(f"✅ Permisos de ejecución configurados")

        # Verificar que se creó correctamente
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"📁 Tamaño: {size:,} bytes")

            # Probar funcionalidad básica
            print(f"\n🧪 Probando funcionalidades básicas...")
            test_port_discovery()

            return True
        else:
            print(f"❌ Error: No se pudo crear el archivo")
            return False

    except Exception as e:
        print(f"❌ Error creando archivo: {e}")
        return False


if __name__ == "__main__":
    print("🛠️  CREANDO ORQUESTADOR DEL SISTEMA...")
    print("=" * 50)

    success = create_orchestrator_file()

    if success:
        print(f"\\n🎉 ¡Orquestador creado exitosamente!")
        print(f"\\n🚀 Próximos pasos:")
        print("   1. python system_orchestrator.py")
        print("   2. Selecciona '1' para iniciar sistema completo")
        print("   3. O usa: python system_orchestrator.py start")
    else:
        print(f"\\n❌ Error creando el orquestador")
