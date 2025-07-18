#!/usr/bin/env python3
"""
Coordinador de arranque para Upgraded-Happiness
Inicia todos los componentes en el orden correcto y monitorea su estado.
"""

import subprocess
import time
import signal
import sys
import os
import socket
import threading
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class ServiceManager:
    """Gestor de servicios del sistema"""

    def __init__(self):
        self.services = {}
        self.running = False
        self.startup_timeout = 30  # segundos

        # Definir servicios y su orden de arranque
        self.service_definitions = [
            {
                'name': 'firewall_agent',
                'command': ['python', 'simple_firewall_agent.py'],
                'port': 5561,
                'description': 'Firewall Agent (Display-Only)',
                'required': True,
                'startup_delay': 2
            },
            {
                'name': 'event_analyzer',
                'command': ['python', 'event_analyzer.py'],
                'port': 5560,
                'description': 'Event Analyzer & Rule Engine',
                'required': True,
                'startup_delay': 3
            }
        ]

        # Señales para cleanup
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Maneja señales del sistema para cleanup"""
        print(f"\n🛑 Received signal {signum}, shutting down...")
        self.stop_all_services()
        sys.exit(0)

    def check_port(self, port: int, timeout: float = 1.0) -> bool:
        """Verifica si un puerto está siendo usado"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def wait_for_port(self, port: int, timeout: float = 30.0) -> bool:
        """Espera hasta que un puerto esté disponible"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.check_port(port):
                return True
            time.sleep(0.5)
        return False

    def start_service(self, service_def: Dict) -> bool:
        """Inicia un servicio individual"""
        name = service_def['name']
        command = service_def['command']
        port = service_def['port']
        description = service_def['description']

        print(f"🚀 Starting {description}...")

        # Verificar que el script existe
        script_path = command[1] if len(command) > 1 else command[0]
        if not os.path.exists(script_path):
            print(f"   ❌ Script not found: {script_path}")
            return False

        try:
            # Iniciar proceso
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Guardar información del servicio
            self.services[name] = {
                'process': process,
                'definition': service_def,
                'start_time': time.time(),
                'status': 'starting'
            }

            # Esperar que el puerto esté disponible
            print(f"   ⏳ Waiting for port {port}...")
            if self.wait_for_port(port, self.startup_timeout):
                self.services[name]['status'] = 'running'
                print(f"   ✅ {description} started successfully (PID: {process.pid})")

                # Delay antes del siguiente servicio
                if service_def.get('startup_delay', 0) > 0:
                    print(f"   ⏸️  Waiting {service_def['startup_delay']}s before next service...")
                    time.sleep(service_def['startup_delay'])

                return True
            else:
                print(f"   ❌ Timeout waiting for {description} on port {port}")
                self.stop_service(name)
                return False

        except Exception as e:
            print(f"   ❌ Failed to start {description}: {e}")
            return False

    def stop_service(self, name: str):
        """Para un servicio específico"""
        if name not in self.services:
            return

        service = self.services[name]
        process = service['process']
        description = service['definition']['description']

        print(f"🛑 Stopping {description}...")

        try:
            # Intentar terminación gentil
            process.terminate()

            # Esperar un poco
            try:
                process.wait(timeout=5)
                print(f"   ✅ {description} stopped gracefully")
            except subprocess.TimeoutExpired:
                # Forzar terminación
                print(f"   ⚡ Force killing {description}...")
                process.kill()
                process.wait()
                print(f"   ✅ {description} killed")

        except Exception as e:
            print(f"   ⚠️  Error stopping {description}: {e}")
        finally:
            del self.services[name]

    def stop_all_services(self):
        """Para todos los servicios en orden inverso"""
        if not self.services:
            return

        print(f"\n🛑 Stopping all services...")

        # Parar en orden inverso
        service_names = list(self.services.keys())
        service_names.reverse()

        for name in service_names:
            self.stop_service(name)

        print(f"✅ All services stopped")

    def check_service_health(self, name: str) -> bool:
        """Verifica el estado de un servicio"""
        if name not in self.services:
            return False

        service = self.services[name]
        process = service['process']
        port = service['definition']['port']

        # Verificar que el proceso sigue corriendo
        if process.poll() is not None:
            return False

        # Verificar que el puerto sigue disponible
        return self.check_port(port)

    def monitor_services(self):
        """Monitorea el estado de los servicios"""
        while self.running:
            time.sleep(10)  # Check cada 10 segundos

            for name in list(self.services.keys()):
                if not self.check_service_health(name):
                    service = self.services[name]
                    description = service['definition']['description']
                    print(f"⚠️  Service {description} appears to be down!")

                    # Si es requerido, intentar restart
                    if service['definition'].get('required', False):
                        print(f"🔄 Attempting to restart {description}...")
                        self.stop_service(name)
                        time.sleep(2)
                        if not self.start_service(service['definition']):
                            print(f"❌ Failed to restart {description}")

    def start_all_services(self) -> bool:
        """Inicia todos los servicios en orden"""
        print(f"🚀 Upgraded-Happiness Security Platform")
        print(f"=" * 50)

        success_count = 0
        total_services = len(self.service_definitions)

        for service_def in self.service_definitions:
            if self.start_service(service_def):
                success_count += 1
            else:
                print(f"❌ Failed to start required service: {service_def['description']}")
                if service_def.get('required', False):
                    print(f"🛑 Stopping due to failed required service")
                    self.stop_all_services()
                    return False

        if success_count == total_services:
            print(f"\n🎉 All services started successfully!")
            self.print_status()
            self.running = True

            # Iniciar monitor en hilo separado
            monitor_thread = threading.Thread(target=self.monitor_services, daemon=True)
            monitor_thread.start()

            return True
        else:
            print(f"\n⚠️  Only {success_count}/{total_services} services started")
            return False

    def print_status(self):
        """Imprime el estado actual del sistema"""
        print(f"\n📊 System Status:")
        print(f"─" * 40)

        for name, service in self.services.items():
            definition = service['definition']
            process = service['process']

            status_icon = "🟢" if service['status'] == 'running' else "🔴"
            uptime = time.time() - service['start_time']

            print(f"{status_icon} {definition['description']}")
            print(f"   PID: {process.pid}, Port: {definition['port']}")
            print(f"   Uptime: {uptime:.0f}s")

        print(f"\n💡 Next steps:")
        print(f"   1. Test integration: python test_integration.py")
        print(f"   2. Send events to port 5560")
        print(f"   3. Monitor firewall agent output")
        print(f"   4. Use analyzer interactive commands")

        print(f"\n⚠️  All firewall commands are in DISPLAY-ONLY mode")
        print(f"   To enable real execution: --apply-real flag")

    def wait_for_shutdown(self):
        """Espera señal de shutdown"""
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_all_services()


def check_dependencies():
    """Verifica que las dependencias estén disponibles"""
    required_files = [
        'simple_firewall_agent.py',
        'event_analyzer.py',
        'rule_engine.py',
        'simple_system_detection.py'
    ]

    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print(f"❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        return False

    # Verificar Python
    try:
        import zmq
        print(f"✅ ZeroMQ available")
    except ImportError:
        print(f"❌ ZeroMQ not available. Install with: pip install pyzmq")
        return False

    return True


def main():
    """Función principal"""
    import argparse

    # Configurar logging
    logging.basicConfig(
        level=logging.WARNING,  # Solo warnings para output limpio
        format='%(levelname)s: %(message)s'
    )

    parser = argparse.ArgumentParser(description='Start Upgraded-Happiness Security Platform')
    parser.add_argument('--check-only', action='store_true', help='Only check dependencies')
    parser.add_argument('--status-only', action='store_true', help='Only show current status')

    args = parser.parse_args()

    # Verificar dependencias
    print(f"🔍 Checking dependencies...")
    if not check_dependencies():
        print(f"\n❌ Dependency check failed")
        return 1

    if args.check_only:
        print(f"\n✅ All dependencies satisfied")
        return 0

    # Verificar estado actual
    manager = ServiceManager()

    if args.status_only:
        ports_in_use = []
        for service_def in manager.service_definitions:
            if manager.check_port(service_def['port']):
                ports_in_use.append((service_def['port'], service_def['description']))

        if ports_in_use:
            print(f"\n🟢 Services currently running:")
            for port, desc in ports_in_use:
                print(f"   Port {port}: {desc}")
        else:
            print(f"\n🔴 No services currently running")
        return 0

    # Verificar que no haya servicios ya corriendo
    conflicting_ports = []
    for service_def in manager.service_definitions:
        if manager.check_port(service_def['port']):
            conflicting_ports.append((service_def['port'], service_def['description']))

    if conflicting_ports:
        print(f"\n⚠️  Some services appear to be already running:")
        for port, desc in conflicting_ports:
            print(f"   Port {port}: {desc}")

        response = input(f"\nContinue anyway? (y/N): ").strip().lower()
        if response != 'y':
            print(f"❌ Aborted")
            return 1

    # Iniciar servicios
    try:
        if manager.start_all_services():
            print(f"\n🎮 Platform is running. Press Ctrl+C to stop.")
            manager.wait_for_shutdown()
            return 0
        else:
            print(f"\n❌ Failed to start platform")
            return 1

    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        manager.stop_all_services()
        return 1


if __name__ == "__main__":
    sys.exit(main())