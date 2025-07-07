#!/usr/bin/env python3
"""
🚀 System Orchestrator - Gestión completa del sistema SCADA + ML + Firewall
Orquesta todos los componentes del sistema de respuesta automática
"""

import subprocess
import sys
import time
import os
import signal
import threading
import json
import logging
from datetime import datetime
from pathlib import Path

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SystemOrchestrator:
    """Orquestador del sistema completo"""

    def __init__(self):
        self.processes = {}
        self.running = False
        self.base_dir = Path(__file__).parent

        # Configuración de componentes
        self.components = {
            'promiscuous_agent': {
                'script': 'promiscuous_agent.py',
                'config': 'enhanced_agent_config.json',
                'description': '📡 Agente de captura promiscua',
                'port': None,
                'required': True,
                'startup_delay': 0
            },
            'ml_detector': {
                'script': 'ml_detector_with_persistence.py',
                'config': None,
                'description': '🤖 Detector ML con persistencia',
                'port': '5559→5560',
                'required': True,
                'startup_delay': 3
            },
            'firewall_agent': {
                'script': 'firewall_agent.py',
                'config': None,
                'description': '🔥 Agente de firewall',
                'port': '5561',
                'required': True,
                'startup_delay': 1
            },
            'dashboard': {
                'script': 'real_zmq_dashboard.py',
                'config': None,
                'description': '📊 Dashboard interactivo',
                'port': '8000',
                'required': True,
                'startup_delay': 2
            },
            'gps_generator': {
                'script': 'generate_gps_traffic.py',
                'config': 'continuous 15',
                'description': '🗺️ Generador de tráfico GPS',
                'port': None,
                'required': False,
                'startup_delay': 5
            }
        }

        # Estado del sistema
        self.system_status = {
            'start_time': None,
            'components_started': 0,
            'components_failed': 0,
            'total_components': len([c for c in self.components.values() if c['required']])
        }

    def check_prerequisites(self):
        """Verificar prerequisitos del sistema"""
        logger.info("🔍 Verificando prerequisitos...")

        issues = []

        # Verificar archivos de script
        for name, component in self.components.items():
            script_path = self.base_dir / component['script']
            if not script_path.exists():
                issues.append(f"Script faltante: {component['script']}")
                logger.error(f"❌ Script faltante: {script_path}")
            else:
                logger.info(f"✅ Script encontrado: {component['script']}")

        # Verificar archivos de configuración
        config_files = ['enhanced_agent_config.json']
        for config_file in config_files:
            config_path = self.base_dir / config_file
            if not config_path.exists():
                issues.append(f"Archivo de configuración faltante: {config_file}")
                logger.warning(f"⚠️ Config faltante: {config_path}")

        # Verificar puertos disponibles
        ports_to_check = [5559, 5560, 5561, 8000]
        for port in ports_to_check:
            if self._is_port_in_use(port):
                issues.append(f"Puerto {port} ya está en uso")
                logger.warning(f"⚠️ Puerto {port} ocupado")

        # Verificar permisos (para firewall)
        if not self._check_firewall_permissions():
            issues.append("Sin permisos para modificar firewall (sudo requerido)")
            logger.warning("⚠️ Sin permisos para firewall")

        if issues:
            logger.error("❌ Problemas encontrados:")
            for issue in issues:
                logger.error(f"   - {issue}")
            return False

        logger.info("✅ Todos los prerequisitos verificados")
        return True

    def _is_port_in_use(self, port):
        """Verificar si un puerto está en uso"""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('localhost', port)) == 0
        except:
            return False

    def _check_firewall_permissions(self):
        """Verificar permisos para modificar firewall"""
        try:
            # Verificar si podemos ejecutar sudo sin contraseña
            result = subprocess.run(['sudo', '-n', 'true'],
                                    capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def start_component(self, name, component):
        """Iniciar un componente específico"""
        try:
            logger.info(f"🚀 Iniciando {component['description']}...")

            # Construir comando
            cmd = [sys.executable, component['script']]
            if component['config']:
                if component['script'] == 'generate_gps_traffic.py':
                    cmd.extend(component['config'].split())
                else:
                    cmd.append(component['config'])

            # Iniciar proceso
            process = subprocess.Popen(
                cmd,
                cwd=self.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.processes[name] = {
                'process': process,
                'component': component,
                'start_time': datetime.now(),
                'status': 'starting'
            }

            # Esperar un poco para verificar que no falle inmediatamente
            time.sleep(1)

            if process.poll() is None:
                self.processes[name]['status'] = 'running'
                self.system_status['components_started'] += 1
                logger.info(f"✅ {component['description']} iniciado")
                return True
            else:
                stdout, stderr = process.communicate()
                logger.error(f"❌ Error iniciando {name}: {stderr}")
                self.system_status['components_failed'] += 1
                return False

        except Exception as e:
            logger.error(f"❌ Excepción iniciando {name}: {e}")
            self.system_status['components_failed'] += 1
            return False

    def start_system(self, include_optional=False):
        """Iniciar todo el sistema"""
        logger.info("🚀 INICIANDO SISTEMA COMPLETO")
        logger.info("=" * 50)

        self.system_status['start_time'] = datetime.now()
        self.running = True

        # Verificar prerequisitos
        if not self.check_prerequisites():
            logger.error("❌ No se puede iniciar el sistema - prerequisitos no cumplidos")
            return False

        # Iniciar componentes en orden
        startup_order = [
            'firewall_agent',  # Primero el agente de firewall
            'promiscuous_agent',  # Luego el agente de captura
            'dashboard',  # Dashboard para visualizar
            'ml_detector',  # ML detector último (necesita los otros)
        ]

        if include_optional:
            startup_order.append('gps_generator')

        for component_name in startup_order:
            if component_name not in self.components:
                continue

            component = self.components[component_name]

            # Aplicar delay de startup
            if component['startup_delay'] > 0:
                logger.info(f"⏰ Esperando {component['startup_delay']}s antes de iniciar {component_name}...")
                time.sleep(component['startup_delay'])

            success = self.start_component(component_name, component)

            if not success and component['required']:
                logger.error(f"❌ Componente crítico {component_name} falló - abortando")
                self.stop_system()
                return False

        # Resumen de inicio
        logger.info("")
        logger.info("📊 RESUMEN DE INICIO:")
        logger.info(f"   ✅ Componentes iniciados: {self.system_status['components_started']}")
        logger.info(f"   ❌ Componentes fallidos: {self.system_status['components_failed']}")
        logger.info(f"   🎯 Componentes requeridos: {self.system_status['total_components']}")

        if self.system_status['components_started'] >= self.system_status['total_components']:
            logger.info("")
            logger.info("🎉 SISTEMA INICIADO EXITOSAMENTE")
            self._print_access_info()
            return True
        else:
            logger.error("❌ No se pudieron iniciar todos los componentes críticos")
            return False

    def _print_access_info(self):
        """Imprimir información de acceso"""
        logger.info("")
        logger.info("🔗 INFORMACIÓN DE ACCESO:")
        logger.info("   📊 Dashboard: http://localhost:8000")
        logger.info("   📡 API Stats: http://localhost:8000/api/stats")
        logger.info("   🔥 Firewall Log: http://localhost:8000/api/firewall/log")
        logger.info("")
        logger.info("🔌 PUERTOS DEL SISTEMA:")
        logger.info("   5559: Eventos capturados → ML Detector")
        logger.info("   5560: Eventos enriquecidos → Dashboard")
        logger.info("   5561: Comandos firewall → Agente")
        logger.info("   8000: Dashboard web")
        logger.info("")
        logger.info("🎯 FUNCIONALIDADES ACTIVAS:")
        logger.info("   ✅ Captura de paquetes en tiempo real")
        logger.info("   ✅ Análisis ML automático")
        logger.info("   ✅ Dashboard interactivo")
        logger.info("   ✅ Respuesta automática a amenazas")
        logger.info("   ✅ Gestión inteligente de firewall")

    def monitor_system(self):
        """Monitorear el estado del sistema"""
        logger.info("👁️ Iniciando monitoreo del sistema...")

        while self.running:
            try:
                time.sleep(10)  # Verificar cada 10 segundos

                dead_processes = []
                for name, proc_info in self.processes.items():
                    process = proc_info['process']

                    if process.poll() is not None:
                        # Proceso ha terminado
                        dead_processes.append(name)
                        stdout, stderr = process.communicate()
                        logger.error(f"💀 Proceso {name} terminó inesperadamente")
                        if stderr:
                            logger.error(f"   Error: {stderr}")

                # Remover procesos muertos
                for name in dead_processes:
                    del self.processes[name]
                    self.system_status['components_failed'] += 1

                # Si perdemos componentes críticos, alertar
                if dead_processes:
                    critical_dead = [name for name in dead_processes
                                     if self.components[name]['required']]
                    if critical_dead:
                        logger.error(f"🚨 Componentes críticos terminaron: {critical_dead}")

            except Exception as e:
                logger.error(f"❌ Error en monitoreo: {e}")

    def stop_system(self):
        """Detener todo el sistema"""
        logger.info("🛑 Deteniendo sistema...")
        self.running = False

        for name, proc_info in self.processes.items():
            try:
                process = proc_info['process']
                logger.info(f"🛑 Deteniendo {name}...")

                # Intentar terminación grácil
                process.terminate()

                # Esperar hasta 5 segundos
                try:
                    process.wait(timeout=5)
                    logger.info(f"✅ {name} detenido gracilmente")
                except subprocess.TimeoutExpired:
                    # Forzar terminación
                    process.kill()
                    logger.warning(f"⚠️ {name} terminado forzosamente")

            except Exception as e:
                logger.error(f"❌ Error deteniendo {name}: {e}")

        self.processes.clear()
        logger.info("✅ Sistema detenido completamente")

    def get_system_status(self):
        """Obtener estado actual del sistema"""
        status = {
            'running': self.running,
            'uptime_seconds': 0,
            'components': {}
        }

        if self.system_status['start_time']:
            status['uptime_seconds'] = (datetime.now() - self.system_status['start_time']).total_seconds()

        for name, proc_info in self.processes.items():
            process = proc_info['process']
            status['components'][name] = {
                'status': 'running' if process.poll() is None else 'dead',
                'pid': process.pid,
                'start_time': proc_info['start_time'].isoformat(),
                'description': proc_info['component']['description']
            }

        return status

    def interactive_menu(self):
        """Menú interactivo para gestionar el sistema"""
        while True:
            print("\n" + "=" * 50)
            print("🛡️ SCADA ML FIREWALL SYSTEM - ORCHESTRATOR")
            print("=" * 50)
            print("1. 🚀 Iniciar sistema completo")
            print("2. 🚀 Iniciar sistema + generador GPS")
            print("3. 📊 Ver estado del sistema")
            print("4. 🛑 Detener sistema")
            print("5. 🔍 Verificar prerequisitos")
            print("6. 📋 Ver logs en tiempo real")
            print("7. ❌ Salir")
            print()

            choice = input("Selecciona una opción: ").strip()

            if choice == '1':
                if not self.running:
                    self.start_system(include_optional=False)
                    if self.running:
                        # Iniciar monitoreo en thread separado
                        monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
                        monitor_thread.start()
                else:
                    print("⚠️ El sistema ya está ejecutándose")

            elif choice == '2':
                if not self.running:
                    self.start_system(include_optional=True)
                    if self.running:
                        monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
                        monitor_thread.start()
                else:
                    print("⚠️ El sistema ya está ejecutándose")

            elif choice == '3':
                status = self.get_system_status()
                print(f"\n📊 Estado del sistema:")
                print(f"   Running: {status['running']}")
                print(f"   Uptime: {status['uptime_seconds']:.1f}s")
                print(f"   Componentes activos: {len(status['components'])}")
                for name, comp_status in status['components'].items():
                    print(f"   - {name}: {comp_status['status']} (PID: {comp_status['pid']})")

            elif choice == '4':
                if self.running:
                    self.stop_system()
                else:
                    print("⚠️ El sistema no está ejecutándose")

            elif choice == '5':
                self.check_prerequisites()

            elif choice == '6':
                print("📋 Logs en tiempo real (Ctrl+C para volver al menú)...")
                try:
                    # Mostrar logs de todos los procesos
                    time.sleep(2)
                    print("💡 Implementar tail de logs aquí...")
                except KeyboardInterrupt:
                    print("\n🔙 Volviendo al menú...")

            elif choice == '7':
                if self.running:
                    print("🛑 Deteniendo sistema antes de salir...")
                    self.stop_system()
                print("👋 ¡Hasta luego!")
                break

            else:
                print("❌ Opción inválida")


def signal_handler(signum, frame):
    """Manejar señales del sistema"""
    logger.info(f"🛑 Señal {signum} recibida, deteniendo sistema...")
    global orchestrator
    if 'orchestrator' in globals() and orchestrator.running:
        orchestrator.stop_system()
    sys.exit(0)


def main():
    """Función principal"""
    global orchestrator

    # Configurar manejo de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🚀 SYSTEM ORCHESTRATOR")
    print("Sistema de Respuesta Automática SCADA + ML + Firewall")
    print("=" * 60)

    orchestrator = SystemOrchestrator()

    if len(sys.argv) > 1:
        # Modo comando
        command = sys.argv[1].lower()

        if command == 'start':
            include_gps = '--with-gps' in sys.argv
            if orchestrator.start_system(include_optional=include_gps):
                # Iniciar monitoreo
                monitor_thread = threading.Thread(target=orchestrator.monitor_system, daemon=True)
                monitor_thread.start()

                # Mantener vivo
                try:
                    while orchestrator.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    orchestrator.stop_system()

        elif command == 'stop':
            print("🛑 Modo stop no implementado (usar kill o Ctrl+C)")

        elif command == 'status':
            status = orchestrator.get_system_status()
            print(json.dumps(status, indent=2))

        elif command == 'check':
            orchestrator.check_prerequisites()

        else:
            print(f"❌ Comando desconocido: {command}")
            print("Comandos disponibles: start, stop, status, check")
    else:
        # Modo interactivo
        try:
            orchestrator.interactive_menu()
        except KeyboardInterrupt:
            print("\n🛑 Interrumpido por usuario")
            if orchestrator.running:
                orchestrator.stop_system()


if __name__ == "__main__":
    main()