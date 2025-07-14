#!/usr/bin/env python3
"""
Script de diagnóstico para upgraded-happiness
Detecta y soluciona problemas comunes de ZMQ y conectividad
"""

import zmq
import time
import json
import subprocess
import psutil
import sys
import socket
from datetime import datetime


class SystemDiagnostic:
    def __init__(self):
        self.context = zmq.Context()
        self.ports = {
            5559: "ML Detector (recv)",
            5560: "Dashboard (recv)",
            5561: "Firewall Agent (recv)",
            5562: "Firewall Commands",
            8000: "Dashboard Web"
        }

    def print_header(self, title):
        print(f"\n{'=' * 60}")
        print(f"🔍 {title}")
        print(f"{'=' * 60}")

    def check_port_availability(self, port):
        """Verifica si un puerto está disponible"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex(('localhost', port))
                return result == 0
        except:
            return False

    def check_processes(self):
        """Verifica qué procesos del sistema están corriendo"""
        self.print_header("VERIFICACIÓN DE PROCESOS")

        target_processes = [
            "firewall_agent",
            "ml_detector",
            "promiscuous_agent",
            "dashboard",
            "real_zmq_dashboard"
        ]

        running_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                for target in target_processes:
                    if target in cmdline.lower():
                        running_processes.append({
                            'name': target,
                            'pid': proc.info['pid'],
                            'cmdline': cmdline
                        })
                        print(f"✅ {target}: PID {proc.info['pid']}")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not running_processes:
            print("❌ No se encontraron procesos del sistema")
            print("💡 Ejecuta: make run-firewall")

        return running_processes

    def check_ports(self):
        """Verifica estado de los puertos"""
        self.print_header("VERIFICACIÓN DE PUERTOS")

        for port, description in self.ports.items():
            is_open = self.check_port_availability(port)
            status = "✅ ACTIVO" if is_open else "❌ CERRADO"
            print(f"Puerto {port} ({description}): {status}")

        return all(self.check_port_availability(p) for p in [5559, 5560, 8000])

    def test_zmq_connections(self):
        """Testa las conexiones ZMQ"""
        self.print_header("TEST DE CONEXIONES ZMQ")

        tests = [
            (5559, zmq.PUSH, "ML Detector"),
            (5560, zmq.PUSH, "Dashboard"),
            (5561, zmq.PUSH, "Firewall Agent")
        ]

        results = []

        for port, socket_type, name in tests:
            try:
                socket = self.context.socket(socket_type)
                socket.setsockopt(zmq.LINGER, 0)
                socket.connect(f"tcp://localhost:{port}")

                # Test con mensaje pequeño
                test_msg = json.dumps({
                    "test": True,
                    "timestamp": time.time(),
                    "diagnostic": name
                })

                socket.send_string(test_msg, zmq.NOBLOCK)
                print(f"✅ {name} (puerto {port}): Conexión exitosa")
                results.append(True)
                socket.close()

            except zmq.Again:
                print(f"⚠️  {name} (puerto {port}): Conectado pero cola llena")
                results.append(True)
                socket.close()
            except Exception as e:
                print(f"❌ {name} (puerto {port}): Error - {e}")
                results.append(False)
                try:
                    socket.close()
                except:
                    pass

        return all(results)

    def test_event_flow(self):
        """Testa el flujo completo de eventos"""
        self.print_header("TEST DE FLUJO DE EVENTOS")

        try:
            # Simular evento desde promiscuous agent
            agent_socket = self.context.socket(zmq.PUSH)
            agent_socket.connect("tcp://localhost:5559")

            test_event = {
                "timestamp": time.time(),
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": "TCP",
                "payload_size": 1024,
                "test_event": True,
                "diagnostic_id": f"test_{int(time.time())}"
            }

            print(f"📤 Enviando evento de prueba al ML Detector...")
            agent_socket.send_string(json.dumps(test_event))
            print(f"✅ Evento enviado: {test_event['diagnostic_id']}")

            agent_socket.close()

            # Dar tiempo para procesamiento
            time.sleep(2)

            print("💡 Verifica en el dashboard si apareció el evento de prueba")
            return True

        except Exception as e:
            print(f"❌ Error en flujo de eventos: {e}")
            return False

    def check_logs(self):
        """Verifica logs por errores comunes"""
        self.print_header("VERIFICACIÓN DE LOGS")

        log_files = [
            "logs/agent.out",
            "logs/ml.out",
            "logs/firewall_agent.out",
            "logs/firewall_dashboard.out"
        ]

        error_patterns = [
            "zmq.error.Again",
            "Resource temporarily unavailable",
            "Connection refused",
            "unrecognized arguments",
            "ERROR",
            "Exception"
        ]

        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    content = f.read()

                print(f"\n📄 {log_file}:")

                for pattern in error_patterns:
                    if pattern in content:
                        lines = content.split('\n')
                        error_lines = [line for line in lines if pattern in line]
                        print(f"  ⚠️  {pattern}: {len(error_lines)} ocurrencias")
                        if error_lines:
                            print(f"     Último: {error_lines[-1][:100]}...")

            except FileNotFoundError:
                print(f"  ❌ {log_file}: No encontrado")
            except Exception as e:
                print(f"  ❌ {log_file}: Error - {e}")

    def suggest_fixes(self):
        """Sugiere soluciones basadas en diagnóstico"""
        self.print_header("SOLUCIONES SUGERIDAS")

        processes = self.check_processes()
        ports_ok = self.check_ports()

        if not processes:
            print("🔧 SOLUCIÓN 1: Iniciar el sistema")
            print("   make emergency-stop")
            print("   make run-firewall")

        elif not ports_ok:
            print("🔧 SOLUCIÓN 2: Reiniciar componentes")
            print("   make emergency-stop")
            print("   sleep 3")
            print("   make run-firewall")

        else:
            print("🔧 SOLUCIÓN 3: Verificar orden de inicio")
            print("   1. Parar todo: make emergency-stop")
            print("   2. Firewall Agent primero: python firewall_agent.py")
            print("   3. ML Detector: python ml_detector_with_persistence.py")
            print("   4. Dashboard: python real_zmq_dashboard_with_firewall.py")
            print("   5. Promiscuous Agent: sudo python promiscuous_agent.py enhanced_agent_config.json")

        print("\n🔧 SOLUCIÓN 4: Fix del dashboard")
        print("   Si hay error 'unrecognized arguments':")
        print("   python real_zmq_dashboard_with_firewall.py --config dashboard_config.json")
        print("   O sin --config:")
        print("   python real_zmq_dashboard_with_firewall.py dashboard_config.json")

    def run_full_diagnostic(self):
        """Ejecuta diagnóstico completo"""
        print(f"🚀 DIAGNÓSTICO UPGRADED-HAPPINESS")
        print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Verificaciones
        self.check_processes()
        self.check_ports()
        self.test_zmq_connections()
        self.test_event_flow()
        self.check_logs()
        self.suggest_fixes()

        print(f"\n{'=' * 60}")
        print("✅ Diagnóstico completado")
        print("🌐 Dashboard: http://localhost:8000")
        print("📊 Monitor: make monitor")
        print(f"{'=' * 60}")

    def cleanup(self):
        """Limpia recursos"""
        self.context.term()


def main():
    diagnostic = SystemDiagnostic()
    try:
        diagnostic.run_full_diagnostic()
    finally:
        diagnostic.cleanup()


if __name__ == "__main__":
    main()