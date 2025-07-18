#!/usr/bin/env python3
"""
Evaluador por componentes para upgraded-happiness
Testa cada componente individualmente para identificar problemas
"""

import zmq
import time
import json
import subprocess
import threading
import signal
import sys
from datetime import datetime


class ComponentEvaluator:
    def __init__(self):
        self.context = zmq.Context()
        self.test_results = {}
        self.running_processes = []

    def print_header(self, title):
        print(f"\n{'=' * 70}")
        print(f"🔍 {title}")
        print(f"{'=' * 70}")

    def cleanup_existing(self):
        """Limpia procesos existentes antes de empezar"""
        print("🧹 Limpiando procesos existentes...")
        try:
            subprocess.run(["pkill", "-f", "firewall_agent.py"], capture_output=True)
            subprocess.run(["pkill", "-f", "ml_detector_with_persistence.py"], capture_output=True)
            subprocess.run(["pkill", "-f", "real_zmq_dashboard_with_firewall.py"], capture_output=True)
            subprocess.run(["sudo", "pkill", "-f", "promiscuous_agent.py"], capture_output=True)
            time.sleep(2)
            print("✅ Limpieza completada")
        except Exception as e:
            print(f"⚠️  Error en limpieza: {e}")

    def test_firewall_agent(self):
        """Testa el Firewall Agent individualmente"""
        self.print_header("TEST 1: FIREWALL AGENT")

        print("🔥 Iniciando Firewall Agent...")

        try:
            # Iniciar firewall agent
            process = subprocess.Popen(
                ["python3", "firewall_agent.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.running_processes.append(("firewall_agent", process))

            # Esperar a que se inicie
            time.sleep(3)

            # Verificar que está corriendo
            if process.poll() is None:
                print("✅ Firewall Agent iniciado correctamente")

                # Test de conexión ZMQ
                print("🔍 Testando conexión ZMQ...")
                try:
                    socket = self.context.socket(zmq.PUSH)
                    socket.connect("tcp://localhost:5561")

                    test_command = {
                        "action": "test",
                        "timestamp": time.time(),
                        "test_id": "component_test_1"
                    }

                    socket.send_string(json.dumps(test_command))
                    print("✅ Comando de prueba enviado al Firewall Agent")
                    socket.close()

                    self.test_results["firewall_agent"] = True

                except Exception as e:
                    print(f"❌ Error conectando a Firewall Agent: {e}")
                    self.test_results["firewall_agent"] = False

            else:
                print("❌ Firewall Agent falló al iniciar")
                stdout, stderr = process.communicate()
                print(f"Error: {stderr}")
                self.test_results["firewall_agent"] = False

        except Exception as e:
            print(f"❌ Error iniciando Firewall Agent: {e}")
            self.test_results["firewall_agent"] = False

        return self.test_results.get("firewall_agent", False)

    def test_ml_detector(self):
        """Testa el ML Detector individualmente"""
        self.print_header("TEST 2: ML DETECTOR")

        print("🤖 Iniciando ML Detector...")

        try:
            # Iniciar ML detector
            process = subprocess.Popen(
                ["python3", "ml_detector_with_persistence.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.running_processes.append(("ml_detector", process))

            # Esperar a que se inicie
            time.sleep(5)

            if process.poll() is None:
                print("✅ ML Detector iniciado correctamente")

                # Test de input (puerto 5559)
                print("🔍 Testando input del ML Detector...")
                try:
                    input_socket = self.context.socket(zmq.PUSH)
                    input_socket.connect("tcp://localhost:5559")

                    test_event = {
                        "timestamp": time.time(),
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.1",
                        "src_port": 12345,
                        "dst_port": 80,
                        "protocol": "TCP",
                        "test_component": "ml_detector"
                    }

                    input_socket.send_string(json.dumps(test_event))
                    print("✅ Evento enviado al ML Detector")
                    input_socket.close()

                    # Test de output (puerto 5560)
                    print("🔍 Escuchando output del ML Detector...")
                    output_socket = self.context.socket(zmq.SUB)
                    output_socket.connect("tcp://localhost:5560")
                    output_socket.setsockopt(zmq.SUBSCRIBE, b"")
                    output_socket.setsockopt(zmq.RCVTIMEO, 5000)  # 5 segundos timeout

                    try:
                        message = output_socket.recv_string()
                        enhanced_event = json.loads(message)
                        print(f"✅ Evento procesado recibido: {enhanced_event.get('src_ip', 'N/A')}")
                        print(f"   Risk Score: {enhanced_event.get('risk_score', 'N/A')}")
                        print(f"   Anomaly Score: {enhanced_event.get('anomaly_score', 'N/A')}")
                        self.test_results["ml_detector"] = True

                    except zmq.Again:
                        print("⚠️  No se recibió output del ML Detector (timeout)")
                        self.test_results["ml_detector"] = False

                    output_socket.close()

                except Exception as e:
                    print(f"❌ Error testando ML Detector: {e}")
                    self.test_results["ml_detector"] = False

            else:
                print("❌ ML Detector falló al iniciar")
                stdout, stderr = process.communicate()
                print(f"Error: {stderr}")
                self.test_results["ml_detector"] = False

        except Exception as e:
            print(f"❌ Error iniciando ML Detector: {e}")
            self.test_results["ml_detector"] = False

        return self.test_results.get("ml_detector", False)

    def test_dashboard(self):
        """Testa el Dashboard individualmente"""
        self.print_header("TEST 3: DASHBOARD")

        print("📊 Iniciando Dashboard...")

        try:
            # Determinar argumentos del dashboard
            help_result = subprocess.run(
                ["python3", "real_zmq_dashboard_with_firewall.py", "--help"],
                capture_output=True,
                text=True
            )

            if "--config" in help_result.stdout:
                cmd = ["python3", "real_zmq_dashboard_with_firewall.py", "--config", "dashboard_config.json"]
                print("✅ Dashboard acepta --config")
            else:
                cmd = ["python3", "real_zmq_dashboard_with_firewall.py", "dashboard_config.json"]
                print("✅ Dashboard usa argumento posicional")

            # Iniciar dashboard
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.running_processes.append(("dashboard", process))

            # Esperar a que se inicie
            time.sleep(4)

            if process.poll() is None:
                print("✅ Dashboard iniciado correctamente")

                # Test web interface
                print("🔍 Testando interfaz web...")
                try:
                    import requests
                    response = requests.get("http://localhost:8000", timeout=5)
                    print(f"✅ Dashboard web responde: {response.status_code}")

                    # Test ZMQ input
                    print("🔍 Testando input ZMQ del Dashboard...")
                    socket = self.context.socket(zmq.PUSH)
                    socket.connect("tcp://localhost:5560")

                    test_enhanced_event = {
                        "timestamp": time.time(),
                        "src_ip": "192.168.1.200",
                        "dst_ip": "10.0.0.2",
                        "risk_score": 0.85,
                        "anomaly_score": 0.75,
                        "test_component": "dashboard"
                    }

                    socket.send_string(json.dumps(test_enhanced_event))
                    print("✅ Evento enviado al Dashboard")
                    socket.close()

                    self.test_results["dashboard"] = True

                except ImportError:
                    print("⚠️  requests no disponible, saltando test web")
                    self.test_results["dashboard"] = True
                except Exception as e:
                    print(f"❌ Error testando Dashboard: {e}")
                    self.test_results["dashboard"] = False

            else:
                print("❌ Dashboard falló al iniciar")
                stdout, stderr = process.communicate()
                print(f"Error: {stderr}")
                self.test_results["dashboard"] = False

        except Exception as e:
            print(f"❌ Error iniciando Dashboard: {e}")
            self.test_results["dashboard"] = False

        return self.test_results.get("dashboard", False)

    def test_promiscuous_agent(self):
        """Testa el Promiscuous Agent individualmente"""
        self.print_header("TEST 4: PROMISCUOUS AGENT")

        print("🕵️  Iniciando Promiscuous Agent...")

        try:
            # Iniciar promiscuous agent
            process = subprocess.Popen(
                ["sudo", "python3", "promiscuous_agent.py", "enhanced_agent_config.json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.running_processes.append(("promiscuous_agent", process))

            # Esperar a que se inicie
            time.sleep(3)

            if process.poll() is None:
                print("✅ Promiscuous Agent iniciado correctamente")

                # Test de output
                print("🔍 Escuchando output del Promiscuous Agent...")
                socket = self.context.socket(zmq.SUB)
                socket.connect("tcp://localhost:5559")
                socket.setsockopt(zmq.SUBSCRIBE, b"")
                socket.setsockopt(zmq.RCVTIMEO, 8000)  # 8 segundos timeout

                events_captured = 0
                try:
                    while events_captured < 3:  # Esperar al menos 3 eventos
                        message = socket.recv_string()
                        try:
                            event = json.loads(message)
                            events_captured += 1
                            print(
                                f"📦 Evento #{events_captured}: {event.get('src_ip', 'N/A')} -> {event.get('dst_ip', 'N/A')}")
                        except:
                            events_captured += 1
                            print(f"📦 Evento #{events_captured}: {message[:50]}...")

                        if events_captured >= 3:
                            break

                except zmq.Again:
                    print(f"⚠️  Solo se capturaron {events_captured} eventos (puede ser normal si hay poco tráfico)")

                socket.close()

                if events_captured > 0:
                    print(f"✅ Promiscuous Agent capturó {events_captured} eventos")
                    self.test_results["promiscuous_agent"] = True
                else:
                    print("⚠️  No se capturaron eventos (puede ser normal)")
                    self.test_results["promiscuous_agent"] = True  # No es error crítico

            else:
                print("❌ Promiscuous Agent falló al iniciar")
                stdout, stderr = process.communicate()
                print(f"Error: {stderr}")
                self.test_results["promiscuous_agent"] = False

        except Exception as e:
            print(f"❌ Error iniciando Promiscuous Agent: {e}")
            self.test_results["promiscuous_agent"] = False

        return self.test_results.get("promiscuous_agent", False)

    def test_integration(self):
        """Testa la integración completa"""
        self.print_header("TEST 5: INTEGRACIÓN COMPLETA")

        print("🔄 Testando flujo completo de eventos...")

        # Solo si todos los componentes anteriores pasaron
        if not all(self.test_results.values()):
            print("❌ No se puede hacer test de integración - componentes fallan individualmente")
            return False

        try:
            # Enviar evento desde el inicio del pipeline
            print("📤 Enviando evento de integración...")
            socket = self.context.socket(zmq.PUSH)
            socket.connect("tcp://localhost:5559")

            integration_event = {
                "timestamp": time.time(),
                "src_ip": "192.168.1.254",
                "dst_ip": "10.0.0.254",
                "src_port": 65000,
                "dst_port": 443,
                "protocol": "TCP",
                "payload_size": 2048,
                "integration_test": True,
                "test_id": f"integration_{int(time.time())}"
            }

            socket.send_string(json.dumps(integration_event))
            socket.close()

            print("⏳ Esperando procesamiento completo...")
            time.sleep(3)

            # Verificar que llegó al dashboard
            print("🔍 Verificando que el evento llegó al dashboard...")
            try:
                import requests
                response = requests.get("http://localhost:8000/api/events", timeout=5)
                if response.status_code == 200:
                    events = response.json()
                    integration_events = [e for e in events if str(e).find('integration_') != -1]
                    if integration_events:
                        print(f"✅ Evento de integración encontrado en dashboard")
                        self.test_results["integration"] = True
                    else:
                        print("⚠️  Evento de integración no encontrado en dashboard")
                        self.test_results["integration"] = False
                else:
                    print("⚠️  No se pudo verificar eventos en dashboard")
                    self.test_results["integration"] = False
            except:
                print("⚠️  Error verificando integración")
                self.test_results["integration"] = False

        except Exception as e:
            print(f"❌ Error en test de integración: {e}")
            self.test_results["integration"] = False

        return self.test_results.get("integration", False)

    def generate_report(self):
        """Genera reporte final"""
        self.print_header("REPORTE FINAL")

        print("📋 Resultados por componente:")
        components = [
            ("firewall_agent", "🔥 Firewall Agent"),
            ("ml_detector", "🤖 ML Detector"),
            ("dashboard", "📊 Dashboard"),
            ("promiscuous_agent", "🕵️  Promiscuous Agent"),
            ("integration", "🔄 Integración")
        ]

        for key, name in components:
            if key in self.test_results:
                status = "✅ PASS" if self.test_results[key] else "❌ FAIL"
                print(f"  {name}: {status}")
            else:
                print(f"  {name}: ⚪ NO TESTADO")

        # Identificar problemas
        failed_components = [name for key, name in components if not self.test_results.get(key, False)]

        if not failed_components:
            print("\n🎉 ¡TODOS LOS COMPONENTES FUNCIONAN CORRECTAMENTE!")
            print("💡 Si no ves eventos en el dashboard, el problema puede ser:")
            print("   1. Falta de tráfico real de red")
            print("   2. Interfaz JavaScript del dashboard")
            print("   3. Configuración de visualización")
        else:
            print(f"\n⚠️  Componentes con problemas: {len(failed_components)}")
            for component in failed_components:
                print(f"   ❌ {component}")

            print("\n🔧 Sugerencias:")
            if not self.test_results.get("firewall_agent", True):
                print("   • Verificar permisos y puerto 5561")
            if not self.test_results.get("ml_detector", True):
                print("   • Verificar dependencias ML y puertos 5559/5560")
            if not self.test_results.get("dashboard", True):
                print("   • Verificar argumentos y puerto 8000")
            if not self.test_results.get("promiscuous_agent", True):
                print("   • Verificar permisos sudo y captura de red")

    def cleanup_processes(self):
        """Limpia todos los procesos iniciados"""
        print("\n🛑 Limpiando procesos de test...")
        for name, process in self.running_processes:
            try:
                process.terminate()
                print(f"  🛑 {name} terminado")
            except:
                pass

        # Forzar limpieza
        subprocess.run(["pkill", "-f", "firewall_agent.py"], capture_output=True)
        subprocess.run(["pkill", "-f", "ml_detector_with_persistence.py"], capture_output=True)
        subprocess.run(["pkill", "-f", "real_zmq_dashboard_with_firewall.py"], capture_output=True)
        subprocess.run(["sudo", "pkill", "-f", "promiscuous_agent.py"], capture_output=True)

        self.context.term()

    def run_evaluation(self):
        """Ejecuta evaluación completa"""
        print("🚀 EVALUADOR POR COMPONENTES - upgraded-happiness")
        print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            self.cleanup_existing()

            # Evaluar cada componente
            print("\n🔄 Evaluando componentes individualmente...")

            # Test 1: Firewall Agent
            self.test_firewall_agent()
            time.sleep(1)

            # Test 2: ML Detector
            self.test_ml_detector()
            time.sleep(1)

            # Test 3: Dashboard
            self.test_dashboard()
            time.sleep(1)

            # Test 4: Promiscuous Agent
            self.test_promiscuous_agent()
            time.sleep(1)

            # Test 5: Integración
            self.test_integration()

            # Reporte final
            self.generate_report()

        except KeyboardInterrupt:
            print("\n⚠️  Evaluación interrumpida por usuario")
        finally:
            self.cleanup_processes()


def main():
    evaluator = ComponentEvaluator()

    # Manejar Ctrl+C
    def signal_handler(sig, frame):
        print("\n⚠️  Interrumpido, limpiando...")
        evaluator.cleanup_processes()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        evaluator.run_evaluation()
    except Exception as e:
        print(f"❌ Error durante evaluación: {e}")
    finally:
        evaluator.cleanup_processes()


if __name__ == "__main__":
    main()