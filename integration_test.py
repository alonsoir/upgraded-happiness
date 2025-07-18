#!/usr/bin/env python3
"""
Script de Testing para verificar integración completa PROTOBUF REAL
Simula el flujo completo de datos entre todos los componentes
"""

import zmq
import time
import json
import random
import threading
from datetime import datetime

# Importar protobuf - USAR ESTRUCTURAS REALES
try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2
    from src.protocols.protobuf import firewall_commands_pb2

    PROTOBUF_AVAILABLE = True
    print("✅ Protobuf disponible")
except ImportError:
    try:
        import network_event_extended_fixed_pb2
        import firewall_commands_pb2

        PROTOBUF_AVAILABLE = True
        print("✅ Protobuf disponible (local)")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        print("❌ Protobuf no disponible")


class IntegrationTester:
    """Tester para verificar integración completa usando estructuras protobuf reales"""

    def __init__(self):
        self.context = zmq.Context()
        self.running = False

        # Sockets para testing
        self.ml_detector_input = None  # Puerto 5559
        self.dashboard_listener = None  # Puerto 5560
        self.firewall_listener = None  # Puerto 5561

        # Contadores
        self.events_sent = 0
        self.events_received = 0
        self.commands_received = 0
        self.batches_received = 0

        print("🧪 Integration Tester inicializado (PROTOBUF REAL)")

    def setup_sockets(self):
        """Configura sockets de testing"""
        try:
            # Socket para enviar eventos al ML detector (simula promiscuous_agent)
            self.ml_detector_input = self.context.socket(zmq.PUB)
            self.ml_detector_input.bind("tcp://*:5559")

            # Socket para recibir eventos del dashboard
            self.dashboard_listener = self.context.socket(zmq.SUB)
            self.dashboard_listener.connect("tcp://localhost:5560")
            self.dashboard_listener.setsockopt(zmq.SUBSCRIBE, b"")
            self.dashboard_listener.setsockopt(zmq.RCVTIMEO, 1000)

            # Socket para recibir comandos firewall
            self.firewall_listener = self.context.socket(zmq.PULL)
            self.firewall_listener.bind("tcp://*:5561")
            self.firewall_listener.setsockopt(zmq.RCVTIMEO, 1000)

            time.sleep(1)  # Esperar a que se conecten los sockets
            print("✅ Sockets configurados")

        except Exception as e:
            print(f"❌ Error configurando sockets: {e}")
            return False

        return True

    def create_test_event(self, event_id: str, risk_level: str = "medium", is_handshake: bool = False) -> bytes:
        """Crea un evento de prueba usando estructura protobuf real"""
        if not PROTOBUF_AVAILABLE:
            return b""

        event = network_event_extended_fixed_pb2.NetworkEvent()
        event.event_id = event_id
        event.timestamp = int(time.time() * 1000)
        event.agent_id = "test_agent"
        event.event_type = "network_test"

        # Información del nodo (campos adicionales del protobuf real)
        event.so_identifier = "linux_iptables"
        event.node_hostname = "test-node-01"
        event.os_version = "Ubuntu 22.04"
        event.firewall_status = "active"
        event.agent_version = "1.0.0"
        event.is_initial_handshake = is_handshake

        # Configurar según nivel de riesgo
        if is_handshake:
            # Para handshakes, datos mínimos
            event.source_ip = "10.0.0.1"
            event.target_ip = "10.0.0.2"
            event.dest_port = 0
            event.src_port = 0
            event.packet_size = 64
            event.description = "Initial handshake from test agent"
        elif risk_level == "high":
            event.source_ip = "192.168.1.100"
            event.target_ip = "10.0.0.1"
            event.dest_port = 22  # SSH - puerto sospechoso
            event.src_port = 54321
            event.packet_size = 1500
            event.description = "Test high risk event - SSH connection"
        elif risk_level == "medium":
            event.source_ip = "192.168.1.200"
            event.target_ip = "10.0.0.2"
            event.dest_port = 80
            event.src_port = 12345
            event.packet_size = 800
            event.description = "Test medium risk event - HTTP connection"
        else:  # low
            event.source_ip = "192.168.1.50"
            event.target_ip = "10.0.0.3"
            event.dest_port = 443
            event.src_port = 8080
            event.packet_size = 200
            event.description = "Test low risk event - HTTPS connection"

        return event.SerializeToString()

    def send_test_events(self):
        """Envía eventos de prueba al ML detector"""
        print("📤 Enviando eventos de prueba...")

        # Primero enviar handshake inicial
        handshake_event = self.create_test_event("test_handshake", is_handshake=True)
        if handshake_event:
            self.ml_detector_input.send(handshake_event)
            self.events_sent += 1
            print(f"🤝 Enviado: handshake inicial")
            time.sleep(0.5)

        # Eventos de diferentes niveles de riesgo
        events = [
            ("test_001", "low"),
            ("test_002", "medium"),
            ("test_003", "high"),
            ("test_004", "high"),
            ("test_005", "medium"),
            ("test_006", "low"),
            ("test_007", "high"),
            ("test_008", "medium"),
            ("test_009", "low"),
            ("test_010", "high"),
        ]

        for event_id, risk_level in events:
            event_data = self.create_test_event(event_id, risk_level)
            if event_data:
                self.ml_detector_input.send(event_data)
                self.events_sent += 1
                print(f"📡 Enviado: {event_id} ({risk_level})")
                time.sleep(0.3)  # Espaciar eventos

        print(f"✅ {self.events_sent} eventos enviados")

    def listen_dashboard_events(self):
        """Escucha eventos enriquecidos del dashboard"""
        print("👂 Escuchando eventos del dashboard...")

        while self.running:
            try:
                message = self.dashboard_listener.recv(zmq.NOBLOCK)

                if PROTOBUF_AVAILABLE:
                    try:
                        event = network_event_extended_fixed_pb2.NetworkEvent()
                        event.ParseFromString(message)

                        self.events_received += 1

                        # Mostrar información completa del evento
                        print(f"📊 Recibido: {event.event_id}")
                        print(f"   IP: {event.source_ip} → {event.target_ip}:{event.dest_port}")
                        print(f"   Scores: A={event.anomaly_score:.2f}, R={event.risk_score:.2f}")
                        print(f"   Nodo: {event.node_hostname} ({event.so_identifier})")
                        print(f"   OS: {event.os_version}")
                        print(f"   Firewall: {event.firewall_status}")
                        print(f"   Agent: {event.agent_version}")
                        print(f"   Handshake: {event.is_initial_handshake}")

                        if event.latitude != 0 and event.longitude != 0:
                            print(f"   GPS: {event.latitude:.2f}, {event.longitude:.2f}")
                        else:
                            print("   GPS: No disponible")

                        print(f"   Desc: {event.description}")
                        print("   " + "=" * 50)

                    except Exception as e:
                        print(f"❌ Error parsing evento: {e}")

            except zmq.Again:
                continue
            except Exception as e:
                print(f"❌ Error recibiendo evento: {e}")

    def listen_firewall_commands(self):
        """Escucha comandos de firewall (individuales y batches)"""
        print("🔥 Escuchando comandos de firewall...")

        while self.running:
            try:
                message = self.firewall_listener.recv(zmq.NOBLOCK)

                if PROTOBUF_AVAILABLE:
                    # Intentar parsear como FirewallCommandBatch primero
                    try:
                        batch = firewall_commands_pb2.FirewallCommandBatch()
                        batch.ParseFromString(message)

                        self.batches_received += 1

                        print(f"📦 Lote recibido: {batch.batch_id}")
                        print(f"   Nodo destino: {batch.target_node_id}")
                        print(f"   SO: {batch.so_identifier}")
                        print(f"   Generado por: {batch.generated_by}")
                        print(f"   Descripción: {batch.description}")
                        print(f"   Comandos: {len(batch.commands)}")
                        print(f"   Dry run all: {batch.dry_run_all}")
                        print(f"   Confianza: {batch.confidence_score}")

                        # Mostrar comandos individuales
                        for i, command in enumerate(batch.commands):
                            action_name = firewall_commands_pb2.CommandAction.Name(command.action)
                            priority_name = firewall_commands_pb2.CommandPriority.Name(command.priority)

                            print(f"   [{i + 1}] {command.command_id}")
                            print(f"       Acción: {action_name}")
                            print(f"       Target: {command.target_ip}:{command.target_port}")
                            print(f"       Duración: {command.duration_seconds}s")
                            print(f"       Prioridad: {priority_name}")
                            print(f"       Dry run: {command.dry_run}")
                            print(f"       Razón: {command.reason}")
                            if command.rate_limit_rule:
                                print(f"       Rate limit: {command.rate_limit_rule}")
                            if command.extra_params:
                                print(f"       Extra params: {dict(command.extra_params)}")

                        print("   " + "=" * 50)
                        continue

                    except Exception as e:
                        pass  # No es un batch, intentar comando individual

                    # Intentar parsear como comando individual
                    try:
                        command = firewall_commands_pb2.FirewallCommand()
                        command.ParseFromString(message)

                        self.commands_received += 1

                        action_name = firewall_commands_pb2.CommandAction.Name(command.action)
                        priority_name = firewall_commands_pb2.CommandPriority.Name(command.priority)

                        print(f"🛡️  Comando recibido: {command.command_id}")
                        print(f"   Acción: {action_name}")
                        print(f"   Target: {command.target_ip}:{command.target_port}")
                        print(f"   Duración: {command.duration_seconds}s")
                        print(f"   Razón: {command.reason}")
                        print(f"   Prioridad: {priority_name}")
                        print(f"   Dry run: {command.dry_run}")
                        print("   " + "=" * 50)

                    except Exception as e:
                        print(f"❌ Error parsing comando: {e}")

            except zmq.Again:
                continue
            except Exception as e:
                print(f"❌ Error recibiendo comando: {e}")

    def test_dashboard_api(self):
        """Prueba las APIs del dashboard"""
        print("🌐 Probando APIs del dashboard...")

        import requests

        base_url = "http://localhost:8000"

        apis = [
            "/health",
            "/api/stats",
            "/api/events",
            "/api/events/gps",
            "/api/firewall/log",
            "/api/firewall/pending"
        ]

        results = {}

        for endpoint in apis:
            try:
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    print(f"✅ {endpoint}: OK")
                    results[endpoint] = response.json()
                else:
                    print(f"⚠️  {endpoint}: Status {response.status_code}")
                    results[endpoint] = None
            except Exception as e:
                print(f"❌ {endpoint}: Error - {e}")
                results[endpoint] = None

        # Mostrar estadísticas interesantes
        if results.get("/health"):
            health = results["/health"]
            print(f"   🏥 Estado: {health.get('status')}")
            print(f"   📦 Protobuf: {health.get('protobuf_enabled')}")
            print(f"   🔥 Firewall: {health.get('firewall_enabled')}")
            print(f"   🤝 Handshakes: {health.get('handshakes_received', 0)}")
            print(f"   🖥️  Nodos: {health.get('nodes_registered', 0)}")

        if results.get("/api/stats"):
            stats = results["/api/stats"]
            print(f"   📊 Eventos totales: {stats.get('total_events', 0)}")
            print(f"   🚨 Anomalías: {stats.get('anomaly_events', 0)}")
            print(f"   ⚠️  Alto riesgo: {stats.get('high_risk_events', 0)}")
            print(f"   🌍 Con GPS: {stats.get('events_with_gps', 0)}")

    def simulate_firewall_command(self):
        """Simula envío de comando de firewall desde dashboard"""
        print("🔥 Simulando comando de firewall...")

        import requests

        # Simular comando de bloqueo
        command_data = {
            "event_id": "test_003",
            "target_ip": "192.168.1.100",
            "source_agent": "test_agent",
            "action": "BLOCK_IP",
            "target_port": 22,
            "duration_seconds": 1800,
            "reason": "Test firewall command from integration test",
            "priority": "HIGH",
            "dry_run": True
        }

        try:
            response = requests.post(
                "http://localhost:8000/api/firewall/block",
                json=command_data,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                print(f"✅ Comando enviado: {result.get('command_id', 'N/A')}")
                print(f"   Mensaje: {result.get('message', 'N/A')}")
                if 'batch_id' in result:
                    print(f"   Batch ID: {result['batch_id']}")
            else:
                print(f"❌ Error enviando comando: {response.status_code}")
                print(f"   {response.text}")

        except Exception as e:
            print(f"❌ Error en API call: {e}")

    def run_comprehensive_test(self):
        """Ejecuta test completo"""
        print("\n🧪 INICIANDO TEST DE INTEGRACIÓN COMPLETA (PROTOBUF REAL)")
        print("=" * 70)

        if not PROTOBUF_AVAILABLE:
            print("❌ Protobuf no disponible - no se puede ejecutar test")
            return

        # Configurar sockets
        if not self.setup_sockets():
            return

        self.running = True

        # Iniciar listeners en threads separados
        dashboard_thread = threading.Thread(target=self.listen_dashboard_events, daemon=True)
        firewall_thread = threading.Thread(target=self.listen_firewall_commands, daemon=True)

        dashboard_thread.start()
        firewall_thread.start()

        # Esperar un poco para que los componentes se inicialicen
        print("⏳ Esperando a que los componentes se inicialicen...")
        time.sleep(3)

        # Paso 1: Enviar eventos de prueba
        print("\n🔄 PASO 1: Enviando eventos de prueba (con handshake)")
        self.send_test_events()

        # Paso 2: Esperar a que lleguen eventos enriquecidos
        print("\n🔄 PASO 2: Esperando eventos enriquecidos...")
        time.sleep(8)  # Más tiempo para procesar todos los eventos

        # Paso 3: Probar APIs del dashboard
        print("\n🔄 PASO 3: Probando APIs del dashboard")
        self.test_dashboard_api()

        # Paso 4: Simular comando de firewall
        print("\n🔄 PASO 4: Simulando comando de firewall")
        self.simulate_firewall_command()

        # Paso 5: Esperar comandos de firewall
        print("\n🔄 PASO 5: Esperando comandos de firewall...")
        time.sleep(5)

        # Paso 6: Mostrar resultados
        print("\n📊 RESULTADOS DEL TEST")
        print("=" * 70)
        print(f"📤 Eventos enviados: {self.events_sent}")
        print(f"📥 Eventos recibidos (enriquecidos): {self.events_received}")
        print(f"🛡️  Comandos individuales recibidos: {self.commands_received}")
        print(f"📦 Lotes de comandos recibidos: {self.batches_received}")

        # Evaluación de resultados
        success_rate = (self.events_received / max(self.events_sent, 1)) * 100

        print(f"\n🎯 EVALUACIÓN:")
        print(f"📈 Tasa de éxito eventos: {success_rate:.1f}%")

        if self.events_received > 0:
            print("✅ Flujo ML detector → Dashboard: FUNCIONANDO")
        else:
            print("❌ Flujo ML detector → Dashboard: FALLANDO")

        if self.commands_received > 0 or self.batches_received > 0:
            print("✅ Flujo Dashboard → Firewall: FUNCIONANDO")
        else:
            print("❌ Flujo Dashboard → Firewall: FALLANDO")

        # Verificar protobuf
        if PROTOBUF_AVAILABLE:
            print("✅ Protobuf: DISPONIBLE")
        else:
            print("❌ Protobuf: NO DISPONIBLE")

        print("\n🎯 RECOMENDACIONES:")
        print("1. Verificar que todos los componentes estén corriendo")
        print("2. Revisar logs de protobuf parsing")
        print("3. Confirmar que los puertos no estén ocupados")
        print("4. Validar que todos usen network_event_extended_fixed_pb2")
        print("5. Verificar que firewall_commands_pb2 tenga los enums correctos")
        print("6. Comprobar que el handshake inicial se procese correctamente")

        self.running = False

        print("\n✅ Test completado!")

    def cleanup(self):
        """Limpia recursos"""
        if self.ml_detector_input:
            self.ml_detector_input.close()
        if self.dashboard_listener:
            self.dashboard_listener.close()
        if self.firewall_listener:
            self.firewall_listener.close()
        if self.context:
            self.context.term()


def main():
    """Función principal"""
    print("🧪 INTEGRATION TESTER - SCADA Real PROTOBUF REAL")
    print("=" * 70)
    print("Este script verifica que toda la cadena de comunicación funcione:")
    print("1. Envía eventos de prueba al ML detector (puerto 5559)")
    print("2. Incluye handshake inicial con información del nodo")
    print("3. Escucha eventos enriquecidos del dashboard (puerto 5560)")
    print("4. Prueba APIs del dashboard (puerto 8000)")
    print("5. Simula comandos de firewall (puerto 5561)")
    print("6. Verifica FirewallCommandBatch y comandos individuales")
    print("7. Valida uso de enums en protobuf")
    print("")
    print("REQUISITOS:")
    print("- lightweight_ml_detector.py corriendo")
    print("- real_zmq_dashboard_with_firewall.py corriendo")
    print("- simple_firewall_agent.py corriendo")
    print("- Protobuf instalado y disponible")
    print("- Archivos .proto compilados correctamente")
    print("")
    print("ESTRUCTURAS PROTOBUF REQUERIDAS:")
    print("- network_event_extended_fixed_pb2.NetworkEvent")
    print("- firewall_commands_pb2.FirewallCommand")
    print("- firewall_commands_pb2.FirewallCommandBatch")
    print("- firewall_commands_pb2.CommandAction (enum)")
    print("- firewall_commands_pb2.CommandPriority (enum)")
    print("")

    input("Presiona Enter para continuar...")

    tester = IntegrationTester()

    try:
        tester.run_comprehensive_test()
    except KeyboardInterrupt:
        print("\n🛑 Test interrumpido por usuario")
    except Exception as e:
        print(f"\n❌ Error en test: {e}")
        import traceback
        traceback.print_exc()
    finally:
        tester.cleanup()


if __name__ == "__main__":
    main()