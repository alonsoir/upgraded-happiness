#!/usr/bin/env python3
"""
Test de Integración para Upgraded-Happiness
Simula eventos y prueba el flujo completo del sistema.
"""

import zmq
import json
import time
import uuid
import threading
import logging
from typing import Dict, List
from simple_system_detection import SimpleSystemDetector

logger = logging.getLogger(__name__)


class IntegrationTester:
    """Simulador de eventos para testing del sistema completo"""

    def __init__(self):
        self.context = zmq.Context()
        self.detector = SimpleSystemDetector()
        self.events_sent = 0

        # Sockets para enviar eventos
        self.event_socket = self.context.socket(zmq.PUSH)
        self.event_socket.connect("tcp://localhost:5560")  # Al analyzer

        print("🧪 Integration Tester Initialized")
        print(f"🆔 Test Node ID: {self.detector.node_id}")

    def send_handshake(self):
        """Envía handshake simulado"""
        system_info = self.detector.get_system_summary()

        handshake_event = {
            'event_id': str(uuid.uuid4()),
            'timestamp': int(time.time() * 1000),
            'source_ip': '127.0.0.1',
            'target_ip': '127.0.0.1',
            'packet_size': 0,
            'dest_port': 0,
            'src_port': 0,
            'agent_id': self.detector.node_id,
            'anomaly_score': 0.0,
            'latitude': 37.3891,  # Sevilla
            'longitude': -5.9845,
            'event_type': 'AGENT_HANDSHAKE',
            'risk_score': 0.0,
            'description': f'Test handshake from {system_info["hostname"]}',
            'is_handshake': True,
            'node_id': self.detector.node_id,
            'protocol': 'HANDSHAKE',
            'interface_name': 'test',
            'system_info': {
                'hostname': system_info['hostname'],
                'os_name': system_info['os_name'],
                'os_version': system_info['os_version'],
                'os_family': system_info['os_family'],
                'architecture': system_info['architecture'],
                'firewall_type': system_info['firewall_type'],
                'firewall_version': system_info['firewall_version'],
                'firewall_status': system_info['firewall_status'],
                'agent_version': system_info['agent_version'],
                'interfaces': system_info['interfaces']
            },
            'metadata': {}
        }

        self.event_socket.send_string(json.dumps(handshake_event))
        self.events_sent += 1

        print(f"📤 Handshake sent for node {self.detector.node_id}")

    def create_test_event(self, source_ip: str, dest_port: int,
                          anomaly_score: float = 0.0, event_type: str = "NETWORK_TRAFFIC") -> Dict:
        """Crea un evento de test"""
        return {
            'event_id': str(uuid.uuid4()),
            'timestamp': int(time.time() * 1000),
            'source_ip': source_ip,
            'target_ip': '192.168.1.10',  # Target SCADA
            'packet_size': 64,
            'dest_port': dest_port,
            'src_port': 12345 + (dest_port % 1000),
            'agent_id': self.detector.node_id,
            'anomaly_score': anomaly_score,
            'latitude': 37.3891,
            'longitude': -5.9845,
            'event_type': event_type,
            'risk_score': anomaly_score * 0.8,
            'description': f'Test event from {source_ip} to port {dest_port}',
            'is_handshake': False,
            'node_id': self.detector.node_id,
            'protocol': 'TCP',
            'interface_name': 'eth0',
            'metadata': {
                'test_scenario': 'integration_test',
                'generated_by': 'test_script'
            }
        }

    def send_event(self, event: Dict):
        """Envía un evento al sistema"""
        self.event_socket.send_string(json.dumps(event))
        self.events_sent += 1

    def test_scenario_normal_traffic(self):
        """Test: Tráfico normal (no debería generar alertas)"""
        print("\n🟢 Testing Normal Traffic...")

        events = [
            self.create_test_event('192.168.1.100', 80, 0.1, 'HTTP_REQUEST'),
            self.create_test_event('192.168.1.101', 443, 0.15, 'HTTPS_REQUEST'),
            self.create_test_event('192.168.1.102', 22, 0.2, 'SSH_CONNECTION'),
        ]

        for event in events:
            self.send_event(event)
            time.sleep(0.5)

        print(f"   ✅ Sent {len(events)} normal traffic events")

    def test_scenario_high_anomaly(self):
        """Test: Evento con anomalía crítica"""
        print("\n🔴 Testing High Anomaly Event...")

        event = self.create_test_event(
            source_ip='10.0.0.100',
            dest_port=502,  # Modbus
            anomaly_score=0.95,
            event_type='SUSPICIOUS_MODBUS_ACCESS'
        )

        self.send_event(event)
        print("   🚨 Sent critical anomaly event (score: 0.95)")

    def test_scenario_port_scanning(self):
        """Test: Simulación de port scanning"""
        print("\n🔍 Testing Port Scanning...")

        scanner_ip = '203.0.113.50'
        sensitive_ports = [22, 23, 80, 443, 502, 1911, 2222, 4840, 20000]

        for i, port in enumerate(sensitive_ports):
            event = self.create_test_event(
                source_ip=scanner_ip,
                dest_port=port,
                anomaly_score=0.3 + (i * 0.05),  # Anomalía creciente
                event_type='PORT_SCAN_ATTEMPT'
            )

            self.send_event(event)
            time.sleep(0.2)  # Escaneo rápido

        print(f"   🔍 Sent port scanning sequence from {scanner_ip}")

    def test_scenario_rate_limiting(self):
        """Test: Exceso de conexiones (rate limiting)"""
        print("\n⏰ Testing Rate Limiting...")

        attacker_ip = '172.16.0.200'

        # Enviar 60 conexiones rápidas (excede threshold de 50)
        for i in range(60):
            event = self.create_test_event(
                source_ip=attacker_ip,
                dest_port=80,
                anomaly_score=0.2,
                event_type='HTTP_FLOOD'
            )

            self.send_event(event)
            time.sleep(0.05)  # Muy rápido

        print(f"   ⚡ Sent 60 rapid connections from {attacker_ip}")

    def test_scenario_sensitive_ports(self):
        """Test: Acceso a puertos sensibles SCADA"""
        print("\n🛡️ Testing Sensitive Port Access...")

        external_ip = '198.51.100.75'
        scada_ports = [
            (502, 'Modbus TCP'),
            (1911, 'Niagara Fox'),
            (4840, 'OPC UA'),
            (20000, 'DNP3')
        ]

        for port, protocol in scada_ports:
            event = self.create_test_event(
                source_ip=external_ip,
                dest_port=port,
                anomaly_score=0.4,
                event_type=f'EXTERNAL_{protocol.upper()}_ACCESS'
            )

            self.send_event(event)
            time.sleep(1)  # Acceso deliberado

        print("   🏭 Sent SCADA protocol access attempts from external IP")

    def test_scenario_mixed_attack(self):
        """Test: Ataque combinado (múltiples técnicas)"""
        print("\n💥 Testing Mixed Attack Scenario...")

        attacker_ip = '198.51.100.123'  # IP claramente maliciosa

        # 1. Reconocimiento inicial
        recon_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        for port in recon_ports:
            event = self.create_test_event(
                source_ip=attacker_ip,
                dest_port=port,
                anomaly_score=0.3,
                event_type='RECONNAISSANCE'
            )
            self.send_event(event)
            time.sleep(0.1)

        time.sleep(2)

        # 2. Ataque a SCADA específico
        event = self.create_test_event(
            source_ip=attacker_ip,
            dest_port=502,
            anomaly_score=0.85,
            event_type='MODBUS_ATTACK'
        )
        self.send_event(event)

        time.sleep(1)

        # 3. Intento de fuerza bruta SSH
        for i in range(25):
            event = self.create_test_event(
                source_ip=attacker_ip,
                dest_port=22,
                anomaly_score=0.6 + (i * 0.01),
                event_type='SSH_BRUTE_FORCE'
            )
            self.send_event(event)
            time.sleep(0.1)

        print(f"   💀 Sent sophisticated attack sequence from {attacker_ip}")

    def run_interactive_test(self):
        """Modo interactivo para testing"""
        print("\n🎮 Interactive Test Mode")
        print("Commands: 'handshake', 'normal', 'anomaly', 'portscan', 'rate', 'scada', 'mixed', 'stats', 'quit'")

        while True:
            try:
                command = input("\ntest> ").strip().lower()

                if command == 'quit' or command == 'exit':
                    break
                elif command == 'handshake':
                    self.send_handshake()
                elif command == 'normal':
                    self.test_scenario_normal_traffic()
                elif command == 'anomaly':
                    self.test_scenario_high_anomaly()
                elif command == 'portscan':
                    self.test_scenario_port_scanning()
                elif command == 'rate':
                    self.test_scenario_rate_limiting()
                elif command == 'scada':
                    self.test_scenario_sensitive_ports()
                elif command == 'mixed':
                    self.test_scenario_mixed_attack()
                elif command == 'stats':
                    print(f"📊 Events sent: {self.events_sent}")
                elif command == 'help':
                    print("Available scenarios:")
                    print("  handshake - Send node handshake")
                    print("  normal    - Normal traffic")
                    print("  anomaly   - High anomaly event")
                    print("  portscan  - Port scanning attack")
                    print("  rate      - Rate limiting test")
                    print("  scada     - SCADA port access")
                    print("  mixed     - Complex attack")
                    print("  stats     - Show statistics")
                elif command:
                    print(f"Unknown command: {command}. Type 'help' for options.")

            except EOFError:
                break
            except KeyboardInterrupt:
                break

    def run_automated_test(self):
        """Ejecuta todos los tests automáticamente"""
        print("\n🤖 Running Automated Test Suite")
        print("=" * 50)

        # 1. Handshake inicial
        print("\n1️⃣ Sending initial handshake...")
        self.send_handshake()
        time.sleep(2)

        # 2. Tráfico normal
        self.test_scenario_normal_traffic()
        time.sleep(3)

        # 3. Anomalía crítica
        self.test_scenario_high_anomaly()
        time.sleep(3)

        # 4. Port scanning
        self.test_scenario_port_scanning()
        time.sleep(5)

        # 5. Rate limiting
        self.test_scenario_rate_limiting()
        time.sleep(5)

        # 6. Puertos sensibles
        self.test_scenario_sensitive_ports()
        time.sleep(3)

        # 7. Ataque mixto
        self.test_scenario_mixed_attack()
        time.sleep(3)

        print("\n✅ Automated test suite completed!")
        print(f"📊 Total events sent: {self.events_sent}")
        print("\n💡 Check the Event Analyzer output for recommendations")

    def cleanup(self):
        """Limpia recursos"""
        self.event_socket.close()
        self.context.term()


def check_services():
    """Verifica que los servicios necesarios estén corriendo"""
    import socket

    services = {
        5560: "Event Analyzer (input)",
        5561: "Firewall Agent"
    }

    print("🔍 Checking required services...")

    all_good = True
    for port, service in services.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()

        if result == 0:
            print(f"   ✅ {service} (port {port}) - Running")
        else:
            print(f"   ❌ {service} (port {port}) - Not available")
            all_good = False

    if not all_good:
        print("\n⚠️  Some services are not running. Please start them first:")
        print("   Terminal 1: python simple_firewall_agent.py")
        print("   Terminal 2: python event_analyzer.py")
        return False

    return True


def main():
    """Función principal"""
    import argparse

    # Configurar logging
    logging.basicConfig(
        level=logging.WARNING,  # Solo warnings/errors para output limpio
        format='%(levelname)s: %(message)s'
    )

    # Argumentos
    parser = argparse.ArgumentParser(description='Integration Tester for Upgraded-Happiness')
    parser.add_argument('--auto', action='store_true', help='Run automated test suite')
    parser.add_argument('--check', action='store_true', help='Only check services')

    args = parser.parse_args()

    print("🧪 Upgraded-Happiness Integration Tester")
    print("=" * 45)

    # Verificar servicios
    if not check_services():
        if not args.check:
            print("\n❌ Cannot proceed with tests")
        return

    if args.check:
        print("\n✅ All services are running")
        return

    # Crear tester
    tester = IntegrationTester()

    try:
        if args.auto:
            tester.run_automated_test()
        else:
            tester.run_interactive_test()
    except KeyboardInterrupt:
        print("\n\n👋 Test session ended")
    finally:
        print(f"\n📊 Final stats: {tester.events_sent} events sent")
        tester.cleanup()


if __name__ == "__main__":
    main()