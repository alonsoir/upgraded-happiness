#!/usr/bin/env python3
"""
Simulador de eventos para testear la cadena ZeroMQ del sistema SCADA
Simula eventos como los que generaría el agente promiscuo
"""

import zmq
import time
import json
import random
import threading
from datetime import datetime
from typing import Dict, List, Optional


class SCADAEventSimulator:
    def __init__(self):
        self.context = zmq.Context()
        self.running = False
        self.events_sent = 0

    def create_mock_network_event(self) -> Dict:
        """Crear evento de red simulado (como los de scapy)"""

        protocols = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTPS", "TLS"]
        ips = ["192.168.1.10", "10.0.0.5", "172.16.0.100", "8.8.8.8"]
        ports = [80, 443, 22, 53, 8080, 3389, 502]  # 502 es Modbus

        event = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": random.choice(ips),
            "dest_ip": random.choice(ips),
            "protocol": random.choice(protocols),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice(ports),
            "packet_size": random.randint(64, 1500),
            "flags": random.choice(["SYN", "ACK", "FIN", "RST", "PSH"]),
            "event_type": "network_capture",
            "agent_id": "test_agent_001"
        }

        # Agregar campos específicos según protocolo
        if event["protocol"] == "DNS":
            event["dns_query"] = random.choice(["google.com", "microsoft.com", "github.com"])
        elif event["protocol"] == "HTTPS":
            event["tls_version"] = "1.3"
            event["cipher_suite"] = "TLS_AES_256_GCM_SHA384"
        elif event["dst_port"] == 502:  # Modbus
            event["modbus_function"] = random.choice([1, 2, 3, 4, 5, 6])
            event["alert_level"] = "HIGH"

        return event

    def create_mock_security_event(self) -> Dict:
        """Crear evento de seguridad simulado"""

        threats = [
            "port_scan_detected",
            "suspicious_connection",
            "protocol_anomaly",
            "connection_flood",
            "modbus_unauthorized_access"
        ]

        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "security_alert",
            "threat_type": random.choice(threats),
            "source_ip": f"192.168.1.{random.randint(1, 254)}",
            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            "description": "Simulated security event for testing",
            "agent_id": "test_agent_001"
        }

        return event

    def send_events_to_broker(self, port: int, num_events: int = 10,
                              interval: float = 1.0, event_type: str = "network") -> None:
        """Enviar eventos simulados al broker ZeroMQ"""

        try:
            # Configurar socket como publisher
            socket = self.context.socket(zmq.PUB)
            socket.bind(f"tcp://*:{port}")

            print(f"📡 Enviando eventos simulados al puerto {port}")
            print(f"   Eventos: {num_events}")
            print(f"   Intervalo: {interval}s")
            print(f"   Tipo: {event_type}")
            print("-" * 50)

            # Dar tiempo para establecer conexión
            time.sleep(2)

            for i in range(num_events):
                if not self.running:
                    break

                # Crear evento según tipo
                if event_type == "network":
                    event = self.create_mock_network_event()
                elif event_type == "security":
                    event = self.create_mock_security_event()
                else:
                    event = self.create_mock_network_event()

                # Serializar evento
                event_json = json.dumps(event)

                # Enviar evento
                topic = event.get("event_type", "unknown")
                socket.send_string(f"{topic} {event_json}")

                self.events_sent += 1

                # Mostrar progreso
                timestamp = event["timestamp"].split("T")[1][:8]
                print(f"✅ [{i + 1:3d}/{num_events}] [{timestamp}] Evento enviado: {topic}")

                if i < num_events - 1:  # No esperar después del último
                    time.sleep(interval)

            print(f"\n🎉 Enviados {self.events_sent} eventos exitosamente")

        except Exception as e:
            print(f"❌ Error enviando eventos: {e}")
        finally:
            socket.close()

    def test_broker_connectivity(self) -> bool:
        """Probar si el broker está escuchando"""

        print("🔍 Probando conectividad con broker...")

        for port in [5555, 5556]:
            try:
                # Intentar conectar como subscriber
                socket = self.context.socket(zmq.SUB)
                socket.setsockopt(zmq.SUBSCRIBE, b"")
                socket.setsockopt(zmq.RCVTIMEO, 3000)
                socket.connect(f"tcp://localhost:{port}")

                # Intentar recibir un mensaje
                try:
                    message = socket.recv_string(zmq.NOBLOCK)
                    print(f"✅ Puerto {port}: ACTIVO - Recibiendo datos")
                except zmq.Again:
                    print(f"⚠️  Puerto {port}: CONECTADO pero sin datos")

                socket.close()

            except Exception as e:
                print(f"❌ Puerto {port}: ERROR - {e}")

        return True

    def simulate_agent_behavior(self, duration: int = 60) -> None:
        """Simular comportamiento completo del agente promiscuo"""

        print(f"🤖 Simulando agente promiscuo por {duration} segundos...")

        # Configurar como publisher en puerto temporal
        pub_port = 55999
        socket = self.context.socket(zmq.PUB)
        socket.bind(f"tcp://*:{pub_port}")

        print(f"📡 Publisher activo en puerto {pub_port}")
        print("   Generando eventos como agente real...")
        print("   Ctrl+C para detener\n")

        start_time = time.time()
        event_count = 0

        try:
            while (time.time() - start_time) < duration and self.running:
                # Alternar entre eventos de red y seguridad
                if event_count % 5 == 0:
                    event = self.create_mock_security_event()
                else:
                    event = self.create_mock_network_event()

                # Enviar evento
                topic = event.get("event_type", "unknown")
                event_json = json.dumps(event)
                socket.send_string(f"{topic} {event_json}")

                event_count += 1

                # Mostrar cada 10 eventos
                if event_count % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = event_count / elapsed
                    print(f"📊 {event_count} eventos enviados ({rate:.1f}/s)")

                # Simular rate variable (como tráfico real)
                sleep_time = random.uniform(0.1, 2.0)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            print("\n🛑 Simulación interrumpida")
        finally:
            socket.close()
            elapsed = time.time() - start_time
            rate = event_count / elapsed if elapsed > 0 else 0
            print(f"\n📈 Resumen: {event_count} eventos en {elapsed:.1f}s ({rate:.1f}/s)")

    def run_interactive_menu(self):
        """Menú interactivo para testing"""

        print("🔧 Simulador de Eventos ZeroMQ - Sistema SCADA")
        print("=" * 55)
        print("1. Test de conectividad básica")
        print("2. Enviar eventos de prueba (10 eventos)")
        print("3. Simular agente promiscuo (1 minuto)")
        print("4. Stress test (100 eventos rápidos)")
        print("5. Simulación personalizada")
        print("=" * 55)

        try:
            choice = input("Seleccione opción (1-5): ").strip()

            if choice == "1":
                self.test_broker_connectivity()

            elif choice == "2":
                self.running = True
                port = 55998  # Puerto temporal para evitar conflictos
                print(f"\n🧪 Enviando 10 eventos de prueba...")
                print(f"   Puede monitorearlo con: tcp://localhost:{port}")
                self.send_events_to_broker(port, 10, 1.0, "network")

            elif choice == "3":
                self.running = True
                self.simulate_agent_behavior(60)

            elif choice == "4":
                self.running = True
                port = 55997
                print(f"\n⚡ Stress test - 100 eventos rápidos...")
                self.send_events_to_broker(port, 100, 0.1, "network")

            elif choice == "5":
                port = int(input("Puerto destino: "))
                num_events = int(input("Número de eventos: "))
                interval = float(input("Intervalo (segundos): "))
                event_type = input("Tipo (network/security): ").strip()

                self.running = True
                self.send_events_to_broker(port, num_events, interval, event_type)

            else:
                print("❌ Opción inválida")

        except KeyboardInterrupt:
            print("\n🛑 Operación cancelada")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            self.running = False


def main():
    """Función principal"""
    simulator = SCADAEventSimulator()

    try:
        simulator.run_interactive_menu()
    finally:
        simulator.context.term()
        print("\n🏁 Simulador cerrado")


if __name__ == "__main__":
    main()