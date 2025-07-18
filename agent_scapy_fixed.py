#!/usr/bin/env python3
"""
Agente de captura de tráfico con Scapy - Versión corregida
"""


# Auto-discovery functions
import socket
import time

import zmq


def find_available_port(start_port=5555, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
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


import os
import sys
import time
import traceback

import zmq
from scapy.all import IP, TCP, UDP, sniff

# Agregar el directorio raíz al path para las importaciones
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, root_dir)

try:
    # Importar con la ruta corregida (protobuf, no protobuff)
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado exitosamente")
except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    print("Verifica que exista: src/protocols/protobuf/network_event_pb2.py")
    sys.exit(1)


class NetworkAgent:
    def __init__(self, broker_address="tcp://localhost:5555", interface="en0"):
        self.broker_address = broker_address
        self.interface = interface
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.packet_count = 0

        print(f"Conectando al broker: {broker_address}")
        try:
            self.socket.connect(broker_address)
            print("✅ Conectado al broker ZeroMQ")
        except Exception as e:
            print(f"❌ Error conectando al broker: {e}")
            raise

    def capture_traffic(self, pkt):
        """Procesar cada paquete capturado"""
        try:
            if pkt.haslayer(IP):
                # Crear evento protobuf
                event = network_event_pb2.NetworkEvent()
                event.event_id = f"evt_{int(time.time() * 1000)}_{self.packet_count}"
                event.timestamp = int(pkt.time * 1e9)  # nanosegundos
                event.source_ip = pkt["IP"].src
                event.target_ip = pkt["IP"].dst
                event.packet_size = len(pkt)
                event.agent_id = "macos-scapy-agent"

                # Detectar puertos si es TCP o UDP
                if pkt.haslayer(TCP):
                    event.dest_port = pkt["TCP"].dport
                    event.src_port = pkt["TCP"].sport
                elif pkt.haslayer(UDP):
                    event.dest_port = pkt["UDP"].dport
                    event.src_port = pkt["UDP"].sport
                else:
                    event.dest_port = 0
                    event.src_port = 0

                # Enviar al broker
                self.socket.send(event.SerializeToString())

                # Log cada 100 paquetes
                self.packet_count += 1
                if self.packet_count % 100 == 0:
                    print(f"Paquetes procesados: {self.packet_count}")
                elif self.packet_count <= 10:  # Mostrar los primeros 10
                    protocol = (
                        "TCP"
                        if pkt.haslayer(TCP)
                        else "UDP"
                        if pkt.haslayer(UDP)
                        else "OTHER"
                    )
                    print(
                        f"[{self.packet_count}] {protocol}: {event.source_ip}:{event.src_port} -> {event.target_ip}:{event.dest_port}"
                    )

        except Exception as e:
            print(f"Error procesando paquete: {e}")
            traceback.print_exc()

    def start_capture(self):
        """Iniciar captura de tráfico"""
        print(f"Iniciando captura en interfaz: {self.interface}")
        print("Presiona Ctrl+C para detener...")

        try:
            # En macOS, ajustar permisos BPF si es necesario
            if sys.platform == "darwin":
                os.system("sudo chmod 644 /dev/bpf* 2>/dev/null")

            # Iniciar captura
            sniff(
                iface=self.interface,
                prn=self.capture_traffic,
                filter="ip",  # Solo paquetes IP
                store=0,  # No almacenar en memoria
                stop_filter=lambda x: False,  # Capturar indefinidamente
            )

        except KeyboardInterrupt:
            print(f"\n🛑 Captura detenida. Total paquetes: {self.packet_count}")
        except PermissionError:
            print("❌ Error de permisos. Ejecuta con sudo:")
            print("sudo python agent_scapy_fixed.py")
        except Exception as e:
            print(f"❌ Error durante captura: {e}")
            traceback.print_exc()
        finally:
            self.cleanup()

    def cleanup(self):
        """Limpiar recursos"""
        print("Cerrando conexiones...")
        self.socket.close()
        self.context.term()


def main():
    """Función principal"""
    print("=== AGENTE DE CAPTURA DE TRÁFICO ===")

    # Configuración
    broker_address = os.getenv("BROKER_ADDRESS", "tcp://localhost:5555")
    interface = os.getenv("NETWORK_INTERFACE", "en0")

    # Verificar interfaz
    print(f"Interfaz configurada: {interface}")
    print("💡 Para ver interfaces disponibles: ifconfig")
    print("💡 Para cambiar interfaz: export NETWORK_INTERFACE=tu_interfaz")
    print("")

    try:
        # Crear y ejecutar agente
        agent = NetworkAgent(broker_address, interface)
        agent.start_capture()

    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
