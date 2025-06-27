import zmq
import sys
import os
from scapy.all import sniff, IP, TCP

# Agregar el directorio raíz al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.protocols.protobuf import network_event_pb2

# Configura el broker
broker_address = "tcp://localhost:5555"
context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.connect(broker_address)

# Ajusta la interfaz de red (usa 'ifconfig' para verificar, normalmente 'en0' en Wi-Fi)
interface = "en0"


def capture_traffic(pkt):
    if pkt.haslayer(IP):
        # Crear el evento usando la clase generada por protobuf
        event = network_event_pb2.NetworkEvent()
        event.event_id = "evt_" + str(pkt.time)
        event.timestamp = int(pkt.time * 1e9)  # nanosegundos
        event.source_ip = pkt['IP'].src
        event.target_ip = pkt['IP'].dst
        event.packet_size = len(pkt)
        event.dest_port = pkt['TCP'].dport if pkt.haslayer(TCP) else 0
        event.src_port = pkt['TCP'].sport if pkt.haslayer(TCP) else 0
        event.agent_id = "macos-agent"

        print(f"Capturado: {event.source_ip} -> {event.target_ip}")
        socket.send(event.SerializeToString())


if __name__ == "__main__":
    print("Iniciando captura de tráfico...")
    print(f"Interfaz: {interface}")
    print(f"Broker: {broker_address}")

    # Ajusta permisos de red en macOS
    os.system("sudo chmod 644 /dev/bpf*")

    try:
        sniff(iface=interface, prn=capture_traffic, filter="ip", store=0)
    except KeyboardInterrupt:
        print("\nDeteniendo captura...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        socket.close()
        context.term()